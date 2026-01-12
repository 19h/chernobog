#include "indirect_call.h"
#include "../analysis/cfg_analysis.h"
#include "../analysis/stack_tracker.h"

//--------------------------------------------------------------------------
// File-based debug logging
//--------------------------------------------------------------------------
#include "../../common/compat.h"

static void icall_debug(const char *fmt, ...) {
#ifndef _WIN32
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = qvsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    
    int fd = open("/tmp/indirect_call_debug.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        write(fd, buf, len);
        close(fd);
    }
#else
    (void)fmt;
#endif
}

//--------------------------------------------------------------------------
// Detection - look for indirect call patterns
//
// Pattern 1: icall with computed target
// Pattern 2: call with target loaded from table and modified
//--------------------------------------------------------------------------
bool indirect_call_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    icall_debug("[indirect_call] detect() called for func 0x%llx\n", 
                (unsigned long long)mba->entry_ea);

    // Look for icall instructions or calls with complex computed targets
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check for icall (indirect call)
            if (ins->opcode == m_icall) {
                icall_debug("[indirect_call] Found m_icall in block %d\n", i);
                return true;
            }

            // Check for call with computed target
            // A direct call has l operand as mop_v (global) or mop_a (address)
            // A computed call has l operand as mop_r (register) or mop_d (result of computation)
            if (ins->opcode == m_call) {
                if (ins->l.t == mop_r || ins->l.t == mop_d) {
                    icall_debug("[indirect_call] Found m_call with computed target in block %d\n", i);
                    return true;
                }
                // Check for direct call to frameless continuation
                // These are obfuscated control flow that IDA converted to calls
                if (ins->l.t == mop_v) {
                    ea_t call_target = ins->l.g;
                    if (frameless_continuation_t::is_frameless_continuation(call_target)) {
                        icall_debug("[indirect_call] Found call to frameless continuation at 0x%llx in block %d\n",
                                    (unsigned long long)call_target, i);
                        return true;
                    }
                }
            }
        }
    }

    // Also check for the ctree pattern:
    // Global table pointer that looks like it's used for indirect calls
    // This is a heuristic based on Hikari's typical naming
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                // Check if this looks like a code pointer table
                uint64_t first_val = 0;
                if (get_bytes(&first_val, 8, ea) == 8) {
                    if (first_val != 0 && is_code(get_flags((ea_t)first_val))) {
                        // This might be a code pointer table
                        // Check if it's referenced in the function
                        xrefblk_t xb;
                        for (bool ok = xb.first_to(ea, XREF_DATA); ok; ok = xb.next_to()) {
                            if (xb.from >= mba->entry_ea) {
                                func_t *func = get_func(mba->entry_ea);
                                if (func && xb.from < func->end_ea) {
                                    icall_debug("[indirect_call] Found code pointer table at 0x%llx referenced from function\n",
                                                (unsigned long long)ea);
                                    return true;
                                }
                            }
                        }
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    icall_debug("[indirect_call] No indirect call patterns detected\n");
    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int indirect_call_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    icall_debug("[indirect_call] run() called for func 0x%llx, maturity=%d\n",
                (unsigned long long)mba->entry_ea, mba->maturity);

    // We need MMAT_CALLS (4) or later to have mcallinfo for modifying calls
    // At earlier maturities, we just resolve and annotate
    bool can_modify = (mba->maturity >= MMAT_CALLS);
    icall_debug("[indirect_call] can_modify=%d (maturity %d, need %d)\n",
                can_modify, mba->maturity, MMAT_CALLS);

    int total_changes = 0;

    // Find all indirect calls
    auto icalls = find_indirect_calls(mba);
    icall_debug("[indirect_call] Found %zu indirect calls\n", icalls.size());

    for (auto &ic : icalls) {
        mblock_t *blk = mba->get_mblock(ic.block_idx);
        if (!blk)
            continue;

        // Try to resolve the call
        if (ic.is_resolved) {
            int changes = replace_indirect_call(mba, blk, ic, ctx);
            if (changes > 0) {
                total_changes += changes;
                icall_debug("[indirect_call] Block %d: resolved indirect call to 0x%llx (%s)\n",
                            ic.block_idx, (unsigned long long)ic.resolved_target,
                            ic.target_name.c_str());
            }
        } else {
            // Annotate what we found
            annotate_indirect_call(blk, ic);
            icall_debug("[indirect_call] Block %d: could not resolve, annotated\n", ic.block_idx);
        }
    }

    icall_debug("[indirect_call] Total changes: %d\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find all indirect calls in the function
//
// NEW APPROACH: Also look for the Hikari pattern directly:
//   1. mov stkvar, &table (global table address to stack)
//   2. ldx from that stkvar with offset (load table[index])
//   3. sub loaded_val, #offset (apply obfuscation offset)
//   4. Eventually used in icall/call
//
// At early maturity, we can extract the pattern before it gets folded.
//--------------------------------------------------------------------------
std::vector<indirect_call_handler_t::indirect_call_t>
indirect_call_handler_t::find_indirect_calls(mbl_array_t *mba) {
    std::vector<indirect_call_t> result;

    if (!mba)
        return result;

    // First pass: look for explicit icall/call with computed target
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            bool is_indirect = false;

            // Check for icall
            if (ins->opcode == m_icall) {
                is_indirect = true;
            }
            // Check for call with computed target
            else if (ins->opcode == m_call) {
                if (ins->l.t == mop_r || ins->l.t == mop_d) {
                    is_indirect = true;
                }
                // Check for direct call to frameless continuation function
                // These are obfuscated jumps that IDA converted to calls
                else if (ins->l.t == mop_v) {
                    ea_t call_target = ins->l.g;
                    if (frameless_continuation_t::is_frameless_continuation(call_target)) {
                        icall_debug("[indirect_call] Found call to frameless continuation: 0x%llx\n",
                                    (unsigned long long)call_target);
                        
                        // Build caller context and try to resolve
                        caller_context_t caller_ctx = frameless_continuation_t::build_caller_context(mba, blk);
                        caller_ctx.caller_func = mba->entry_ea;
                        caller_ctx.callee_func = call_target;
                        
                        ea_t final_target = frameless_continuation_t::resolve_continuation_jump(call_target, caller_ctx);
                        
                        if (final_target != BADADDR && is_code(get_flags(final_target))) {
                            icall_debug("[indirect_call] Resolved frameless continuation: 0x%llx -> 0x%llx\n",
                                       (unsigned long long)call_target, (unsigned long long)final_target);
                            
                            // Create an indirect_call_t for this resolved call
                            indirect_call_t ic;
                            ic.block_idx = i;
                            ic.call_insn = ins;
                            ic.table_addr = BADADDR;
                            ic.table_index = -1;
                            ic.offset = 0;
                            ic.resolved_target = final_target;
                            ic.is_resolved = true;
                            ic.is_frameless_continuation = true;
                            ic.continuation_target = call_target;
                            
                            // Get name of resolved target
                            qstring name;
                            if (get_name(&name, final_target) > 0) {
                                ic.target_name = name.c_str();
                            }
                            
                            result.push_back(ic);
                            continue;  // Don't fall through to regular handling
                        }
                    }
                }
            }

            if (is_indirect) {
                indirect_call_t ic;
                ic.block_idx = i;
                ic.call_insn = ins;
                ic.table_addr = BADADDR;
                ic.table_index = -1;
                ic.offset = 0;
                ic.resolved_target = BADADDR;
                ic.is_resolved = false;

                // Try to analyze and resolve
                if (analyze_indirect_call(blk, ins, &ic)) {
                    icall_debug("[indirect_call] Analyzed call in block %d: table=0x%llx, index=%d, offset=%lld\n",
                                i, (unsigned long long)ic.table_addr, ic.table_index, (long long)ic.offset);
                }

                result.push_back(ic);
            }
        }
    }

    // If no icalls found, try to find the Hikari pattern at early maturity
    // Look for: sub reg, ldx_result, #large_offset
    if (result.empty()) {
        icall_debug("[indirect_call] No icall found, scanning for Hikari sub pattern...\n");
        icall_debug("[indirect_call] Maturity=%d, num_blocks=%d\n", mba->maturity, mba->qty);
        
        // Dump all subs to see what's there
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk) continue;
            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                if (ins->opcode == m_sub) {
                    icall_debug("[indirect_call]   sub at 0x%llx: l.t=%d r.t=%d d.t=%d",
                                (unsigned long long)ins->ea, ins->l.t, ins->r.t, ins->d.t);
                    if (ins->r.t == mop_n)
                        icall_debug(" r=#0x%llx", (unsigned long long)ins->r.nnn->value);
                    icall_debug("\n");
                }
            }
        }
        
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk) continue;
            
            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                // Look for: sub reg, ?, #large_const
                // where large_const looks like an obfuscation offset (> 0x10000)
                if (ins->opcode == m_sub && ins->r.t == mop_n) {
                    int64_t offset = ins->r.nnn->value;
                    if (offset > 0x10000 && offset < 0x1000000) {
                        icall_debug("[indirect_call] Found potential offset sub at 0x%llx: offset=%lld\n",
                                    (unsigned long long)ins->ea, (long long)offset);
                        
                        // This might be part of the pattern - create a placeholder
                        indirect_call_t ic;
                        ic.block_idx = i;
                        ic.call_insn = ins;  // Not actually a call, but the sub
                        ic.table_addr = BADADDR;
                        ic.table_index = -1;
                        ic.offset = offset;
                        ic.resolved_target = BADADDR;
                        ic.is_resolved = false;
                        
                        // Try to find table address from mov instructions
                        for (minsn_t *prev = blk->head; prev != ins; prev = prev->next) {
                            if (prev->opcode == m_mov && prev->l.t == mop_a && prev->l.a) {
                                if (prev->l.a->t == mop_v) {
                                    ea_t global = prev->l.a->g;
                                    uint64_t first_entry = 0;
                                    if (get_bytes(&first_entry, 8, global) == 8) {
                                        if (first_entry != 0 && is_code(get_flags((ea_t)first_entry))) {
                                            ic.table_addr = global;
                                            icall_debug("[indirect_call]   Table candidate: 0x%llx\n",
                                                        (unsigned long long)global);
                                        }
                                    }
                                }
                            }
                            // Look for ldx with constant offset
                            if (prev->opcode == m_ldx && prev->r.t == mop_n) {
                                ic.table_index = (int)(prev->r.nnn->value / 8);
                                icall_debug("[indirect_call]   Index from ldx: %d\n", ic.table_index);
                            }
                        }
                        
                        // If we have all components, try to resolve
                        if (ic.table_addr != BADADDR && ic.table_index >= 0) {
                            ic.resolved_target = compute_target(ic.table_addr, ic.table_index, ic.offset);
                            if (ic.resolved_target != BADADDR) {
                                ic.is_resolved = true;
                                get_name(&ic.target_name, ic.resolved_target);
                                icall_debug("[indirect_call]   RESOLVED: 0x%llx (%s)\n",
                                            (unsigned long long)ic.resolved_target,
                                            ic.target_name.c_str());
                                result.push_back(ic);
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze an indirect call to extract table/index/offset
//
// We're looking for patterns like:
//   sub reg1, ldx(...), #offset   ; or
//   add reg1, ldx(...), #-offset
// followed by:
//   icall reg1
//
// Or at higher levels:
//   reg1 = table[index] - offset
//   call reg1
//--------------------------------------------------------------------------
bool indirect_call_handler_t::analyze_indirect_call(mblock_t *blk, minsn_t *call_insn,
                                                    indirect_call_t *out) {
    if (!blk || !call_insn || !out)
        return false;

    icall_debug("[indirect_call] Analyzing call at ea=0x%llx, opcode=%d\n", 
                (unsigned long long)call_insn->ea, call_insn->opcode);
    icall_debug("[indirect_call]   l.t=%d, r.t=%d, d.t=%d\n", 
                call_insn->l.t, call_insn->r.t, call_insn->d.t);
    if (call_insn->l.t == mop_r) {
        icall_debug("[indirect_call]   l.r=%d (target register)\n", call_insn->l.r);
    }
    // Dump all instructions in ALL blocks to find the target computation
    icall_debug("[indirect_call]   Dumping all blocks looking for table reference:\n");
    mbl_array_t *mba_dump = blk->mba;
    for (int bi = 0; bi < mba_dump->qty; bi++) {
        mblock_t *dump_blk = mba_dump->get_mblock(bi);
        if (!dump_blk) continue;
        icall_debug("[indirect_call]   Block %d:\n", bi);
        for (minsn_t *ins = dump_blk->head; ins; ins = ins->next) {
            icall_debug("[indirect_call]     ea=%llx op=%d l.t=%d r.t=%d d.t=%d",
                        (unsigned long long)ins->ea, ins->opcode, ins->l.t, ins->r.t, ins->d.t);
            if (ins->d.t == mop_r)
                icall_debug(" -> reg%d", ins->d.r);
            if (ins->d.t == mop_f)
                icall_debug(" -> stkvar");
            if (ins->l.t == mop_r)
                icall_debug(" from reg%d", ins->l.r);
            if (ins->l.t == mop_n)
                icall_debug(" from #0x%llx", (unsigned long long)ins->l.nnn->value);
            if (ins->l.t == mop_v)
                icall_debug(" from global 0x%llx", (unsigned long long)ins->l.g);
            if (ins->l.t == mop_a && ins->l.a) {
                icall_debug(" from &");
                if (ins->l.a->t == mop_v)
                    icall_debug("global 0x%llx", (unsigned long long)ins->l.a->g);
                else
                    icall_debug("(type %d)", ins->l.a->t);
            }
            if (ins->r.t == mop_a && ins->r.a) {
                icall_debug(" r=&");
                if (ins->r.a->t == mop_v)
                    icall_debug("global 0x%llx", (unsigned long long)ins->r.a->g);
            }
            // For ldx, the base address comes from r operand
            if (ins->opcode == m_ldx) {
                icall_debug(" [ldx: base.t=%d, idx.t=%d]", ins->l.t, ins->r.t);
            }
            // Check for sub instruction with table pattern
            if (ins->opcode == m_sub || ins->opcode == m_ldx) {
                icall_debug(" [INTERESTING]");
            }
            icall_debug("\n");
        }
    }

    // For m_icall, the structure depends on maturity level
    // At early maturity: icall l_operand (target in l)
    // At later maturity: might be different
    // 
    // Let's check all operands to understand the structure
    mop_t *target_op = nullptr;
    
    if (call_insn->opcode == m_icall) {
        // m_icall: target address is typically in l operand
        if (call_insn->l.t != mop_z) {
            target_op = &call_insn->l;
            icall_debug("[indirect_call]   Using l operand (type %d)\n", call_insn->l.t);
        } else if (call_insn->d.t != mop_z) {
            target_op = &call_insn->d;
            icall_debug("[indirect_call]   Using d operand (type %d)\n", call_insn->d.t);
        }
    } else if (call_insn->opcode == m_call) {
        if (call_insn->l.t == mop_d || call_insn->l.t == mop_r) {
            target_op = &call_insn->l;
            icall_debug("[indirect_call]   Using call l operand (type %d)\n", call_insn->l.t);
        }
    }

    if (!target_op) {
        icall_debug("[indirect_call]   No target operand found (all types: l=%d, r=%d, d=%d)\n",
                    call_insn->l.t, call_insn->r.t, call_insn->d.t);
        return false;
    }

    icall_debug("[indirect_call]   Target operand type: %d\n", target_op->t);

    // Trace back to find the computation
    ea_t table_addr = BADADDR;
    int table_index = -1;
    int64_t offset = 0;

    if (trace_call_target(blk, call_insn, &table_addr, &table_index, &offset)) {
        out->table_addr = table_addr;
        out->table_index = table_index;
        out->offset = offset;

        icall_debug("[indirect_call]   Traced: table=0x%llx, index=%d, offset=%lld\n",
                    (unsigned long long)table_addr, table_index, (long long)offset);

        // If we have a constant index, resolve the target
        if (table_addr != BADADDR && table_index >= 0) {
            out->resolved_target = compute_target(table_addr, table_index, offset);
            if (out->resolved_target != BADADDR) {
                out->is_resolved = true;
                get_name(&out->target_name, out->resolved_target);
                icall_debug("[indirect_call]   Resolved to 0x%llx (%s)\n",
                            (unsigned long long)out->resolved_target,
                            out->target_name.c_str());
            }
        }

        return true;
    }

    icall_debug("[indirect_call]   Could not trace call target\n");
    return false;
}

//--------------------------------------------------------------------------
// XOR key extraction info - tracks XOR operations with global variables
//--------------------------------------------------------------------------
struct xor_key_info_t {
    ea_t global_addr;           // Address of global variable
    uint64_t immediate;         // Immediate value XOR'd with global
    uint64_t global_value;      // Value read from global at analysis time
    uint64_t result;            // immediate XOR global_value
    mreg_t dest_reg;            // Destination register
    bool has_neg;               // Whether result is negated
    bool valid;                 // Whether we successfully resolved this
    
    xor_key_info_t() : global_addr(BADADDR), immediate(0), global_value(0),
                       result(0), dest_reg(mr_none), has_neg(false), valid(false) {}
};

//--------------------------------------------------------------------------
// Read a value from a global variable
//--------------------------------------------------------------------------
static bool read_global_value(ea_t addr, uint64_t *out, int size = 4) {
    if (addr == BADADDR || !out)
        return false;
    
    *out = 0;
    if (get_bytes(out, size, addr) != size)
        return false;
    
    // Sign extend for 32-bit values
    if (size == 4) {
        int32_t signed_val = (int32_t)*out;
        *out = (uint64_t)(int64_t)signed_val;
    }
    
    return true;
}

//--------------------------------------------------------------------------
// Find XOR patterns with global variables in microcode
// Tracks data flow: load from global -> XOR with immediate
//--------------------------------------------------------------------------
static std::vector<xor_key_info_t> find_xor_with_globals(mbl_array_t *mba) {
    std::vector<xor_key_info_t> results;
    
    if (!mba)
        return results;
    
    // Track register values for data flow
    std::map<mreg_t, uint64_t> reg_immediates;  // reg -> immediate value
    std::map<mreg_t, ea_t> reg_globals;         // reg -> global address
    
    for (int bi = 0; bi < mba->qty; bi++) {
        mblock_t *blk = mba->get_mblock(bi);
        if (!blk) continue;
        
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Track mov of immediate to register
            if (ins->opcode == m_mov && ins->d.t == mop_r) {
                if (ins->l.t == mop_n) {
                    reg_immediates[ins->d.r] = ins->l.nnn->value;
                    icall_debug("[indirect_call]     Tracking: reg%d = 0x%llx (imm)\n",
                                ins->d.r, (unsigned long long)ins->l.nnn->value);
                } else if (ins->l.t == mop_v) {
                    // Loading from global
                    reg_globals[ins->d.r] = ins->l.g;
                    icall_debug("[indirect_call]     Tracking: reg%d = [0x%llx] (global)\n",
                                ins->d.r, (unsigned long long)ins->l.g);
                }
            }
            
            // Track ldx (load) from global
            if (ins->opcode == m_ldx && ins->d.t == mop_r) {
                if (ins->r.t == mop_v) {
                    reg_globals[ins->d.r] = ins->r.g;
                    icall_debug("[indirect_call]     Tracking: reg%d = ldx [0x%llx]\n",
                                ins->d.r, (unsigned long long)ins->r.g);
                } else if (ins->l.t == mop_v) {
                    reg_globals[ins->d.r] = ins->l.g;
                    icall_debug("[indirect_call]     Tracking: reg%d = ldx [0x%llx] (from l)\n",
                                ins->d.r, (unsigned long long)ins->l.g);
                }
            }
            
            // Look for XOR patterns
            if (ins->opcode == m_xor && ins->d.t == mop_r) {
                xor_key_info_t info;
                info.dest_reg = ins->d.r;
                
                // Pattern 1: xor reg_with_global, #imm
                // Pattern 2: xor #imm, reg_with_global
                // Pattern 3: xor reg1, reg2 where one is from global
                
                if (ins->l.t == mop_n && ins->r.t == mop_v) {
                    // xor #imm, global
                    info.immediate = ins->l.nnn->value;
                    info.global_addr = ins->r.g;
                } else if (ins->r.t == mop_n && ins->l.t == mop_v) {
                    // xor global, #imm
                    info.immediate = ins->r.nnn->value;
                    info.global_addr = ins->l.g;
                } else if (ins->l.t == mop_r && ins->r.t == mop_n) {
                    // xor reg, #imm - check if reg was loaded from global
                    if (reg_globals.count(ins->l.r)) {
                        info.global_addr = reg_globals[ins->l.r];
                        info.immediate = ins->r.nnn->value;
                    }
                } else if (ins->r.t == mop_r && ins->l.t == mop_n) {
                    // xor #imm, reg
                    if (reg_globals.count(ins->r.r)) {
                        info.global_addr = reg_globals[ins->r.r];
                        info.immediate = ins->l.nnn->value;
                    }
                } else if (ins->l.t == mop_r && ins->r.t == mop_r) {
                    // xor reg1, reg2 - one might be immediate, other global
                    if (reg_immediates.count(ins->l.r) && reg_globals.count(ins->r.r)) {
                        info.immediate = reg_immediates[ins->l.r];
                        info.global_addr = reg_globals[ins->r.r];
                    } else if (reg_immediates.count(ins->r.r) && reg_globals.count(ins->l.r)) {
                        info.immediate = reg_immediates[ins->r.r];
                        info.global_addr = reg_globals[ins->l.r];
                    }
                }
                
                // If we found a valid XOR with global, read the global value
                if (info.global_addr != BADADDR) {
                    uint64_t gval = 0;
                    if (read_global_value(info.global_addr, &gval, 4)) {
                        info.global_value = gval;
                        info.result = info.immediate ^ info.global_value;
                        info.valid = true;
                        
                        icall_debug("[indirect_call]     XOR: 0x%llx ^ [0x%llx]=0x%llx -> 0x%llx\n",
                                   (unsigned long long)info.immediate,
                                   (unsigned long long)info.global_addr,
                                   (unsigned long long)info.global_value,
                                   (unsigned long long)info.result);
                        
                        results.push_back(info);
                    }
                }
                
                // Update register tracking for the result
                reg_immediates.erase(ins->d.r);
                reg_globals.erase(ins->d.r);
            }
            
            // Track NEG operations (negate result)
            if (ins->opcode == m_neg && ins->d.t == mop_r) {
                // Find if this negates a previous XOR result
                for (auto &xinfo : results) {
                    if (xinfo.dest_reg == ins->l.r || xinfo.dest_reg == ins->d.r) {
                        xinfo.has_neg = true;
                        xinfo.result = (uint64_t)(-(int64_t)xinfo.result);
                        xinfo.dest_reg = ins->d.r;
                        icall_debug("[indirect_call]     NEG: result = %lld\n",
                                   (long long)(int64_t)xinfo.result);
                    }
                }
            }
            
            // Clear register tracking on other writes
            if (ins->d.t == mop_r && ins->opcode != m_xor && ins->opcode != m_neg) {
                if (ins->opcode != m_mov || (ins->l.t != mop_n && ins->l.t != mop_v)) {
                    reg_immediates.erase(ins->d.r);
                    reg_globals.erase(ins->d.r);
                }
            }
        }
    }
    
    return results;
}

//--------------------------------------------------------------------------
// Binary-level pattern scanner for Hikari IndirectCall
// Scans x86-64 bytes directly to find XOR patterns before IDA optimizes them
//
// Pattern we're looking for in the caller:
//   mov  rax, [rbp+var_XXX]      ; Load table pointer  
//   movsxd rdx, dword [global1]  ; Load index source
//   xor  rdx, CONST1             ; Compute index
//   mov  esi, CONST2             
//   xor  esi, dword [global2]    ; Compute offset source
//   neg  esi                     ; Negate
//   movsxd rsi, esi              ; Sign extend
//   add  rsi, [rax+rdx*8]        ; target = table[index*8] + offset
//   jmp  [rbp+var_YYY]           ; Indirect jump
//--------------------------------------------------------------------------
struct hikari_pattern_t {
    ea_t table_ptr_global;      // Global holding table pointer (e.g., off_10064C180)
    ea_t index_global;          // Global for index computation
    uint32_t index_xor_const;   // XOR constant for index
    ea_t offset_global;         // Global for offset computation  
    uint32_t offset_xor_const;  // XOR constant for offset
    bool has_neg;               // Whether offset is negated
    bool valid;
    
    hikari_pattern_t() : table_ptr_global(BADADDR), index_global(BADADDR),
                          index_xor_const(0), offset_global(BADADDR),
                          offset_xor_const(0), has_neg(false), valid(false) {}
};

static hikari_pattern_t scan_binary_for_pattern(ea_t func_start, ea_t func_end) {
    hikari_pattern_t result;
    
    // Scan for XOR with 32-bit immediate: 81 F? XX XX XX XX (xor r32, imm32)
    // or 35 XX XX XX XX (xor eax, imm32)
    insn_t insn;
    ea_t ea = func_start;
    
    std::vector<std::pair<ea_t, uint32_t>> xor_immediates;  // ea -> xor constant
    std::vector<ea_t> neg_locations;
    ea_t table_lea = BADADDR;
    
    while (ea < func_end) {
        if (decode_insn(&insn, ea) == 0)
            break;
        
        // Look for LEA with global (table pointer)
        // Pattern: 48 8D 0D XX XX XX XX (lea rcx, [rip+disp])
        uint8_t b0 = get_byte(ea);
        uint8_t b1 = get_byte(ea + 1);
        uint8_t b2 = get_byte(ea + 2);
        
        if (b0 == 0x48 && b1 == 0x8D) {
            // Might be LEA r64, [rip+disp32]
            uint8_t modrm = b2;
            if ((modrm & 0xC7) == 0x05) {  // RIP-relative
                int32_t disp = get_dword(ea + 3);
                ea_t target = ea + 7 + disp;
                // Check if it's a pointer to code
                uint64_t ptr_val = 0;
                if (get_bytes(&ptr_val, 8, target) == 8) {
                    if (ptr_val != 0 && is_code(get_flags((ea_t)ptr_val))) {
                        table_lea = target;
                        icall_debug("[indirect_call] Binary scan: found table LEA at 0x%llx -> 0x%llx\n",
                                   (unsigned long long)ea, (unsigned long long)target);
                    }
                }
            }
        }
        
        // Look for XOR with immediate: 81 F1 XX XX XX XX (xor ecx, imm32)
        // or 35 XX XX XX XX (xor eax, imm32)
        if (b0 == 0x81 && (b1 & 0xF8) == 0xF0) {
            // xor r32, imm32
            uint32_t imm = get_dword(ea + 2);
            xor_immediates.push_back({ea, imm});
            icall_debug("[indirect_call] Binary scan: XOR at 0x%llx with 0x%x\n",
                       (unsigned long long)ea, imm);
        }
        if (b0 == 0x35) {
            // xor eax, imm32
            uint32_t imm = get_dword(ea + 1);
            xor_immediates.push_back({ea, imm});
            icall_debug("[indirect_call] Binary scan: XOR EAX at 0x%llx with 0x%x\n",
                       (unsigned long long)ea, imm);
        }
        // 48 35 is xor rax, imm32 (sign-extended)
        if (b0 == 0x48 && b1 == 0x35) {
            uint32_t imm = get_dword(ea + 2);
            xor_immediates.push_back({ea, imm});
            icall_debug("[indirect_call] Binary scan: XOR RAX at 0x%llx with 0x%x\n",
                       (unsigned long long)ea, imm);
        }
        
        // Look for NEG: F7 D8-DF (neg r32)
        if (b0 == 0xF7 && (b1 & 0xF8) == 0xD8) {
            neg_locations.push_back(ea);
            icall_debug("[indirect_call] Binary scan: NEG at 0x%llx\n",
                       (unsigned long long)ea);
        }
        
        // Look for global loads: 8B 0D XX XX XX XX (mov ecx, [rip+disp])
        if (b0 == 0x8B && (b1 & 0xC7) == 0x05) {
            int32_t disp = get_dword(ea + 2);
            ea_t global = ea + 6 + disp;
            icall_debug("[indirect_call] Binary scan: MOV from global 0x%llx at 0x%llx\n",
                       (unsigned long long)global, (unsigned long long)ea);
        }
        
        ea = get_item_end(ea);
    }
    
    // If we found XORs, try to resolve them
    if (xor_immediates.size() >= 1 && table_lea != BADADDR) {
        result.table_ptr_global = table_lea;
        result.valid = true;
        
        // First XOR is typically the index, second is offset
        if (xor_immediates.size() >= 1) {
            result.index_xor_const = xor_immediates[0].second;
        }
        if (xor_immediates.size() >= 2) {
            result.offset_xor_const = xor_immediates[1].second;
            result.has_neg = !neg_locations.empty();
        }
        
        icall_debug("[indirect_call] Binary scan: table=0x%llx, idx_xor=0x%x, off_xor=0x%x, neg=%d\n",
                   (unsigned long long)result.table_ptr_global,
                   result.index_xor_const, result.offset_xor_const, result.has_neg);
    }
    
    return result;
}

//--------------------------------------------------------------------------
// Trace the call target computation backwards
//
// Handle Hikari's XOR-based index/offset computation:
// Uses both microcode analysis AND binary pattern scanning
//
// KEY INSIGHT: IDA often folds XOR operations into constants by the time 
// we see them in microcode. So we need to:
// 1. Track immediate values being moved to registers/stack
// 2. Find where those values are used in table load calculations
// 3. Trace the ADD/MUL pattern: base + index*8 to find the index
//--------------------------------------------------------------------------
bool indirect_call_handler_t::trace_call_target(mblock_t *blk, minsn_t *call_insn,
                                                ea_t *out_table, int *out_index,
                                                int64_t *out_offset) {
    if (!blk || !call_insn || !blk->mba)
        return false;

    *out_table = BADADDR;
    *out_index = -1;
    *out_offset = 0;

    mbl_array_t *mba = blk->mba;

    icall_debug("[indirect_call]   trace_call_target: starting enhanced analysis\n");

    // Track register/stack values (for already-computed XOR results)
    std::map<mreg_t, int64_t> reg_values;           // reg -> immediate value
    std::map<int64_t, int64_t> stkvar_values;       // stack offset -> value
    std::vector<ea_t> tables;
    int64_t resolved_offset = 0;
    int resolved_index = -1;
    
    // Pass 1: Collect all relevant information from microcode
    for (int bi = 0; bi < mba->qty; bi++) {
        mblock_t *scan_blk = mba->get_mblock(bi);
        if (!scan_blk) continue;
        
        for (minsn_t *ins = scan_blk->head; ins; ins = ins->next) {
            // Track mov of immediate to register
            if (ins->opcode == m_mov && ins->d.t == mop_r && ins->l.t == mop_n) {
                reg_values[ins->d.r] = ins->l.nnn->value;
            }
            
            // Track mov of immediate to stack variable
            if (ins->opcode == m_mov && ins->d.t == mop_S && ins->l.t == mop_n) {
                stkvar_values[ins->d.s->off] = ins->l.nnn->value;
                icall_debug("[indirect_call]     Tracking stkvar[%lld] = 0x%llx\n",
                            (long long)ins->d.s->off, (unsigned long long)ins->l.nnn->value);
            }
            
            // Track mov of register to stack
            if (ins->opcode == m_mov && ins->d.t == mop_S && ins->l.t == mop_r) {
                if (reg_values.count(ins->l.r)) {
                    stkvar_values[ins->d.s->off] = reg_values[ins->l.r];
                    icall_debug("[indirect_call]     Tracking stkvar[%lld] = reg%d = 0x%llx\n",
                                (long long)ins->d.s->off, ins->l.r,
                                (unsigned long long)reg_values[ins->l.r]);
                }
            }
            
            // Look for: mov stkvar, &global_table
            if (ins->opcode == m_mov && ins->l.t == mop_a && ins->l.a) {
                if (ins->l.a->t == mop_v) {
                    ea_t global = ins->l.a->g;
                    uint64_t first_entry = 0;
                    if (get_bytes(&first_entry, 8, global) == 8) {
                        if (first_entry != 0 && is_code(get_flags((ea_t)first_entry))) {
                            tables.push_back(global);
                            icall_debug("[indirect_call]     Found table: 0x%llx (first_entry=0x%llx)\n",
                                        (unsigned long long)global, (unsigned long long)first_entry);
                        }
                    }
                }
            }
            
            // Look for ldx - the table load operation
            // Pattern: ldx dest, base_reg, offset_operand
            // The offset might be: register (computed index*8), stack var, or immediate
            if (ins->opcode == m_ldx) {
                icall_debug("[indirect_call]     ldx at 0x%llx: base.t=%d, idx.t=%d\n",
                            (unsigned long long)ins->ea, ins->l.t, ins->r.t);
                
                // If the offset/index operand is a stack variable
                if (ins->r.t == mop_S) {
                    int64_t stk_off = ins->r.s->off;
                    if (stkvar_values.count(stk_off)) {
                        int64_t idx_val = stkvar_values[stk_off];
                        // The value might be index*8, so divide by 8
                        if (idx_val % 8 == 0 && idx_val > 0 && idx_val < 100000) {
                            resolved_index = (int)(idx_val / 8);
                            icall_debug("[indirect_call]     Index from stkvar[%lld] = %lld -> idx=%d\n",
                                        (long long)stk_off, (long long)idx_val, resolved_index);
                        }
                    }
                }
                
                // If the offset is a register
                if (ins->r.t == mop_r) {
                    if (reg_values.count(ins->r.r)) {
                        int64_t idx_val = reg_values[ins->r.r];
                        if (idx_val % 8 == 0 && idx_val > 0 && idx_val < 100000) {
                            resolved_index = (int)(idx_val / 8);
                            icall_debug("[indirect_call]     Index from reg%d = %lld -> idx=%d\n",
                                        ins->r.r, (long long)idx_val, resolved_index);
                        }
                    }
                }
                
                // If the offset is a constant
                if (ins->r.t == mop_n) {
                    int64_t idx_val = ins->r.nnn->value;
                    if (idx_val % 8 == 0 && idx_val >= 0) {
                        resolved_index = (int)(idx_val / 8);
                        icall_debug("[indirect_call]     Index from immediate = %lld -> idx=%d\n",
                                    (long long)idx_val, resolved_index);
                    }
                }
            }
            
            // Look for sub operations (offset computation)
            if (ins->opcode == m_sub && ins->r.t == mop_n) {
                int64_t sub_val = ins->r.nnn->value;
                if (sub_val > resolved_offset && sub_val > 0x1000) {
                    resolved_offset = sub_val;
                    icall_debug("[indirect_call]     Found sub offset: %lld\n", (long long)sub_val);
                }
            }
            
            // Look for ADD patterns that might contain index*8
            // Pattern: add dest, base, mul(index, 8)
            if (ins->opcode == m_add) {
                // Check if one operand is a multiplication by 8
                auto check_mul8 = [&](const mop_t &op) -> int {
                    if (op.t == mop_d && op.d && op.d->opcode == m_mul) {
                        minsn_t *mul = op.d;
                        if (mul->r.t == mop_n && mul->r.nnn->value == 8) {
                            // Left operand of mul is the index
                            if (mul->l.t == mop_n) {
                                return (int)mul->l.nnn->value;
                            }
                            if (mul->l.t == mop_r && reg_values.count(mul->l.r)) {
                                return (int)reg_values[mul->l.r];
                            }
                        }
                        if (mul->l.t == mop_n && mul->l.nnn->value == 8) {
                            if (mul->r.t == mop_n) {
                                return (int)mul->r.nnn->value;
                            }
                            if (mul->r.t == mop_r && reg_values.count(mul->r.r)) {
                                return (int)reg_values[mul->r.r];
                            }
                        }
                    }
                    return -1;
                };
                
                int idx = check_mul8(ins->l);
                if (idx < 0) idx = check_mul8(ins->r);
                if (idx >= 0 && idx < 10000) {
                    resolved_index = idx;
                    icall_debug("[indirect_call]     Index from add+mul pattern: %d\n", resolved_index);
                }
            }
        }
    }
    
    // NEW: Look for the computed index directly
    // When IDA folds XORs, we see patterns like:
    //   mov reg, #0x29c  (this is the already-computed index = 668)
    //   ... later used to compute table[index*8]
    // We can identify the index by looking for small constants that could be indices
    // and correlating with the table access pattern
    if (resolved_index < 0 && !tables.empty()) {
        icall_debug("[indirect_call]     Looking for pre-computed index constants...\n");
        
        // Collect all small immediate values that could be indices
        std::vector<std::pair<int64_t, ea_t>> candidate_indices;  // value, ea
        
        for (int bi = 0; bi < mba->qty; bi++) {
            mblock_t *scan_blk = mba->get_mblock(bi);
            if (!scan_blk) continue;
            
            for (minsn_t *ins = scan_blk->head; ins; ins = ins->next) {
                if (ins->opcode == m_mov && ins->l.t == mop_n) {
                    int64_t val = ins->l.nnn->value;
                    // Reasonable index range: 0 to ~10000
                    if (val > 0 && val < 10000) {
                        candidate_indices.push_back({val, ins->ea});
                        icall_debug("[indirect_call]       Candidate index: %lld at 0x%llx\n",
                                    (long long)val, (unsigned long long)ins->ea);
                    }
                }
            }
        }
        
        // Validate each candidate by checking if table[idx] - offset makes sense
        ea_t table_addr = tables[0];
        for (const auto &[idx_val, ea] : candidate_indices) {
            // Read table[idx]
            ea_t entry_addr = table_addr + idx_val * 8;
            uint64_t entry_val = 0;
            if (get_bytes(&entry_val, 8, entry_addr) == 8) {
                ea_t target = (ea_t)(entry_val - resolved_offset);
                // Check if result is valid code
                if (is_code(get_flags(target)) || get_func(target) != nullptr) {
                    resolved_index = (int)idx_val;
                    icall_debug("[indirect_call]       VALIDATED index %lld: table[%lld]=0x%llx, -offset=0x%llx (valid code)\n",
                                (long long)idx_val, (long long)idx_val,
                                (unsigned long long)entry_val, (unsigned long long)target);
                    break;
                }
            }
        }
    }
    
    // Use enhanced XOR pattern detection with data flow tracking (legacy fallback)
    if (resolved_index < 0) {
        auto xor_results = find_xor_with_globals(mba);
        icall_debug("[indirect_call]     Found %zu XOR patterns with globals\n", xor_results.size());
        
        for (const auto &xr : xor_results) {
            if (!xr.valid) continue;
            
            if (xr.has_neg && resolved_offset == 0) {
                resolved_offset = (int64_t)xr.result;
                icall_debug("[indirect_call]     Using as OFFSET: %lld\n", (long long)resolved_offset);
            } else {
                int64_t result = (int64_t)xr.result;
                if (result >= 0 && result < 10000 && resolved_index < 0) {
                    resolved_index = (int)result;
                    icall_debug("[indirect_call]     Using as INDEX: %d\n", resolved_index);
                }
            }
        }
    }
    
    ea_t table_addr = tables.empty() ? BADADDR : tables[0];
    
    if (table_addr != BADADDR && resolved_index >= 0) {
        *out_table = table_addr;
        *out_index = resolved_index;
        *out_offset = resolved_offset;
        icall_debug("[indirect_call]     SUCCESS: table=0x%llx, index=%d, offset=%lld\n",
                    (unsigned long long)table_addr, resolved_index, (long long)resolved_offset);
        return true;
    }
    
    icall_debug("[indirect_call]     Pattern incomplete: table=%llx, index=%d, offset=%lld\n",
                (unsigned long long)table_addr, resolved_index, (long long)resolved_offset);
    return false;
}

//--------------------------------------------------------------------------
// Find table base address from operand
//--------------------------------------------------------------------------
ea_t indirect_call_handler_t::find_table_base(mblock_t *blk, const mop_t &op) {
    if (op.t == mop_v) {
        return op.g;
    }
    if (op.t == mop_a && op.a && op.a->t == mop_v) {
        return op.a->g;
    }
    // Could trace through more complex expressions...
    return BADADDR;
}

//--------------------------------------------------------------------------
// Extract constant index from operand
//--------------------------------------------------------------------------
bool indirect_call_handler_t::extract_constant_index(mblock_t *blk, const mop_t &op,
                                                     int *out_index) {
    if (op.t == mop_n) {
        *out_index = (int)(op.nnn->value / 8);  // Assume 8-byte entries
        return true;
    }
    return false;
}

//--------------------------------------------------------------------------
// Read target from table and apply offset
//--------------------------------------------------------------------------
ea_t indirect_call_handler_t::compute_target(ea_t table_addr, int index, int64_t offset) {
    if (table_addr == BADADDR || index < 0)
        return BADADDR;

    ea_t entry_addr = table_addr + index * 8;  // 64-bit entries
    uint64_t entry_val = 0;

    if (get_bytes(&entry_val, 8, entry_addr) != 8) {
        icall_debug("[indirect_call]   Failed to read table entry at 0x%llx\n",
                    (unsigned long long)entry_addr);
        return BADADDR;
    }

    ea_t target = (ea_t)(entry_val - offset);

    icall_debug("[indirect_call]   table[%d] = 0x%llx, - %lld = 0x%llx\n",
                index, (unsigned long long)entry_val, (long long)offset,
                (unsigned long long)target);

    // Validate target is code
    if (is_code(get_flags(target))) {
        return target;
    }

    // Might still be valid if within function bounds
    func_t *func = get_func(target);
    if (func) {
        return target;
    }

    icall_debug("[indirect_call]   Target 0x%llx is not code\n", (unsigned long long)target);
    return BADADDR;
}

//--------------------------------------------------------------------------
// Replace indirect call with direct call
//
// Converting m_icall to m_call:
// - m_icall: l = computed target address, d = mcallinfo_t
// - m_call:  l = direct function address (mop_v), d = mcallinfo_t
//
// IMPORTANT: Only replace if target is a valid function entry point.
// If not, just annotate - modifying calls to non-function addresses crashes.
//--------------------------------------------------------------------------
int indirect_call_handler_t::replace_indirect_call(mbl_array_t *mba, mblock_t *blk,
                                                   indirect_call_t &ic, deobf_ctx_t *ctx) {
    if (!mba || !blk || !ic.call_insn || !ic.is_resolved)
        return 0;

    icall_debug("[indirect_call] Attempting to replace call in block %d with direct call to 0x%llx\n",
                ic.block_idx, (unsigned long long)ic.resolved_target);
    icall_debug("[indirect_call]   Original opcode: %d, l.t=%d, r.t=%d, d.t=%d\n",
                ic.call_insn->opcode, ic.call_insn->l.t, 
                ic.call_insn->r.t, ic.call_insn->d.t);

    // Check if the target is a valid function entry point
    // If not, we risk crashing IDA with INTERR 50822
    func_t *target_func = get_func(ic.resolved_target);
    bool is_func_start = (target_func && target_func->start_ea == ic.resolved_target);
    
    // Also check if it might be an external/import
    flags64_t flags = get_flags(ic.resolved_target);
    bool is_extern = has_any_name(flags) && !is_code(flags);
    
    icall_debug("[indirect_call]   Target check: is_func=%d, is_func_start=%d, is_extern=%d\n",
                (target_func != nullptr), is_func_start, is_extern);

    // If target is not a proper function start, just annotate and return
    // This avoids INTERR 50822 crash
    if (!is_func_start && !is_extern) {
        icall_debug("[indirect_call]   Target is NOT a function start - skipping replacement to avoid crash\n");
        
        // Try to create a function at the target
        if (!target_func && is_code(flags)) {
            icall_debug("[indirect_call]   Attempting to create function at target...\n");
            if (add_func(ic.resolved_target)) {
                target_func = get_func(ic.resolved_target);
                is_func_start = (target_func && target_func->start_ea == ic.resolved_target);
                icall_debug("[indirect_call]   Created function: is_func_start=%d\n", is_func_start);
            } else {
                icall_debug("[indirect_call]   Failed to create function\n");
            }
        }
        
        // If still not a function start, just add a comment
        if (!is_func_start) {
            qstring comment;
            comment.sprnt("DEOBF: Resolved indirect call -> 0x%llX (not a function start, not replaced)",
                          (unsigned long long)ic.resolved_target);
            set_cmt(ic.call_insn->ea, comment.c_str(), false);
            return 0;
        }
    }

    minsn_t *call = ic.call_insn;

    icall_debug("[indirect_call]   Before modification: opcode=%d, l.t=%d, r.t=%d, d.t=%d\n",
                call->opcode, call->l.t, call->r.t, call->d.t);

    // For m_icall, we want to replace the computed target with the resolved constant
    // 
    // Two approaches depending on whether mcallinfo is present:
    // 1. Unknown call (d.empty()): Keep m_icall, just set l to constant
    // 2. Known call (d has mcallinfo): Can convert to m_call
    
    bool is_unknown = call->d.empty();
    icall_debug("[indirect_call]   is_unknown_call=%d (d.t=%d)\n", is_unknown, call->d.t);
    
    if (call->opcode == m_icall) {
        // Strategy depends on whether mcallinfo exists:
        // 
        // If mcallinfo exists (d.t == mop_f): We can safely convert to m_call
        // and just update the callee address - arguments are preserved.
        //
        // If unknown call (d.empty()): We need to create mcallinfo ourselves,
        // copying any argument information from the r operand if present.
        
        if (!is_unknown && call->d.t == mop_f && call->d.f != nullptr) {
            // Has mcallinfo - can do full conversion to m_call
            icall_debug("[indirect_call]   Converting m_icall to m_call (has mcallinfo)\n");
            
            mcallinfo_t *mci = call->d.f;
            mci->callee = ic.resolved_target;
            
            // Try to get function type for better decompilation
            tinfo_t func_type;
            if (get_tinfo(&func_type, ic.resolved_target)) {
                mci->set_type(func_type);
                icall_debug("[indirect_call]   Set function type from database\n");
            }
            
            // Clear and set l to resolved target
            call->l.erase();
            call->l.t = mop_v;
            call->l.g = ic.resolved_target;
            call->l.size = NOSIZE;
            
            // m_call requires r to be empty
            call->r.erase();
            
            // Convert opcode
            call->opcode = m_call;
            
            icall_debug("[indirect_call]   Converted to m_call with preserved args\n");
        } else {
            // Unknown call - create mcallinfo and convert to m_call
            // We need to create a proper mcallinfo to get clean decompilation
            icall_debug("[indirect_call]   Converting unknown m_icall to m_call\n");
            
            // Create new mcallinfo
            mcallinfo_t *mci = new mcallinfo_t(ic.resolved_target, 0);
            mci->cc = CM_CC_FASTCALL;
            
            // Try to get function type - this will give us proper args/return
            tinfo_t func_type;
            if (get_tinfo(&func_type, ic.resolved_target)) {
                mci->set_type(func_type);
                icall_debug("[indirect_call]   Set function type from target\n");
            } else {
                // No type info - set void return 
                mci->return_type.create_simple_type(BT_VOID);
            }
            
            // Set the mcallinfo
            call->d.erase();
            call->d.t = mop_f;
            call->d.f = mci;
            call->d.size = 0;  // Void return
            
            // Clear and set l to resolved target
            call->l.erase();
            call->l.t = mop_v;
            call->l.g = ic.resolved_target;
            call->l.size = NOSIZE;
            
            // m_call requires r to be empty
            call->r.erase();
            
            // Convert opcode
            call->opcode = m_call;
            
            icall_debug("[indirect_call]   Converted to m_call, target=0x%llx\n",
                        (unsigned long long)ic.resolved_target);
        }
                    
    } else if (call->opcode == m_call) {
        // Already m_call, just update target
        if (call->d.t == mop_f && call->d.f != nullptr) {
            call->d.f->callee = ic.resolved_target;
        }
        call->l.erase();
        call->l.t = mop_v;
        call->l.g = ic.resolved_target;
        call->l.size = 0;
        
        icall_debug("[indirect_call]   Updated m_call target to 0x%llx\n",
                    (unsigned long long)ic.resolved_target);
    }

    // Verify the instruction looks correct
    icall_debug("[indirect_call]   After: opcode=%d, l.t=%d, l.g=0x%llx, l.size=%d, r.t=%d, d.t=%d\n",
                call->opcode, call->l.t, (unsigned long long)call->l.g, call->l.size,
                call->r.t, call->d.t);

    // Mark the block as modified
    blk->mark_lists_dirty();
    blk->mba->mark_chains_dirty();

    // Add comment to the original address
    qstring comment;
    qstring target_name;
    get_name(&target_name, ic.resolved_target);
    comment.sprnt("DEOBF: Resolved indirect call -> %s (0x%llX)",
                  target_name.empty() ? "?" : target_name.c_str(),
                  (unsigned long long)ic.resolved_target);
    set_cmt(call->ea, comment.c_str(), false);

    if (ctx)
        ctx->indirect_resolved++;

    return 1;
}

//--------------------------------------------------------------------------
// Annotate unresolved indirect call
//--------------------------------------------------------------------------
void indirect_call_handler_t::annotate_indirect_call(mblock_t *blk, const indirect_call_t &ic) {
    if (!blk || !ic.call_insn)
        return;

    qstring comment;
    comment.sprnt("DEOBF: Indirect call (unresolved)");
    if (ic.table_addr != BADADDR) {
        comment.cat_sprnt("\n  Table: 0x%llX", (unsigned long long)ic.table_addr);
    }
    if (ic.table_index >= 0) {
        comment.cat_sprnt("\n  Index: %d", ic.table_index);
    }
    if (ic.offset != 0) {
        comment.cat_sprnt("\n  Offset: %lld", (long long)ic.offset);
    }

    set_cmt(ic.call_insn->ea, comment.c_str(), false);
}
