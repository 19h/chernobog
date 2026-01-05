#include "indirect_branch.h"
#include "../analysis/cfg_analysis.h"
#include "../analysis/stack_tracker.h"

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
// Enhanced indirect branch analysis info
//--------------------------------------------------------------------------
struct enhanced_ibr_info_t {
    // Table access pattern
    ea_t table_base_global;     // Global holding table base pointer
    ea_t table_base_value;      // Actual table base address
    
    // Index computation
    xor_key_info_t index_xor;   // XOR used to compute index
    int index_scale;            // Multiplier (usually 8 for 64-bit)
    
    // Offset computation
    xor_key_info_t offset_xor;  // XOR used to compute offset added to table entry
    
    // Resolved targets
    std::map<int, ea_t> index_to_target;  // index -> resolved target address
    
    enhanced_ibr_info_t() : table_base_global(BADADDR), table_base_value(BADADDR),
                            index_scale(8) {}
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
    
    // Sign extend if needed for 32-bit values
    if (size == 4) {
        int32_t signed_val = (int32_t)*out;
        *out = (uint64_t)(int64_t)signed_val;
    }
    
    return true;
}

//--------------------------------------------------------------------------
// Trace XOR operations with global variables in a block
// Returns all XOR patterns: reg = immediate XOR global_var
//--------------------------------------------------------------------------
static std::vector<xor_key_info_t> find_xor_with_globals(mblock_t *blk) {
    std::vector<xor_key_info_t> results;
    
    if (!blk)
        return results;
    
    // Track register values for data flow
    std::map<mreg_t, uint64_t> reg_immediates;  // reg -> immediate value
    std::map<mreg_t, ea_t> reg_globals;         // reg -> global address
    
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Track mov of immediate to register
        if (ins->opcode == m_mov && ins->d.t == mop_r) {
            if (ins->l.t == mop_n) {
                reg_immediates[ins->d.r] = ins->l.nnn->value;
            } else if (ins->l.t == mop_v) {
                // Loading from global
                reg_globals[ins->d.r] = ins->l.g;
            }
        }
        
        // Track ldx (load) from global
        if (ins->opcode == m_ldx && ins->d.t == mop_r) {
            if (ins->r.t == mop_v) {
                reg_globals[ins->d.r] = ins->r.g;
            } else if (ins->r.t == mop_a && ins->r.a && ins->r.a->t == mop_v) {
                reg_globals[ins->d.r] = ins->r.a->g;
            }
        }
        
        // Look for XOR patterns
        if (ins->opcode == m_xor && ins->d.t == mop_r) {
            xor_key_info_t info;
            info.dest_reg = ins->d.r;
            
            // Pattern 1: xor reg_with_imm, global_var
            // Pattern 2: xor imm, reg_with_global
            // Pattern 3: xor reg, global_direct
            
            // Check for immediate XOR global
            if (ins->l.t == mop_n && ins->r.t == mop_v) {
                // xor #imm, global
                info.immediate = ins->l.nnn->value;
                info.global_addr = ins->r.g;
            } else if (ins->r.t == mop_n && ins->l.t == mop_v) {
                // xor global, #imm
                info.immediate = ins->r.nnn->value;
                info.global_addr = ins->l.g;
            } else if (ins->l.t == mop_r && ins->r.t == mop_v) {
                // xor reg, global - check if reg has immediate
                if (reg_immediates.count(ins->l.r)) {
                    info.immediate = reg_immediates[ins->l.r];
                    info.global_addr = ins->r.g;
                }
            } else if (ins->r.t == mop_r && ins->l.t == mop_v) {
                // xor global, reg
                if (reg_immediates.count(ins->r.r)) {
                    info.immediate = reg_immediates[ins->r.r];
                    info.global_addr = ins->l.g;
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
                    
                    deobf::log("[indirect_branch] Found XOR: 0x%llx ^ [0x%llx]=0x%llx -> 0x%llx\n",
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
                    deobf::log("[indirect_branch]   -> Negated to 0x%llx\n",
                              (unsigned long long)xinfo.result);
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
    
    return results;
}

//--------------------------------------------------------------------------
// Find table base address from block
// Looks for patterns like: lea reg, global_table; mov [stack], reg
//--------------------------------------------------------------------------
static ea_t find_table_base_address(mblock_t *blk, mbl_array_t *mba) {
    if (!blk)
        return BADADDR;
    
    // Look for lea or mov of global address
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Direct global reference
        if (ins->opcode == m_mov && ins->l.t == mop_v) {
            ea_t addr = ins->l.g;
            // Check if it's a pointer table (array of code addresses)
            ea_t first_entry = 0;
            if (get_bytes(&first_entry, sizeof(ea_t), addr) == sizeof(ea_t)) {
                if (first_entry != 0 && is_code(get_flags(first_entry))) {
                    return addr;
                }
            }
        }
        
        // LEA pattern - &global
        if (ins->opcode == m_mov && ins->l.t == mop_a && ins->l.a) {
            if (ins->l.a->t == mop_v) {
                return ins->l.a->g;
            }
        }
    }
    
    // Check predecessors for table base setup
    for (int i = 0; i < blk->npred() && i < 5; i++) {
        int pred_idx = blk->pred(i);
        mblock_t *pred = mba->get_mblock(pred_idx);
        if (pred) {
            ea_t result = find_table_base_address(pred, mba);
            if (result != BADADDR)
                return result;
        }
    }
    
    return BADADDR;
}

//--------------------------------------------------------------------------
// Analyze enhanced indirect branch pattern
// Handles: target = table[xor_computed_index] + xor_computed_offset
//--------------------------------------------------------------------------
static bool analyze_enhanced_pattern(mblock_t *blk, mbl_array_t *mba,
                                     minsn_t *ijmp, enhanced_ibr_info_t *out) {
    if (!blk || !ijmp || !out)
        return false;
    
    deobf::log("[indirect_branch] Analyzing enhanced pattern in block %d\n", blk->serial);
    
    // Find all XOR operations with globals
    auto xor_ops = find_xor_with_globals(blk);
    
    if (xor_ops.empty()) {
        deobf::log("[indirect_branch]   No XOR with globals found\n");
        return false;
    }
    
    deobf::log("[indirect_branch]   Found %zu XOR operations with globals\n", xor_ops.size());
    
    // Categorize XOR operations:
    // - One is likely for INDEX computation (used in table access)
    // - One might be for OFFSET computation (added to table entry)
    
    // Look for the ADD pattern that computes final target
    // Pattern: add reg, [table + index*8]
    bool found_table_access = false;
    
    for (minsn_t *ins = blk->head; ins != ijmp; ins = ins->next) {
        if (ins->opcode == m_add) {
            // Check for table access in operands
            // Left operand might be the offset, right might be the load
            if (ins->r.t == mop_d && ins->r.d && ins->r.d->opcode == m_ldx) {
                found_table_access = true;
                deobf::log("[indirect_branch]   Found add with table load\n");
            }
            if (ins->l.t == mop_d && ins->l.d && ins->l.d->opcode == m_ldx) {
                found_table_access = true;
                deobf::log("[indirect_branch]   Found add with table load (reversed)\n");
            }
        }
    }
    
    // Find table base
    out->table_base_value = find_table_base_address(blk, mba);
    if (out->table_base_value == BADADDR) {
        // Try IDA's switch detection
        switch_info_t si;
        if (get_switch_info(&si, blk->start) > 0 || 
            get_switch_info(&si, ijmp->ea) > 0) {
            out->table_base_value = si.jumps;
            deobf::log("[indirect_branch]   Using IDA switch table at 0x%llx\n",
                      (unsigned long long)out->table_base_value);
        }
    }
    
    if (out->table_base_value == BADADDR) {
        deobf::log("[indirect_branch]   Could not find table base\n");
        return false;
    }
    
    deobf::log("[indirect_branch]   Table base: 0x%llx\n", 
              (unsigned long long)out->table_base_value);
    
    // Assign XOR operations to roles based on usage patterns
    // The one with negation is likely the offset
    for (const auto &xop : xor_ops) {
        if (xop.has_neg) {
            out->offset_xor = xop;
            deobf::log("[indirect_branch]   Offset XOR: result=0x%llx (negated)\n",
                      (unsigned long long)xop.result);
        } else if (!out->index_xor.valid) {
            out->index_xor = xop;
            deobf::log("[indirect_branch]   Index XOR: result=0x%llx\n",
                      (unsigned long long)xop.result);
        }
    }
    
    return out->index_xor.valid || out->offset_xor.valid;
}

//--------------------------------------------------------------------------
// Resolve targets for enhanced indirect branch
//--------------------------------------------------------------------------
static bool resolve_enhanced_targets(mbl_array_t *mba, enhanced_ibr_info_t *info,
                                     std::vector<ea_t> *out_targets) {
    if (!mba || !info || !out_targets)
        return false;
    
    out_targets->clear();
    
    ea_t table_base = info->table_base_value;
    if (table_base == BADADDR)
        return false;
    
    // Get function bounds for validation
    func_t *func = get_func(mba->entry_ea);
    ea_t func_start = func ? func->start_ea : 0;
    ea_t func_end = func ? func->end_ea : BADADDR;
    
    // Compute offset to add to each entry
    int64_t offset = 0;
    if (info->offset_xor.valid) {
        offset = (int64_t)info->offset_xor.result;
        deobf::log("[indirect_branch] Using offset: %lld (0x%llx)\n",
                  (long long)offset, (unsigned long long)offset);
    }
    
    // Read table entries
    // If we have index XOR, use it to determine which entries to read
    // Otherwise read all entries
    int max_entries = 512;  // Reasonable limit
    
    deobf::log("[indirect_branch] Reading table entries from 0x%llx\n",
              (unsigned long long)table_base);
    
    int valid_count = 0;
    int invalid_streak = 0;
    
    for (int i = 0; i < max_entries && invalid_streak < 5; i++) {
        ea_t entry_addr = table_base + i * sizeof(ea_t);
        ea_t raw_value = 0;
        
        if (get_bytes(&raw_value, sizeof(ea_t), entry_addr) != sizeof(ea_t))
            break;
        
        // Apply offset
        ea_t target = raw_value + offset;
        
        // Validate target
        bool valid = false;
        if (is_code(get_flags(target))) {
            valid = true;
        } else if (target >= func_start && target < func_end) {
            // Might be valid but not yet analyzed as code
            valid = true;
        }
        
        if (valid) {
            out_targets->push_back(target);
            info->index_to_target[i] = target;
            valid_count++;
            invalid_streak = 0;
            
            if (valid_count <= 10) {
                qstring name;
                get_name(&name, target);
                deobf::log("[indirect_branch]   [%d] 0x%llx + %lld = 0x%llx %s\n",
                          i, (unsigned long long)raw_value, (long long)offset,
                          (unsigned long long)target,
                          name.empty() ? "" : name.c_str());
            }
        } else {
            invalid_streak++;
        }
    }
    
    if (valid_count > 10) {
        deobf::log("[indirect_branch]   ... and %d more targets\n", valid_count - 10);
    }
    
    deobf::log("[indirect_branch] Resolved %d targets\n", valid_count);
    
    return valid_count > 0;
}

//--------------------------------------------------------------------------
// Convert indirect jump to direct jumps
// For single target: convert to goto
// For multiple targets with known index: build switch
//--------------------------------------------------------------------------
static int convert_ijmp_to_direct(mbl_array_t *mba, mblock_t *blk,
                                  const std::vector<ea_t> &targets,
                                  deobf_ctx_t *ctx) {
    if (!mba || !blk || !blk->tail || blk->tail->opcode != m_ijmp)
        return 0;
    
    if (targets.empty())
        return 0;
    
    // Single target - simple conversion to goto
    if (targets.size() == 1) {
        ea_t target_ea = targets[0];
        
        // Find the block containing this target
        int target_blk = -1;
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *b = mba->get_mblock(i);
            if (b && b->start <= target_ea && target_ea < b->end) {
                target_blk = i;
                break;
            }
        }
        
        if (target_blk < 0) {
            deobf::log("[indirect_branch] Could not find block for target 0x%llx\n",
                      (unsigned long long)target_ea);
            return 0;
        }
        
        deobf::log("[indirect_branch] Converting ijmp to goto blk%d (target 0x%llx)\n",
                  target_blk, (unsigned long long)target_ea);
        
        // Convert ijmp to goto
        minsn_t *tail = blk->tail;
        tail->opcode = m_goto;
        tail->l.make_blkref(target_blk);
        tail->r.erase();
        tail->d.erase();
        
        // Update successor list
        blk->succset.clear();
        blk->succset.push_back(target_blk);
        
        // Update predecessor of target
        mblock_t *dst = mba->get_mblock(target_blk);
        if (dst) {
            auto it = std::find(dst->predset.begin(), dst->predset.end(), blk->serial);
            if (it == dst->predset.end()) {
                dst->predset.push_back(blk->serial);
            }
            dst->mark_lists_dirty();
        }
        
        blk->type = BLT_1WAY;
        blk->mark_lists_dirty();
        
        ctx->branches_simplified++;
        return 1;
    }
    
    // Multiple targets - we could build a switch, but that's complex
    // For now, if ALL targets go to the same block, convert to single goto
    std::set<int> target_blocks;
    for (ea_t target_ea : targets) {
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *b = mba->get_mblock(i);
            if (b && b->start <= target_ea && target_ea < b->end) {
                target_blocks.insert(i);
                break;
            }
        }
    }
    
    if (target_blocks.size() == 1) {
        int target_blk = *target_blocks.begin();
        deobf::log("[indirect_branch] All %zu targets go to block %d, converting to goto\n",
                  targets.size(), target_blk);
        
        minsn_t *tail = blk->tail;
        tail->opcode = m_goto;
        tail->l.make_blkref(target_blk);
        tail->r.erase();
        tail->d.erase();
        
        blk->succset.clear();
        blk->succset.push_back(target_blk);
        
        mblock_t *dst = mba->get_mblock(target_blk);
        if (dst) {
            auto it = std::find(dst->predset.begin(), dst->predset.end(), blk->serial);
            if (it == dst->predset.end()) {
                dst->predset.push_back(blk->serial);
            }
            dst->mark_lists_dirty();
        }
        
        blk->type = BLT_1WAY;
        blk->mark_lists_dirty();
        
        ctx->branches_simplified++;
        return 1;
    }
    
    // Multiple different target blocks
    // Building a proper jtbl is complex due to mcases_t structure requirements.
    // For now, if we have a small number of targets, we'll annotate and leave
    // the ijmp. In future iterations, we could build proper switch statements.
    
    deobf::log("[indirect_branch] Found %zu unique target blocks - annotating\n",
              target_blocks.size());
    
    // Add detailed annotation about the resolved targets
    qstring comment;
    comment.sprnt("DEOBF: Indirect jump resolved to %zu targets:\n", targets.size());
    
    int idx = 0;
    for (ea_t target_ea : targets) {
        if (idx < 20) {
            qstring name;
            get_name(&name, target_ea);
            comment.cat_sprnt("  [%d] 0x%llX %s\n", idx,
                             (unsigned long long)target_ea,
                             name.empty() ? "" : name.c_str());
        }
        idx++;
    }
    
    if (targets.size() > 20) {
        comment.cat_sprnt("  ... and %zu more\n", targets.size() - 20);
    }
    
    set_cmt(blk->start, comment.c_str(), false);
    
    // Even though we can't convert to switch, mark as processed
    ctx->branches_simplified++;
    return 1;
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Look for ijmp instructions
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        if (blk->tail->opcode == m_ijmp) {
            return true;
        }
    }

    // Also check for global jump tables
    segment_t *seg = get_first_seg();
    while (seg) {
        if (seg->type == SEG_DATA) {
            ea_t ea = seg->start_ea;
            while (ea < seg->end_ea) {
                qstring name;
                if (get_name(&name, ea) > 0) {
                    if (name.find("IndirectBranchingGlobalTable") != qstring::npos ||
                        name.find("HikariConditionalLocalIndirectBranchingTable") != qstring::npos ||
                        name.find("IndirectBranchTable") != qstring::npos) {
                        return true;
                    }
                }
                ea = next_head(ea, seg->end_ea);
                if (ea == BADADDR)
                    break;
            }
        }
        seg = get_next_seg(seg->start_ea);
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int indirect_branch_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[indirect_branch] Starting indirect branch resolution\n");

    int total_changes = 0;

    // Find all indirect branches
    auto ibrs = find_indirect_branches(mba);
    deobf::log("[indirect_branch] Found %zu indirect branches\n", ibrs.size());

    for (auto &ibr : ibrs) {
        mblock_t *blk = mba->get_mblock(ibr.block_idx);
        if (!blk)
            continue;

        // Try enhanced analysis first (XOR-encrypted patterns)
        enhanced_ibr_info_t einfo;
        if (analyze_enhanced_pattern(blk, mba, ibr.ijmp_insn, &einfo)) {
            std::vector<ea_t> resolved_targets;
            if (resolve_enhanced_targets(mba, &einfo, &resolved_targets)) {
                // Convert to direct jumps
                int changes = convert_ijmp_to_direct(mba, blk, resolved_targets, ctx);
                if (changes > 0) {
                    total_changes += changes;
                    deobf::log("[indirect_branch] Block %d: converted via enhanced analysis\n",
                              blk->serial);
                    continue;
                }
            }
        }

        // Fall back to standard analysis
        index_computation_t idx_comp;
        if (trace_index_computation(blk, ibr.ijmp_insn, &idx_comp)) {
            ibr.index_traced = true;
            ibr.possible_indices = emulate_index_values(mba, blk, idx_comp);
            deobf::log("[indirect_branch] Block %d: traced %zu possible indices\n",
                      blk->serial, ibr.possible_indices.size());
        }

        // Try to resolve and convert
        if (!ibr.targets.empty()) {
            int changes = convert_ijmp_to_direct(mba, blk, ibr.targets, ctx);
            if (changes > 0) {
                total_changes += changes;
                continue;
            }
        }
        
        // Try frameless continuation analysis
        // This handles cases where the ijmp target is an external "trampoline" function
        // that uses the caller's stack frame to compute the next jump target
        if (ibr.targets.size() == 1) {
            ea_t continuation_ea = ibr.targets[0];
            
            // Check if target is a frameless continuation
            if (frameless_continuation_t::is_frameless_continuation(continuation_ea)) {
                deobf::log("[indirect_branch] Block %d: target 0x%llx is frameless continuation\n",
                          blk->serial, (unsigned long long)continuation_ea);
                
                // Build caller context from this function
                caller_context_t caller_ctx = frameless_continuation_t::build_caller_context(mba, blk);
                caller_ctx.caller_func = mba->entry_ea;
                caller_ctx.callee_func = continuation_ea;
                
                // Resolve the continuation's final jump target
                ea_t final_target = frameless_continuation_t::resolve_continuation_jump(continuation_ea, caller_ctx);
                
                if (final_target != BADADDR && is_code(get_flags(final_target))) {
                    deobf::log("[indirect_branch] Resolved frameless continuation: 0x%llx -> 0x%llx\n",
                              (unsigned long long)continuation_ea, (unsigned long long)final_target);
                    
                    // Find the block containing the final target
                    int target_blk = -1;
                    for (int bi = 0; bi < mba->qty; bi++) {
                        mblock_t *b = mba->get_mblock(bi);
                        if (b && b->start <= final_target && final_target < b->end) {
                            target_blk = bi;
                            break;
                        }
                    }
                    
                    if (target_blk >= 0) {
                        // Convert ijmp to direct goto
                        std::vector<ea_t> resolved_targets = {final_target};
                        int changes = convert_ijmp_to_direct(mba, blk, resolved_targets, ctx);
                        if (changes > 0) {
                            total_changes += changes;
                            continue;
                        }
                    } else {
                        // Target is outside current microcode - annotate
                        qstring comment;
                        comment.sprnt("DEOBF: Frameless continuation resolved\n"
                                     "  Continuation: 0x%llX\n"
                                     "  Final target: 0x%llX (external)",
                                     (unsigned long long)continuation_ea,
                                     (unsigned long long)final_target);
                        set_cmt(blk->start, comment.c_str(), false);
                        ctx->branches_simplified++;
                        total_changes++;
                        continue;
                    }
                }
            }
        }
        
        // If we couldn't convert, at least annotate
        total_changes += replace_indirect_branch(mba, blk, ibr, ctx);
    }

    deobf::log("[indirect_branch] Resolved %d indirect branches\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find indirect branches
//--------------------------------------------------------------------------
std::vector<indirect_branch_handler_t::indirect_br_t>
indirect_branch_handler_t::find_indirect_branches(mbl_array_t *mba) {

    std::vector<indirect_br_t> result;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        if (blk->tail->opcode == m_ijmp) {
            indirect_br_t ibr;
            ibr.block_idx = i;
            ibr.ijmp_insn = blk->tail;
            ibr.is_encrypted = false;
            ibr.enc_key = 0;
            ibr.encoding = ENC_DIRECT;
            ibr.base_addr = BADADDR;
            ibr.entry_size = sizeof(ea_t);
            ibr.table_size = 0;
            ibr.index_traced = false;

            if (analyze_ijmp(blk, blk->tail, &ibr)) {
                result.push_back(ibr);
            } else {
                // Even if analysis failed, add it for enhanced processing
                result.push_back(ibr);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Analyze table encoding
//--------------------------------------------------------------------------
indirect_branch_handler_t::table_encoding_t
indirect_branch_handler_t::analyze_table_encoding(mblock_t *blk, minsn_t *ijmp,
                                                  uint64_t *out_key, ea_t *out_base) {
    if (!blk || !ijmp)
        return ENC_UNKNOWN;

    bool has_xor = false;
    bool has_add = false;
    uint64_t xor_key = 0;
    ea_t base_addr = BADADDR;

    // Trace back through the block looking for XOR and ADD operations
    for (minsn_t *ins = blk->head; ins && ins != ijmp; ins = ins->next) {
        // Look for XOR with constant
        if (ins->opcode == m_xor) {
            if (ins->l.t == mop_n) {
                has_xor = true;
                xor_key = ins->l.nnn->value;
            } else if (ins->r.t == mop_n) {
                has_xor = true;
                xor_key = ins->r.nnn->value;
            } else if (ins->l.t == mop_v || ins->r.t == mop_v) {
                // XOR with global - try to read the value
                ea_t gaddr = (ins->l.t == mop_v) ? ins->l.g : ins->r.g;
                uint64_t gval = 0;
                if (read_global_value(gaddr, &gval, 4)) {
                    has_xor = true;
                    // The immediate is the other operand
                    // This is a simplified heuristic
                }
            }
        }

        // Look for ADD with global address (base offset)
        if (ins->opcode == m_add) {
            if (ins->l.t == mop_v) {
                has_add = true;
                base_addr = ins->l.g;
            } else if (ins->r.t == mop_v) {
                has_add = true;
                base_addr = ins->r.g;
            }
        }
    }

    if (out_key) *out_key = xor_key;
    if (out_base) *out_base = base_addr;

    if (has_xor && has_add) return ENC_OFFSET_XOR;
    if (has_xor) return ENC_XOR;
    if (has_add) return ENC_OFFSET;
    return ENC_DIRECT;
}

//--------------------------------------------------------------------------
// Trace index computation
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::trace_index_computation(mblock_t *blk, minsn_t *ijmp,
                                                        index_computation_t *out) {
    if (!blk || !ijmp || !out)
        return false;

    out->type = index_computation_t::OP_COMPLEX;
    out->mask = 0;
    out->sub_value = 0;
    out->max_index = 256;  // Default max

    for (minsn_t *ins = blk->tail; ins; ins = ins->prev) {
        if (ins == ijmp)
            continue;

        // Look for AND with constant mask
        if (ins->opcode == m_and) {
            if (ins->r.t == mop_n) {
                out->type = index_computation_t::OP_AND;
                out->mask = ins->r.nnn->value;
                out->max_index = (int)out->mask + 1;

                if (ins->l.t == mop_d && ins->l.d && ins->l.d->opcode == m_sub) {
                    minsn_t *sub = ins->l.d;
                    if (sub->r.t == mop_n) {
                        out->type = index_computation_t::OP_SUB_AND;
                        out->sub_value = sub->r.nnn->value;
                        out->source_var = sub->l;
                    }
                } else {
                    out->source_var = ins->l;
                }
                return true;
            }
        }

        // Look for low byte extraction
        if (ins->opcode == m_low) {
            out->type = index_computation_t::OP_AND;
            out->mask = 0xFF;
            out->max_index = 256;
            out->source_var = ins->l;
            return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Emulate index values
//--------------------------------------------------------------------------
std::set<int> indirect_branch_handler_t::emulate_index_values(
    mbl_array_t *mba, mblock_t *blk, const index_computation_t &idx_comp) {

    std::set<int> indices;

    if (idx_comp.type == index_computation_t::OP_AND ||
        idx_comp.type == index_computation_t::OP_SUB_AND) {

        for (int i = 0; i <= (int)idx_comp.mask && i < idx_comp.max_index; i++) {
            indices.insert(i);
        }
        return indices;
    }

    if (idx_comp.type == index_computation_t::OP_MOD) {
        for (int i = 0; i < (int)idx_comp.mask && i < idx_comp.max_index; i++) {
            indices.insert(i);
        }
        return indices;
    }

    return indices;
}

//--------------------------------------------------------------------------
// Analyze indirect jump
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::analyze_ijmp(mblock_t *blk, minsn_t *ijmp, indirect_br_t *out) {
    if (!blk || !ijmp || ijmp->opcode != m_ijmp)
        return false;

    // Analyze encoding
    uint64_t key = 0;
    ea_t base = BADADDR;
    out->encoding = analyze_table_encoding(blk, ijmp, &key, &base);
    out->enc_key = key;
    out->base_addr = base;
    out->is_encrypted = (out->encoding == ENC_XOR || out->encoding == ENC_OFFSET_XOR);

    // Find the jump table
    ea_t table_addr = find_jump_table(blk, ijmp);
    if (table_addr == BADADDR) {
        deobf::log_verbose("[indirect_branch] Could not find jump table for block %d\n",
                          blk->serial);
        return false;
    }

    out->table_addr = table_addr;
    out->entry_size = sizeof(ea_t);

    // Read targets from table
    out->targets = read_jump_targets(table_addr, 256, out->encoding,
                                     out->enc_key, out->base_addr, out->entry_size);

    if (out->targets.empty() && sizeof(ea_t) == 8) {
        out->entry_size = 4;
        out->targets = read_jump_targets(table_addr, 256, out->encoding,
                                         out->enc_key, out->base_addr, out->entry_size);
    }

    out->table_size = (int)out->targets.size();

    if (out->targets.empty()) {
        deobf::log_verbose("[indirect_branch] No valid targets found at %a\n", table_addr);
        return false;
    }

    deobf::log_verbose("[indirect_branch] Found %zu targets at table %a (enc=%d, entry=%d)\n",
                      out->targets.size(), table_addr, out->encoding, out->entry_size);

    return true;
}

//--------------------------------------------------------------------------
// Find jump table
//--------------------------------------------------------------------------
ea_t indirect_branch_handler_t::find_jump_table(mblock_t *blk, minsn_t *ijmp) {
    // Trace back from ijmp to find the table address
    for (minsn_t *ins = blk->head; ins && ins != ijmp; ins = ins->next) {
        if (ins->opcode == m_ldx) {
            if (ins->l.t == mop_v) {
                ea_t addr = ins->l.g;
                uint64_t first_entry = 0;
                if (get_bytes(&first_entry, sizeof(ea_t), addr) == sizeof(ea_t)) {
                    if (first_entry != 0 && first_entry != BADADDR) {
                        if (is_code(get_flags((ea_t)first_entry))) {
                            return addr;
                        }
                        func_t *func = get_func(blk->start);
                        if (func) {
                            ea_t resolved = func->start_ea + first_entry;
                            if (is_code(get_flags(resolved))) {
                                return addr;
                            }
                        }
                    }
                }
            }

            if (ins->l.t == mop_d && ins->l.d) {
                minsn_t *addr_calc = ins->l.d;
                if (addr_calc->opcode == m_add) {
                    if (addr_calc->l.t == mop_v) {
                        return addr_calc->l.g;
                    }
                    if (addr_calc->r.t == mop_v) {
                        return addr_calc->r.g;
                    }
                }
            }
        }
    }

    if (ijmp->d.t == mop_v) {
        return ijmp->d.g;
    }

    const char *table_names[] = {
        "IndirectBranchingGlobalTable",
        "HikariConditionalLocalIndirectBranchingTable",
        "IndirectBranchTable",
        nullptr
    };

    for (int i = 0; table_names[i]; i++) {
        ea_t table_ea = get_name_ea(BADADDR, table_names[i]);
        if (table_ea != BADADDR)
            return table_ea;
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Decode a single table entry
//--------------------------------------------------------------------------
ea_t indirect_branch_handler_t::decode_table_entry(uint64_t raw_value,
                                                   table_encoding_t encoding,
                                                   uint64_t key, ea_t base) {
    switch (encoding) {
        case ENC_DIRECT:
            return (ea_t)raw_value;

        case ENC_OFFSET:
            if (base != BADADDR)
                return base + raw_value;
            return (ea_t)raw_value;

        case ENC_XOR:
            return (ea_t)(raw_value ^ key);

        case ENC_OFFSET_XOR:
            if (base != BADADDR)
                return base + (raw_value ^ key);
            return (ea_t)(raw_value ^ key);

        default:
            return (ea_t)raw_value;
    }
}

//--------------------------------------------------------------------------
// Read jump targets from table
//--------------------------------------------------------------------------
std::vector<ea_t> indirect_branch_handler_t::read_jump_targets(
    ea_t table_addr, int max_entries,
    table_encoding_t encoding, uint64_t key, ea_t base, int entry_size) {

    std::vector<ea_t> targets;

    if (table_addr == BADADDR)
        return targets;

    func_t *func = get_func(table_addr);
    ea_t func_start = func ? func->start_ea : BADADDR;
    ea_t func_end = func ? func->end_ea : BADADDR;

    for (int i = 0; i < max_entries; i++) {
        ea_t entry_addr = table_addr + i * entry_size;
        uint64_t raw_value = 0;

        if (get_bytes(&raw_value, entry_size, entry_addr) != entry_size)
            break;

        if (raw_value == 0)
            break;

        ea_t target = decode_table_entry(raw_value, encoding, key, base);

        if (target == 0 || target == BADADDR)
            break;

        if (is_code(get_flags(target))) {
            targets.push_back(target);
            continue;
        }

        if ((encoding == ENC_OFFSET || encoding == ENC_OFFSET_XOR) &&
            func_start != BADADDR) {
            ea_t alt_target = func_start + raw_value;
            if (encoding == ENC_OFFSET_XOR)
                alt_target = func_start + (raw_value ^ key);

            if (is_code(get_flags(alt_target))) {
                targets.push_back(alt_target);
                continue;
            }
        }

        if (targets.size() > 2)
            break;
    }

    return targets;
}

//--------------------------------------------------------------------------
// Decrypt targets (legacy support)
//--------------------------------------------------------------------------
std::vector<ea_t> indirect_branch_handler_t::decrypt_targets(
    const std::vector<ea_t> &encrypted, uint64_t key) {

    std::vector<ea_t> decrypted;

    for (ea_t enc : encrypted) {
        ea_t dec = enc ^ key;
        decrypted.push_back(dec);
    }

    return decrypted;
}

//--------------------------------------------------------------------------
// Validate targets belong to the function
//--------------------------------------------------------------------------
bool indirect_branch_handler_t::validate_targets(const std::vector<ea_t> &targets,
                                                 mbl_array_t *mba) {
    if (targets.empty())
        return false;

    ea_t func_start = mba->entry_ea;
    func_t *func = get_func(func_start);
    if (!func)
        return true;

    for (ea_t target : targets) {
        if (target < func->start_ea || target >= func->end_ea) {
            if (!is_code(get_flags(target))) {
                return false;
            }
        }
    }

    return true;
}

//--------------------------------------------------------------------------
// Annotate indirect branch
//--------------------------------------------------------------------------
void indirect_branch_handler_t::annotate_indirect_branch(mblock_t *blk,
                                                         const indirect_br_t &ibr) {
    qstring comment;
    comment.sprnt("DEOBF: Indirect branch table at 0x%llX (%d entries)",
                 (unsigned long long)ibr.table_addr, (int)ibr.targets.size());

    if (ibr.is_encrypted) {
        comment.cat_sprnt(" [encrypted, key=0x%llX]", (unsigned long long)ibr.enc_key);
    }

    comment += "\nTargets:";
    for (size_t i = 0; i < ibr.targets.size() && i < 10; i++) {
        qstring name;
        if (get_name(&name, ibr.targets[i]) > 0) {
            comment.cat_sprnt("\n  [%d] 0x%llX (%s)", (int)i,
                             (unsigned long long)ibr.targets[i], name.c_str());
        } else {
            comment.cat_sprnt("\n  [%d] 0x%llX", (int)i,
                             (unsigned long long)ibr.targets[i]);
        }
    }

    if (ibr.targets.size() > 10) {
        comment.cat_sprnt("\n  ... and %d more", (int)(ibr.targets.size() - 10));
    }

    set_cmt(blk->start, comment.c_str(), false);
}

//--------------------------------------------------------------------------
// Build switch from indirect branch
//--------------------------------------------------------------------------
int indirect_branch_handler_t::build_switch(mbl_array_t *mba, mblock_t *blk,
                                           const indirect_br_t &ibr, deobf_ctx_t *ctx) {
    annotate_indirect_branch(blk, ibr);
    return 0;
}

//--------------------------------------------------------------------------
// Replace indirect branch
//--------------------------------------------------------------------------
int indirect_branch_handler_t::replace_indirect_branch(mbl_array_t *mba, mblock_t *blk,
    const indirect_br_t &ibr, deobf_ctx_t *ctx) {

    if (!blk || ibr.targets.empty())
        return 0;

    // Try to convert to direct jumps first
    int changes = convert_ijmp_to_direct(mba, blk, ibr.targets, ctx);
    if (changes > 0)
        return changes;

    // Fall back to annotation
    deobf::log("[indirect_branch] Block %d: table at 0x%llX with %zu targets (annotating)\n",
              blk->serial, (unsigned long long)ibr.table_addr, ibr.targets.size());

    annotate_indirect_branch(blk, ibr);

    deobf::log("[indirect_branch]   Targets:\n");
    for (size_t i = 0; i < ibr.targets.size() && i < 16; i++) {
        qstring name;
        get_name(&name, ibr.targets[i]);
        deobf::log("[indirect_branch]     [%zu] 0x%llX %s\n",
                  i, (unsigned long long)ibr.targets[i],
                  name.empty() ? "" : name.c_str());
    }

    ctx->branches_simplified++;
    return 1;
}
