#include "indirect_call.h"
#include "../analysis/opaque_eval.h"
#include "../../hybrid/z3_bridge.hpp"

//--------------------------------------------------------------------------
// File-based debug logging
//--------------------------------------------------------------------------
#include "../../common/compat.h"

static void icall_debug(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    deobf::debug_vlog("/tmp/indirect_call_debug.log", fmt, args);
    va_end(args);
}

static bool is_valid_database_ea(ea_t ea)
{
    if ( ea == BADADDR )
        return false;

    const ea_t min_ea = inf_get_min_ea();
    const ea_t max_ea = inf_get_max_ea();
    return ea >= min_ea && ea < max_ea;
}

static func_t *get_func_safe(ea_t ea)
{
    if ( !is_valid_database_ea(ea) )
        return nullptr;
    return get_func(ea);
}

static flags64_t get_flags_safe(ea_t ea)
{
    if ( !is_valid_database_ea(ea) )
        return 0;
    return get_flags(ea);
}

//--------------------------------------------------------------------------
// Detection - look for indirect call patterns
//
// Pattern 1: icall with computed target
// Pattern 2: call with target loaded from table and modified
//--------------------------------------------------------------------------
bool indirect_call_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    icall_debug("[indirect_call] detect() called for func 0x%llx\n", 
                (unsigned long long)mba->entry_ea);

    // Look for icall instructions or calls with complex computed targets
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            // Check for icall (indirect call)
            if ( ins->opcode == m_icall ) {
                icall_debug("[indirect_call] Found m_icall in block %d\n", i);
                return true;
            }

            // Check for call with computed target
            // A direct call has l operand as mop_v (global) or mop_a (address)
            // A computed call has l operand as mop_r (register) or mop_d (result of computation)
            if ( ins->opcode == m_call ) {
                if ( ins->l.t == mop_r || ins->l.t == mop_d ) {
                    icall_debug("[indirect_call] Found m_call with computed target in block %d\n", i);
                    return true;
                }
            }
        }
    }

    icall_debug("[indirect_call] No indirect call patterns detected\n");
    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int indirect_call_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
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

    for ( auto &ic : icalls ) {
        mblock_t *blk = mba->get_mblock(ic.block_idx);
        if ( !blk ) 
            continue;

        // Try to resolve the call
        if ( ic.is_resolved && can_modify ) {
            int changes = replace_indirect_call(mba, blk, ic, ctx);
            if ( changes > 0 ) {
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
// Resolution is attempted only for explicit computed call operands.
//--------------------------------------------------------------------------
std::vector<indirect_call_handler_t::indirect_call_t>
indirect_call_handler_t::find_indirect_calls(mbl_array_t *mba)
{
    std::vector<indirect_call_t> result;

    if ( !mba ) 
        return result;

    // First pass: look for explicit icall/call with computed target
    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            bool is_indirect = false;

            // Check for icall
            if ( ins->opcode == m_icall ) {
                is_indirect = true;
            }
            // Check for call with computed target
            else if ( ins->opcode == m_call ) {
                if ( ins->l.t == mop_r || ins->l.t == mop_d ) {
                    is_indirect = true;
                }
            }

            if ( is_indirect ) {
                indirect_call_t ic;
                ic.block_idx = i;
                ic.call_insn = ins;
                ic.table_addr = BADADDR;
                ic.table_index = -1;
                ic.offset = 0;
                ic.resolved_target = BADADDR;
                ic.is_resolved = false;

                // Try to analyze and resolve
                if ( analyze_indirect_call(blk, ins, &ic) ) {
                    icall_debug("[indirect_call] Analyzed call in block %d: table=0x%llx, index=%d, offset=%lld\n",
                                i, (unsigned long long)ic.table_addr, ic.table_index, (long long)ic.offset);
                }

                result.push_back(ic);
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
                                                    indirect_call_t *out)
                                                    {
    if ( !blk || !call_insn || !out ) 
        return false;

    icall_debug("[indirect_call] Analyzing call at ea=0x%llx, opcode=%d\n", 
                (unsigned long long)call_insn->ea, call_insn->opcode);
    icall_debug("[indirect_call]   l.t=%d, r.t=%d, d.t=%d\n", 
                call_insn->l.t, call_insn->r.t, call_insn->d.t);
    if ( call_insn->r.t == mop_r ) {
        icall_debug("[indirect_call]   r.r=%d (target offset register)\n", call_insn->r.r);
    }
    // The diagnostic dump is O(blocks + instructions) per call. Avoid even
    // walking the function when file debugging is disabled.
    if ( deobf::debug_enabled() ) {
        icall_debug("[indirect_call]   Dumping all blocks looking for table reference:\n");
        mbl_array_t *mba_dump = blk->mba;
        for ( int bi = 0; bi < mba_dump->qty; bi++ ) {
            mblock_t *dump_blk = mba_dump->get_mblock(bi);
            if ( !dump_blk) continue;
            icall_debug("[indirect_call]   Block %d:\n", bi);
            for ( minsn_t *ins = dump_blk->head; ins; ins = ins->next ) {
            icall_debug("[indirect_call]     ea=%llx op=%d l.t=%d r.t=%d d.t=%d",
                        (unsigned long long)ins->ea, ins->opcode, ins->l.t, ins->r.t, ins->d.t);
            if ( ins->d.t == mop_r ) 
                icall_debug(" -> reg%d", ins->d.r);
            if ( ins->d.t == mop_f ) 
                icall_debug(" -> stkvar");
            if ( ins->l.t == mop_r ) 
                icall_debug(" from reg%d", ins->l.r);
            if ( ins->l.t == mop_n ) 
                icall_debug(" from #0x%llx", (unsigned long long)ins->l.nnn->value);
            if ( ins->l.t == mop_v ) 
                icall_debug(" from global 0x%llx", (unsigned long long)ins->l.g);
            if ( ins->l.t == mop_a && ins->l.a ) {
                icall_debug(" from &");
                if ( ins->l.a->t == mop_v ) 
                    icall_debug("global 0x%llx", (unsigned long long)ins->l.a->g);
                else
                    icall_debug("(type %d)", ins->l.a->t);
            }
            if ( ins->r.t == mop_a && ins->r.a ) {
                icall_debug(" r=&");
                if ( ins->r.a->t == mop_v ) 
                    icall_debug("global 0x%llx", (unsigned long long)ins->r.a->g);
            }
            // For ldx, the base address comes from r operand
            if ( ins->opcode == m_ldx ) {
                icall_debug(" [ldx: base.t=%d, idx.t=%d]", ins->l.t, ins->r.t);
            }
            // Check for sub instruction with table pattern
            if ( ins->opcode == m_sub || ins->opcode == m_ldx ) {
                icall_debug(" [INTERESTING]");
            }
                icall_debug("\n");
            }
        }
    }

    mop_t *target_op = nullptr;
    
    if ( call_insn->opcode == m_icall ) {
        // SDK form: icall {l=selector, r=offset}, d=call information.
        if ( !call_insn->r.empty() ) {
            target_op = &call_insn->r;
            icall_debug("[indirect_call]   Using r offset operand (type %d)\n",
                        call_insn->r.t);
        }
    } else if ( call_insn->opcode == m_call ) {
        if ( call_insn->l.t == mop_d || call_insn->l.t == mop_r ) {
            target_op = &call_insn->l;
            icall_debug("[indirect_call]   Using call l operand (type %d)\n", call_insn->l.t);
        }
    }

    if ( !target_op ) {
        icall_debug("[indirect_call]   No target operand found (all types: l=%d, r=%d, d=%d)\n",
                    call_insn->l.t, call_insn->r.t, call_insn->d.t);
        return false;
    }

    icall_debug("[indirect_call]   Target operand type: %d\n", target_op->t);

    // Resolve only the call's own expression. The evaluator recursively folds
    // integer operations and exact loads from non-writable segments; it does
    // not correlate unrelated constants or tables elsewhere in the function.
    const std::optional<uint64_t> target =
        call_insn->opcode == m_icall && target_op->t == mop_v
        ? std::optional<uint64_t>(target_op->g)
        : opaque_eval_t::evaluate_operand(*target_op);
    if ( !target ) {
        icall_debug("[indirect_call]   Call target expression is not constant\n");
        const auto candidates =
            chernobog::hybrid::hybrid_current_indirect_target_candidates(
                uint64_t(blk->mba->entry_ea), uint64_t(call_insn->ea));
        for ( const auto &candidate : candidates ) {
            deobf::log_verbose(
                "[indirect_call][rax] Observed candidate %a at %a "
                "(%zu observations, %zu runs); retained indirect because "
                "concrete coverage is non-exhaustive\n",
                ea_t(candidate.target), call_insn->ea,
                candidate.observations, candidate.runs.size());
        }
        return false;
    }

    const ea_t target_ea = static_cast<ea_t>(*target);
    if ( !is_valid_database_ea(target_ea) )
        return false;

    const flags64_t target_flags = get_flags_safe(target_ea);
    if ( !is_code(target_flags) && !get_func_safe(target_ea) &&
         !has_any_name(target_flags) )
        return false;

    out->resolved_target = target_ea;
    out->is_resolved = true;
    get_name(&out->target_name, target_ea);
    icall_debug("[indirect_call]   Direct expression resolved to 0x%llx (%s)\n",
                (unsigned long long)target_ea, out->target_name.c_str());
    return true;
}

//--------------------------------------------------------------------------
// Replace indirect call with direct call
//
// Converting m_icall to m_call:
// - m_icall: l = selector, r = computed target offset, d = mcallinfo_t
// - m_call:  l = direct function address (mop_v), d = mcallinfo_t
//
// IMPORTANT: Only replace if target is a valid function entry point.
// If not, just annotate - modifying calls to non-function addresses crashes.
//--------------------------------------------------------------------------
int indirect_call_handler_t::replace_indirect_call(mbl_array_t *mba, mblock_t *blk,
                                                   indirect_call_t &ic, deobf_ctx_t *ctx)
                                                   {
    if ( !mba || !blk || !ic.call_insn || !ic.is_resolved ) 
        return 0;

    icall_debug("[indirect_call] Attempting to replace call in block %d with direct call to 0x%llx\n",
                ic.block_idx, (unsigned long long)ic.resolved_target);
    icall_debug("[indirect_call]   Original opcode: %d, l.t=%d, r.t=%d, d.t=%d\n",
                ic.call_insn->opcode, ic.call_insn->l.t, 
                ic.call_insn->r.t, ic.call_insn->d.t);

    // Check if the target is a valid function entry point
    // If not, we risk crashing IDA with INTERR 50822
    if ( !is_valid_database_ea(ic.resolved_target) ) {
        icall_debug("[indirect_call]   Target 0x%llx is outside database EA range, skipping replacement\n",
                    (unsigned long long)ic.resolved_target);
        return 0;
    }

    func_t *target_func = get_func_safe(ic.resolved_target);
    bool is_func_start = (target_func && target_func->start_ea == ic.resolved_target);
    
    // Also check if it might be an external/import
    flags64_t flags = get_flags_safe(ic.resolved_target);
    bool is_extern = has_any_name(flags) && !is_code(flags);
    
    icall_debug("[indirect_call]   Target check: is_func=%d, is_func_start=%d, is_extern=%d\n",
                (target_func != nullptr), is_func_start, is_extern);

    // If target is not a proper function start, just annotate and return
    // This avoids INTERR 50822 crash
    if ( !is_func_start && !is_extern ) {
        icall_debug("[indirect_call]   Target is NOT a function start - skipping replacement to avoid crash\n");
        
        // Function creation is a separate database-analysis decision. If this
        // is not already a function entry, retain the indirect call.
        if ( !is_func_start ) {
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

    // An m_icall can become m_call only when its existing mcallinfo can be
    // preserved verbatim.
    bool is_unknown = call->d.empty();
    icall_debug("[indirect_call]   is_unknown_call=%d (d.t=%d)\n", is_unknown, call->d.t);
    
    if ( call->opcode == m_icall ) {
        // Strategy depends on whether mcallinfo exists:
        // 
        // If mcallinfo exists (d.t == mop_f): We can safely convert to m_call
        // and just update the callee address - arguments are preserved.
        //
        // If unknown call (d.empty()): We need to create mcallinfo ourselves,
        // copying any argument information from the r operand if present.
        
        if ( !is_unknown && call->d.t == mop_f && call->d.f != nullptr ) {
            // Has mcallinfo - can do full conversion to m_call
            icall_debug("[indirect_call]   Converting m_icall to m_call (has mcallinfo)\n");
            
            mcallinfo_t *mci = call->d.f;
            mci->callee = ic.resolved_target;
            
            // Try to get function type for better decompilation
            tinfo_t func_type;
            if ( get_tinfo(&func_type, ic.resolved_target) ) {
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
            // Without mcallinfo, argument and return locations are unknown.
            // Synthesizing a fastcall/void prototype can erase real arguments.
            annotate_indirect_call(blk, ic);
            return 0;
        }
                    
    } else if ( call->opcode == m_call ) {
        if ( call->d.t != mop_f || call->d.f == nullptr )
            return 0;
        // Already m_call, just update target
        call->d.f->callee = ic.resolved_target;
        call->l.erase();
        call->l.t = mop_v;
        call->l.g = ic.resolved_target;
        call->l.size = NOSIZE;
        
        icall_debug("[indirect_call]   Updated m_call target to 0x%llx\n",
                    (unsigned long long)ic.resolved_target);
    } else {
        return 0;
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

    if ( ctx ) 
        ctx->indirect_resolved++;

    return 1;
}

//--------------------------------------------------------------------------
// Annotate unresolved indirect call
//--------------------------------------------------------------------------
void indirect_call_handler_t::annotate_indirect_call(mblock_t *blk, const indirect_call_t &ic)
{
    if ( !blk || !ic.call_insn ) 
        return;

    qstring comment;
    if ( ic.is_resolved ) {
        comment.sprnt("DEOBF: Indirect call target = %s (0x%llX; not rewritten at this maturity)",
                      ic.target_name.empty() ? "?" : ic.target_name.c_str(),
                      (unsigned long long)ic.resolved_target);
    } else {
        comment.sprnt("DEOBF: Indirect call (unresolved)");
    }
    if ( ic.table_addr != BADADDR ) {
        comment.cat_sprnt("\n  Table: 0x%llX", (unsigned long long)ic.table_addr);
    }
    if ( ic.table_index >= 0 ) {
        comment.cat_sprnt("\n  Index: %d", ic.table_index);
    }
    if ( ic.offset != 0 ) {
        comment.cat_sprnt("\n  Offset: %lld", (long long)ic.offset);
    }

    set_cmt(ic.call_insn->ea, comment.c_str(), false);
}
