#include "identity_call.h"
#include "../analysis/pattern_match.h"

// Static members
std::set<ea_t> identity_call_handler_t::s_identity_funcs;
std::set<ea_t> identity_call_handler_t::s_non_identity_funcs;

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool identity_call_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Look for calls followed by indirect calls through the result
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Look for call instructions
            if (ins->opcode == m_call) {
                // Check if the call target is a known or potential identity function
                if (ins->l.t == mop_v || ins->l.t == mop_a) {
                    ea_t target = BADADDR;
                    if (ins->l.t == mop_v) {
                        target = ins->l.g;
                    } else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v) {
                        target = ins->l.a->g;
                    }
                    if (is_identity_function(target)) {
                        return true;
                    }
                }
            }

            // Look for icall (indirect call) through a register that was
            // just loaded from a call result
            if (ins->opcode == m_icall) {
                return true;  // Potential pattern
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Check if a function is an identity function
//--------------------------------------------------------------------------
bool identity_call_handler_t::is_identity_function(ea_t func_ea) {
    // Check cache first
    if (s_identity_funcs.count(func_ea))
        return true;
    if (s_non_identity_funcs.count(func_ea))
        return false;

    bool result = analyze_identity_func(func_ea);

    if (result)
        s_identity_funcs.insert(func_ea);
    else
        s_non_identity_funcs.insert(func_ea);

    return result;
}

//--------------------------------------------------------------------------
// Analyze if a function is an identity function
//--------------------------------------------------------------------------
bool identity_call_handler_t::analyze_identity_func(ea_t ea) {
    func_t *func = get_func(ea);
    if (!func)
        return false;

    // Identity functions are typically very short
    if (func->end_ea - func->start_ea > 32)
        return false;

    // Get function name for heuristics
    qstring name;
    get_func_name(&name, ea);

    // Decompile and check if it's just "return a1"
    hexrays_failure_t hf;
    cfuncptr_t cfunc = decompile(func, &hf, DECOMP_NO_WAIT);
    if (!cfunc)
        return false;

    // Check the function body - should be trivial
    citem_t *body = cfunc->body.find_parent_of(nullptr);
    if (!body)
        return false;

    // For an identity function, we expect:
    // - Single return statement
    // - Return value is the first argument

    // Alternative: Check at assembly level
    // Look for: mov rax, rdi; ret  (or similar)
    ea_t curr = func->start_ea;
    insn_t insn;
    int insn_count = 0;

    while (curr < func->end_ea && insn_count < 10) {
        if (decode_insn(&insn, curr) == 0)
            break;

        insn_count++;

        // Skip nops (for most architectures, check if instruction does nothing)
        // This is a simplified check - proper NOP detection would be arch-specific
        if (insn.size == 1 && get_byte(insn.ea) == 0x90) {
            curr = insn.ea + insn.size;
            continue;
        }

        // Check for mov rax, rdi (or equivalent first arg -> return reg)
        // On x64: rdi is first arg, rax is return
        // On ARM64: x0 is both first arg and return

        // If we hit a ret early, check if we've seen the right pattern
        if (is_ret_insn(insn)) {
            // If the function is just "ret" or "mov rax, rdi; ret"
            // it's likely an identity function
            if (insn_count <= 3) {
                return true;
            }
        }

        curr = insn.ea + insn.size;
    }

    // Very short function that doesn't call anything is suspicious
    if (insn_count <= 5) {
        // Check if function has no calls
        bool has_call = false;
        curr = func->start_ea;
        while (curr < func->end_ea) {
            if (decode_insn(&insn, curr) == 0)
                break;
            if (is_call_insn(insn)) {
                has_call = true;
                break;
            }
            curr = insn.ea + insn.size;
        }

        if (!has_call) {
            return true;  // Short function with no calls - likely identity
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass
//--------------------------------------------------------------------------
int identity_call_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[identity_call] Starting identity call resolution\n");

    int total_changes = 0;

    // Find all identity call patterns
    auto identity_calls = find_identity_calls(mba, ctx);
    deobf::log("[identity_call] Found %zu identity call patterns\n", identity_calls.size());

    for (const auto &ic : identity_calls) {
        mblock_t *blk = mba->get_mblock(ic.block_idx);
        if (!blk)
            continue;

        int changes = replace_identity_call(mba, blk, ic, ctx);
        total_changes += changes;

        if (changes > 0) {
            ctx->indirect_resolved++;
            deobf::log("[identity_call] Resolved call at block %d: %a -> %a\n",
                      ic.block_idx, ic.global_ptr, ic.resolved_target);
        }
    }

    deobf::log("[identity_call] Resolved %d identity calls\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find identity call patterns
//--------------------------------------------------------------------------
std::vector<identity_call_handler_t::identity_call_t>
identity_call_handler_t::find_identity_calls(mbl_array_t *mba, deobf_ctx_t *ctx) {

    std::vector<identity_call_t> result;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Look for call to potential identity function with global argument
            if (ins->opcode == m_call) {
                ea_t call_target = BADADDR;

                // Get call target
                if (ins->l.t == mop_v) {
                    call_target = ins->l.g;
                } else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v) {
                    call_target = ins->l.a->g;
                }

                if (call_target == BADADDR)
                    continue;

                // Check if this is an identity function
                if (!is_identity_function(call_target))
                    continue;

                // Check the argument - should be a global pointer
                // The argument is typically in ins->d (call arguments) or preceding instructions
                ea_t global_ptr = BADADDR;

                // Look at the instruction's operands for a global reference
                // In microcode, call arguments are typically in preceding mov/push instructions
                // or the call instruction itself may reference them

                // Search backwards for the argument setup
                for (minsn_t *prev = ins->prev; prev && prev != blk->head->prev; prev = prev->prev) {
                    // Look for load from global
                    if (prev->opcode == m_mov || prev->opcode == m_ldx) {
                        if (prev->l.t == mop_v) {
                            // Global variable
                            global_ptr = prev->l.g;
                            break;
                        } else if (prev->l.t == mop_a && prev->l.a && prev->l.a->t == mop_v) {
                            // Address of global
                            global_ptr = prev->l.a->g;
                            break;
                        }
                    }
                }

                if (global_ptr == BADADDR) {
                    // Try checking the call's first argument directly
                    if (ins->d.t == mop_v) {
                        global_ptr = ins->d.g;
                    } else if (ins->d.t == mop_a && ins->d.a && ins->d.a->t == mop_v) {
                        global_ptr = ins->d.a->g;
                    }
                }

                if (global_ptr == BADADDR)
                    continue;

                // Resolve the actual target from the global pointer
                ea_t resolved = resolve_global_pointer(global_ptr);
                if (resolved == BADADDR)
                    continue;

                identity_call_t ic;
                ic.block_idx = i;
                ic.call_insn = ins;
                ic.identity_func = call_target;
                ic.global_ptr = global_ptr;
                ic.resolved_target = resolved;

                result.push_back(ic);
            }
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Resolve global pointer to get actual target
//--------------------------------------------------------------------------
ea_t identity_call_handler_t::resolve_global_pointer(ea_t ptr_addr) {
    // Read the pointer value from the global
    ea_t target = BADADDR;

    // Determine pointer size based on segment
    segment_t *seg = getseg(ptr_addr);
    if (!seg)
        return BADADDR;

    // Read 8 bytes for 64-bit or 4 bytes for 32-bit
    int ptr_size = (inf_is_64bit()) ? 8 : 4;

    if (ptr_size == 8) {
        uint64_t val;
        if (get_bytes(&val, 8, ptr_addr) == 8) {
            target = (ea_t)val;
        }
    } else {
        uint32_t val;
        if (get_bytes(&val, 4, ptr_addr) == 4) {
            target = (ea_t)val;
        }
    }

    // Validate that the target is in a code segment
    if (target != BADADDR) {
        segment_t *target_seg = getseg(target);
        if (target_seg && (target_seg->perm & SEGPERM_EXEC)) {
            return target;
        }
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Replace identity call with direct call
//--------------------------------------------------------------------------
int identity_call_handler_t::replace_identity_call(mbl_array_t *mba, mblock_t *blk,
                                                    const identity_call_t &ic, deobf_ctx_t *ctx) {
    if (!blk || !ic.call_insn)
        return 0;

    minsn_t *call_ins = ic.call_insn;

    // Look for the subsequent icall that uses the result
    // Pattern: call identity_func -> mov result to reg -> icall through reg
    minsn_t *icall_ins = nullptr;

    // The icall might be in the same block or next instructions
    for (minsn_t *next = call_ins->next; next; next = next->next) {
        if (next->opcode == m_icall) {
            icall_ins = next;
            break;
        }
        // Also check for m_call with indirect operand
        if (next->opcode == m_call && next->l.t == mop_r) {
            icall_ins = next;
            break;
        }
    }

    if (icall_ins) {
        // Replace the indirect call with direct call to resolved target
        // Convert icall to call with direct target

        // Modify the instruction
        icall_ins->opcode = m_call;
        icall_ins->l.t = mop_v;
        icall_ins->l.g = ic.resolved_target;
        icall_ins->l.size = 0;  // Code address

        // NOP out the identity function call
        call_ins->opcode = m_nop;

        // Mark block as modified
        blk->mark_lists_dirty();

        deobf::log_verbose("[identity_call] Replaced icall with direct call to %a\n",
                          ic.resolved_target);

        // Add comment
        qstring comment;
        comment.sprnt("Resolved: identity(%a) -> %a", ic.global_ptr, ic.resolved_target);
        set_cmt(mba->entry_ea, comment.c_str(), false);

        return 1;
    }

    // Alternative: The result might be returned and called elsewhere
    // In this case, just annotate for now
    deobf::log_verbose("[identity_call] Found identity call but no subsequent icall\n");

    return 0;
}
