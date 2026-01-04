#include "identity_call.h"
#include "../analysis/pattern_match.h"
#include "../analysis/arch_utils.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>  // For NN_mov, NN_jmp, etc.
#endif

// Static members
std::set<ea_t> identity_call_handler_t::s_identity_funcs;
std::set<ea_t> identity_call_handler_t::s_non_identity_funcs;
std::map<ea_t, ea_t> identity_call_handler_t::s_trampoline_cache;
std::map<ea_t, std::vector<deferred_identity_call_t>> identity_call_handler_t::s_deferred_analysis;

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool identity_call_handler_t::detect(mbl_array_t *mba) {
    if (!mba)
        return false;

    // Scan all blocks for calls to identity functions and for ijmp.
    // If we find both (identity call somewhere + ijmp somewhere), we have the pattern.

    bool found_identity_call = false;
    bool found_ijmp = false;
    ea_t identity_func_addr = BADADDR;

    // Helper lambda to extract call target from instruction
    auto get_call_target = [](minsn_t *ins) -> ea_t {
        ea_t target = BADADDR;

        // Direct m_call
        if (ins->opcode == m_call) {
            if (ins->l.t == mop_v)
                target = ins->l.g;
            else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v)
                target = ins->l.a->g;
        }
        // m_mov with nested call (mov call(...) => temp)
        else if (ins->opcode == m_mov && ins->l.t == mop_d && ins->l.d) {
            minsn_t *sub = ins->l.d;
            if (sub->opcode == m_call) {
                if (sub->l.t == mop_v)
                    target = sub->l.g;
                else if (sub->l.t == mop_a && sub->l.a && sub->l.a->t == mop_v)
                    target = sub->l.a->g;
            }
        }
        return target;
    };

    // Scan all blocks
    bool found_icall = false;
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->head)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check for ijmp (indirect jump)
            if (ins->opcode == m_ijmp) {
                found_ijmp = true;
            }
            // Check for icall (indirect call) - used in "call identity; return v()" pattern
            if (ins->opcode == m_icall) {
                found_icall = true;
            }

            // Check for call to identity function
            ea_t target = get_call_target(ins);
            if (target != BADADDR) {
                if (is_identity_function(target)) {
                    found_identity_call = true;
                    identity_func_addr = target;
                    deobf::log("[identity_call] detect: %a is identity function\n", target);
                }
            }
        }
    }

    if (found_identity_call && (found_ijmp || found_icall)) {
        deobf::log("[identity_call] Detected pattern: identity call to %a + %s\n",
                  identity_func_addr, found_ijmp ? "ijmp" : "icall");
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Check if a function is an identity function
//--------------------------------------------------------------------------
bool identity_call_handler_t::is_identity_function(ea_t func_ea) {
    if (func_ea == BADADDR)
        return false;

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
// Identity function: just returns its first argument
// Pattern varies by architecture:
//   x86-64: mov rax, rdi; ret
//   ARM64:  ret (x0 is both first arg and return reg)
//--------------------------------------------------------------------------
bool identity_call_handler_t::analyze_identity_func(ea_t ea) {
    // Use the architecture-independent analysis from arch_utils
    return arch::analyze_identity_function(ea);
}

//--------------------------------------------------------------------------
// Phase 1: Main deobfuscation pass - analyze and store for annotation
// NOTE: We do NOT patch bytes during decompilation - that causes INTERR.
// Instead, we store analysis results and apply annotations in Phase 2.
//--------------------------------------------------------------------------
int identity_call_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[identity_call] Analyzing identity call patterns\n");

    ea_t func_ea = mba->entry_ea;

    // Find all identity call patterns
    auto identity_calls = find_identity_calls(mba, ctx);
    deobf::log("[identity_call] Found %zu identity call patterns\n", identity_calls.size());

    if (identity_calls.empty())
        return 0;

    std::vector<deferred_identity_call_t> deferred;

    for (const auto &ic : identity_calls) {
        qstring target_name;
        if (get_func_name(&target_name, ic.final_target) <= 0) {
            target_name.sprnt("sub_%a", ic.final_target);
        }

        // Store for Phase 2 (annotations and potential microcode modification)
        deferred_identity_call_t dc;
        dc.call_ea = ic.call_ea;
        dc.ijmp_ea = ic.ijmp_ea;
        dc.identity_func = ic.identity_func;
        dc.global_ptr = ic.global_ptr;
        dc.final_target = ic.final_target;
        dc.target_name = target_name;
        dc.is_ijmp_pattern = ic.is_ijmp_pattern;
        deferred.push_back(dc);

        deobf::log("[identity_call] Analyzed: call@%a -> %s (%a)\n",
                  ic.call_ea, target_name.c_str(), ic.final_target);

        // Add annotation immediately (this is safe during decompilation)
        qstring comment;
        comment.sprnt("RESOLVED: -> %s (%a)", target_name.c_str(), ic.final_target);
        set_cmt(ic.call_ea, comment.c_str(), false);

        // Rename the global pointer to make decompiled code more readable
        qstring ptr_name;
        ptr_name.sprnt("ptr_%s", target_name.c_str());
        set_name(ic.global_ptr, ptr_name.c_str(), SN_NOWARN | SN_NOCHECK);

        // Set the function type for the resolved target if not already set
        // This helps the decompiler understand the target's signature
        // Check if a function exists at this address; if not, try to create one
        func_t *target_func = get_func(ic.final_target);
        if (!target_func) {
            // No function at this address - try to create one
            if (add_func(ic.final_target)) {
                target_func = get_func(ic.final_target);
                deobf::log_verbose("[identity_call] Created function at %a\n", ic.final_target);
            }
        }

        if (target_func) {
            tinfo_t current_type;
            bool has_type = get_tinfo(&current_type, ic.final_target);
            if (!has_type || current_type.empty()) {
                // Set a default type: __int64 __fastcall()
                // This indicates the function takes no arguments and returns int64
                const char *type_str = "__int64 __fastcall f();";
                tinfo_t func_type;
                qstring parsed_name;
                if (parse_decl(&func_type, &parsed_name, nullptr, type_str, PT_SIL)) {
                    apply_tinfo(ic.final_target, func_type, TINFO_DEFINITE);
                    deobf::log_verbose("[identity_call] Set type for %a\n", ic.final_target);
                }
            }
        }

        ctx->indirect_resolved++;
    }

    // Store for Phase 2
    if (!deferred.empty()) {
        s_deferred_analysis[func_ea] = std::move(deferred);
    }

    deobf::log("[identity_call] Analyzed %zu patterns\n", identity_calls.size());

    return (int)identity_calls.size();
}

//--------------------------------------------------------------------------
// Phase 2: Apply deferred transformations at MMAT_LOCOPT
// At this maturity, we attempt microcode-level modifications to replace
// the identity call pattern with a direct call/jump.
//--------------------------------------------------------------------------
int identity_call_handler_t::apply_deferred(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    ea_t func_ea = mba->entry_ea;

    auto it = s_deferred_analysis.find(func_ea);
    if (it == s_deferred_analysis.end())
        return 0;

    deobf::log("[identity_call] Phase 2: Processing %zu patterns at maturity %d\n",
              it->second.size(), mba->maturity);

    int changes = 0;

    // At MMAT_LOCOPT (maturity 3), we can try microcode modifications
    // but we need to be very careful to maintain CFG consistency
    for (const auto &dc : it->second) {
        // For now, just log the pattern - microcode modification is risky
        // The annotations from Phase 1 already help the user understand the code
        deobf::log("[identity_call] Pattern: %a -> %s (annotations applied)\n",
                  dc.call_ea, dc.target_name.c_str());

        // Try to find and modify the call instruction in microcode
        // This is safer than patching x86 bytes during decompilation
        for (int i = 0; i < mba->qty; i++) {
            mblock_t *blk = mba->get_mblock(i);
            if (!blk || !blk->head)
                continue;

            for (minsn_t *ins = blk->head; ins; ins = ins->next) {
                // Look for the identity call by EA
                if (ins->ea != dc.call_ea)
                    continue;

                // Found the instruction at our target EA
                // Check if it's a call or mov containing a call
                minsn_t *call_ins = nullptr;

                if (ins->opcode == m_call) {
                    call_ins = ins;
                } else if (ins->opcode == m_mov && ins->l.t == mop_d && ins->l.d &&
                          ins->l.d->opcode == m_call) {
                    call_ins = ins->l.d;
                }

                if (call_ins && call_ins->l.t == mop_v &&
                    call_ins->l.g == dc.identity_func) {
                    // Change the call target from identity_func to final_target
                    deobf::log("[identity_call] Redirecting call: %a -> %a\n",
                              call_ins->l.g, dc.final_target);

                    call_ins->l.g = dc.final_target;

                    // Update mcallinfo to reflect the new target
                    if (call_ins->d.t == mop_f && call_ins->d.f) {
                        mcallinfo_t *ci = call_ins->d.f;
                        ci->args.clear();
                        ci->solid_args = 0;
                        ci->callee = dc.final_target;
                    }

                    changes++;

                    // Now find the indirect branch (ijmp or icall) and handle it
                    for (int j = 0; j < mba->qty; j++) {
                        mblock_t *blk2 = mba->get_mblock(j);
                        if (!blk2)
                            continue;

                        for (minsn_t *check_ins = blk2->head; check_ins; check_ins = check_ins->next) {
                            if (check_ins->ea != dc.ijmp_ea)
                                continue;

                            if (check_ins->opcode == m_ijmp) {
                                deobf::log("[identity_call] Found ijmp in block %d, converting to nop\n", j);
                                check_ins->opcode = m_nop;
                                check_ins->l.erase();
                                check_ins->r.erase();
                                check_ins->d.erase();
                                changes++;
                            } else if (check_ins->opcode == m_icall) {
                                deobf::log("[identity_call] Found icall in block %d, converting to nop\n", j);
                                // For icall pattern: the identity call result is called
                                // Just nop it since we've already redirected the identity call
                                check_ins->opcode = m_nop;
                                check_ins->l.erase();
                                check_ins->r.erase();
                                check_ins->d.erase();
                                changes++;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    // Clear the deferred analysis after processing
    s_deferred_analysis.erase(it);

    deobf::log("[identity_call] Phase 2 complete: %d modifications\n", changes);
    return changes;
}

//--------------------------------------------------------------------------
// Check if we have pending analysis
//--------------------------------------------------------------------------
bool identity_call_handler_t::has_pending_analysis(ea_t func_ea) {
    auto it = s_deferred_analysis.find(func_ea);
    return it != s_deferred_analysis.end() && !it->second.empty();
}

//--------------------------------------------------------------------------
// Clear deferred analysis for a function
//--------------------------------------------------------------------------
void identity_call_handler_t::clear_deferred(ea_t func_ea) {
    s_deferred_analysis.erase(func_ea);
}

//--------------------------------------------------------------------------
// Helper: Check if address is valid global pointer
//--------------------------------------------------------------------------
static bool is_valid_global_ptr(ea_t addr, ea_t exclude_target) {
    if (addr == BADADDR || addr == exclude_target)
        return false;
    // Must be in a data segment with valid pointer to code
    segment_t *seg = getseg(addr);
    if (!seg || (seg->perm & SEGPERM_EXEC))
        return false;  // Skip code segments
    // Read the pointer and check it points to code
    uint64_t val = 0;
    if (get_bytes(&val, 8, addr) != 8)
        return false;
    segment_t *target_seg = getseg((ea_t)val);
    return target_seg && (target_seg->perm & SEGPERM_EXEC);
}

//--------------------------------------------------------------------------
// Find identity call patterns
//--------------------------------------------------------------------------
std::vector<identity_call_handler_t::identity_call_t>
identity_call_handler_t::find_identity_calls(mbl_array_t *mba, deobf_ctx_t *ctx) {
    std::vector<identity_call_t> result;

    // Helper struct to hold call info
    struct call_info_t {
        minsn_t *call_ins;
        minsn_t *container_ins;
        ea_t target;
        ea_t global_ptr;
        ea_t call_ea;
    };

    // Helper lambda to extract call info
    auto get_call_info = [](minsn_t *ins) -> call_info_t {
        call_info_t info = {nullptr, nullptr, BADADDR, BADADDR, BADADDR};

        // Direct m_call
        if (ins->opcode == m_call) {
            info.call_ins = ins;
            info.container_ins = ins;
            info.call_ea = ins->ea;

            if (ins->l.t == mop_v) {
                info.target = ins->l.g;
            } else if (ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v) {
                info.target = ins->l.a->g;
            }

            // Try to get argument from mcallinfo
            if (ins->d.t == mop_f && ins->d.f && !ins->d.f->args.empty()) {
                const mcallarg_t &arg0 = ins->d.f->args[0];
                if (arg0.t == mop_v)
                    info.global_ptr = arg0.g;
                else if (arg0.t == mop_a && arg0.a && arg0.a->t == mop_v)
                    info.global_ptr = arg0.a->g;
            }

            // At early maturity, search native instructions for argument
            if (info.global_ptr == BADADDR && ins->ea != BADADDR) {
                ea_t search_ea = ins->ea;
                insn_t asm_ins;
                int search_count = 0;
                while (search_count++ < 20 && search_ea > 0) {
                    ea_t prev_ea = get_item_head(search_ea - 1);
                    if (prev_ea == BADADDR || prev_ea >= search_ea)
                        break;
                    search_ea = prev_ea;

                    if (decode_insn(&asm_ins, search_ea) == 0)
                        break;

                    // Look for argument load from memory (arch-independent)
                    ea_t mem_addr = BADADDR;
                    if (arch::is_arg_load_from_mem(asm_ins, &mem_addr)) {
                        if (is_valid_global_ptr(mem_addr, info.target)) {
                            info.global_ptr = mem_addr;
                            break;
                        }
                    }
                }
            }
        }
        // m_mov with nested call
        else if (ins->opcode == m_mov && ins->l.t == mop_d && ins->l.d) {
            minsn_t *sub = ins->l.d;
            if (sub->opcode == m_call) {
                info.call_ins = sub;
                info.container_ins = ins;
                info.call_ea = ins->ea;

                if (sub->l.t == mop_v) {
                    info.target = sub->l.g;
                } else if (sub->l.t == mop_a && sub->l.a && sub->l.a->t == mop_v) {
                    info.target = sub->l.a->g;
                }

                // Try mcallinfo
                if (sub->d.t == mop_f && sub->d.f && !sub->d.f->args.empty()) {
                    const mcallarg_t &arg0 = sub->d.f->args[0];
                    if (arg0.t == mop_v)
                        info.global_ptr = arg0.g;
                }

                // Search native instructions for argument (arch-independent)
                if (info.global_ptr == BADADDR && ins->ea != BADADDR) {
                    ea_t search_ea = ins->ea;
                    insn_t asm_ins;
                    int search_count = 0;
                    while (search_count++ < 20 && search_ea > 0) {
                        ea_t prev_ea = get_item_head(search_ea - 1);
                        if (prev_ea == BADADDR || prev_ea >= search_ea)
                            break;
                        search_ea = prev_ea;

                        if (decode_insn(&asm_ins, search_ea) == 0)
                            break;

                        ea_t mem_addr = BADADDR;
                        if (arch::is_arg_load_from_mem(asm_ins, &mem_addr)) {
                            if (is_valid_global_ptr(mem_addr, info.target)) {
                                info.global_ptr = mem_addr;
                                break;
                            }
                        }
                    }
                }
            }
        }
        return info;
    };

    // First pass: collect all call instructions and ijmp/icall instructions
    std::vector<std::pair<int, call_info_t>> calls;
    std::vector<std::pair<int, minsn_t*>> indirect_branches;  // ijmp or icall

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->head)
            continue;

        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Collect both ijmp and icall patterns
            if (ins->opcode == m_ijmp || ins->opcode == m_icall) {
                indirect_branches.push_back({i, ins});
            }

            call_info_t cinfo = get_call_info(ins);
            if (cinfo.target != BADADDR) {
                calls.push_back({i, cinfo});
            }
        }
    }

    deobf::log_verbose("[identity_call] find: found %zu calls, %zu indirect branches\n",
                      calls.size(), indirect_branches.size());

    // Match calls to identity functions with indirect branches (ijmp or icall)
    for (const auto &call_pair : calls) {
        int call_blk = call_pair.first;
        const call_info_t &cinfo = call_pair.second;

        if (!is_identity_function(cinfo.target))
            continue;

        deobf::log_verbose("[identity_call] find: identity call to %a in block %d, arg=%a\n",
                          cinfo.target, call_blk, cinfo.global_ptr);

        // Find matching indirect branch (ijmp or icall)
        for (const auto &branch_pair : indirect_branches) {
            int branch_blk = branch_pair.first;
            minsn_t *branch_ins = branch_pair.second;

            // Check if branch is related to call
            bool is_match = false;
            if (branch_blk == call_blk) {
                for (minsn_t *p = cinfo.container_ins->next; p; p = p->next) {
                    if (p == branch_ins) {
                        is_match = true;
                        break;
                    }
                }
            } else {
                // At early maturity, accept any indirect branch
                is_match = true;
            }

            if (!is_match)
                continue;

            ea_t global_ptr = cinfo.global_ptr;
            ea_t resolved = BADADDR;
            ea_t final_target = BADADDR;

            // Try to resolve the pointer
            if (global_ptr != BADADDR) {
                resolved = resolve_global_pointer(global_ptr);
                if (resolved != BADADDR) {
                    final_target = resolve_trampoline_chain(resolved);

                    // Check if this is a self-reference - if so, likely wrong pointer
                    func_t *curr_func = get_func(mba->entry_ea);
                    if (final_target == mba->entry_ea ||
                        (curr_func && final_target >= curr_func->start_ea &&
                         final_target < curr_func->end_ea)) {
                        deobf::log("[identity_call] Initial ptr %a resolved to self-ref %a, trying LEA search\n",
                                  global_ptr, final_target);
                        // Clear and try LEA-based table search instead
                        global_ptr = BADADDR;
                        resolved = BADADDR;
                        final_target = BADADDR;
                    }
                }
            }

            // If no simple global pointer or it was wrong, try to extract table base
            // Pattern (x86-64): lea rax, table; mov rdi, [rax+rcx*8]; call identity
            // Pattern (ARM64):  adrp x8, table; ldr x0, [x8, #off]; bl identity
            if (final_target == BADADDR && cinfo.call_ea != BADADDR) {
                ea_t search_ea = cinfo.call_ea;
                insn_t asm_ins;
                int search_count = 0;
                ea_t table_base = BADADDR;
                ea_t simple_ptr = BADADDR;

                while (search_count++ < 30 && search_ea > 0) {
                    ea_t prev_ea = get_item_head(search_ea - 1);
                    if (prev_ea == BADADDR || prev_ea >= search_ea)
                        break;
                    search_ea = prev_ea;

                    if (decode_insn(&asm_ins, search_ea) == 0)
                        break;

                    // Look for LEA/ADR instruction - loads the table base address
                    // Only take the first (closest to call) we find
                    if (table_base == BADADDR && arch::is_lea_insn(asm_ins.itype)) {
                        ea_t base = BADADDR;
                        // x86: LEA reg, [mem] - address in Op2
                        // ARM64: ADR/ADRP - computed address
                        if (asm_ins.Op2.type == o_mem) {
                            base = asm_ins.Op2.addr;
                        } else if (asm_ins.Op1.type == o_imm) {
                            // Some disassemblers put the address in Op1
                            base = (ea_t)asm_ins.Op1.value;
                        }
                        if (base != BADADDR && is_valid_global_ptr(base, cinfo.target)) {
                            table_base = base;
                            deobf::log("[identity_call] Found table base via LEA/ADR: %a\n", base);
                        }
                    }

                    // Also check for argument load from memory (simple case)
                    ea_t mem_addr = BADADDR;
                    if (arch::is_arg_load_from_mem(asm_ins, &mem_addr)) {
                        if (mem_addr != BADADDR && is_valid_global_ptr(mem_addr, cinfo.target)) {
                            simple_ptr = mem_addr;
                            // Don't break - continue to look for LEA/ADR
                        }
                    }
                }

                // Prefer LEA-based table resolution over simple pointer
                // (LEA indicates indexed table which is a more specific pattern)
                if (table_base != BADADDR) {
                    global_ptr = table_base;

                    // Read both table entries and check if they resolve to same target
                    ea_t target0 = resolve_global_pointer(table_base);
                    ea_t target1 = resolve_global_pointer(table_base + 8);

                    deobf::log("[identity_call] Table at %a: [0]=%a, [1]=%a\n",
                              table_base, target0, target1);

                    if (target0 != BADADDR) {
                        ea_t final0 = resolve_trampoline_chain(target0);
                        ea_t final1 = (target1 != BADADDR) ? resolve_trampoline_chain(target1) : BADADDR;

                        deobf::log("[identity_call] Resolved: [0]=%a->%a, [1]=%a->%a\n",
                                  target0, final0, target1, final1);

                        // Check if both targets are different and neither is self-reference
                        func_t *curr_func = get_func(mba->entry_ea);
                        bool t0_is_self = (final0 == mba->entry_ea) ||
                            (curr_func && final0 >= curr_func->start_ea && final0 < curr_func->end_ea);
                        bool t1_is_self = (final1 == mba->entry_ea) ||
                            (curr_func && final1 >= curr_func->start_ea && final1 < curr_func->end_ea);

                        // If both resolve to the same target, we can simplify
                        if (final0 == final1 || final1 == BADADDR) {
                            resolved = target0;
                            final_target = final0;
                            deobf::log("[identity_call] Both table entries resolve to %a\n", final_target);
                        } else if (!t0_is_self && t1_is_self) {
                            // Entry 0 is valid, entry 1 is self-ref - use entry 0
                            resolved = target0;
                            final_target = final0;
                            deobf::log("[identity_call] Using table[0]=%a (table[1] is self-ref)\n", final_target);
                        } else if (t0_is_self && !t1_is_self) {
                            // Entry 1 is valid, entry 0 is self-ref - use entry 1
                            resolved = target1;
                            final_target = final1;
                            deobf::log("[identity_call] Using table[1]=%a (table[0] is self-ref)\n", final_target);
                        } else if (!t0_is_self && !t1_is_self) {
                            // Both are valid different targets - conditional, use first
                            resolved = target0;
                            final_target = final0;
                            deobf::log("[identity_call] Conditional: targets differ, using %a\n", final_target);
                        } else {
                            // Both are self-reference - this is a CFF dispatcher
                            // The deflatten handler should handle this pattern
                            deobf::log("[identity_call] CFF dispatcher detected: both table entries loop back to function\n");

                            // Add annotation so user knows this is CFF
                            qstring comment;
                            comment.sprnt("CFF DISPATCHER: table@%a, targets loop back to function", table_base);
                            set_cmt(cinfo.call_ea, comment.c_str(), false);
                        }
                    }
                }

                // Fall back to simple pointer if table resolution didn't work
                if (final_target == BADADDR && simple_ptr != BADADDR) {
                    global_ptr = simple_ptr;
                    resolved = resolve_global_pointer(simple_ptr);
                    if (resolved != BADADDR) {
                        final_target = resolve_trampoline_chain(resolved);
                        deobf::log("[identity_call] Fallback to simple ptr %a -> %a\n", simple_ptr, final_target);
                    }
                }
            }

            if (final_target == BADADDR) {
                deobf::log_verbose("[identity_call] find: pattern found but couldn't resolve target\n");
                continue;
            }

            // Skip self-referencing patterns (would create infinite recursion)
            if (final_target == mba->entry_ea) {
                deobf::log("[identity_call] Skipping self-reference: target %a == function entry\n", final_target);
                continue;
            }

            // Also skip if target is within the current function (internal jump)
            func_t *curr_func = get_func(mba->entry_ea);
            if (curr_func && final_target >= curr_func->start_ea && final_target < curr_func->end_ea) {
                deobf::log("[identity_call] Skipping internal reference: target %a is within function\n", final_target);
                continue;
            }

            identity_call_t ic;
            ic.block_idx = branch_blk;
            ic.call_insn = cinfo.container_ins;
            ic.ijmp_insn = branch_ins;
            ic.identity_func = cinfo.target;
            ic.global_ptr = global_ptr;
            ic.resolved_target = resolved;
            ic.final_target = final_target;
            ic.call_ea = cinfo.call_ea;
            ic.ijmp_ea = branch_ins->ea;
            ic.is_ijmp_pattern = (branch_ins->opcode == m_ijmp);

            deobf::log("[identity_call] find: pattern matched: call@%a -> ptr=%a -> %a -> final %a\n",
                      cinfo.call_ea, cinfo.global_ptr, resolved, final_target);

            result.push_back(ic);
            break;
        }
    }

    return result;
}

//--------------------------------------------------------------------------
// Resolve global pointer to get actual target
//--------------------------------------------------------------------------
ea_t identity_call_handler_t::resolve_global_pointer(ea_t ptr_addr) {
    if (ptr_addr == BADADDR)
        return BADADDR;

    // Use architecture-independent pointer reading
    ea_t target = arch::read_ptr(ptr_addr);

    // Validate target is in code
    if (target != BADADDR) {
        segment_t *target_seg = getseg(target);
        if (target_seg && (target_seg->perm & SEGPERM_EXEC)) {
            return target;
        }
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Check if a code location is a trampoline
//--------------------------------------------------------------------------
bool identity_call_handler_t::is_trampoline_code(ea_t addr, ea_t *next_ptr_out) {
    // Use architecture-independent trampoline detection
    return arch::is_trampoline_code(addr, next_ptr_out);
}

//--------------------------------------------------------------------------
// Resolve trampoline chain recursively
//--------------------------------------------------------------------------
ea_t identity_call_handler_t::resolve_trampoline_chain(ea_t start_addr, int max_depth) {
    if (start_addr == BADADDR || max_depth <= 0)
        return start_addr;

    // Check cache
    auto it = s_trampoline_cache.find(start_addr);
    if (it != s_trampoline_cache.end()) {
        return it->second;
    }

    ea_t current = start_addr;
    std::set<ea_t> visited;

    while (max_depth-- > 0) {
        if (visited.count(current)) {
            deobf::log_verbose("[identity_call] Cycle detected at %a\n", current);
            break;
        }
        visited.insert(current);

        ea_t next_ptr = BADADDR;
        if (is_trampoline_code(current, &next_ptr)) {
            ea_t next_target = resolve_global_pointer(next_ptr);
            if (next_target == BADADDR) {
                deobf::log_verbose("[identity_call] Chain broken at %a\n", current);
                break;
            }

            deobf::log_verbose("[identity_call] Chain: %a -> ptr %a -> %a\n",
                              current, next_ptr, next_target);

            current = next_target;
        } else {
            break;
        }
    }

    s_trampoline_cache[start_addr] = current;
    return current;
}

//--------------------------------------------------------------------------
// Transform identity call by patching native instructions
// This approach patches the actual binary instructions in IDA's database,
// which is more reliable than microcode manipulation.
//
// Transform: call identity(ptr); jmp reg  ->  jmp target; nop...
//--------------------------------------------------------------------------
int identity_call_handler_t::transform_identity_call(mbl_array_t *mba,
    const deferred_identity_call_t &dc, deobf_ctx_t *ctx) {

    (void)mba;
    (void)ctx;

    ea_t target = dc.final_target;
    if (target == BADADDR)
        return 0;

    // Decode the original instructions
    insn_t call_insn, jmp_insn;
    if (decode_insn(&call_insn, dc.call_ea) == 0)
        return 0;
    if (decode_insn(&jmp_insn, dc.ijmp_ea) == 0)
        return 0;

    // Verify we have the expected pattern (arch-independent)
    if (!arch::is_call_insn(call_insn.itype)) {
        deobf::log("[identity_call] Expected call at %a\n", dc.call_ea);
        return 0;
    }

    // Check for indirect jump via register (arch-independent)
    if (!arch::is_indirect_jump_via_return_reg(jmp_insn)) {
        deobf::log("[identity_call] Expected indirect jump at %a, got type %d\n",
                  dc.ijmp_ea, jmp_insn.itype);
        return 0;
    }

    // Calculate instruction sizes
    size_t call_size = call_insn.size;
    size_t jmp_size = jmp_insn.size;
    size_t total_size = (dc.ijmp_ea + jmp_size) - dc.call_ea;

    deobf::log("[identity_call] Patching %zu bytes at %a: call(%zu) + jmp(%zu)\n",
              total_size, dc.call_ea, call_size, jmp_size);

    // Build the patch using arch-independent instruction building
    uint8_t patch[32];
    memset(patch, 0, sizeof(patch));

    // Build direct jump instruction
    size_t jmp_len = arch::build_direct_jump(patch, sizeof(patch), dc.call_ea, target);
    if (jmp_len == 0) {
        deobf::log("[identity_call] Failed to build jump instruction (target may be out of range)\n");
        // Fallback to annotations
        qstring comment;
        comment.sprnt("TRAMPOLINE -> %s (%a)", dc.target_name.c_str(), target);
        set_cmt(dc.call_ea, comment.c_str(), false);
        return 0;
    }

    // Fill rest with NOPs
    size_t nop_size = arch::get_min_insn_size();
    for (size_t i = jmp_len; i + nop_size <= total_size && i < sizeof(patch); ) {
        size_t written = arch::get_nop_bytes(patch + i, sizeof(patch) - i);
        if (written == 0) break;
        i += written;
    }

    // Apply the patch
    bool patched = true;
    for (size_t i = 0; i < total_size && i < sizeof(patch); i++) {
        if (!patch_byte(dc.call_ea + i, patch[i])) {
            patched = false;
            break;
        }
    }

    if (!patched) {
        deobf::log("[identity_call] Failed to patch bytes at %a\n", dc.call_ea);

        // Fallback to annotations
        qstring comment;
        comment.sprnt("TRAMPOLINE -> %s (%a)", dc.target_name.c_str(), target);
        set_cmt(dc.call_ea, comment.c_str(), false);

        qstring ptr_name;
        ptr_name.sprnt("ptr_%s", dc.target_name.c_str());
        set_name(dc.global_ptr, ptr_name.c_str(), SN_NOWARN | SN_NOCHECK);

        return 0;
    }

    // Force IDA to re-analyze the patched area
    del_items(dc.call_ea, DELIT_EXPAND, total_size);
    auto_make_code(dc.call_ea);
    auto_wait();

    // Add cross-reference to target
    add_cref(dc.call_ea, target, fl_JN);

    // Add comment
    qstring comment;
    comment.sprnt("Deobfuscated: jmp %s", dc.target_name.c_str());
    set_cmt(dc.call_ea, comment.c_str(), false);

    // Rename the global pointer
    qstring ptr_name;
    ptr_name.sprnt("ptr_%s", dc.target_name.c_str());
    set_name(dc.global_ptr, ptr_name.c_str(), SN_NOWARN | SN_NOCHECK);

    deobf::log("[identity_call] Patched to direct jmp to %s (%a)\n",
              dc.target_name.c_str(), target);

    return 1;
}

//--------------------------------------------------------------------------
// Create a proper call instruction (helper for future use)
//--------------------------------------------------------------------------
minsn_t *identity_call_handler_t::create_call_insn(mbl_array_t *mba, ea_t target, ea_t source_ea) {
    // Allocate a new instruction from the mba
    minsn_t *call = new minsn_t(source_ea);
    call->opcode = m_call;
    call->l.t = mop_v;
    call->l.g = target;
    call->l.size = 0;

    // For a proper call, we'd also set up:
    // - call->d with mcallinfo (calling convention, arguments, return type)
    // This is complex and depends on the target function's prototype

    return call;
}

//--------------------------------------------------------------------------
// Resolve an indexed table to get both entries and determine pattern type
// This is the main utility function for other handlers (like deflatten)
//--------------------------------------------------------------------------
identity_call_handler_t::table_resolution_t
identity_call_handler_t::resolve_indexed_table(ea_t table_base, ea_t func_ea) {
    table_resolution_t result;
    result.table_base = table_base;
    result.entry0_target = BADADDR;
    result.entry1_target = BADADDR;
    result.both_same = false;
    result.is_cff_dispatcher = false;

    if (table_base == BADADDR)
        return result;

    // Read both table entries
    ea_t target0 = resolve_global_pointer(table_base);
    ea_t target1 = resolve_global_pointer(table_base + 8);

    if (target0 == BADADDR) {
        deobf::log_verbose("[identity_call] resolve_indexed_table: no valid target at %a\n", table_base);
        return result;
    }

    // Resolve trampoline chains to get final targets
    ea_t final0 = resolve_trampoline_chain(target0);
    ea_t final1 = (target1 != BADADDR) ? resolve_trampoline_chain(target1) : BADADDR;

    result.entry0_target = final0;
    result.entry1_target = final1;

    deobf::log_verbose("[identity_call] resolve_indexed_table: %a -> [0]=%a, [1]=%a\n",
                      table_base, final0, final1);

    // Check if both entries resolve to the same target
    if (final0 == final1 || final1 == BADADDR) {
        result.both_same = true;
    }

    // Check for CFF dispatcher pattern (targets loop back to function)
    if (func_ea != BADADDR) {
        func_t *func = get_func(func_ea);
        bool t0_is_self = (final0 == func_ea) ||
            (func && final0 >= func->start_ea && final0 < func->end_ea);
        bool t1_is_self = (final1 == func_ea) ||
            (func && final1 >= func->start_ea && final1 < func->end_ea);

        // If both targets loop back to the function, it's a CFF dispatcher
        if (t0_is_self && t1_is_self) {
            result.is_cff_dispatcher = true;
            deobf::log("[identity_call] resolve_indexed_table: CFF dispatcher detected at %a\n", table_base);
        }
        // If one target loops back, annotate but not full CFF
        else if (t0_is_self || t1_is_self) {
            deobf::log_verbose("[identity_call] resolve_indexed_table: partial self-ref at %a\n", table_base);
        }
    }

    return result;
}
