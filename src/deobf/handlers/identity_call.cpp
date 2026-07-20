#include "identity_call.h"
#include "../analysis/pattern_match.h"
#include "../analysis/arch_utils.h"

#ifndef ALLINS_HPP_INCLUDED
#define ALLINS_HPP_INCLUDED
#include <allins.hpp>  // For NN_mov, NN_jmp, etc.
#endif

// Static members
std::map<ssize_t, std::set<ea_t>> identity_call_handler_t::s_identity_funcs;
std::map<ssize_t, std::set<ea_t>> identity_call_handler_t::s_non_identity_funcs;
std::map<ssize_t, std::map<ea_t, ea_t>>
    identity_call_handler_t::s_trampoline_cache;
std::map<ssize_t, identity_call_handler_t::deferred_cache_t>
    identity_call_handler_t::s_deferred_analysis;

std::set<ea_t> &identity_call_handler_t::identity_cache()
{
    return s_identity_funcs[get_dbctx_id()];
}

std::set<ea_t> &identity_call_handler_t::non_identity_cache()
{
    return s_non_identity_funcs[get_dbctx_id()];
}

std::map<ea_t, ea_t> &identity_call_handler_t::trampoline_cache()
{
    return s_trampoline_cache[get_dbctx_id()];
}

identity_call_handler_t::deferred_cache_t &
identity_call_handler_t::deferred_cache()
{
    return s_deferred_analysis[get_dbctx_id()];
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool identity_call_handler_t::detect(mbl_array_t *mba)
{
    if ( !mba ) 
        return false;

    // Helper lambda to extract call target from instruction
    auto get_call_target = [](minsn_t *ins) -> ea_t {
        ea_t target = BADADDR;

        // Direct m_call
        if ( ins->opcode == m_call ) {
            if ( ins->l.t == mop_v ) 
                target = ins->l.g;
            else if ( ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v ) 
                target = ins->l.a->g;
        }
        // m_mov with nested call (mov call(...) => temp)
        else if ( ins->opcode == m_mov && ins->l.t == mop_d && ins->l.d ) {
            minsn_t *sub = ins->l.d;
            if ( sub->opcode == m_call ) {
                if ( sub->l.t == mop_v ) 
                    target = sub->l.g;
                else if ( sub->l.t == mop_a && sub->l.a && sub->l.a->t == mop_v ) 
                    target = sub->l.a->g;
            }
        }
        return target;
    };

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk || !blk->head ) 
            continue;

        ea_t preceding_identity = BADADDR;
        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            if ( preceding_identity != BADADDR
              && (ins->opcode == m_ijmp || ins->opcode == m_icall) ) {
                deobf::log_verbose(
                    "[identity_call] Detected adjacent identity/indirect pattern at %a\n",
                    preceding_identity);
                return true;
            }

            // Check for call to identity function
            ea_t target = get_call_target(ins);
            preceding_identity = target != BADADDR && is_identity_function(target)
                ? target : BADADDR;
        }
    }
    return false;
}

//--------------------------------------------------------------------------
// Check if a function is an identity function
//--------------------------------------------------------------------------
bool identity_call_handler_t::is_identity_function(ea_t func_ea)
{
    if ( func_ea == BADADDR ) 
        return false;

    // Check cache first
    if ( identity_cache().count(func_ea) )
        return true;
    if ( non_identity_cache().count(func_ea) )
        return false;

    bool result = analyze_identity_func(func_ea);

    if ( result ) 
        identity_cache().insert(func_ea);
    else
        non_identity_cache().insert(func_ea);

    return result;
}

//--------------------------------------------------------------------------
// Analyze if a function is an identity function
// Identity function: just returns its first argument
// Pattern varies by architecture:
//   x86-64: mov rax, rdi; ret
//   ARM64:  ret (x0 is both first arg and return reg)
//--------------------------------------------------------------------------
bool identity_call_handler_t::analyze_identity_func(ea_t ea)
{
    // Use the architecture-independent analysis from arch_utils
    return arch::analyze_identity_function(ea);
}

//--------------------------------------------------------------------------
// Phase 1: analyze and retain provenance for diagnostics.  Detection is not a
// microcode mutation and therefore must not be reported as one.
//--------------------------------------------------------------------------
int identity_call_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    deobf::log("[identity_call] Analyzing identity call patterns\n");

    ea_t func_ea = mba->entry_ea;

    // Find all identity call patterns
    auto identity_calls = find_identity_calls(mba, ctx);
    deobf::log("[identity_call] Found %zu identity call patterns\n", identity_calls.size());

    if ( identity_calls.empty() ) 
        return 0;

    std::vector<deferred_identity_call_t> deferred;

    for ( const auto &ic : identity_calls ) {
        qstring target_name;
        if ( get_func_name(&target_name, ic.final_target) <= 0 ) {
            target_name.sprnt("sub_%a", ic.final_target);
        }

        // Store the result so later maturity callbacks do not repeat the
        // relatively expensive pointer-chain analysis.
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

    }

    // Store for Phase 2
    if ( !deferred.empty() ) {
        deferred_cache()[func_ea] = std::move(deferred);
    }

    deobf::log("[identity_call] Analyzed %zu patterns\n", identity_calls.size());

    return 0;
}

//--------------------------------------------------------------------------
// Phase 2: consume deferred diagnostic results.  A correct structural rewrite
// must preserve the identity call's side effects and the consumer's complete
// call information; neither is established by the current pattern record.
//--------------------------------------------------------------------------
int identity_call_handler_t::apply_deferred(mbl_array_t *mba, deobf_ctx_t *ctx)
{
    if ( !mba || !ctx ) 
        return 0;

    ea_t func_ea = mba->entry_ea;

    deferred_cache_t &cache = deferred_cache();
    auto p = cache.find(func_ea);
    if ( p == cache.end() )
        return 0;

    deobf::log("[identity_call] Phase 2: Processing %zu patterns at maturity %d\n",
              p->second.size(), mba->maturity);

    // Redirecting the producer call and deleting the later icall/ijmp changes
    // call order and loses the indirect call's arguments. A sound rewrite must
    // instead replace the consumer and prove the producer side-effect-free.
    for ( const auto &dc : p->second ) {
        deobf::log("[identity_call] Pattern: %a -> %s (analysis only)\n",
                  dc.call_ea, dc.target_name.c_str());
    }

    // Clear the deferred analysis after processing
    cache.erase(p);

    deobf::log("[identity_call] Phase 2 complete: analysis only\n");
    return 0;
}

//--------------------------------------------------------------------------
// Check if we have pending analysis
//--------------------------------------------------------------------------
bool identity_call_handler_t::has_pending_analysis(ea_t func_ea)
{
    const ssize_t database = get_dbctx_id();
    const auto databases = s_deferred_analysis.find(database);
    if ( databases == s_deferred_analysis.end() )
        return false;
    const auto p = databases->second.find(func_ea);
    return p != databases->second.end() && !p->second.empty();
}

//--------------------------------------------------------------------------
// Clear deferred analysis for a function
//--------------------------------------------------------------------------
void identity_call_handler_t::clear_deferred(ea_t func_ea)
{
    const ssize_t database = get_dbctx_id();
    auto databases = s_deferred_analysis.find(database);
    if ( databases == s_deferred_analysis.end() )
        return;
    databases->second.erase(func_ea);
    if ( databases->second.empty() )
        s_deferred_analysis.erase(databases);
}

void identity_call_handler_t::clear_caches()
{
    const ssize_t database = get_dbctx_id();
    s_identity_funcs.erase(database);
    s_non_identity_funcs.erase(database);
    s_trampoline_cache.erase(database);
    s_deferred_analysis.erase(database);
}

//--------------------------------------------------------------------------
// Helper: Check if address is valid global pointer
//--------------------------------------------------------------------------
static bool is_valid_global_ptr(ea_t addr, ea_t exclude_target)
{
    if ( addr == BADADDR || addr == exclude_target ) 
        return false;
    // Must be in a data segment with valid pointer to code
    segment_t *seg = getseg(addr);
    if ( !seg || (seg->perm & SEGPERM_EXEC) ) 
        return false;  // Skip code segments
    // Read the pointer and check it points to code
    const ea_t value = arch::read_ptr(addr);
    if ( value == BADADDR )
        return false;
    segment_t *target_seg = getseg(value);
    return target_seg && (target_seg->perm & SEGPERM_EXEC);
}

//--------------------------------------------------------------------------
// Find identity call patterns
//--------------------------------------------------------------------------
std::vector<identity_call_handler_t::identity_call_t>
identity_call_handler_t::find_identity_calls(mbl_array_t *mba, deobf_ctx_t *ctx)
{
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
        if ( ins->opcode == m_call ) {
            info.call_ins = ins;
            info.container_ins = ins;
            info.call_ea = ins->ea;

            if ( ins->l.t == mop_v ) {
                info.target = ins->l.g;
            } else if ( ins->l.t == mop_a && ins->l.a && ins->l.a->t == mop_v ) {
                info.target = ins->l.a->g;
            }

            // Try to get argument from mcallinfo
            if ( ins->d.t == mop_f && ins->d.f && !ins->d.f->args.empty() ) {
                const mcallarg_t &arg0 = ins->d.f->args[0];
                if ( arg0.t == mop_v ) 
                    info.global_ptr = arg0.g;
                else if ( arg0.t == mop_a && arg0.a && arg0.a->t == mop_v ) 
                    info.global_ptr = arg0.a->g;
            }

            // At early maturity, search native instructions for argument
            if ( info.global_ptr == BADADDR && ins->ea != BADADDR ) {
                ea_t search_ea = ins->ea;
                insn_t asm_ins;
                int search_count = 0;
                while ( search_count++ < 20 && search_ea > 0 ) {
                    ea_t prev_ea = get_item_head(search_ea - 1);
                    if ( prev_ea == BADADDR || prev_ea >= search_ea ) 
                        break;
                    search_ea = prev_ea;

                    if ( decode_insn(&asm_ins, search_ea) == 0 ) 
                        break;

                    // Look for argument load from memory (arch-independent)
                    ea_t mem_addr = BADADDR;
                    if ( arch::is_arg_load_from_mem(asm_ins, &mem_addr) ) {
                        if ( is_valid_global_ptr(mem_addr, info.target) ) {
                            info.global_ptr = mem_addr;
                            break;
                        }
                    }
                }
            }
        }
        // m_mov with nested call
        else if ( ins->opcode == m_mov && ins->l.t == mop_d && ins->l.d ) {
            minsn_t *sub = ins->l.d;
            if ( sub->opcode == m_call ) {
                info.call_ins = sub;
                info.container_ins = ins;
                info.call_ea = ins->ea;

                if ( sub->l.t == mop_v ) {
                    info.target = sub->l.g;
                } else if ( sub->l.t == mop_a && sub->l.a && sub->l.a->t == mop_v ) {
                    info.target = sub->l.a->g;
                }

                // Try mcallinfo
                if ( sub->d.t == mop_f && sub->d.f && !sub->d.f->args.empty() ) {
                    const mcallarg_t &arg0 = sub->d.f->args[0];
                    if ( arg0.t == mop_v ) 
                        info.global_ptr = arg0.g;
                }

                // Search native instructions for argument (arch-independent)
                if ( info.global_ptr == BADADDR && ins->ea != BADADDR ) {
                    ea_t search_ea = ins->ea;
                    insn_t asm_ins;
                    int search_count = 0;
                    while ( search_count++ < 20 && search_ea > 0 ) {
                        ea_t prev_ea = get_item_head(search_ea - 1);
                        if ( prev_ea == BADADDR || prev_ea >= search_ea ) 
                            break;
                        search_ea = prev_ea;

                        if ( decode_insn(&asm_ins, search_ea) == 0 ) 
                            break;

                        ea_t mem_addr = BADADDR;
                        if ( arch::is_arg_load_from_mem(asm_ins, &mem_addr) ) {
                            if ( is_valid_global_ptr(mem_addr, info.target) ) {
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

    for ( int i = 0; i < mba->qty; ++i ) {
        mblock_t *blk = mba->get_mblock(i);
        if ( !blk || !blk->head ) 
            continue;

        for ( minsn_t *ins = blk->head; ins; ins = ins->next ) {
            // Collect both ijmp and icall patterns
            if ( ins->opcode == m_ijmp || ins->opcode == m_icall ) {
                indirect_branches.push_back({i, ins});
            }

            call_info_t cinfo = get_call_info(ins);
            if ( cinfo.target != BADADDR ) {
                calls.push_back({i, cinfo});
            }
        }
    }

    deobf::log_verbose("[identity_call] find: found %zu calls, %zu indirect branches\n",
                      calls.size(), indirect_branches.size());

    // Match calls to identity functions with indirect branches (ijmp or icall)
    for ( const auto &call_pair : calls ) {
        int call_blk = call_pair.first;
        const call_info_t &cinfo = call_pair.second;

        if ( !is_identity_function(cinfo.target) ) 
            continue;

        deobf::log_verbose("[identity_call] find: identity call to %a in block %d, arg=%a\n",
                          cinfo.target, call_blk, cinfo.global_ptr);

        // Find matching indirect branch (ijmp or icall)
        for ( const auto &branch_pair : indirect_branches ) {
            int branch_blk = branch_pair.first;
            minsn_t *branch_ins = branch_pair.second;

            // Check if branch is related to call
            const bool is_match = branch_blk == call_blk
                && cinfo.container_ins->next == branch_ins;

            if ( !is_match ) 
                continue;

            ea_t global_ptr = cinfo.global_ptr;
            ea_t resolved = BADADDR;
            ea_t final_target = BADADDR;

            // Try to resolve the pointer
            if ( global_ptr != BADADDR ) {
                resolved = resolve_global_pointer(global_ptr);
                if ( resolved != BADADDR ) {
                    final_target = resolve_trampoline_chain(resolved);

                    // Check if this is a self-reference - if so, likely wrong pointer
                    func_t *curr_func = get_func(mba->entry_ea);
                    if ( final_target == mba->entry_ea ||
                        (curr_func && final_target >= curr_func->start_ea &&
                         final_target < curr_func->end_ea))
                         {
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
            if ( final_target == BADADDR && cinfo.call_ea != BADADDR ) {
                ea_t search_ea = cinfo.call_ea;
                insn_t asm_ins;
                int search_count = 0;
                ea_t table_base = BADADDR;
                ea_t simple_ptr = BADADDR;

                while ( search_count++ < 30 && search_ea > 0 ) {
                    ea_t prev_ea = get_item_head(search_ea - 1);
                    if ( prev_ea == BADADDR || prev_ea >= search_ea ) 
                        break;
                    search_ea = prev_ea;

                    if ( decode_insn(&asm_ins, search_ea) == 0 ) 
                        break;

                    // Look for LEA/ADR instruction - loads the table base address
                    // Only take the first (closest to call) we find
                    if ( table_base == BADADDR && arch::is_lea_insn(asm_ins.itype) ) {
                        ea_t base = BADADDR;
                        // x86: LEA reg, [mem] - address in Op2
                        // ARM64: ADR/ADRP - computed address
                        if ( asm_ins.Op2.type == o_mem ) {
                            base = asm_ins.Op2.addr;
                        } else if ( asm_ins.Op1.type == o_imm ) {
                            // Some disassemblers put the address in Op1
                            base = (ea_t)asm_ins.Op1.value;
                        }
                        if ( base != BADADDR && is_valid_global_ptr(base, cinfo.target) ) {
                            table_base = base;
                            deobf::log("[identity_call] Found table base via LEA/ADR: %a\n", base);
                        }
                    }

                    // Also check for argument load from memory (simple case)
                    ea_t mem_addr = BADADDR;
                    if ( arch::is_arg_load_from_mem(asm_ins, &mem_addr) ) {
                        if ( mem_addr != BADADDR && is_valid_global_ptr(mem_addr, cinfo.target) ) {
                            simple_ptr = mem_addr;
                            // Don't break - continue to look for LEA/ADR
                        }
                    }
                }

                // Prefer LEA-based table resolution over simple pointer
                // (LEA indicates indexed table which is a more specific pattern)
                if ( table_base != BADADDR ) {
                    global_ptr = table_base;

                    // Read both table entries and admit the table only if both
                    // runtime-selectable entries resolve to the same target.
                    ea_t target0 = resolve_global_pointer(table_base);
                    ea_t target1 = BADADDR;
                    const ea_t stride = static_cast<ea_t>(arch::get_ptr_size());
                    if ( table_base <= BADADDR - 1 - stride )
                        target1 = resolve_global_pointer(table_base + stride);

                    deobf::log("[identity_call] Table at %a: [0]=%a, [1]=%a\n",
                              table_base, target0, target1);

                    if ( target0 != BADADDR ) {
                        ea_t final0 = resolve_trampoline_chain(target0);
                        ea_t final1 = (target1 != BADADDR) ? resolve_trampoline_chain(target1) : BADADDR;

                        deobf::log("[identity_call] Resolved: [0]=%a->%a, [1]=%a->%a\n",
                                  target0, final0, target1, final1);

                        // If both resolve to the same target, we can simplify
                        if ( final0 != BADADDR && final0 == final1 ) {
                            resolved = target0;
                            final_target = final0;
                            deobf::log("[identity_call] Both table entries resolve to %a\n", final_target);
                        } else {
                            deobf::log_verbose(
                                "[identity_call] Table targets differ or are incomplete; leaving unresolved\n");
                        }
                    }
                }

                // Fall back to simple pointer if table resolution didn't work
                if ( final_target == BADADDR && simple_ptr != BADADDR ) {
                    global_ptr = simple_ptr;
                    resolved = resolve_global_pointer(simple_ptr);
                    if ( resolved != BADADDR ) {
                        final_target = resolve_trampoline_chain(resolved);
                        deobf::log("[identity_call] Fallback to simple ptr %a -> %a\n", simple_ptr, final_target);
                    }
                }
            }

            if ( final_target == BADADDR ) {
                deobf::log_verbose("[identity_call] find: pattern found but couldn't resolve target\n");
                continue;
            }

            // Skip self-referencing patterns (would create infinite recursion)
            if ( final_target == mba->entry_ea ) {
                deobf::log("[identity_call] Skipping self-reference: target %a == function entry\n", final_target);
                continue;
            }

            // Also skip if target is within the current function (internal jump)
            func_t *curr_func = get_func(mba->entry_ea);
            if ( curr_func && final_target >= curr_func->start_ea && final_target < curr_func->end_ea ) {
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
ea_t identity_call_handler_t::resolve_global_pointer(ea_t ptr_addr)
{
    if ( ptr_addr == BADADDR ) 
        return BADADDR;

    // Use architecture-independent pointer reading
    ea_t target = arch::read_ptr(ptr_addr);

    // Validate target is in code
    if ( target != BADADDR ) {
        segment_t *target_seg = getseg(target);
        if ( target_seg && (target_seg->perm & SEGPERM_EXEC) ) {
            return target;
        }
    }

    return BADADDR;
}

//--------------------------------------------------------------------------
// Check if a code location is a trampoline
//--------------------------------------------------------------------------
bool identity_call_handler_t::is_trampoline_code(ea_t addr, ea_t *next_ptr_out)
{
    // Use architecture-independent trampoline detection
    return arch::is_trampoline_code(addr, next_ptr_out);
}

//--------------------------------------------------------------------------
// Resolve trampoline chain recursively
//--------------------------------------------------------------------------
ea_t identity_call_handler_t::resolve_trampoline_chain(ea_t start_addr, int max_depth)
{
    if ( start_addr == BADADDR || max_depth <= 0 ) 
        return start_addr;

    // Check cache
    std::map<ea_t, ea_t> &cache = trampoline_cache();
    auto p = cache.find(start_addr);
    if ( p != cache.end() ) {
        return p->second;
    }

    ea_t current = start_addr;
    std::set<ea_t> visited;

    while ( max_depth-- > 0 ) {
        if ( visited.count(current) ) {
            deobf::log_verbose("[identity_call] Cycle detected at %a\n", current);
            break;
        }
        visited.insert(current);

        ea_t next_ptr = BADADDR;
        if ( is_trampoline_code(current, &next_ptr) ) {
            ea_t next_target = resolve_global_pointer(next_ptr);
            if ( next_target == BADADDR ) {
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

    cache[start_addr] = current;
    return current;
}

//--------------------------------------------------------------------------
// Transform identity call by patching native instructions
// Resolve an indexed table to get both entries and determine pattern type
// This is the main utility function for other handlers (like deflatten)
//--------------------------------------------------------------------------
identity_call_handler_t::table_resolution_t
identity_call_handler_t::resolve_indexed_table(ea_t table_base, ea_t func_ea)
{
    table_resolution_t result;
    result.table_base = table_base;
    result.entry0_target = BADADDR;
    result.entry1_target = BADADDR;
    result.both_same = false;
    result.is_cff_dispatcher = false;

    if ( table_base == BADADDR ) 
        return result;

    // Read both target-width table entries.
    ea_t target0 = resolve_global_pointer(table_base);
    ea_t target1 = BADADDR;
    const ea_t stride = static_cast<ea_t>(arch::get_ptr_size());
    if ( table_base <= BADADDR - 1 - stride )
        target1 = resolve_global_pointer(table_base + stride);

    if ( target0 == BADADDR ) {
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
    if ( final0 != BADADDR && final0 == final1 ) {
        result.both_same = true;
    }

    // Check for CFF dispatcher pattern (targets loop back to function)
    if ( func_ea != BADADDR ) {
        func_t *func = get_func(func_ea);
        bool t0_is_self = (final0 == func_ea) ||
            (func && final0 >= func->start_ea && final0 < func->end_ea);
        bool t1_is_self = (final1 == func_ea) ||
            (func && final1 >= func->start_ea && final1 < func->end_ea);

        // If both targets loop back to the function, it's a CFF dispatcher
        if ( t0_is_self && t1_is_self ) {
            result.is_cff_dispatcher = true;
            deobf::log("[identity_call] resolve_indexed_table: CFF dispatcher detected at %a\n", table_base);
        }
        // If one target loops back, annotate but not full CFF
        else if ( t0_is_self || t1_is_self ) {
            deobf::log_verbose("[identity_call] resolve_indexed_table: partial self-ref at %a\n", table_base);
        }
    }

    return result;
}
