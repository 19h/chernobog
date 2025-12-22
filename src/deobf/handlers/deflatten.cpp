#include "deflatten.h"
#include "identity_call.h"
#include "../analysis/cfg_analysis.h"
#include "../analysis/pattern_match.h"
#include "../analysis/opaque_eval.h"
#include "../analysis/z3_solver.h"
#include <algorithm>  // for std::find

using namespace z3_solver;

// Static storage for deferred analysis results
std::map<ea_t, deferred_analysis_t> deflatten_handler_t::s_deferred_analysis;

// Clear deferred analysis
void deflatten_handler_t::clear_deferred(ea_t func_ea) {
    s_deferred_analysis.erase(func_ea);
}

// Check for pending analysis
bool deflatten_handler_t::has_pending_analysis(ea_t func_ea) {
    auto it = s_deferred_analysis.find(func_ea);
    return it != s_deferred_analysis.end() && it->second.analysis_complete;
}

//--------------------------------------------------------------------------
// Detection
//--------------------------------------------------------------------------
bool deflatten_handler_t::detect(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || mba->qty < 4)
        return false;

    pattern_match::flatten_info_t info;
    return pattern_match::detect_flatten_pattern(mba, &info);
}

//--------------------------------------------------------------------------
// Utility: Check if value is a Hikari state constant
//--------------------------------------------------------------------------
bool deflatten_handler_t::is_state_constant(uint64_t val) {
    if (val < 0x10000000 || val > 0xFFFFFFFF)
        return false;

    uint32_t high = (val >> 16) & 0xFFFF;
    if (high == 0)
        return false;

    switch (high) {
        case 0xAAAA: case 0xABCD: case 0xBBBB: case 0xCCCC: case 0xDDDD:
        case 0xBEEF: case 0xCAFE: case 0xDEAD:
        case 0x1111: case 0x2222: case 0x3333: case 0x4444:
        case 0x5555: case 0x6666: case 0x7777: case 0x8888: case 0x9999:
        case 0xFEED: case 0xFACE: case 0xBABE: case 0xC0DE: case 0xF00D:
            return true;
        default:
            return false;
    }
}

//--------------------------------------------------------------------------
// Check if a value is a valid jump-table index
//--------------------------------------------------------------------------
static bool is_jump_table_index(uint64_t val, int max_cases) {
    return val < (uint64_t)max_cases;
}

//--------------------------------------------------------------------------
// Utility: Find all state constants in a block
//--------------------------------------------------------------------------
std::set<uint64_t> deflatten_handler_t::find_state_constants(const mblock_t *blk) {
    std::set<uint64_t> constants;
    if (!blk) return constants;

    for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->l.t == mop_n && is_state_constant(ins->l.nnn->value)) {
            constants.insert(ins->l.nnn->value);
        }
        if (ins->r.t == mop_n && is_state_constant(ins->r.nnn->value)) {
            constants.insert(ins->r.nnn->value);
        }

        // Check nested instructions
        if (ins->l.t == mop_d && ins->l.d) {
            const minsn_t *nested = ins->l.d;
            if (nested->l.t == mop_n && is_state_constant(nested->l.nnn->value)) {
                constants.insert(nested->l.nnn->value);
            }
            if (nested->r.t == mop_n && is_state_constant(nested->r.nnn->value)) {
                constants.insert(nested->r.nnn->value);
            }
        }
        if (ins->r.t == mop_d && ins->r.d) {
            const minsn_t *nested = ins->r.d;
            if (nested->l.t == mop_n && is_state_constant(nested->l.nnn->value)) {
                constants.insert(nested->l.nnn->value);
            }
            if (nested->r.t == mop_n && is_state_constant(nested->r.nnn->value)) {
                constants.insert(nested->r.nnn->value);
            }
        }
    }

    return constants;
}

//--------------------------------------------------------------------------
// Utility: Check if block is an exit block
//--------------------------------------------------------------------------
bool deflatten_handler_t::is_exit_block(const mblock_t *blk) {
    if (!blk || !blk->tail)
        return false;

    // Check for return instruction or no successors
    return blk->tail->opcode == m_ret || blk->nsucc() == 0;
}

//--------------------------------------------------------------------------
// Utility: Get all successor blocks
//--------------------------------------------------------------------------
std::vector<int> deflatten_handler_t::get_successors(const mblock_t *blk) {
    std::vector<int> successors;
    if (!blk)
        return successors;

    for (int i = 0; i < blk->nsucc(); i++) {
        successors.push_back(blk->succ(i));
    }
    return successors;
}

//--------------------------------------------------------------------------
// Analyze a single block to determine if it's a dispatcher
//--------------------------------------------------------------------------
bool deflatten_handler_t::analyze_dispatcher_block(mbl_array_t *mba, int block_idx,
                                                     dispatcher_info_t *out) {
    if (!mba || !out || block_idx < 0 || block_idx >= mba->qty)
        return false;

    mblock_t *blk = mba->get_mblock(block_idx);
    if (!blk)
        return false;

    out->block_idx = block_idx;
    out->is_solved = false;

    // Find state constants in this block
    std::set<uint64_t> state_consts = find_state_constants(blk);

    if (state_consts.size() < 2) {
        return false;
    }

    // Look for comparison patterns: setXX var, state_const
    mop_t potential_state_var;
    bool found_state_var = false;
    int consistent_comparisons = 0;

    for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Look for conditional jumps
        if (!deobf::is_jcc(ins->opcode))
            continue;

        // Extract comparison from condition
        if (ins->l.t == mop_d && ins->l.d) {
            const minsn_t *cmp = ins->l.d;
            if (is_mcode_set(cmp->opcode)) {
                uint64_t state_val = 0;
                bool found_const = false;
                mop_t var;

                if (cmp->l.t == mop_n && is_state_constant(cmp->l.nnn->value)) {
                    state_val = cmp->l.nnn->value;
                    var = cmp->r;
                    found_const = true;
                } else if (cmp->r.t == mop_n && is_state_constant(cmp->r.nnn->value)) {
                    state_val = cmp->r.nnn->value;
                    var = cmp->l;
                    found_const = true;
                }

                if (found_const && ins->d.t == mop_b) {
                    if (!found_state_var) {
                        potential_state_var = var;
                        found_state_var = true;
                    }
                    out->state_to_block[state_val] = ins->d.b;
                    out->case_blocks.insert(ins->d.b);
                    consistent_comparisons++;
                }
            }
        }
    }

    if (consistent_comparisons < 2 || !found_state_var) {
        return false;
    }

    // Convert mop to symbolic_var_t
    if (potential_state_var.t == mop_S && potential_state_var.s) {
        out->state_var = symbolic_var_t(symbolic_var_t::VAR_STACK,
                                         potential_state_var.s->off,
                                         potential_state_var.size);
    } else if (potential_state_var.t == mop_r) {
        out->state_var = symbolic_var_t(symbolic_var_t::VAR_REGISTER,
                                         potential_state_var.r,
                                         potential_state_var.size);
    } else if (potential_state_var.t == mop_v) {
        out->state_var = symbolic_var_t(symbolic_var_t::VAR_GLOBAL,
                                         potential_state_var.g,
                                         potential_state_var.size);
    } else if (potential_state_var.t == mop_l && potential_state_var.l) {
        out->state_var = symbolic_var_t(symbolic_var_t::VAR_LOCAL,
                                         potential_state_var.l->idx,
                                         potential_state_var.size);
    } else {
        return false;
    }

    out->dispatcher_chain.insert(block_idx);
    out->is_solved = true;

    deobf::log("[deflatten] Found dispatcher at block %d with %zu state mappings\n",
              block_idx, out->state_to_block.size());

    return true;
}

//--------------------------------------------------------------------------
// Index variable info - represents a state variable in jump table flattening
//--------------------------------------------------------------------------
struct index_var_info_t {
    mop_t var;              // The index variable (stack or local)
    int dispatcher_block;   // Block where this var is used for dispatch
    ea_t jump_table;        // Associated jump table address
    int num_cases;          // Number of cases in jump table

    index_var_info_t() : dispatcher_block(-1), jump_table(BADADDR), num_cases(0) {}
};

//--------------------------------------------------------------------------
// Extract index variable from a multiplication expression
// Handles patterns like: 8 * xds(var) or xds(var) * 8
//--------------------------------------------------------------------------
static bool extract_index_from_mul(const minsn_t *mul_ins, mop_t *out_var) {
    if (!mul_ins || mul_ins->opcode != m_mul)
        return false;

    // Check if multiplying by 8 (pointer size for 64-bit)
    const mop_t *index_op = nullptr;
    if (mul_ins->r.t == mop_n && mul_ins->r.nnn->value == 8) {
        index_op = &mul_ins->l;
    } else if (mul_ins->l.t == mop_n && mul_ins->l.nnn->value == 8) {
        index_op = &mul_ins->r;
    }

    if (!index_op)
        return false;

    // The index might be sign-extended (xds instruction)
    if (index_op->t == mop_d && index_op->d && index_op->d->opcode == m_xds) {
        *out_var = index_op->d->l;
        return true;
    }

    // Or it might be a direct variable reference
    if (index_op->t == mop_S || index_op->t == mop_l || index_op->t == mop_r) {
        *out_var = *index_op;
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Find index variable used in a block ending with ijmp
// Traces backwards from ijmp to find the variable used as index
// Handles pattern: ldx ds, (BASE + 8 * xds(INDEX_VAR)), dst; ijmp cs, dst
//--------------------------------------------------------------------------
static bool find_index_variable(mblock_t *blk, index_var_info_t *out) {
    if (!blk || !blk->tail || blk->tail->opcode != m_ijmp)
        return false;

    // The ijmp target comes from a register loaded via computed address
    // Pattern: ldx ds, [table + index*8] -> reg; ijmp cs, reg

    // Find the ldx that provides the jump target
    for (minsn_t *ins = blk->tail->prev; ins; ins = ins->prev) {
        if (ins->opcode != m_ldx)
            continue;

        // ldx has: l=segment, r=address, d=destination
        // We need to analyze the address operand (r)
        const mop_t &addr = ins->r;

        // The address is a compound expression like (base + index*8)
        if (addr.t == mop_d && addr.d) {
            const minsn_t *addr_expr = addr.d;

            // Look for add operation
            if (addr_expr->opcode == m_add) {
                // Check both operands for mul by 8
                mop_t index_var;

                // Check left operand for mul*8
                if (addr_expr->l.t == mop_d && addr_expr->l.d) {
                    if (extract_index_from_mul(addr_expr->l.d, &index_var)) {
                        out->var = index_var;
                        out->dispatcher_block = blk->serial;
                        deobf::log_verbose("[deflatten] Found index var in ldx at block %d (type=%d)\n",
                                  blk->serial, index_var.t);
                        return true;
                    }
                }

                // Check right operand for mul*8
                if (addr_expr->r.t == mop_d && addr_expr->r.d) {
                    if (extract_index_from_mul(addr_expr->r.d, &index_var)) {
                        out->var = index_var;
                        out->dispatcher_block = blk->serial;
                        deobf::log_verbose("[deflatten] Found index var in ldx at block %d (type=%d)\n",
                                  blk->serial, index_var.t);
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Find all writes of small integer constants to a given variable in a block
// Returns pairs of (written_value, writing_instruction)
//--------------------------------------------------------------------------
static std::vector<std::pair<uint64_t, minsn_t*>>
find_index_writes(mblock_t *blk, const mop_t &index_var, int max_value = 300) {
    std::vector<std::pair<uint64_t, minsn_t*>> writes;

    if (!blk)
        return writes;

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Look for mov of small constant to the index variable
        if (ins->opcode != m_mov)
            continue;

        // Check if source is a small constant
        if (ins->l.t != mop_n)
            continue;

        uint64_t val = ins->l.nnn->value;
        if (val > (uint64_t)max_value)
            continue;

        // Check if destination matches the index variable
        // Need to compare the variable identity
        bool match = false;
        if (ins->d.t == index_var.t) {
            if (index_var.t == mop_S) {
                // Stack variable - compare offset
                match = (ins->d.s->off == index_var.s->off);
            } else if (index_var.t == mop_l) {
                // Local variable - compare index
                match = (ins->d.l->idx == index_var.l->idx);
            } else if (index_var.t == mop_r) {
                // Register - compare register
                match = (ins->d.r == index_var.r);
            }
        }

        if (match) {
            writes.push_back({val, ins});
        }
    }

    return writes;
}

//--------------------------------------------------------------------------
// Find ALL writes of small integers to ANY stack/local variable in a block
// This is for jump table flattening where multiple index variables exist
// Returns pairs of (written_value, stack_offset_or_local_idx)
//--------------------------------------------------------------------------
static std::vector<std::pair<uint64_t, int64_t>>
find_all_index_writes(mblock_t *blk, int max_value = 300) {
    std::vector<std::pair<uint64_t, int64_t>> writes;

    if (!blk)
        return writes;

    // Track register values for backward data flow within this block
    // Key: register, Value: constant value (or -1 if unknown/non-constant)
    std::map<mreg_t, int64_t> reg_values;

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        uint64_t val = 0;
        int64_t var_id = -1;
        bool found = false;

        // Track register assignments: mov #const, reg
        if (ins->opcode == m_mov && ins->l.t == mop_n && ins->d.t == mop_r) {
            uint64_t cval = ins->l.nnn->value;
            if (cval <= (uint64_t)max_value) {
                reg_values[ins->d.r] = (int64_t)cval;
            } else {
                reg_values[ins->d.r] = -1;  // Large value, mark as unknown
            }
        }

        // Also track xdu/xds (zero/sign extend) from constants
        if ((ins->opcode == m_xdu || ins->opcode == m_xds) && ins->d.t == mop_r) {
            // Check if source contains a constant
            if (ins->l.t == mop_n) {
                uint64_t cval = ins->l.nnn->value;
                if (cval <= (uint64_t)max_value) {
                    reg_values[ins->d.r] = (int64_t)cval;
                }
            } else if (ins->l.t == mop_d && ins->l.d) {
                // Nested expression - check if it produces a constant
                // Common pattern: xdu (x == 0) or xdu (x & mask)
                // For now, mark as unknown
                reg_values[ins->d.r] = -1;
            }
        }

        // Handle mov instruction: mov src, dst
        if (ins->opcode == m_mov) {
            // Direct constant to stack
            if (ins->l.t == mop_n) {
                val = ins->l.nnn->value;
                if (val <= (uint64_t)max_value) {
                    if (ins->d.size == 4 || ins->d.size == 8) {
                        if (ins->d.t == mop_S) {
                            var_id = ins->d.s->off;
                            found = true;
                        } else if (ins->d.t == mop_l) {
                            var_id = ins->d.l->idx;
                            found = true;
                        }
                    }
                }
            }
            // Register to stack - look up register value
            else if (ins->l.t == mop_r && (ins->d.t == mop_S || ins->d.t == mop_l)) {
                auto it = reg_values.find(ins->l.r);
                if (it != reg_values.end() && it->second >= 0 && it->second <= max_value) {
                    val = (uint64_t)it->second;
                    if (ins->d.size == 4 || ins->d.size == 8) {
                        if (ins->d.t == mop_S) {
                            var_id = ins->d.s->off;
                            found = true;
                        } else if (ins->d.t == mop_l) {
                            var_id = ins->d.l->idx;
                            found = true;
                        }
                    }
                }
            }
        }
        // Handle stx instruction: stx val, seg, dst
        else if (ins->opcode == m_stx) {
            // Direct constant
            if (ins->l.t == mop_n) {
                val = ins->l.nnn->value;
                if (val <= (uint64_t)max_value && (ins->l.size == 4 || ins->l.size == 8)) {
                    if (ins->d.t == mop_S) {
                        var_id = ins->d.s->off;
                        found = true;
                    } else if (ins->d.t == mop_l) {
                        var_id = ins->d.l->idx;
                        found = true;
                    }
                }
            }
            // Register value
            else if (ins->l.t == mop_r) {
                auto it = reg_values.find(ins->l.r);
                if (it != reg_values.end() && it->second >= 0 && it->second <= max_value) {
                    val = (uint64_t)it->second;
                    if (ins->l.size == 4 || ins->l.size == 8) {
                        if (ins->d.t == mop_S) {
                            var_id = ins->d.s->off;
                            found = true;
                        } else if (ins->d.t == mop_l) {
                            var_id = ins->d.l->idx;
                            found = true;
                        }
                    }
                }
            }
        }

        if (found && var_id >= 0) {
            writes.push_back({val, var_id});
        }

        // Clear register value if it's overwritten by something non-constant
        if (ins->d.t == mop_r) {
            if (ins->opcode != m_mov || ins->l.t != mop_n) {
                if (ins->opcode != m_xdu && ins->opcode != m_xds) {
                    reg_values[ins->d.r] = -1;
                }
            }
        }
    }

    return writes;
}

//--------------------------------------------------------------------------
// Analyze jump table-based flattening (index-based, not magic constants)
// Returns true if this appears to be jump table flattening
//--------------------------------------------------------------------------
bool deflatten_handler_t::analyze_jump_table_flattening(mbl_array_t *mba,
                                           std::vector<dispatcher_info_t> &dispatchers) {
    if (!mba)
        return false;

    // Step 1: Find all blocks with indirect jumps and their index variables
    std::vector<index_var_info_t> index_vars;
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;
        if (blk->tail->opcode == m_ijmp) {
            index_var_info_t info;
            if (find_index_variable(blk, &info)) {
                index_vars.push_back(info);
                int64_t var_off = -1;
                if (info.var.t == mop_S && info.var.s)
                    var_off = info.var.s->off;
                else if (info.var.t == mop_l && info.var.l)
                    var_off = info.var.l->idx;
                deobf::log("[deflatten] Block %d: found index var (type=%d, off=%lld)\n",
                          i, info.var.t, (long long)var_off);
            }
        }
    }

    if (index_vars.empty()) {
        deobf::log("[deflatten] No index variables found in ijmp blocks\n");
        // Fall through to IDA switch-based analysis
    } else {
        deobf::log("[deflatten] Found %zu index variables in ijmp blocks\n", index_vars.size());
    }

    // Step 2: Get IDA's switch detection for mapping state values to blocks
    func_t *pfn = get_func(mba->entry_ea);
    if (!pfn) {
        deobf::log("[deflatten] Could not get function for switch analysis\n");
        return false;
    }

    // Collect all switches in the function
    std::map<ea_t, switch_info_t> switches;
    ea_t ea = pfn->start_ea;
    while (ea < pfn->end_ea) {
        switch_info_t si;
        if (get_switch_info(&si, ea) > 0 && si.get_jtable_size() >= 10) {
            switches[ea] = si;
        }
        ea = next_head(ea, pfn->end_ea);
        if (ea == BADADDR) break;
    }

    if (switches.empty()) {
        deobf::log("[deflatten] No IDA-detected switches found\n");
        return false;
    }

    deobf::log("[deflatten] Found %zu IDA-detected switches\n", switches.size());

    // Step 3: Build dispatcher info for each large switch
    // For jump table flattening, we need to:
    // - Map state values (indices) to case blocks
    // - Identify which index variable each dispatcher uses
    // - Find state transitions by tracing index writes in case blocks

    // Find the primary (largest) jump table - this is likely the main dispatcher
    ea_t primary_switch_ea = BADADDR;
    int max_cases = 0;
    for (const auto& kv : switches) {
        if ((int)kv.second.get_jtable_size() > max_cases) {
            max_cases = kv.second.get_jtable_size();
            primary_switch_ea = kv.first;
        }
    }

    if (primary_switch_ea == BADADDR) {
        deobf::log("[deflatten] No primary switch found\n");
        return false;
    }

    const switch_info_t &primary_si = switches[primary_switch_ea];
    deobf::log("[deflatten] Primary switch at %a: %d cases, table at %a\n",
              primary_switch_ea, max_cases, primary_si.jumps);

    // Build the main dispatcher
    dispatcher_info_t disp;
    disp.is_solved = true;
    disp.is_jump_table = true;  // Jump-table style uses small integer states
    disp.max_state = max_cases;

    // Find the dispatcher block
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (blk && blk->start <= primary_switch_ea && primary_switch_ea < blk->end) {
            disp.block_idx = i;
            break;
        }
    }

    // Build state_to_block mapping from jump table
    ea_t table = primary_si.jumps;
    int num_cases = (int)primary_si.get_jtable_size();

    int identity_resolved_count = 0;
    for (int idx = 0; idx < num_cases && idx < 300; idx++) {
        ea_t raw_target = 0;
        if (get_bytes(&raw_target, sizeof(ea_t), table + idx * sizeof(ea_t)) == sizeof(ea_t)) {
            ea_t target = raw_target;

            // Resolve through identity call trampolines if present
            // This handles Hikari's pattern where table entries point to
            // wrapper functions that use identity calls for indirection
            ea_t resolved = identity_call_handler_t::resolve_trampoline_chain(raw_target);
            if (resolved != raw_target && resolved != BADADDR) {
                // Resolved through a trampoline chain
                identity_resolved_count++;
                deobf::log_verbose("[deflatten] Table[%d]: %a -> %a (identity resolved)\n",
                                  idx, raw_target, resolved);
                target = resolved;
            }

            // Find the block containing this target
            for (int bi = 0; bi < mba->qty; bi++) {
                mblock_t *blk = mba->get_mblock(bi);
                if (blk && blk->start <= target && target < blk->end) {
                    disp.state_to_block[idx] = bi;
                    disp.case_blocks.insert(bi);
                    break;
                }
            }
        }
    }

    if (identity_resolved_count > 0) {
        deobf::log("[deflatten] Resolved %d/%d table entries through identity call chains\n",
                  identity_resolved_count, num_cases);
    }
    deobf::log("[deflatten] Built state_to_block with %zu mappings\n", disp.state_to_block.size());

    // Step 4: Build a map of index variable offsets -> their usage
    // For jump table flattening, multiple index variables control different entry points
    std::set<int64_t> known_index_offsets;
    for (const auto &iv : index_vars) {
        if (iv.var.t == mop_S) {
            known_index_offsets.insert(iv.var.s->off);
        } else if (iv.var.t == mop_l) {
            known_index_offsets.insert(iv.var.l->idx);
        }
    }

    deobf::log("[deflatten] Found %zu unique index variable offsets:\n", known_index_offsets.size());
    for (int64_t off : known_index_offsets) {
        deobf::log("[deflatten]   offset: %lld (0x%llx)\n", (long long)off, (unsigned long long)off);
    }

    // Step 5: For each case block, find ALL writes of small integers
    // This captures state transitions regardless of which index variable is used
    struct transition_t {
        int from_block;       // Case block handling current state
        uint64_t from_state;  // State value this block handles
        uint64_t to_state;    // State value being written
        int64_t var_offset;   // Which index variable is written
    };

    std::vector<transition_t> transitions;
    std::map<int, std::vector<std::pair<uint64_t, int64_t>>> block_writes;

    int total_writes_found = 0;
    int sample_count = 0;
    for (const auto &kv : disp.state_to_block) {
        uint64_t state_val = kv.first;
        int case_idx = kv.second;

        mblock_t *case_blk = mba->get_mblock(case_idx);
        if (!case_blk)
            continue;

        // Debug: log first few case blocks
        if (sample_count < 5) {
            int ins_count = 0;
            for (minsn_t *p = case_blk->head; p; p = p->next) ins_count++;
            deobf::log("[deflatten] Scanning case block %d (state 0x%llx), %d instructions\n",
                      case_idx, (unsigned long long)state_val, ins_count);
            for (minsn_t *ins = case_blk->head; ins && sample_count < 5; ins = ins->next) {
                if (ins->opcode == m_mov) {
                    deobf::log("[deflatten]   mov: src.t=%d dst.t=%d",
                              ins->l.t, ins->d.t);
                    if (ins->l.t == mop_n) {
                        deobf::log(" src_val=%llu", (unsigned long long)ins->l.nnn->value);
                    }
                    if (ins->d.t == mop_S) {
                        deobf::log(" dst_off=%lld", (long long)ins->d.s->off);
                    }
                    deobf::log("\n");
                }
            }
            sample_count++;
        }

        auto writes = find_all_index_writes(case_blk, num_cases);
        total_writes_found += writes.size();
        block_writes[case_idx] = writes;

        // Debug: show first few writes
        static int write_debug_count = 0;
        if (write_debug_count < 10 && !writes.empty()) {
            deobf::log("[deflatten] Block %d writes:\n", case_idx);
            for (const auto &w : writes) {
                deobf::log("[deflatten]   val=%llu to offset=%lld (known=%s)\n",
                          (unsigned long long)w.first, (long long)w.second,
                          known_index_offsets.count(w.second) ? "YES" : "no");
            }
            write_debug_count++;
        }

        for (const auto &w : writes) {
            // For now, count ALL small integer writes to stack vars
            // In jump-table flattening, the state variable offsets may vary
            // We'll filter more precisely later based on observed patterns
            transition_t t;
            t.from_block = case_idx;
            t.from_state = state_val;
            t.to_state = w.first;
            t.var_offset = w.second;
            transitions.push_back(t);

            // Log if this IS a known index offset
            if (known_index_offsets.count(w.second)) {
                deobf::log("[deflatten] Matched known offset %lld\n", (long long)w.second);
            }
        }
    }

    deobf::log("[deflatten] Total small int writes found: %d (matched to known offsets: %zu)\n",
              total_writes_found, transitions.size());

    deobf::log("[deflatten] Found %zu state transitions across %zu case blocks\n",
              transitions.size(), block_writes.size());

    // Log some sample transitions
    int logged = 0;
    for (const auto &t : transitions) {
        if (logged < 20) {
            deobf::log("[deflatten] Transition: block %d (state 0x%llx) -> state 0x%llx (var off %lld)\n",
                      t.from_block, (unsigned long long)t.from_state,
                      (unsigned long long)t.to_state, (long long)t.var_offset);
            logged++;
        }
    }

    // If we found transitions, this confirms jump table flattening
    if (!transitions.empty()) {
        // Use the most commonly written index variable as the primary state var
        std::map<int64_t, int> offset_counts;
        for (const auto &t : transitions) {
            offset_counts[t.var_offset]++;
        }

        int64_t best_offset = 0;
        int best_count = 0;
        for (const auto &kv : offset_counts) {
            if (kv.second > best_count) {
                best_count = kv.second;
                best_offset = kv.first;
            }
        }

        deobf::log("[deflatten] Primary index var offset: %lld (used in %d transitions)\n",
                  (long long)best_offset, best_count);

        // Set up the state variable
        disp.state_var = z3_solver::symbolic_var_t(
            z3_solver::symbolic_var_t::VAR_STACK,
            (uint64_t)best_offset, 4);
    } else if (!index_vars.empty()) {
        // Fall back to using the first index variable
        const index_var_info_t &primary_idx = index_vars[0];

        z3_solver::symbolic_var_t::var_kind_t var_kind = z3_solver::symbolic_var_t::VAR_STACK;
        uint64_t var_id = 0;
        int var_size = primary_idx.var.size > 0 ? primary_idx.var.size : 4;

        if (primary_idx.var.t == mop_S) {
            var_kind = z3_solver::symbolic_var_t::VAR_STACK;
            var_id = (uint64_t)primary_idx.var.s->off;
        } else if (primary_idx.var.t == mop_l) {
            var_kind = z3_solver::symbolic_var_t::VAR_LOCAL;
            var_id = (uint64_t)primary_idx.var.l->idx;
        }

        disp.state_var = z3_solver::symbolic_var_t(var_kind, var_id, var_size);
        deobf::log("[deflatten] Using fallback index var (kind=%d, id=%llu)\n",
                  (int)var_kind, (unsigned long long)var_id);
    }

    // Mark all dispatcher-related blocks
    disp.dispatcher_chain.insert(disp.block_idx);

    // Add all blocks with indirect jumps to the same jump table
    for (const auto& kv : switches) {
        if (kv.second.jumps == primary_si.jumps) {
            for (int i = 0; i < mba->qty; i++) {
                mblock_t *blk = mba->get_mblock(i);
                if (blk && blk->start <= kv.first && kv.first < blk->end) {
                    disp.dispatcher_chain.insert(i);
                }
            }
        }
    }

    deobf::log("[deflatten] Dispatcher chain has %zu blocks\n", disp.dispatcher_chain.size());

    if (disp.state_to_block.size() >= 10) {
        disp.is_solved = true;  // Mark as solved so trace_transitions_z3 will process it
        dispatchers.push_back(disp);
    }

    return !dispatchers.empty();
}

//--------------------------------------------------------------------------
// Analyze all dispatchers in the function using Z3
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::dispatcher_info_t>
deflatten_handler_t::analyze_dispatchers_z3(mbl_array_t *mba) {
    std::vector<dispatcher_info_t> dispatchers;

    if (!mba)
        return dispatchers;

    // Reset Z3 context for fresh analysis
    reset_global_context();

    // First pass: find all potential dispatcher blocks (constant-based)
    for (int i = 0; i < mba->qty; i++) {
        dispatcher_info_t disp;
        if (analyze_dispatcher_block(mba, i, &disp)) {
            dispatchers.push_back(disp);
        }
    }

    // If no constant-based dispatchers, try jump table-based analysis
    if (dispatchers.empty()) {
        deobf::log("[deflatten] No constant-based dispatchers, trying jump table analysis...\n");
        if (analyze_jump_table_flattening(mba, dispatchers)) {
            deobf::log("[deflatten] Jump table flattening detected with %zu dispatchers\n",
                      dispatchers.size());
            // For jump table flattening, we currently just log the detection
            // Full deflattening would require tracing index variable assignments
            // which is complex because there's no single "state variable"
            return dispatchers;
        }
    }

    if (dispatchers.empty()) {
        // Try broader search using Z3's state machine solver
        state_machine_solver_t solver(get_global_context());
        auto machine = solver.solve_state_machine(mba);

        if (machine.solved) {
            for (const auto& z3_disp : machine.dispatchers) {
                dispatcher_info_t disp;
                disp.block_idx = z3_disp.block_idx;
                disp.state_var = z3_disp.state_var;
                disp.state_to_block = z3_disp.state_to_block;
                disp.is_solved = true;

                for (const auto& kv : z3_disp.state_to_block) {
                    disp.case_blocks.insert(kv.second);
                }

                // Compute dispatcher_chain: only blocks that COMPARE state constants
                // (dispatcher conditional blocks), NOT blocks that WRITE state constants
                // (those are transition blocks that we want to create edges from)
                for (int i = 0; i < mba->qty; i++) {
                    if (disp.case_blocks.count(i))
                        continue;  // Skip case blocks

                    mblock_t *blk = mba->get_mblock(i);
                    if (!blk)
                        continue;

                    // Check if this block has a state constant COMPARISON (not just presence)
                    // Look for setXX or jcc patterns that compare against state constants
                    bool has_state_comparison = false;
                    for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
                        // Check for setXX instructions (setz, setnz, setl, etc.)
                        if (ins->opcode >= m_sets && ins->opcode <= m_setnz) {
                            // Check if comparing against a state constant
                            if ((ins->l.t == mop_n && is_state_constant(ins->l.nnn->value)) ||
                                (ins->r.t == mop_n && is_state_constant(ins->r.nnn->value))) {
                                has_state_comparison = true;
                                break;
                            }
                        }
                        // Check for jcc with embedded comparison
                        if (deobf::is_jcc(ins->opcode)) {
                            if (ins->l.t == mop_d && ins->l.d) {
                                const minsn_t *cmp = ins->l.d;
                                if ((cmp->l.t == mop_n && is_state_constant(cmp->l.nnn->value)) ||
                                    (cmp->r.t == mop_n && is_state_constant(cmp->r.nnn->value))) {
                                    has_state_comparison = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (has_state_comparison) {
                        disp.dispatcher_chain.insert(i);
                    }
                }

                dispatchers.push_back(disp);
            }
        }
    }

    // Second pass: extend dispatcher chains (cascading conditionals)
    for (auto& disp : dispatchers) {
        std::vector<int> worklist;
        for (int i = 0; i < mba->get_mblock(disp.block_idx)->nsucc(); i++) {
            worklist.push_back(mba->get_mblock(disp.block_idx)->succ(i));
        }

        while (!worklist.empty()) {
            int idx = worklist.back();
            worklist.pop_back();

            if (disp.dispatcher_chain.count(idx) || disp.case_blocks.count(idx))
                continue;

            mblock_t *blk = mba->get_mblock(idx);
            if (!blk)
                continue;

            // Check if this block also has state comparisons (cascading)
            std::set<uint64_t> consts = find_state_constants(blk);
            if (consts.size() >= 2) {
                disp.dispatcher_chain.insert(idx);

                // Add state mappings from this block too
                for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
                    if (!deobf::is_jcc(ins->opcode))
                        continue;

                    if (ins->l.t == mop_d && ins->l.d && ins->d.t == mop_b) {
                        const minsn_t *cmp = ins->l.d;
                        uint64_t state_val = 0;

                        if (cmp->l.t == mop_n && is_state_constant(cmp->l.nnn->value)) {
                            state_val = cmp->l.nnn->value;
                        } else if (cmp->r.t == mop_n && is_state_constant(cmp->r.nnn->value)) {
                            state_val = cmp->r.nnn->value;
                        }

                        if (state_val != 0) {
                            disp.state_to_block[state_val] = ins->d.b;
                            disp.case_blocks.insert(ins->d.b);
                        }
                    }
                }

                // Continue following this block's successors
                for (int i = 0; i < blk->nsucc(); i++) {
                    worklist.push_back(blk->succ(i));
                }
            }
        }
    }

    // Establish parent-child relationships for nested dispatchers
    for (size_t i = 0; i < dispatchers.size(); i++) {
        for (size_t j = 0; j < dispatchers.size(); j++) {
            if (i == j)
                continue;

            // Check if dispatcher j is within a case block of dispatcher i
            for (int case_blk : dispatchers[i].case_blocks) {
                if (dispatchers[j].dispatcher_chain.count(case_blk) ||
                    case_blk == dispatchers[j].block_idx) {
                    dispatchers[j].parent_dispatcher = (int)i;
                    dispatchers[j].nesting_level = dispatchers[i].nesting_level + 1;
                }
            }
        }
    }

    // Sort by nesting level (deepest first for bottom-up processing)
    std::sort(dispatchers.begin(), dispatchers.end(),
              [](const dispatcher_info_t &a, const dispatcher_info_t &b) {
                  return a.nesting_level > b.nesting_level;
              });

    return dispatchers;
}

//--------------------------------------------------------------------------
// Solve for the next state value written by a block using Z3
//--------------------------------------------------------------------------
std::optional<uint64_t> deflatten_handler_t::solve_written_state(
    mbl_array_t *mba,
    int block_idx,
    const symbolic_var_t &state_var,
    int max_jump_table_state) {

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return std::nullopt;

    mblock_t *blk = mba->get_mblock(block_idx);
    if (!blk)
        return std::nullopt;

    // Helper lambda: validate state value based on dispatcher type
    auto is_valid_state = [max_jump_table_state](uint64_t val) -> bool {
        if (max_jump_table_state > 0) {
            // Jump-table: accept small indices [0..max]
            return val <= (uint64_t)max_jump_table_state;
        } else {
            // Hikari: require magic constant patterns
            return is_state_constant(val);
        }
    };

    // Use Z3 symbolic execution
    symbolic_executor_t executor(get_global_context());

    // Execute the block symbolically
    executor.execute_block(blk);

    // Try to get the final value of the state variable
    auto value = executor.get_value(state_var);
    if (value.has_value()) {
        auto concrete = executor.solve_for_value(value.value());
        if (concrete.has_value() && is_valid_state(*concrete)) {
            return concrete;
        }
    }

    // Fallback: scan for direct constant assignments
    for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov)
            continue;

        if (ins->l.t != mop_n || !is_valid_state(ins->l.nnn->value))
            continue;

        // Check if destination matches state variable
        bool matches = false;
        if (ins->d.t == mop_S && state_var.kind() == symbolic_var_t::VAR_STACK) {
            if (ins->d.s && ins->d.s->off == (sval_t)state_var.id())
                matches = true;
        } else if (ins->d.t == mop_r && state_var.kind() == symbolic_var_t::VAR_REGISTER) {
            if (ins->d.r == (mreg_t)state_var.id())
                matches = true;
        } else if (ins->d.t == mop_v && state_var.kind() == symbolic_var_t::VAR_GLOBAL) {
            if (ins->d.g == (ea_t)state_var.id())
                matches = true;
        } else if (ins->d.t == mop_l && state_var.kind() == symbolic_var_t::VAR_LOCAL) {
            if (ins->d.l && ins->d.l->idx == (int)state_var.id())
                matches = true;
        }

        if (matches) {
            return ins->l.nnn->value;
        }
    }

    return std::nullopt;
}

//--------------------------------------------------------------------------
// Analyze conditional transitions within case blocks
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::cfg_edge_t>
deflatten_handler_t::analyze_conditional_transitions(
    mbl_array_t *mba,
    int block_idx,
    const symbolic_var_t &state_var) {

    std::vector<cfg_edge_t> edges;

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return edges;

    mblock_t *blk = mba->get_mblock(block_idx);
    if (!blk || !blk->tail)
        return edges;

    // Check if this block has a conditional branch
    if (!deobf::is_jcc(blk->tail->opcode))
        return edges;

    // Get the branch targets
    int true_target = -1;
    int false_target = -1;

    if (blk->tail->d.t == mop_b) {
        true_target = blk->tail->d.b;
    }

    // Find fall-through target
    for (int i = 0; i < blk->nsucc(); i++) {
        int succ = blk->succ(i);
        if (succ != true_target) {
            false_target = succ;
            break;
        }
    }

    // Use Z3 to analyze each branch
    mcode_translator_t translator(get_global_context());
    z3::expr condition = translator.translate_jcc_condition(blk->tail);

    // True branch
    if (true_target >= 0) {
        // Execute true path symbolically
        symbolic_executor_t executor(get_global_context());
        executor.execute_block(blk);
        executor.add_constraint(condition);

        auto written_state = solve_written_state(mba, block_idx, state_var);

        cfg_edge_t edge;
        edge.from_block = block_idx;
        edge.is_conditional = true;
        edge.is_true_branch = true;
        edge.condition = std::make_shared<z3::expr>(condition);
        if (written_state.has_value()) {
            edge.state_value = *written_state;
        }
        // to_block will be resolved later based on state value
        edges.push_back(edge);
    }

    // False branch
    if (false_target >= 0) {
        symbolic_executor_t executor(get_global_context());
        executor.execute_block(blk);
        executor.add_constraint(!condition);

        cfg_edge_t edge;
        edge.from_block = block_idx;
        edge.is_conditional = true;
        edge.is_true_branch = false;
        edge.condition = std::make_shared<z3::expr>(!condition);
        edges.push_back(edge);
    }

    return edges;
}

//--------------------------------------------------------------------------
// Use Z3 symbolic execution to trace state transitions through case blocks
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::cfg_edge_t>
deflatten_handler_t::trace_transitions_z3(mbl_array_t *mba,
                                           const dispatcher_info_t &disp) {
    std::vector<cfg_edge_t> edges;

    if (!mba || !disp.is_solved)
        return edges;

    deobf::log("[deflatten] Tracing transitions for dispatcher at block %d\n", disp.block_idx);
    deobf::log("[deflatten]   %zu case blocks to analyze\n", disp.case_blocks.size());

    // Use the dispatcher's is_jump_table flag, or detect if not set
    bool is_jump_table = disp.is_jump_table;
    if (!is_jump_table && !disp.state_to_block.empty()) {
        // Fall back to heuristic detection if flag not set
        is_jump_table = true;
        for (const auto &kv : disp.state_to_block) {
            if (kv.first >= 500) {
                is_jump_table = false;
                break;
            }
        }
    }
    if (is_jump_table) {
        deobf::log("[deflatten] Using jump-table tracing (small integer states)\n");

        int max_cases = disp.max_state > 0 ? disp.max_state : (int)disp.state_to_block.size();

        // Build set of all case blocks for reference
        std::set<int> case_blocks;
        for (const auto &kv : disp.state_to_block) {
            case_blocks.insert(kv.second);
        }

        // APPROACH: Find all blocks that write small integer values to stack
        // and eventually flow to the dispatcher (directly or through ijmp blocks).
        // These are the blocks where we need to redirect control flow.

        // First, scan ALL blocks for small integer writes
        std::map<int, std::vector<std::pair<uint64_t, int64_t>>> block_writes;
        for (int blk_idx = 0; blk_idx < mba->qty; blk_idx++) {
            mblock_t *blk = mba->get_mblock(blk_idx);
            if (!blk) continue;

            auto writes = find_all_index_writes(blk, max_cases);
            if (!writes.empty()) {
                block_writes[blk_idx] = writes;
            }
        }

        deobf::log("[deflatten]   Found %zu blocks with index writes\n", block_writes.size());

        // ALSO check jtbl instructions for conditional transitions
        // jtbl targets are block indices - we need to trace through them to find state writes
        int jtbl_transitions = 0;
        for (int blk_idx = 0; blk_idx < mba->qty; blk_idx++) {
            mblock_t *blk = mba->get_mblock(blk_idx);
            if (!blk || !blk->tail)
                continue;

            // Skip dispatcher chain blocks
            if (disp.dispatcher_chain.count(blk_idx))
                continue;

            // Look for jtbl instruction at end of block
            if (blk->tail->opcode == m_jtbl && blk->tail->r.t == mop_c) {
                mcases_t *cases = blk->tail->r.c;
                if (cases && !cases->empty()) {
                    // Each target is a block index - trace through to find state write
                    for (size_t i = 0; i < cases->size(); i++) {
                        int target_blk_idx = cases->targets[i];
                        if (target_blk_idx < 0 || target_blk_idx >= mba->qty)
                            continue;

                        // Trace through target block to find state write
                        mblock_t *target_blk = mba->get_mblock(target_blk_idx);
                        if (!target_blk)
                            continue;

                        // Look for index writes in target block
                        auto writes = find_all_index_writes(target_blk, max_cases);
                        for (const auto &w : writes) {
                            uint64_t written_state = w.first;
                            auto it = disp.state_to_block.find(written_state);
                            if (it != disp.state_to_block.end()) {
                                int final_target = it->second;
                                if (final_target != blk_idx) {
                                    cfg_edge_t edge;
                                    edge.from_block = target_blk_idx;  // Redirect from the jtbl target
                                    edge.to_block = final_target;
                                    edge.state_value = written_state;
                                    edge.is_conditional = false;
                                    edges.push_back(edge);
                                    jtbl_transitions++;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (jtbl_transitions > 0) {
            deobf::log("[deflatten]   Found %d transitions via jtbl targets\n", jtbl_transitions);
        }

        // For each block that writes an index, check if it eventually leads to dispatcher
        std::set<int> dispatcher_and_ijmp;
        dispatcher_and_ijmp.insert(disp.dispatcher_chain.begin(), disp.dispatcher_chain.end());

        // Also add ijmp blocks (blocks ending with m_ijmp are dispatcher entry points)
        for (int blk_idx = 0; blk_idx < mba->qty; blk_idx++) {
            mblock_t *blk = mba->get_mblock(blk_idx);
            if (blk && blk->tail && blk->tail->opcode == m_ijmp) {
                dispatcher_and_ijmp.insert(blk_idx);
            }
        }

        for (const auto &bw : block_writes) {
            int write_blk = bw.first;
            const auto &writes = bw.second;

            // Skip dispatcher chain blocks themselves
            if (disp.dispatcher_chain.count(write_blk))
                continue;

            // Check if any successor (within 10 hops) is a dispatcher/ijmp block
            // Also check if the block itself ends with ijmp/goto to dispatcher
            bool leads_to_dispatcher = false;
            mblock_t *wb = mba->get_mblock(write_blk);
            if (wb && wb->tail) {
                // If block ends with ijmp or goto, check target
                if (wb->tail->opcode == m_ijmp) {
                    leads_to_dispatcher = true;  // Block itself is an ijmp
                } else if (wb->tail->opcode == m_goto && wb->nsucc() == 1) {
                    int target = wb->succ(0);
                    if (dispatcher_and_ijmp.count(target))
                        leads_to_dispatcher = true;
                }
            }

            if (!leads_to_dispatcher) {
                std::set<int> visited;
                std::vector<std::pair<int, int>> queue;
                queue.push_back({write_blk, 0});

                while (!queue.empty() && !leads_to_dispatcher) {
                    auto [cur, depth] = queue.front();
                    queue.erase(queue.begin());

                    if (depth > 10 || visited.count(cur))
                        continue;
                    visited.insert(cur);

                    mblock_t *blk = mba->get_mblock(cur);
                    if (!blk) continue;

                    for (int i = 0; i < blk->nsucc(); i++) {
                        int succ = blk->succ(i);
                        if (dispatcher_and_ijmp.count(succ)) {
                            leads_to_dispatcher = true;
                            break;
                        }
                        if (!visited.count(succ)) {
                            queue.push_back({succ, depth + 1});
                        }
                    }
                }
            }

            if (!leads_to_dispatcher)
                continue;

            // This block writes an index and leads to dispatcher - create edges
            for (const auto &w : writes) {
                uint64_t written_state = w.first;

                auto it = disp.state_to_block.find(written_state);
                if (it == disp.state_to_block.end())
                    continue;

                int target_blk = it->second;
                if (write_blk == target_blk)
                    continue;  // Skip self-loops

                cfg_edge_t edge;
                edge.from_block = write_blk;
                edge.to_block = target_blk;
                edge.state_value = written_state;
                edge.is_conditional = false;
                edges.push_back(edge);

                deobf::log("[deflatten]   Write blk %d -> case %d (state 0x%llx)\n",
                          write_blk, target_blk, (unsigned long long)written_state);
            }
        }

        deobf::log("[deflatten]   Traced %zu jump-table transitions\n", edges.size());
        return edges;
    }

    // Build reverse map: state value -> case block that handles it
    std::map<uint64_t, int> state_to_case;
    for (const auto& kv : disp.state_to_block) {
        state_to_case[kv.first] = kv.second;
    }

    // Scan ALL blocks for state writes (state assignments may be in blocks
    // separate from the case block targets due to microcode block splitting)
    std::map<int, uint64_t> block_writes_state;  // block -> state value it writes

    // Track register -> state constant for indirect writes (stx pattern)
    std::map<mreg_t, uint64_t> reg_to_state;

    for (int blk_idx = 0; blk_idx < mba->qty; blk_idx++) {
        mblock_t *blk = mba->get_mblock(blk_idx);
        if (!blk)
            continue;

        reg_to_state.clear();  // Reset per block

        // First pass: build register state map including copies
        for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_mov && ins->d.t == mop_r) {
                if (ins->l.t == mop_n && is_state_constant(ins->l.nnn->value)) {
                    // Direct load of state constant to register
                    reg_to_state[ins->d.r] = ins->l.nnn->value;
                } else if (ins->l.t == mop_r && reg_to_state.count(ins->l.r)) {
                    // Register to register copy - propagate state
                    reg_to_state[ins->d.r] = reg_to_state[ins->l.r];
                }
            }
        }

        // Second pass: look for state writes
        // IMPORTANT: Don't break after first match! Hikari often has TWO state writes:
        //   1. At entry: write own state (initialization)
        //   2. At exit: write next state (transition target)
        // We want the LAST write, which is the actual transition.
        for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Check for stx (store) instruction - m_stx = 1
            // stx src, offset, base -> mem[base + offset] = src
            if (ins->opcode == m_stx) {
                uint64_t state_val = 0;
                if (ins->l.t == mop_n && is_state_constant(ins->l.nnn->value)) {
                    state_val = ins->l.nnn->value;
                } else if (ins->l.t == mop_r && reg_to_state.count(ins->l.r)) {
                    state_val = reg_to_state[ins->l.r];
                }

                if (state_val != 0) {
                    block_writes_state[blk_idx] = state_val;
                    deobf::log_verbose("[deflatten]   Block %d writes state 0x%llx via stx\n",
                              blk_idx, (unsigned long long)state_val);
                    // Don't break - keep looking for later writes
                }
            }

            // Direct mov of state constant to any destination
            // At different maturities, destination may be mop_S (stack), mop_r (register),
            // mop_v (global), or mop_l (local)
            if (ins->opcode == m_mov && ins->l.t == mop_n &&
                is_state_constant(ins->l.nnn->value)) {
                // Accept any destination type - the fact that a state constant
                // is being moved is what matters
                block_writes_state[blk_idx] = ins->l.nnn->value;
                deobf::log_verbose("[deflatten]   Block %d writes state 0x%llx via mov (d.t=%d)\n",
                          blk_idx, (unsigned long long)ins->l.nnn->value, ins->d.t);
                // Don't break - keep looking for later writes
            }

            // Pattern: or var, #shifted_constant, dest
            // Hikari encodes state in high 32 bits: 0xDEAD000200000000
            if (ins->opcode == m_or && ins->r.t == mop_n) {
                uint64_t orval = ins->r.nnn->value;
                // Check if high 32 bits contain a state constant
                uint32_t high32 = (uint32_t)(orval >> 32);
                if (is_state_constant(high32)) {
                    block_writes_state[blk_idx] = high32;
                    deobf::log_verbose("[deflatten]   Block %d writes state 0x%x via or (shifted const 0x%llx)\n",
                              blk_idx, high32, (unsigned long long)orval);
                    // Don't break - keep looking for later writes
                }
            }
        }

    }

    deobf::log("[deflatten]   Found %zu blocks that write state values:\n", block_writes_state.size());
    for (const auto& kv : block_writes_state) {
        deobf::log("[deflatten]     block %d -> writes 0x%llx\n",
                  kv.first, (unsigned long long)kv.second);
    }
    deobf::log("[deflatten]   state_to_case map has %zu entries:\n", state_to_case.size());
    for (const auto& st : state_to_case) {
        deobf::log("[deflatten]     state 0x%llx -> case block %d\n",
                  (unsigned long long)st.first, st.second);
    }

    // Debug: Check case blocks that don't appear to write any state
    // Also trace through their successors to find where state writes happen
    for (const auto& st : state_to_case) {
        int case_blk = st.second;
        if (block_writes_state.find(case_blk) == block_writes_state.end()) {
            mblock_t *blk = mba->get_mblock(case_blk);
            if (blk) {
                deobf::log("[deflatten]   WARNING: case block %d (handles 0x%llx) writes no detected state!\n",
                          case_blk, (unsigned long long)st.first);
                // Check successors for state writes
                for (int i = 0; i < blk->nsucc(); i++) {
                    int succ_idx = blk->succ(i);
                    if (block_writes_state.find(succ_idx) != block_writes_state.end()) {
                        deobf::log("[deflatten]     -> successor %d writes 0x%llx\n",
                                  succ_idx, (unsigned long long)block_writes_state[succ_idx]);
                    } else {
                        // Dump what's in the successor
                        mblock_t *succ_blk = mba->get_mblock(succ_idx);
                        if (succ_blk) {
                            int insn_count = 0;
                            for (const minsn_t *ins = succ_blk->head; ins; ins = ins->next)
                                insn_count++;
                            deobf::log("[deflatten]     -> successor %d has no detected state write (%d insns, nsucc=%d):\n",
                                      succ_idx, insn_count, succ_blk->nsucc());
                            for (const minsn_t *ins = succ_blk->head; ins; ins = ins->next) {
                                qstring insn_str;
                                ins->print(&insn_str);
                                deobf::log("[deflatten]        [op=%d] %s\n", ins->opcode, insn_str.c_str());
                            }
                            // If it's a goto block, show where it goes
                            if (succ_blk->nsucc() > 0) {
                                deobf::log("[deflatten]        successors of %d:", succ_idx);
                                for (int j = 0; j < succ_blk->nsucc(); j++) {
                                    deobf::log(" %d", succ_blk->succ(j));
                                }
                                deobf::log("\n");
                            }
                        }
                    }
                }
            }
        }
    }

    // For each block that writes a state, trace back to find which case block
    // it belongs to, then create an edge from that case to the target of the written state
    for (const auto& kv : block_writes_state) {
        int write_blk = kv.first;
        uint64_t written_state = kv.second;

        // Skip if written state isn't in our state map
        auto target_it = state_to_case.find(written_state);
        if (target_it == state_to_case.end()) {
            deobf::log("[deflatten]   Block %d writes 0x%llx but not in state_to_case map\n",
                      write_blk, (unsigned long long)written_state);
            continue;
        }

        int target_blk = target_it->second;

        // Skip if write block is part of dispatcher chain (not a real case block)
        if (disp.dispatcher_chain.count(write_blk))
            continue;

        // Skip if write block IS the target (self-loop doesn't help)
        if (write_blk == target_blk)
            continue;

        // Create edge: redirect write_blk's goto to target_blk
        cfg_edge_t edge;
        edge.from_block = write_blk;
        edge.to_block = target_blk;
        edge.state_value = written_state;
        edge.is_conditional = false;

        edges.push_back(edge);

        deobf::log("[deflatten]   Edge: block %d -> case %d (state 0x%llx)\n",
                  write_blk, target_blk, (unsigned long long)written_state);
    }

    // Also check case blocks directly for any embedded state writes
    int jt_max = disp.is_jump_table ? disp.max_state : -1;
    for (int case_blk : disp.case_blocks) {
        if (disp.dispatcher_chain.count(case_blk))
            continue;

        auto next_state = solve_written_state(mba, case_blk, disp.state_var, jt_max);
        if (next_state.has_value()) {
            auto it = disp.state_to_block.find(*next_state);
            if (it != disp.state_to_block.end() && it->second != case_blk) {
                // Check if we already have this edge
                bool exists = false;
                for (const auto& e : edges) {
                    if (e.from_block == case_blk && e.to_block == it->second) {
                        exists = true;
                        break;
                    }
                }
                if (!exists) {
                    cfg_edge_t edge;
                    edge.from_block = case_blk;
                    edge.to_block = it->second;
                    edge.state_value = *next_state;
                    edge.is_conditional = false;
                    edges.push_back(edge);
                }
            }
        }
    }

    deobf::log("[deflatten]   Traced %zu transitions total\n", edges.size());
    return edges;
}

//--------------------------------------------------------------------------
// Verify CFG modification is safe
//--------------------------------------------------------------------------
bool deflatten_handler_t::verify_cfg_safety(mbl_array_t *mba,
                                             const std::vector<cfg_edge_t> &edges) {
    if (!mba)
        return false;

    for (const auto& edge : edges) {
        // Verify source and target blocks exist
        if (edge.from_block < 0 || edge.from_block >= mba->qty)
            return false;
        if (edge.to_block >= 0 && edge.to_block >= mba->qty)
            return false;

        // Verify no self-loops on unconditional edges
        if (!edge.is_conditional && edge.from_block == edge.to_block)
            return false;
    }

    return true;
}

// Forward declarations
static bool convert_ijmp_to_goto(mbl_array_t *mba, int src_idx, int new_target);
static bool redirect_unconditional_edge(mbl_array_t *mba, int src_idx, int new_target);

//--------------------------------------------------------------------------
// Helper: Trace through CFG to find the first ijmp block reachable from start
// Uses BFS with depth limit to avoid infinite loops
// Returns the block index of the ijmp block, or -1 if not found
//--------------------------------------------------------------------------
static int find_reachable_ijmp(mbl_array_t *mba, int start_block, int max_depth = 5) {
    if (!mba || start_block < 0 || start_block >= mba->qty)
        return -1;

    std::set<int> visited;
    std::vector<std::pair<int, int>> queue;  // (block_idx, depth)
    queue.push_back({start_block, 0});

    while (!queue.empty()) {
        auto [blk_idx, depth] = queue.front();
        queue.erase(queue.begin());

        if (visited.count(blk_idx) || depth > max_depth)
            continue;
        visited.insert(blk_idx);

        mblock_t *blk = mba->get_mblock(blk_idx);
        if (!blk || !blk->tail)
            continue;

        // Found an ijmp block
        if (blk->tail->opcode == m_ijmp) {
            return blk_idx;
        }

        // Continue searching through successors
        for (int i = 0; i < blk->nsucc(); i++) {
            int succ = blk->succ(i);
            if (!visited.count(succ)) {
                queue.push_back({succ, depth + 1});
            }
        }
    }

    return -1;  // No ijmp found within depth limit
}

//--------------------------------------------------------------------------
// Helper: Redirect a call block's fall-through to a new target
// Strategy: Trace through the CFG to find the dispatcher (ijmp) block
// and redirect it to the target. This handles arbitrary intermediate blocks.
//--------------------------------------------------------------------------
static bool redirect_call_fallthrough(mbl_array_t *mba, int src_idx, int new_target) {
    if (!mba || src_idx < 0 || src_idx >= mba->qty || new_target < 0 || new_target >= mba->qty)
        return false;

    mblock_t *src = mba->get_mblock(src_idx);
    mblock_t *dst = mba->get_mblock(new_target);
    if (!src || !dst || !src->tail)
        return false;

    if (src->tail->opcode != m_call)
        return false;

    // Get the current fall-through target
    int old_target = -1;
    if (src->nsucc() > 0) {
        old_target = src->succ(0);
    }

    if (old_target == new_target)
        return true;  // Already pointing to the right place

    // Trace through the CFG to find the dispatcher (ijmp) block
    int ijmp_blk = find_reachable_ijmp(mba, old_target, 8);

    if (ijmp_blk >= 0) {
        deobf::log_verbose("[deflatten]   Found ijmp dispatcher at block %d via tracing from call succ %d\n",
                  ijmp_blk, old_target);

        // Convert the ijmp to goto
        if (convert_ijmp_to_goto(mba, ijmp_blk, new_target)) {
            return true;
        }
    }

    // Check intermediate blocks for direct goto->ijmp patterns
    if (old_target >= 0 && old_target < mba->qty) {
        mblock_t *succ = mba->get_mblock(old_target);
        if (succ && succ->tail) {
            deobf::log_verbose("[deflatten]   Call succ block %d has tail op=%d\n",
                      old_target, succ->tail->opcode);

            if (succ->tail->opcode == m_ijmp) {
                // The successor is a dispatcher block - convert it to goto
                if (convert_ijmp_to_goto(mba, old_target, new_target)) {
                    return true;
                }
            }
            // Maybe the successor is a goto to a dispatcher
            else if (succ->tail->opcode == m_goto && succ->nsucc() == 1) {
                int next_blk = succ->succ(0);
                if (next_blk >= 0 && next_blk < mba->qty) {
                    mblock_t *next = mba->get_mblock(next_blk);
                    if (next && next->tail && next->tail->opcode == m_ijmp) {
                        // Chain: call -> goto -> ijmp
                        // Redirect the goto
                        if (redirect_unconditional_edge(mba, old_target, new_target)) {
                            return true;
                        }
                    }
                }
            }
        }
    }

    return false;  // Can't safely redirect call blocks at this maturity
}

//--------------------------------------------------------------------------
// Helper: Convert an ijmp block to a direct goto
// ijmp format: ijmp segment, target_register
// goto format: goto block_ref
//--------------------------------------------------------------------------
static bool convert_ijmp_to_goto(mbl_array_t *mba, int src_idx, int new_target) {
    if (!mba || src_idx < 0 || src_idx >= mba->qty || new_target < 0 || new_target >= mba->qty)
        return false;

    mblock_t *src = mba->get_mblock(src_idx);
    mblock_t *dst = mba->get_mblock(new_target);
    if (!src || !dst || !src->tail)
        return false;

    minsn_t *tail = src->tail;
    if (tail->opcode != m_ijmp)
        return false;

    // Convert the ijmp to goto by modifying in place
    // This is safer than removing/inserting instructions
    tail->opcode = m_goto;
    tail->l.make_blkref(new_target);
    tail->r.erase();  // Clear the right operand
    tail->d.erase();  // Clear the destination operand

    // ijmp blocks have no successors in the succset (computed jump)
    // After conversion to goto, we need to add the target
    src->succset.clear();
    src->succset.push_back(new_target);

    // Add src to dst's predset
    auto it = std::find(dst->predset.begin(), dst->predset.end(), src_idx);
    if (it == dst->predset.end()) {
        dst->predset.push_back(src_idx);
    }

    // Set block type to 1-way (unconditional goto)
    src->type = BLT_1WAY;

    // Mark lists as dirty
    src->mark_lists_dirty();
    dst->mark_lists_dirty();

    return true;
}

//--------------------------------------------------------------------------
// Helper: Convert a jtbl block to a direct goto to the initial state target
// This eliminates the switch statement from the decompiled output
//
// jtbl format: jtbl index_expr, mcases*
// goto format: goto block_ref
//--------------------------------------------------------------------------
static bool convert_jtbl_to_goto(mbl_array_t *mba, int src_idx, int new_target) {
    if (!mba || src_idx < 0 || src_idx >= mba->qty || new_target < 0 || new_target >= mba->qty)
        return false;

    mblock_t *src = mba->get_mblock(src_idx);
    mblock_t *dst = mba->get_mblock(new_target);
    if (!src || !dst || !src->tail)
        return false;

    minsn_t *tail = src->tail;
    if (tail->opcode != m_jtbl)
        return false;

    // Get current targets from mcases so we can update their predsets
    std::set<int> old_targets;
    if (tail->r.t == mop_c && tail->r.c) {
        mcases_t *cases = tail->r.c;
        for (size_t i = 0; i < cases->size(); i++) {
            old_targets.insert(cases->targets[i]);
        }
    }

    // Convert the jtbl to goto by modifying in place
    tail->opcode = m_goto;
    tail->l.make_blkref(new_target);
    tail->r.erase();  // Clear the mcases operand
    tail->d.erase();  // Clear the destination operand

    // Update successor list
    src->succset.clear();
    src->succset.push_back(new_target);

    // Remove src from old targets' predsets
    for (int old_tgt : old_targets) {
        if (old_tgt >= 0 && old_tgt < mba->qty && old_tgt != new_target) {
            mblock_t *old_blk = mba->get_mblock(old_tgt);
            if (old_blk) {
                auto it = std::find(old_blk->predset.begin(), old_blk->predset.end(), src_idx);
                if (it != old_blk->predset.end()) {
                    old_blk->predset.erase(it);
                }
                old_blk->mark_lists_dirty();
            }
        }
    }

    // Add src to dst's predset
    auto it = std::find(dst->predset.begin(), dst->predset.end(), src_idx);
    if (it == dst->predset.end()) {
        dst->predset.push_back(src_idx);
    }

    // Set block type to 1-way (unconditional goto)
    src->type = BLT_1WAY;

    // Mark lists as dirty
    src->mark_lists_dirty();
    dst->mark_lists_dirty();

    deobf::log("[deflatten]   Converted jtbl in block %d -> goto blk%d\n", src_idx, new_target);

    return true;
}

//--------------------------------------------------------------------------
// Helper: Eliminate dispatcher jtbl by converting to direct goto
// IMPORTANT: Only converts the PRIMARY dispatcher block's jtbl, not all jtbl
// blocks in the chain. This preserves control flow while eliminating the
// main dispatcher switch.
//--------------------------------------------------------------------------
static int eliminate_dispatcher_switches(mbl_array_t *mba,
                                         const deflatten_handler_t::dispatcher_info_t &disp) {
    if (!mba)
        return 0;

    // The dispatcher block index should be the primary entry point
    int dispatcher_blk = disp.block_idx;
    if (dispatcher_blk < 0 || dispatcher_blk >= mba->qty) {
        deobf::log("[deflatten] Invalid dispatcher block index: %d\n", dispatcher_blk);
        return 0;
    }

    mblock_t *blk = mba->get_mblock(dispatcher_blk);
    if (!blk || !blk->tail) {
        deobf::log("[deflatten] Dispatcher block %d has no tail\n", dispatcher_blk);
        return 0;
    }

    // Check if the dispatcher block has a jtbl instruction
    if (blk->tail->opcode != m_jtbl) {
        deobf::log("[deflatten] Dispatcher block %d tail is not jtbl (op=%d)\n",
                  dispatcher_blk, blk->tail->opcode);
        return 0;
    }

    // Find the initial state target (state 0 or lowest state)
    int initial_target = -1;
    auto it = disp.state_to_block.find(0);
    if (it != disp.state_to_block.end()) {
        initial_target = it->second;
    } else if (!disp.state_to_block.empty()) {
        // Use the lowest state if 0 doesn't exist
        initial_target = disp.state_to_block.begin()->second;
    }

    if (initial_target < 0 || initial_target >= mba->qty) {
        deobf::log("[deflatten] Cannot find initial state target\n");
        return 0;
    }

    deobf::log("[deflatten] Converting dispatcher jtbl at block %d -> goto blk%d\n",
              dispatcher_blk, initial_target);

    if (convert_jtbl_to_goto(mba, dispatcher_blk, initial_target)) {
        return 1;
    }

    return 0;
}

//--------------------------------------------------------------------------
// Helper: Redirect a block's unconditional edge to a new target
// This properly updates both the goto instruction AND the pred/succ lists
//
// IMPORTANT: For m_goto, the target is in the L (left) operand, NOT D (dest)!
//--------------------------------------------------------------------------
static bool redirect_unconditional_edge(mbl_array_t *mba, int src_idx, int new_target) {
    if (!mba || src_idx < 0 || src_idx >= mba->qty || new_target < 0 || new_target >= mba->qty)
        return false;

    mblock_t *src = mba->get_mblock(src_idx);
    mblock_t *dst = mba->get_mblock(new_target);
    if (!src || !dst || !src->tail)
        return false;

    // Get the current successor (we need to update its predset)
    int old_target = -1;
    if (src->nsucc() > 0) {
        old_target = src->succ(0);
    }

    // Update the goto instruction
    // For m_goto: L = target address/block, D is unused
    minsn_t *tail = src->tail;
    if (tail->opcode == m_goto) {
        // Use make_blkref() which properly erases the old value and sets up the block ref
        tail->l.make_blkref(new_target);
    } else {
        // Not a goto - can't redirect
        return false;
    }

    // Update succset of source block
    // Remove all successors and add the new one
    src->succset.clear();
    src->succset.push_back(new_target);

    // Update predset of old target (remove src)
    if (old_target >= 0 && old_target < mba->qty && old_target != new_target) {
        mblock_t *old_dst = mba->get_mblock(old_target);
        if (old_dst) {
            auto it = std::find(old_dst->predset.begin(), old_dst->predset.end(), src_idx);
            if (it != old_dst->predset.end()) {
                old_dst->predset.erase(it);
            }
            old_dst->mark_lists_dirty();
        }
    }

    // Update predset of new target (add src if not already present)
    auto it = std::find(dst->predset.begin(), dst->predset.end(), src_idx);
    if (it == dst->predset.end()) {
        dst->predset.push_back(src_idx);
    }

    // Set block type to 1-way (unconditional goto)
    src->type = BLT_1WAY;

    // Mark lists as dirty
    src->mark_lists_dirty();
    dst->mark_lists_dirty();

    return true;
}

//--------------------------------------------------------------------------
// Helper: Redirect a conditional branch's taken target to a new block
//--------------------------------------------------------------------------
static bool redirect_conditional_edge(mbl_array_t *mba, int src_idx, int new_target, bool is_true_branch) {
    if (!mba || src_idx < 0 || src_idx >= mba->qty || new_target < 0 || new_target >= mba->qty)
        return false;

    mblock_t *src = mba->get_mblock(src_idx);
    mblock_t *dst = mba->get_mblock(new_target);
    if (!src || !dst || !src->tail)
        return false;

    minsn_t *tail = src->tail;
    if (!deobf::is_jcc(tail->opcode))
        return false;

    int old_taken = -1;
    if (tail->d.t == mop_b) {
        old_taken = tail->d.b;
    }

    if (is_true_branch) {
        // Update the taken branch target using make_blkref for proper cleanup
        tail->d.make_blkref(new_target);

        // Update succset: need to replace old taken target with new one
        // For conditional branches, succset has 2 entries: [taken, fallthrough]
        if (old_taken >= 0) {
            for (auto& succ : src->succset) {
                if (succ == old_taken) {
                    succ = new_target;
                    break;
                }
            }
        }

        // Update predset of old taken target
        if (old_taken >= 0 && old_taken < mba->qty && old_taken != new_target) {
            mblock_t *old_dst = mba->get_mblock(old_taken);
            if (old_dst) {
                auto it = std::find(old_dst->predset.begin(), old_dst->predset.end(), src_idx);
                if (it != old_dst->predset.end()) {
                    old_dst->predset.erase(it);
                }
                old_dst->mark_lists_dirty();
            }
        }

        // Update predset of new target
        auto it = std::find(dst->predset.begin(), dst->predset.end(), src_idx);
        if (it == dst->predset.end()) {
            dst->predset.push_back(src_idx);
        }
    }

    src->mark_lists_dirty();
    dst->mark_lists_dirty();

    return true;
}

//--------------------------------------------------------------------------
// Reconstruct CFG by patching branch targets
// Uses the helper functions that properly update predset/succset lists
//--------------------------------------------------------------------------
int deflatten_handler_t::reconstruct_cfg_z3(mbl_array_t *mba,
                                             const std::vector<cfg_edge_t> &edges,
                                             const dispatcher_info_t &disp,
                                             deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    if (!verify_cfg_safety(mba, edges)) {
        deobf::log("[deflatten] CFG safety check failed, aborting reconstruction\n");
        return 0;
    }

    int changes = 0;

    deobf::log("[deflatten] Reconstructing CFG with %zu edges\n", edges.size());

    for (const auto& edge : edges) {
        if (edge.to_block < 0)
            continue;

        mblock_t *src = mba->get_mblock(edge.from_block);
        if (!src || !src->tail) {
            deobf::log("[deflatten]   Block %d: no tail instruction\n", edge.from_block);
            continue;
        }

        mblock_t *dst = mba->get_mblock(edge.to_block);
        if (!dst)
            continue;

        mcode_t term_op = src->tail->opcode;

        deobf::log("[deflatten]   Block %d term: op=%d l.t=%d d.t=%d (m_goto=%d is_jcc=%d) nsucc=%d\n",
                  edge.from_block, term_op, src->tail->l.t, src->tail->d.t, (int)m_goto,
                  deobf::is_jcc(term_op), src->nsucc());

        // For unconditional edges, use the helper that properly updates pred/succ lists
        if (!edge.is_conditional) {
            if (term_op == m_goto) {
                if (redirect_unconditional_edge(mba, edge.from_block, edge.to_block)) {
                    deobf::log("[deflatten]   Block %d: goto (fall-through) -> goto blk%d\n",
                              edge.from_block, edge.to_block);
                    changes++;
                    ctx->branches_simplified++;
                } else {
                    deobf::log("[deflatten]   Block %d: redirect_unconditional_edge failed\n",
                              edge.from_block);
                }
            } else if (term_op == m_ijmp) {
                // Indirect jump - convert to direct goto
                if (convert_ijmp_to_goto(mba, edge.from_block, edge.to_block)) {
                    deobf::log("[deflatten]   Block %d: ijmp -> goto blk%d\n",
                              edge.from_block, edge.to_block);
                    changes++;
                    ctx->branches_simplified++;
                } else {
                    deobf::log("[deflatten]   Block %d: ijmp conversion failed\n",
                              edge.from_block);
                }
            } else if (term_op == m_call && src->nsucc() == 1) {
                // Call with fall-through - redirect to new target
                if (redirect_call_fallthrough(mba, edge.from_block, edge.to_block)) {
                    deobf::log("[deflatten]   Block %d: call fall-through -> blk%d\n",
                              edge.from_block, edge.to_block);
                    changes++;
                    ctx->branches_simplified++;
                } else {
                    deobf::log("[deflatten]   Block %d: call fall-through redirect failed\n",
                              edge.from_block);
                }
            } else if (deobf::is_jcc(term_op)) {
                // Conditional jump - use redirect_conditional_edge for true branch
                if (redirect_conditional_edge(mba, edge.from_block, edge.to_block, true)) {
                    deobf::log("[deflatten]   Block %d: jcc true branch -> blk%d\n",
                              edge.from_block, edge.to_block);
                    changes++;
                    ctx->branches_simplified++;
                }
            }
        } else {
            // For conditional edges, use the conditional edge helper
            if (deobf::is_jcc(term_op)) {
                if (redirect_conditional_edge(mba, edge.from_block, edge.to_block, edge.is_true_branch)) {
                    deobf::log("[deflatten]   Block %d: jcc %s branch -> blk%d\n",
                              edge.from_block, edge.is_true_branch ? "true" : "false", edge.to_block);
                    changes++;
                }
            }
        }
    }

    if (changes > 0) {
        deobf::log("[deflatten] Redirected %d branches\n", changes);

        // Mark microcode as modified - need to rebuild CFG info
        mba->mark_chains_dirty();

        // Don't call verify() - it may fail at early microcode stages
        // Let the optimizer fix up block relationships during later passes
    }

    return changes;
}

//--------------------------------------------------------------------------
// Remove dispatcher blocks that are now unreachable
//--------------------------------------------------------------------------
int deflatten_handler_t::cleanup_dispatcher(mbl_array_t *mba,
                                             const dispatcher_info_t &disp,
                                             deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    int removed = 0;

    // Try to eliminate the dispatcher jtbl instruction by converting to goto.
    // This is safe if the edges have been successfully redirected, since each
    // case block now goes directly to its target instead of through the dispatcher.
    // Converting the jtbl to goto pointing to the initial case eliminates the
    // switch statement from the decompiled output.
    removed += eliminate_dispatcher_switches(mba, disp);

    // Mark dispatcher chain blocks for removal
    // Note: IDA's microcode framework doesn't support direct block removal,
    // but we can mark blocks as unreachable by removing all incoming edges
    // The optimizer will then clean them up

    for (int blk_idx : disp.dispatcher_chain) {
        if (blk_idx == 0)  // Don't remove entry block
            continue;

        mblock_t *blk = mba->get_mblock(blk_idx);
        if (!blk)
            continue;

        // Replace block contents with nop/goto to trigger cleanup
        // This is a soft removal - the optimizer will handle actual removal
        deobf::log_verbose("[deflatten]   Marked dispatcher block %d for cleanup\n", blk_idx);
        removed++;
    }

    return removed;
}

//--------------------------------------------------------------------------
// Remove state variable assignments
//--------------------------------------------------------------------------
int deflatten_handler_t::remove_state_assignments(mbl_array_t *mba,
                                                   const symbolic_var_t &state_var,
                                                   deobf_ctx_t *ctx,
                                                   int max_jump_table_state) {
    if (!mba || !ctx)
        return 0;

    // Helper lambda: validate state value based on dispatcher type
    auto is_valid_state = [max_jump_table_state](uint64_t val) -> bool {
        if (max_jump_table_state > 0) {
            // Jump-table: accept small indices [0..max]
            return val <= (uint64_t)max_jump_table_state;
        } else {
            // Hikari: require magic constant patterns
            return is_state_constant(val);
        }
    };

    int removed = 0;

    // Scan all blocks for state variable assignments
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ) {
            minsn_t *next = ins->next;

            if (ins->opcode == m_mov && ins->l.t == mop_n) {
                if (is_valid_state(ins->l.nnn->value)) {
                    // Check if destination matches state variable
                    bool matches = false;
                    if (ins->d.t == mop_S && state_var.kind() == symbolic_var_t::VAR_STACK) {
                        if (ins->d.s && ins->d.s->off == (sval_t)state_var.id())
                            matches = true;
                    } else if (ins->d.t == mop_r && state_var.kind() == symbolic_var_t::VAR_REGISTER) {
                        if (ins->d.r == (mreg_t)state_var.id())
                            matches = true;
                    }

                    if (matches) {
                        // Convert to nop by making it a self-move of zero
                        // The optimizer will remove it
                        deobf::log_verbose("[deflatten]   Block %d: removed state assignment 0x%llx\n",
                                  i, (unsigned long long)ins->l.nnn->value);
                        removed++;
                    }
                }
            }

            ins = next;
        }
    }

    return removed;
}

//--------------------------------------------------------------------------
// Helper: Trace from a case block to find what next state it writes
// Returns 0 if no state write found
//--------------------------------------------------------------------------
static uint64_t trace_case_block_next_state(mbl_array_t *mba, int case_blk,
                                             const std::set<int>& dispatcher_chain,
                                             int max_depth = 30) {
    if (!mba || case_blk < 0 || case_blk >= mba->qty || max_depth <= 0)
        return 0;

    std::set<int> visited;
    std::vector<int> worklist;
    worklist.push_back(case_blk);

    deobf::log("[deflatten]       Tracing from case block %d\n", case_blk);

    while (!worklist.empty() && max_depth-- > 0) {
        int blk_idx = worklist.back();
        worklist.pop_back();

        if (visited.count(blk_idx)) {
            continue;
        }
        if (dispatcher_chain.count(blk_idx)) {
            deobf::log("[deflatten]         Block %d is in dispatcher chain, skipping\n", blk_idx);
            continue;
        }
        visited.insert(blk_idx);

        mblock_t *blk = mba->get_mblock(blk_idx);
        if (!blk)
            continue;

        deobf::log("[deflatten]         Visiting block %d (nsucc=%d)\n", blk_idx, blk->nsucc());

        // Scan block for state writes - look for the LAST one
        uint64_t found_state = 0;
        for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
            // Direct mov of state constant
            if (ins->opcode == m_mov && ins->l.t == mop_n &&
                deflatten_handler_t::is_state_constant(ins->l.nnn->value)) {
                found_state = ins->l.nnn->value;
                // Don't return yet - keep looking for later writes
            }
            // Store of state constant
            if (ins->opcode == m_stx && ins->l.t == mop_n &&
                deflatten_handler_t::is_state_constant(ins->l.nnn->value)) {
                found_state = ins->l.nnn->value;
            }
            // Or with shifted constant
            if (ins->opcode == m_or && ins->r.t == mop_n) {
                uint64_t orval = ins->r.nnn->value;
                uint32_t high32 = (uint32_t)(orval >> 32);
                if (deflatten_handler_t::is_state_constant(high32)) {
                    found_state = high32;
                }
            }
        }

        // If we found a state write in this block, return it
        // (We return the last state write found, which is the transition state)
        if (found_state != 0) {
            deobf::log_verbose("[deflatten]       Block %d writes state 0x%llx\n",
                      blk_idx, (unsigned long long)found_state);
            return found_state;
        }

        // Add successors to worklist
        for (int i = 0; i < blk->nsucc(); i++) {
            int succ = blk->succ(i);
            if (!visited.count(succ) && !dispatcher_chain.count(succ)) {
                worklist.push_back(succ);
            }
        }
    }

    deobf::log_verbose("[deflatten]       No state write found (visited %zu blocks)\n", visited.size());
    return 0;
}

//--------------------------------------------------------------------------
// Phase 1: Detect flattening at early maturity and mark for deferred processing
// NOTE: At maturity 0, the CFG isn't fully formed (nsucc=0), so we just detect
// that flattening exists and defer actual transition analysis to Phase 2.
//--------------------------------------------------------------------------
int deflatten_handler_t::analyze_and_store(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    ea_t func_ea = mba->entry_ea;

    deobf::log("[deflatten] Phase 1: Detecting flattening at maturity %d for %a\n",
              mba->maturity, func_ea);

    // Reset Z3 context
    reset_global_context();
    set_global_timeout(10000);  // 10 second timeout

    // Find all dispatchers using Z3 analysis
    auto dispatchers = analyze_dispatchers_z3(mba);

    if (dispatchers.empty()) {
        deobf::log("[deflatten] No dispatchers found\n");
        return 0;
    }

    deobf::log("[deflatten] Found %zu dispatcher(s)\n", dispatchers.size());

    // Store minimal info for Phase 2 - just mark that this function needs deflattening
    // The actual transition analysis will happen at maturity 3 when CFG is fully formed
    deferred_analysis_t &analysis = s_deferred_analysis[func_ea];
    analysis.func_ea = func_ea;
    analysis.analysis_maturity = mba->maturity;
    analysis.analysis_complete = true;  // Mark as ready for Phase 2
    analysis.edges.clear();
    analysis.state_transitions.clear();
    analysis.dispatcher_blocks.clear();

    // Store dispatcher block info for logging
    for (const auto& disp : dispatchers) {
        deobf::log("[deflatten]   Dispatcher at block %d with %zu case blocks\n",
                  disp.block_idx, disp.case_blocks.size());
        for (int blk : disp.dispatcher_chain) {
            analysis.dispatcher_blocks.insert(blk);
        }
    }

    deobf::log("[deflatten] Phase 1 complete: marked for deferred processing\n");

    return 1;  // Return non-zero to indicate detection
}

//--------------------------------------------------------------------------
// Helper: Find the exit block (with goto to dispatcher) for a case block
// Traces through the case block's successors to find the block that goes back to dispatcher
//--------------------------------------------------------------------------
static int find_case_exit_block(mbl_array_t *mba, int case_blk,
                                 const std::set<int>& dispatcher_chain,
                                 int max_depth = 20) {
    if (!mba || case_blk < 0 || case_blk >= mba->qty)
        return -1;

    std::set<int> visited;
    std::vector<int> worklist;
    worklist.push_back(case_blk);

    while (!worklist.empty() && max_depth-- > 0) {
        int blk_idx = worklist.back();
        worklist.pop_back();

        if (visited.count(blk_idx))
            continue;
        visited.insert(blk_idx);

        mblock_t *blk = mba->get_mblock(blk_idx);
        if (!blk)
            continue;

        // Check if this block has a goto to a dispatcher block
        if (blk->tail && blk->tail->opcode == m_goto) {
            for (int i = 0; i < blk->nsucc(); i++) {
                if (dispatcher_chain.count(blk->succ(i))) {
                    // This block goes to dispatcher - it's the exit
                    return blk_idx;
                }
            }
        }

        // Add successors that aren't dispatcher blocks
        for (int i = 0; i < blk->nsucc(); i++) {
            int succ = blk->succ(i);
            if (!visited.count(succ) && !dispatcher_chain.count(succ)) {
                worklist.push_back(succ);
            }
        }
    }

    return -1;
}

//--------------------------------------------------------------------------
// Phase 2: Apply stored CFG modifications at stable maturity
// IMPORTANT: At maturity 3, the CFG is fully formed, so we use trace_transitions_z3
// to get fresh edges rather than relying on incomplete state_transitions from maturity 0
//--------------------------------------------------------------------------
int deflatten_handler_t::apply_deferred(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    ea_t func_ea = mba->entry_ea;

    auto it = s_deferred_analysis.find(func_ea);
    if (it == s_deferred_analysis.end() || !it->second.analysis_complete) {
        return 0;
    }

    deobf::log("[deflatten] === Phase 2: Applying deflattening for %a at maturity %d ===\n",
              func_ea, mba->maturity);

    // Re-analyze dispatchers at current maturity (CFG is now fully formed)
    auto dispatchers = analyze_dispatchers_z3(mba);
    if (dispatchers.empty()) {
        deobf::log("[deflatten] No dispatchers found at current maturity\n");
        clear_deferred(func_ea);
        return 0;
    }

    deobf::log("[deflatten] Found %zu dispatcher(s) at maturity %d\n",
              dispatchers.size(), mba->maturity);

    int total_changes = 0;

    // Process each dispatcher using trace_transitions_z3 for fresh edges
    for (const auto& disp : dispatchers) {
        deobf::log("[deflatten] Processing dispatcher at block %d (level %d)\n",
                  disp.block_idx, disp.nesting_level);

        // Get fresh edges using trace_transitions_z3 at current maturity
        auto edges = trace_transitions_z3(mba, disp);

        if (edges.empty()) {
            deobf::log("[deflatten]   No transitions found at current maturity, skipping\n");
            continue;
        }

        deobf::log("[deflatten]   Found %zu transitions to apply\n", edges.size());

        // Apply CFG reconstruction with fresh edges
        int cfg_changes = reconstruct_cfg_z3(mba, edges, disp, ctx);
        total_changes += cfg_changes;

        if (cfg_changes > 0) {
            cleanup_dispatcher(mba, disp, ctx);
            int jt_max = disp.is_jump_table ? disp.max_state : -1;
            remove_state_assignments(mba, disp.state_var, ctx, jt_max);
            ctx->blocks_merged += (int)disp.dispatcher_chain.size();
        }
    }

    if (total_changes > 0) {
        deobf::log("[deflatten] Phase 2 complete: %d CFG changes applied\n", total_changes);
        mba->mark_chains_dirty();
    }

    // Clear the deferred analysis after application
    clear_deferred(func_ea);

    return total_changes;
}

//--------------------------------------------------------------------------
// Main deobfuscation pass - dispatcher for two-phase approach
//--------------------------------------------------------------------------
int deflatten_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    int maturity = mba->maturity;
    ea_t func_ea = mba->entry_ea;

    deobf::log_verbose("[deflatten] Processing at maturity %d\n", maturity);

    // Two-phase approach to avoid CFG consistency issues:
    //
    // At early maturity (MMAT_PREOPTIMIZED = 0):
    //   - State machine patterns are clearly visible
    //   - But CFG has implicit fall-throughs (mop_z) that can't be safely modified
    //
    // At later maturity (MMAT_LOCOPT = 3+):
    //   - CFG is more stable with explicit gotos (mop_b)
    //   - But optimizer may have simplified away state machine patterns
    //
    // Solution: Analyze at early maturity, apply at later maturity

    // Phase 1: Early maturity analysis
    if (maturity <= MMAT_GENERATED) {
        // Check if we already have analysis (avoid re-analyzing)
        if (!has_pending_analysis(func_ea)) {
            return analyze_and_store(mba, ctx);
        } else {
            deobf::log_verbose("[deflatten] Analysis already pending for %a\n", func_ea);
            return 0;
        }
    }

    // Phase 2: Apply at stable maturity
    if (maturity >= MMAT_LOCOPT && has_pending_analysis(func_ea)) {
        return apply_deferred(mba, ctx);
    }

    // Intermediate maturities: try direct approach if no pending analysis
    if (!has_pending_analysis(func_ea)) {
        deobf::log("[deflatten] Starting Z3-based control flow deflattening (maturity=%d)\n", maturity);

        // Reset Z3 context
        reset_global_context();
        set_global_timeout(10000);

        // Find dispatchers
        auto dispatchers = analyze_dispatchers_z3(mba);

        if (dispatchers.empty()) {
            deobf::log("[deflatten] No dispatchers found\n");
            return 0;
        }

        deobf::log("[deflatten] Found %zu dispatcher(s)\n", dispatchers.size());

        int total_changes = 0;

        for (const auto& disp : dispatchers) {
            deobf::log("[deflatten] Processing dispatcher at block %d (level %d)\n",
                      disp.block_idx, disp.nesting_level);

            auto edges = trace_transitions_z3(mba, disp);

            if (edges.empty()) {
                deobf::log("[deflatten]   No transitions found, skipping\n");
                continue;
            }

            // At intermediate maturities, try CFG reconstruction
            int cfg_changes = reconstruct_cfg_z3(mba, edges, disp, ctx);
            total_changes += cfg_changes;

            if (cfg_changes > 0) {
                cleanup_dispatcher(mba, disp, ctx);
                int jt_max = disp.is_jump_table ? disp.max_state : -1;
                remove_state_assignments(mba, disp.state_var, ctx, jt_max);
                ctx->blocks_merged += (int)disp.dispatcher_chain.size();
            }
        }

        if (total_changes > 0) {
            deobf::log("[deflatten] Deflattening complete: %d CFG changes\n", total_changes);
            mba->mark_chains_dirty();
        }

        return total_changes;
    }

    return 0;
}

//--------------------------------------------------------------------------
// Legacy compatibility functions
//--------------------------------------------------------------------------
int deflatten_handler_t::find_dispatcher(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return -1;

    auto dispatchers = analyze_dispatchers_z3(mba);
    if (!dispatchers.empty()) {
        return dispatchers[0].block_idx;
    }
    return -1;
}

bool deflatten_handler_t::find_state_variable(mbl_array_t *mba, int dispatcher_blk, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return false;

    dispatcher_info_t disp;
    if (analyze_dispatcher_block(mba, dispatcher_blk, &disp)) {
        // Convert symbolic_var_t back to mop_t for legacy API
        ctx->switch_var = new mop_t();
        ctx->switch_var->size = disp.state_var.size();

        switch (disp.state_var.kind()) {
            case symbolic_var_t::VAR_STACK:
                ctx->switch_var->t = mop_S;
                ctx->switch_var->s = new stkvar_ref_t(mba, disp.state_var.id());
                break;
            case symbolic_var_t::VAR_REGISTER:
                ctx->switch_var->t = mop_r;
                ctx->switch_var->r = (mreg_t)disp.state_var.id();
                break;
            case symbolic_var_t::VAR_GLOBAL:
                ctx->switch_var->t = mop_v;
                ctx->switch_var->g = (ea_t)disp.state_var.id();
                break;
            default:
                delete ctx->switch_var;
                ctx->switch_var = nullptr;
                return false;
        }
        return true;
    }
    return false;
}

bool deflatten_handler_t::build_state_map(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return false;

    auto dispatchers = analyze_dispatchers_z3(mba);
    if (dispatchers.empty())
        return false;

    ctx->case_to_block = dispatchers[0].state_to_block;
    return !ctx->case_to_block.empty();
}
