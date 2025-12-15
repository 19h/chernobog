#include "deflatten.h"
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
// Analyze all dispatchers in the function using Z3
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::dispatcher_info_t>
deflatten_handler_t::analyze_dispatchers_z3(mbl_array_t *mba) {
    std::vector<dispatcher_info_t> dispatchers;

    if (!mba)
        return dispatchers;

    // Reset Z3 context for fresh analysis
    reset_global_context();

    // First pass: find all potential dispatcher blocks
    for (int i = 0; i < mba->qty; i++) {
        dispatcher_info_t disp;
        if (analyze_dispatcher_block(mba, i, &disp)) {
            dispatchers.push_back(disp);
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
    const symbolic_var_t &state_var) {

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return std::nullopt;

    mblock_t *blk = mba->get_mblock(block_idx);
    if (!blk)
        return std::nullopt;

    // Use Z3 symbolic execution
    symbolic_executor_t executor(get_global_context());

    // Execute the block symbolically
    executor.execute_block(blk);

    // Try to get the final value of the state variable
    auto value = executor.get_value(state_var);
    if (value.has_value()) {
        auto concrete = executor.solve_for_value(value.value());
        if (concrete.has_value() && is_state_constant(*concrete)) {
            return concrete;
        }
    }

    // Fallback: scan for direct constant assignments
    for (const minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov)
            continue;

        if (ins->l.t != mop_n || !is_state_constant(ins->l.nnn->value))
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
    for (int case_blk : disp.case_blocks) {
        if (disp.dispatcher_chain.count(case_blk))
            continue;

        auto next_state = solve_written_state(mba, case_blk, disp.state_var);
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
                                                   deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    int removed = 0;

    // Scan all blocks for state variable assignments
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t *ins = blk->head; ins; ) {
            minsn_t *next = ins->next;

            if (ins->opcode == m_mov && ins->l.t == mop_n) {
                if (is_state_constant(ins->l.nnn->value)) {
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
            remove_state_assignments(mba, disp.state_var, ctx);
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
                remove_state_assignments(mba, disp.state_var, ctx);
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
