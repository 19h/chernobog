#include "deflatten.h"
#include "../analysis/cfg_analysis.h"
#include "../analysis/pattern_match.h"
#include "../analysis/opaque_eval.h"

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
// Main deobfuscation pass - ENHANCED for hierarchical flattening
//--------------------------------------------------------------------------
int deflatten_handler_t::run(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!mba || !ctx)
        return 0;

    deobf::log("[deflatten] Starting control flow deflattening (hierarchical mode)\n");

    // Step 1: Find ALL dispatchers (supports nested/hierarchical)
    auto dispatchers = find_all_dispatchers(mba);

    if (dispatchers.empty()) {
        // Fallback to single dispatcher mode
        deobf::log("[deflatten] No hierarchical dispatchers found, trying single mode\n");

        int dispatcher = find_dispatcher(mba, ctx);
        if (dispatcher < 0) {
            deobf::log("[deflatten] Could not find dispatcher block\n");
            return 0;
        }

        ctx->switch_block = dispatcher;
        deobf::log("[deflatten] Found dispatcher at block %d\n", dispatcher);

        if (!find_state_variable(mba, dispatcher, ctx)) {
            deobf::log("[deflatten] Could not identify state variable\n");
            return 0;
        }

        if (!build_state_map(mba, ctx)) {
            deobf::log("[deflatten] Could not build state map\n");
            return 0;
        }

        auto edges = trace_transitions(mba, ctx);
        return reconstruct_cfg(mba, edges, ctx);
    }

    deobf::log("[deflatten] Found %zu dispatcher(s) (hierarchical)\n", dispatchers.size());

    // Log dispatcher hierarchy
    for (size_t i = 0; i < dispatchers.size(); i++) {
        const auto &disp = dispatchers[i];
        deobf::log("[deflatten]   Dispatcher %zu: block %d, level %d, parent %d, state var type %d\n",
                  i, disp.block_idx, disp.nesting_level, disp.parent_dispatcher, disp.state_var.t);
    }

    // Process hierarchically (bottom-up: deepest nested first)
    return deflatten_hierarchical(mba, dispatchers, ctx);
}

//--------------------------------------------------------------------------
// Find ALL dispatchers - supports hierarchical/nested flattening
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::dispatcher_info_t>
deflatten_handler_t::find_all_dispatchers(mbl_array_t *mba) {

    std::vector<dispatcher_info_t> dispatchers;

    if (!mba)
        return dispatchers;

    // First pass: find all potential dispatcher blocks
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        mop_t state_var;
        if (is_dispatcher_block(blk, &state_var)) {
            dispatcher_info_t disp;
            disp.block_idx = i;
            disp.state_var = state_var;
            disp.parent_dispatcher = -1;
            disp.nesting_level = 0;
            disp.is_while_loop = is_in_infinite_loop(mba, i);

            dispatchers.push_back(disp);
        }
    }

    if (dispatchers.size() <= 1)
        return dispatchers;

    // Second pass: establish parent-child relationships
    // A dispatcher B is a child of dispatcher A if:
    // - B is reachable from a case block of A
    // - B is within a while(true) that starts in a case of A

    for (size_t i = 0; i < dispatchers.size(); i++) {
        auto &disp = dispatchers[i];

        // Find case blocks for this dispatcher
        build_state_map_for_dispatcher(mba, &disp);

        // Check if any case block contains another dispatcher
        for (const auto &pair : disp.state_to_block) {
            int case_block = pair.second;

            for (size_t j = 0; j < dispatchers.size(); j++) {
                if (i == j)
                    continue;

                auto &other = dispatchers[j];

                // Check if other dispatcher is dominated by this case block
                // or is directly reachable from it
                mblock_t *case_blk = mba->get_mblock(case_block);
                if (case_blk) {
                    for (int k = 0; k < case_blk->nsucc(); k++) {
                        if (case_blk->succ(k) == other.block_idx) {
                            other.parent_dispatcher = (int)i;
                            other.nesting_level = disp.nesting_level + 1;
                        }
                    }
                }

                // Also check if other is in a block that's a successor chain from case
                if (other.block_idx > case_block && other.block_idx < case_block + 10) {
                    // Heuristic: nearby blocks might be nested
                    if (other.parent_dispatcher < 0) {
                        other.parent_dispatcher = (int)i;
                        other.nesting_level = disp.nesting_level + 1;
                    }
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
// Check if a block is a dispatcher
//--------------------------------------------------------------------------
bool deflatten_handler_t::is_dispatcher_block(mblock_t *blk, mop_t *out_state_var) {
    if (!blk)
        return false;

    int score = 0;
    mop_t potential_state_var;

    // Check for jtbl instruction (jump table)
    if (blk->tail && blk->tail->opcode == m_jtbl) {
        score += 50;
        if (blk->tail->l.t != mop_z) {
            potential_state_var = blk->tail->l;
        }
    }

    // Check for many successors
    if (blk->nsucc() >= 3) {
        score += blk->nsucc() * 5;
    }

    // Check for multiple conditional jumps comparing same variable
    mop_t first_cmp_var;
    bool has_first = false;
    int consistent_cmp_count = 0;

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (deobf::is_jcc(ins->opcode) || (ins->opcode >= m_setz && ins->opcode <= m_setle)) {
            // Extract the comparison variable
            mop_t cmp_var;

            if (ins->l.t == mop_S || ins->l.t == mop_v || ins->l.t == mop_r) {
                cmp_var = ins->l;
            } else if (ins->l.t == mop_d && ins->l.d) {
                // Nested - look inside
                minsn_t *nested = ins->l.d;
                if (nested->l.t == mop_S || nested->l.t == mop_v || nested->l.t == mop_r) {
                    cmp_var = nested->l;
                } else if (nested->r.t == mop_S || nested->r.t == mop_v || nested->r.t == mop_r) {
                    cmp_var = nested->r;
                }
            }

            if (cmp_var.t != mop_z) {
                if (!has_first) {
                    first_cmp_var = cmp_var;
                    has_first = true;
                    consistent_cmp_count = 1;
                } else {
                    // Check if same variable
                    bool same = false;
                    if (cmp_var.t == first_cmp_var.t) {
                        if (cmp_var.t == mop_S && cmp_var.s && first_cmp_var.s) {
                            same = (cmp_var.s->off == first_cmp_var.s->off);
                        } else if (cmp_var.t == mop_v) {
                            same = (cmp_var.g == first_cmp_var.g);
                        } else if (cmp_var.t == mop_r) {
                            same = (cmp_var.r == first_cmp_var.r);
                        }
                    }

                    if (same) {
                        consistent_cmp_count++;
                    }
                }
            }
        }
    }

    if (consistent_cmp_count >= 2) {
        score += consistent_cmp_count * 10;
        potential_state_var = first_cmp_var;
    }

    // Threshold for dispatcher detection
    if (score >= 20) {
        if (out_state_var && potential_state_var.t != mop_z) {
            *out_state_var = potential_state_var;
        }
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Check if block is inside an infinite loop (while(true))
//--------------------------------------------------------------------------
bool deflatten_handler_t::is_in_infinite_loop(mbl_array_t *mba, int block_idx) {
    if (!mba)
        return false;

    mblock_t *blk = mba->get_mblock(block_idx);
    if (!blk)
        return false;

    // Check if any successor eventually leads back to this block
    std::set<int> visited;
    std::vector<int> worklist;

    for (int i = 0; i < blk->nsucc(); i++) {
        worklist.push_back(blk->succ(i));
    }

    while (!worklist.empty()) {
        int curr = worklist.back();
        worklist.pop_back();

        if (visited.count(curr))
            continue;
        visited.insert(curr);

        if (curr == block_idx) {
            return true;  // Found back edge
        }

        mblock_t *curr_blk = mba->get_mblock(curr);
        if (!curr_blk)
            continue;

        // Don't follow too many blocks
        if (visited.size() > 50)
            break;

        for (int i = 0; i < curr_blk->nsucc(); i++) {
            worklist.push_back(curr_blk->succ(i));
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Find state variable for a specific dispatcher
//--------------------------------------------------------------------------
bool deflatten_handler_t::find_state_variable_for_dispatcher(mbl_array_t *mba,
                                                              dispatcher_info_t *disp) {
    if (!mba || !disp)
        return false;

    mblock_t *blk = mba->get_mblock(disp->block_idx);
    if (!blk)
        return false;

    // Try to find from jtbl
    if (blk->tail && blk->tail->opcode == m_jtbl) {
        if (blk->tail->l.t != mop_z) {
            disp->state_var = blk->tail->l;
            return true;
        }
    }

    // Try to find from comparisons
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode >= m_setz && ins->opcode <= m_setle) {
            if (ins->l.t == mop_S || ins->l.t == mop_r) {
                disp->state_var = ins->l;
                return true;
            }
            if (ins->r.t == mop_S || ins->r.t == mop_r) {
                disp->state_var = ins->r;
                return true;
            }
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// Build state map for a specific dispatcher
//--------------------------------------------------------------------------
bool deflatten_handler_t::build_state_map_for_dispatcher(mbl_array_t *mba,
                                                          dispatcher_info_t *disp) {
    if (!mba || !disp)
        return false;

    mblock_t *blk = mba->get_mblock(disp->block_idx);
    if (!blk)
        return false;

    disp->state_to_block.clear();
    disp->case_blocks.clear();

    // Map successors to state values
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (!deobf::is_jcc(ins->opcode))
            continue;

        // Try to get the comparison constant
        uint64_t state_val = 0;
        bool found_val = false;

        if (ins->l.t == mop_d && ins->l.d) {
            minsn_t *cmp = ins->l.d;
            if (cmp->r.t == mop_n) {
                state_val = cmp->r.nnn->value;
                found_val = true;
            } else if (cmp->l.t == mop_n) {
                state_val = cmp->l.nnn->value;
                found_val = true;
            }
        } else if (ins->r.t == mop_n) {
            state_val = ins->r.nnn->value;
            found_val = true;
        }

        if (found_val && ins->d.t == mop_b) {
            disp->state_to_block[state_val] = ins->d.b;
            disp->case_blocks.insert(ins->d.b);
        }
    }

    // Also add direct successors
    for (int i = 0; i < blk->nsucc(); i++) {
        disp->case_blocks.insert(blk->succ(i));
    }

    return !disp->state_to_block.empty() || !disp->case_blocks.empty();
}

//--------------------------------------------------------------------------
// Get written state value with specific state var
//--------------------------------------------------------------------------
std::optional<uint64_t> deflatten_handler_t::get_written_state(mblock_t *blk,
                                                                const mop_t &state_var) {
    if (!blk)
        return std::nullopt;

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov && ins->opcode != m_stx)
            continue;

        bool matches = false;

        if (ins->d.t == mop_S && state_var.t == mop_S) {
            if (ins->d.s && state_var.s && ins->d.s->off == state_var.s->off)
                matches = true;
        } else if (ins->d.t == mop_r && state_var.t == mop_r) {
            if (ins->d.r == state_var.r)
                matches = true;
        } else if (ins->d.t == mop_v && state_var.t == mop_v) {
            if (ins->d.g == state_var.g)
                matches = true;
        }

        if (matches && ins->l.t == mop_n) {
            return ins->l.nnn->value;
        }
    }

    return std::nullopt;
}

//--------------------------------------------------------------------------
// Trace transitions for a specific dispatcher
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::edge_t>
deflatten_handler_t::trace_transitions_for_dispatcher(mbl_array_t *mba,
                                                       const dispatcher_info_t &disp) {
    std::vector<edge_t> edges;

    for (int case_blk : disp.case_blocks) {
        mblock_t *blk = mba->get_mblock(case_blk);
        if (!blk)
            continue;

        auto next_state = get_written_state(blk, disp.state_var);
        if (!next_state.has_value())
            continue;

        auto it = disp.state_to_block.find(*next_state);
        if (it == disp.state_to_block.end())
            continue;

        edge_t edge;
        edge.from_block = case_blk;
        edge.to_block = it->second;
        edge.is_conditional = false;
        edge.condition = nullptr;
        edge.dispatcher_level = disp.nesting_level;

        edges.push_back(edge);
    }

    return edges;
}

//--------------------------------------------------------------------------
// Deflatten hierarchically (process deepest dispatchers first)
//--------------------------------------------------------------------------
int deflatten_handler_t::deflatten_hierarchical(mbl_array_t *mba,
    const std::vector<dispatcher_info_t> &dispatchers, deobf_ctx_t *ctx) {

    int total_changes = 0;

    // Process each dispatcher (already sorted deepest first)
    for (const auto &disp : dispatchers) {
        deobf::log("[deflatten] Processing dispatcher at block %d (level %d)\n",
                  disp.block_idx, disp.nesting_level);

        // Find state variable if not already set
        dispatcher_info_t disp_copy = disp;
        if (disp_copy.state_var.t == mop_z) {
            find_state_variable_for_dispatcher(mba, &disp_copy);
        }

        // Build state map
        build_state_map_for_dispatcher(mba, &disp_copy);

        if (disp_copy.state_to_block.empty()) {
            deobf::log("[deflatten]   No state map - skipping\n");
            continue;
        }

        deobf::log("[deflatten]   State map has %zu entries, %zu case blocks\n",
                  disp_copy.state_to_block.size(), disp_copy.case_blocks.size());

        // Trace transitions
        auto edges = trace_transitions_for_dispatcher(mba, disp_copy);
        deobf::log("[deflatten]   Traced %zu edges\n", edges.size());

        // Reconstruct this dispatcher's CFG
        total_changes += reconstruct_cfg(mba, edges, ctx);
    }

    deobf::log("[deflatten] Hierarchical deflattening complete, %d total changes\n", total_changes);
    return total_changes;
}

//--------------------------------------------------------------------------
// Find dispatcher block
//--------------------------------------------------------------------------
int deflatten_handler_t::find_dispatcher(mbl_array_t *mba, deobf_ctx_t *ctx) {
    // Use CFG analysis to find dispatcher
    int dispatcher = cfg_analysis::find_dispatcher_block(mba);

    if (dispatcher >= 0) {
        // Verify it looks like a flattening dispatcher
        mblock_t *blk = mba->get_mblock(dispatcher);
        if (blk) {
            // Should have multiple successors or jtbl
            if (blk->nsucc() >= 2 || (blk->tail && blk->tail->opcode == m_jtbl)) {
                return dispatcher;
            }
        }
    }

    // Fallback: look for block with most conditional jumps
    int best = -1;
    int best_score = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        int score = 0;

        // Count successors
        score += blk->nsucc() * 2;

        // Check for switch/jtbl
        if (blk->tail && blk->tail->opcode == m_jtbl)
            score += 100;

        // Count conditional jumps
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (deobf::is_jcc(ins->opcode))
                score += 3;
        }

        // Check for load of state variable (common pattern)
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_ldx || ins->opcode == m_mov) {
                if (ins->l.t == mop_S)  // Stack variable
                    score += 1;
            }
        }

        if (score > best_score) {
            best_score = score;
            best = i;
        }
    }

    return best;
}

//--------------------------------------------------------------------------
// Find state variable
//--------------------------------------------------------------------------
bool deflatten_handler_t::find_state_variable(mbl_array_t *mba, int dispatcher_blk, deobf_ctx_t *ctx) {
    mblock_t *blk = mba->get_mblock(dispatcher_blk);
    if (!blk)
        return false;

    // Look for the variable being loaded/compared in the dispatcher
    // Typically: load state_var; compare with constants; branch

    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        // Look for comparison instructions
        if (ins->opcode >= m_setz && ins->opcode <= m_setle) {
            // One operand should be the state variable
            if (ins->l.t == mop_S || ins->l.t == mop_v) {
                ctx->switch_var = new mop_t(ins->l);
                return true;
            }
            if (ins->r.t == mop_S || ins->r.t == mop_v) {
                ctx->switch_var = new mop_t(ins->r);
                return true;
            }
        }

        // Look for jtbl operand
        if (ins->opcode == m_jtbl) {
            if (ins->l.t != mop_z) {  // Not a constant
                ctx->switch_var = new mop_t(ins->l);
                return true;
            }
        }
    }

    // Fallback: look for most commonly loaded stack variable across case blocks
    std::map<sval_t, int> stack_var_counts;

    for (int i = 0; i < mba->qty; i++) {
        if (i == dispatcher_blk)
            continue;

        mblock_t *case_blk = mba->get_mblock(i);
        if (!case_blk)
            continue;

        // Look for stores to stack variables (state updates)
        for (minsn_t *ins = case_blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_mov || ins->opcode == m_stx) {
                if (ins->d.t == mop_S) {
                    stack_var_counts[ins->d.s->off]++;
                }
            }
        }
    }

    // Find the most commonly written stack variable
    sval_t best_var = 0;
    int best_count = 0;

    for (const auto &p : stack_var_counts) {
        if (p.second > best_count) {
            best_count = p.second;
            best_var = p.first;
        }
    }

    if (best_count > 0) {
        ctx->switch_var = new mop_t();
        ctx->switch_var->t = mop_S;
        ctx->switch_var->s = new stkvar_ref_t(mba, best_var);
        return true;
    }

    return false;
}

//--------------------------------------------------------------------------
// Build state -> block mapping
//--------------------------------------------------------------------------
bool deflatten_handler_t::build_state_map(mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!ctx->switch_var)
        return false;

    ctx->case_to_block.clear();

    // For each block, find what state value it handles
    // This is determined by the comparison in the dispatcher

    mblock_t *disp = mba->get_mblock(ctx->switch_block);
    if (!disp)
        return false;

    // Parse the switch structure
    // Can be either jtbl or cascading conditionals

    if (disp->tail && disp->tail->opcode == m_jtbl) {
        // Jump table - cases are in the table
        // The table maps values to block indices

        // For jtbl, we need to extract the case values from the table
        // This is complex - need to read the jump table data

        deobf::log("[deflatten] jtbl-based switch detected\n");

        // For now, use a heuristic: assign sequential state values to successors
        for (int i = 0; i < disp->nsucc(); i++) {
            int succ = disp->succ(i);
            ctx->case_to_block[i] = succ;
        }
    } else {
        // Cascading conditionals
        // Pattern: if (state == X) goto block_X; else if (state == Y) goto block_Y; ...

        for (minsn_t *ins = disp->head; ins; ins = ins->next) {
            if (!deobf::is_jcc(ins->opcode))
                continue;

            // Try to extract the comparison value
            auto state_val = get_state_comparison(ins, ctx);
            if (state_val.has_value()) {
                // Get the target block
                if (ins->d.t == mop_b) {
                    ctx->case_to_block[*state_val] = ins->d.b;
                    deobf::log_verbose("[deflatten] State %llu -> block %d\n",
                                      (unsigned long long)*state_val, ins->d.b);
                }
            }
        }
    }

    // Also scan all blocks for state value writes to get full mapping
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        auto written = get_written_state(blk, ctx);
        if (written.has_value()) {
            // This block writes this state value, probably transitions to block handling that state
            deobf::log_verbose("[deflatten] Block %d writes state %llu\n",
                              i, (unsigned long long)*written);
        }
    }

    return !ctx->case_to_block.empty();
}

//--------------------------------------------------------------------------
// Trace state transitions to find original edges
//--------------------------------------------------------------------------
std::vector<deflatten_handler_t::edge_t> deflatten_handler_t::trace_transitions(
    mbl_array_t *mba, deobf_ctx_t *ctx) {

    std::vector<edge_t> edges;

    // For each case block, find what state it writes and map to target
    for (int i = 0; i < mba->qty; i++) {
        if (i == ctx->switch_block)
            continue;

        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Get the state value this block writes (its successor state)
        auto next_state = get_written_state(blk, ctx);
        if (!next_state.has_value())
            continue;

        // Find which block handles that state
        auto it = ctx->case_to_block.find(*next_state);
        if (it == ctx->case_to_block.end())
            continue;

        // Create edge from this block to target
        edge_t edge;
        edge.from_block = i;
        edge.to_block = it->second;
        edge.is_conditional = false;
        edge.condition = nullptr;

        // Check if this is a conditional transition
        // (block has multiple state writes under different conditions)

        edges.push_back(edge);
    }

    return edges;
}

//--------------------------------------------------------------------------
// Reconstruct CFG with direct branches
//--------------------------------------------------------------------------
int deflatten_handler_t::reconstruct_cfg(mbl_array_t *mba,
    const std::vector<edge_t> &edges, deobf_ctx_t *ctx) {

    int changes = 0;

    // For each edge, modify the source block to jump directly to target
    for (const auto &edge : edges) {
        mblock_t *src = mba->get_mblock(edge.from_block);
        if (!src)
            continue;

        // Remove the state variable update
        // Replace the branch to loop_end/dispatcher with direct branch to target

        // Find and remove state variable stores
        for (minsn_t *ins = src->head; ins; ) {
            minsn_t *next = ins->next;

            if (ins->opcode == m_mov || ins->opcode == m_stx) {
                // Check if this stores to state variable
                if (ctx->switch_var && ins->d.t == ctx->switch_var->t) {
                    if (ins->d.t == mop_S && ctx->switch_var->t == mop_S) {
                        if (ins->d.s->off == ctx->switch_var->s->off) {
                            // This is a state update - can mark for removal
                            // Don't actually remove yet as it may break things
                            deobf::log_verbose("[deflatten] Found state update in block %d\n",
                                              edge.from_block);
                        }
                    }
                }
            }

            ins = next;
        }

        // Modify terminator to jump directly to target
        if (src->tail && (src->tail->opcode == m_goto || deobf::is_jcc(src->tail->opcode))) {
            // Update the jump target
            if (src->tail->d.t == mop_b) {
                int old_target = src->tail->d.b;
                src->tail->d.b = edge.to_block;
                changes++;

                deobf::log_verbose("[deflatten] Redirected block %d: %d -> %d\n",
                                  edge.from_block, old_target, edge.to_block);
            }
        }

        ctx->branches_simplified++;
    }

    return changes;
}

//--------------------------------------------------------------------------
// Helper: get state value written by block
//--------------------------------------------------------------------------
std::optional<uint64_t> deflatten_handler_t::get_written_state(mblock_t *blk, deobf_ctx_t *ctx) {
    if (!blk || !ctx->switch_var)
        return std::nullopt;

    // Look for store to state variable
    for (minsn_t *ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov && ins->opcode != m_stx)
            continue;

        // Check if destination matches state variable
        bool matches = false;

        if (ins->d.t == mop_S && ctx->switch_var->t == mop_S) {
            if (ins->d.s->off == ctx->switch_var->s->off)
                matches = true;
        } else if (ins->d.t == mop_v && ctx->switch_var->t == mop_v) {
            if (ins->d.g == ctx->switch_var->g)
                matches = true;
        }

        if (matches && ins->l.t == mop_n) {
            return ins->l.nnn->value;
        }
    }

    return std::nullopt;
}

//--------------------------------------------------------------------------
// Helper: get state value from comparison
//--------------------------------------------------------------------------
std::optional<uint64_t> deflatten_handler_t::get_state_comparison(minsn_t *cmp_insn, deobf_ctx_t *ctx) {
    if (!cmp_insn || !ctx->switch_var)
        return std::nullopt;

    // Look for setXX or jXX instructions comparing state var with constant

    // The comparison may be nested in the condition
    mop_t *cmp_left = nullptr;
    mop_t *cmp_right = nullptr;

    if (cmp_insn->l.t == mop_d && cmp_insn->l.d) {
        // Nested comparison
        minsn_t *nested = cmp_insn->l.d;
        if (nested->opcode >= m_setz && nested->opcode <= m_setle) {
            cmp_left = &nested->l;
            cmp_right = &nested->r;
        }
    } else {
        // Direct comparison operands
        cmp_left = &cmp_insn->l;
        cmp_right = &cmp_insn->r;
    }

    if (!cmp_left || !cmp_right)
        return std::nullopt;

    // Check if one operand is state var and other is constant
    mop_t *const_op = nullptr;

    if (cmp_right->t == mop_n) {
        const_op = cmp_right;
    } else if (cmp_left->t == mop_n) {
        const_op = cmp_left;
    }

    if (const_op) {
        return const_op->nnn->value;
    }

    return std::nullopt;
}
