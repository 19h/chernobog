#include "cfg_analysis.h"
#include "pattern_match.h"

namespace cfg_analysis {

//--------------------------------------------------------------------------
// Build CFG information
//--------------------------------------------------------------------------
std::vector<block_info_t> analyze_cfg(mbl_array_t *mba) {
    std::vector<block_info_t> blocks;

    if (!mba)
        return blocks;

    blocks.resize(mba->qty);

    // First pass: collect basic info and successors
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        blocks[i].block_idx = i;
        blocks[i].dominator = -1;
        blocks[i].post_dominator = -1;
        blocks[i].is_loop_header = false;
        blocks[i].is_loop_exit = false;
        blocks[i].loop_depth = 0;

        if (!blk)
            continue;

        // Get successors
        for (int j = 0; j < blk->nsucc(); j++) {
            int succ = blk->succ(j);
            if (succ >= 0 && succ < mba->qty) {
                blocks[i].successors.push_back(succ);
            }
        }
    }

    // Second pass: compute predecessors from successors
    for (int i = 0; i < mba->qty; i++) {
        for (int succ : blocks[i].successors) {
            if (succ >= 0 && succ < (int)blocks.size()) {
                blocks[succ].predecessors.push_back(i);
            }
        }
    }

    // Compute dominators
    compute_dominators(mba, blocks);

    return blocks;
}

//--------------------------------------------------------------------------
// Compute immediate dominators using iterative dataflow
//--------------------------------------------------------------------------
void compute_dominators(mbl_array_t *mba, std::vector<block_info_t> &blocks) {
    if (!mba || blocks.empty())
        return;

    int n = blocks.size();

    // Initialize: every block dominated by all blocks except entry
    std::vector<std::set<int>> dom(n);
    for (int i = 0; i < n; i++) {
        if (i == 0) {
            dom[i].insert(0);  // Entry dominates itself
        } else {
            for (int j = 0; j < n; j++)
                dom[i].insert(j);
        }
    }

    // Iterate until fixpoint
    bool changed = true;
    while (changed) {
        changed = false;

        for (int i = 1; i < n; i++) {  // Skip entry block
            std::set<int> new_dom;

            // Dom(n) = {n} U intersection of Dom(pred) for all predecessors
            bool first = true;
            for (int pred : blocks[i].predecessors) {
                if (first) {
                    new_dom = dom[pred];
                    first = false;
                } else {
                    std::set<int> intersection;
                    std::set_intersection(new_dom.begin(), new_dom.end(),
                                         dom[pred].begin(), dom[pred].end(),
                                         std::inserter(intersection, intersection.begin()));
                    new_dom = intersection;
                }
            }

            new_dom.insert(i);  // Block always dominates itself

            if (new_dom != dom[i]) {
                dom[i] = new_dom;
                changed = true;
            }
        }
    }

    // Extract immediate dominators
    for (int i = 1; i < n; i++) {
        // idom is the closest dominator that is not the block itself
        for (int d : dom[i]) {
            if (d != i) {
                // Check if d is immediate (no other dominator between d and i)
                bool is_immediate = true;
                for (int other : dom[i]) {
                    if (other != i && other != d) {
                        // Check if other is dominated by d
                        if (dom[other].count(d) && dom[i].count(other)) {
                            is_immediate = false;
                            break;
                        }
                    }
                }
                if (is_immediate) {
                    blocks[i].dominator = d;
                    break;
                }
            }
        }
    }
}

//--------------------------------------------------------------------------
// Find natural loops
//--------------------------------------------------------------------------
std::vector<loop_info_t> find_loops(mbl_array_t *mba, const std::vector<block_info_t> &blocks) {
    std::vector<loop_info_t> loops;

    if (!mba || blocks.empty())
        return loops;

    // Find backedges (edge n -> h where h dominates n)
    for (size_t i = 0; i < blocks.size(); i++) {
        for (int succ : blocks[i].successors) {
            // Check if successor dominates this block (backedge)
            if (dominates(succ, i, blocks)) {
                // Found a backedge from i to succ
                // succ is the loop header

                // Check if we already have a loop with this header
                loop_info_t *existing = nullptr;
                for (auto &loop : loops) {
                    if (loop.header == succ) {
                        existing = &loop;
                        break;
                    }
                }

                if (existing) {
                    existing->backedges.push_back(i);
                } else {
                    loop_info_t loop;
                    loop.header = succ;
                    loop.backedges.push_back(i);
                    loops.push_back(loop);
                }
            }
        }
    }

    // For each loop, find all blocks in the body
    for (auto &loop : loops) {
        loop.body.insert(loop.header);

        // Use worklist to find all blocks that reach backedge sources
        std::vector<int> worklist = loop.backedges;
        while (!worklist.empty()) {
            int blk = worklist.back();
            worklist.pop_back();

            if (loop.body.count(blk))
                continue;

            loop.body.insert(blk);

            // Add predecessors to worklist
            for (int pred : blocks[blk].predecessors) {
                if (!loop.body.count(pred)) {
                    worklist.push_back(pred);
                }
            }
        }

        // Find exit blocks (blocks in loop with successor outside loop)
        for (int blk : loop.body) {
            for (int succ : blocks[blk].successors) {
                if (!loop.body.count(succ)) {
                    loop.exits.push_back(blk);
                    break;
                }
            }
        }
    }

    return loops;
}

//--------------------------------------------------------------------------
// Check if A dominates B
//--------------------------------------------------------------------------
bool dominates(int a, int b, const std::vector<block_info_t> &blocks) {
    if (a == b)
        return true;

    // Walk up dominator tree from b
    int curr = b;
    while (curr >= 0 && curr < (int)blocks.size()) {
        if (blocks[curr].dominator == a)
            return true;
        if (blocks[curr].dominator == curr || blocks[curr].dominator < 0)
            break;
        curr = blocks[curr].dominator;
    }

    return false;
}

//--------------------------------------------------------------------------
// Get all reachable blocks
//--------------------------------------------------------------------------
std::set<int> get_reachable(int from, mbl_array_t *mba) {
    std::set<int> reachable;

    if (!mba || from < 0 || from >= mba->qty)
        return reachable;

    std::vector<int> worklist;
    worklist.push_back(from);

    while (!worklist.empty()) {
        int curr = worklist.back();
        worklist.pop_back();

        if (reachable.count(curr))
            continue;

        reachable.insert(curr);

        mblock_t *blk = mba->get_mblock(curr);
        if (!blk)
            continue;

        for (int i = 0; i < blk->nsucc(); i++) {
            int succ = blk->succ(i);
            if (succ >= 0 && !reachable.count(succ)) {
                worklist.push_back(succ);
            }
        }
    }

    return reachable;
}

//--------------------------------------------------------------------------
// Get all blocks that can reach target
//--------------------------------------------------------------------------
std::set<int> get_reaching(int to, mbl_array_t *mba) {
    std::set<int> reaching;

    if (!mba || to < 0 || to >= mba->qty)
        return reaching;

    // Build predecessor map
    std::vector<std::vector<int>> preds(mba->qty);
    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (int j = 0; j < blk->nsucc(); j++) {
            int succ = blk->succ(j);
            if (succ >= 0 && succ < mba->qty) {
                preds[succ].push_back(i);
            }
        }
    }

    // BFS backwards from target
    std::vector<int> worklist;
    worklist.push_back(to);

    while (!worklist.empty()) {
        int curr = worklist.back();
        worklist.pop_back();

        if (reaching.count(curr))
            continue;

        reaching.insert(curr);

        for (int pred : preds[curr]) {
            if (!reaching.count(pred)) {
                worklist.push_back(pred);
            }
        }
    }

    return reaching;
}

//--------------------------------------------------------------------------
// Find dispatcher block (for control flow flattening)
//--------------------------------------------------------------------------
int find_dispatcher_block(mbl_array_t *mba) {
    if (!mba)
        return -1;

    // The dispatcher block typically:
    // 1. Has many successors (one per case)
    // 2. Contains a switch/jtbl instruction or many conditional jumps
    // 3. Is part of a loop (has backedges to it)

    int best_candidate = -1;
    int max_succs = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t *blk = mba->get_mblock(i);
        if (!blk)
            continue;

        int nsucc = blk->nsucc();

        // Look for jtbl instruction
        if (blk->tail && blk->tail->opcode == m_jtbl) {
            return i;  // Definitely the dispatcher
        }

        // Count conditional jumps
        int jcc_count = 0;
        for (minsn_t *ins = blk->head; ins; ins = ins->next) {
            if (deobf::is_jcc(ins->opcode))
                jcc_count++;
        }

        // Block with many conditional jumps is likely dispatcher
        if (jcc_count >= 3 && jcc_count > max_succs) {
            max_succs = jcc_count;
            best_candidate = i;
        }

        // Block with many successors is likely dispatcher
        if (nsucc > 3 && nsucc > max_succs) {
            max_succs = nsucc;
            best_candidate = i;
        }
    }

    return best_candidate;
}

//--------------------------------------------------------------------------
// Find backedge targets
//--------------------------------------------------------------------------
std::vector<int> find_backedge_targets(mbl_array_t *mba) {
    std::vector<int> targets;

    if (!mba)
        return targets;

    auto blocks = analyze_cfg(mba);

    for (size_t i = 0; i < blocks.size(); i++) {
        for (int succ : blocks[i].successors) {
            if (dominates(succ, i, blocks)) {
                // Found backedge to succ
                if (std::find(targets.begin(), targets.end(), succ) == targets.end()) {
                    targets.push_back(succ);
                }
            }
        }
    }

    return targets;
}

//--------------------------------------------------------------------------
// Check if block is dead
//--------------------------------------------------------------------------
bool is_dead_block(mblock_t *blk, mbl_array_t *mba, deobf_ctx_t *ctx) {
    if (!blk || !mba)
        return false;

    // Check if block has no predecessors (except entry block)
    int blk_idx = blk->serial;
    if (blk_idx != 0 && blk->npred() == 0)
        return true;

    // Check if all incoming branches are always-false
    // This would require analyzing the conditions at predecessor blocks

    return false;
}

//--------------------------------------------------------------------------
// Get branch condition for edge
//--------------------------------------------------------------------------
minsn_t *get_branch_condition(int from_blk, int to_blk, mbl_array_t *mba) {
    if (!mba)
        return nullptr;

    mblock_t *blk = mba->get_mblock(from_blk);
    if (!blk || !blk->tail)
        return nullptr;

    minsn_t *tail = blk->tail;

    // Unconditional jump - no condition
    if (tail->opcode == m_goto)
        return nullptr;

    // Conditional jump
    if (deobf::is_jcc(tail->opcode)) {
        // Check if this jump goes to to_blk
        if (tail->d.t == mop_b && tail->d.b == to_blk) {
            return tail;
        }
    }

    return nullptr;
}

} // namespace cfg_analysis
