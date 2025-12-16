#include "unflattener_base.h"

namespace chernobog {

//--------------------------------------------------------------------------
// Z3StateSolver Implementation
//--------------------------------------------------------------------------

Z3StateSolver::Z3StateSolver(z3_solver::z3_context_t& ctx)
    : ctx_(ctx), translator_(ctx) {
}

void Z3StateSolver::set_timeout(unsigned ms) {
    timeout_ms_ = ms;
    ctx_.set_timeout(ms);
}

void Z3StateSolver::reset() {
    ctx_.reset();
    translator_.reset();
    transition_cache_.clear();
}

std::vector<StateVariable> Z3StateSolver::find_state_variables(mbl_array_t* mba) {
    std::vector<StateVariable> candidates;

    if (!mba)
        return candidates;

    // Look for variables that:
    // 1. Are compared against multiple large constants
    // 2. Are written in multiple blocks
    // 3. Control conditional jumps

    std::map<uint64_t, int> var_compare_count;  // var_id -> count of comparisons
    std::map<uint64_t, std::set<uint64_t>> var_constants;  // var_id -> constants compared against

    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            // Look for conditional jumps comparing against constants
            if (is_mcode_jcond(ins->opcode)) {
                minsn_t* cond = (ins->l.t == mop_d) ? ins->l.d : nullptr;
                if (!cond)
                    continue;

                // Check for comparison with constant
                const mop_t* var_op = nullptr;
                uint64_t const_val = 0;

                if (cond->r.t == mop_n && cond->r.nnn) {
                    var_op = &cond->l;
                    const_val = cond->r.nnn->value;
                } else if (cond->l.t == mop_n && cond->l.nnn) {
                    var_op = &cond->r;
                    const_val = cond->l.nnn->value;
                }

                if (var_op && UnflattenerBase::is_state_constant(const_val)) {
                    // Create a key for this variable
                    uint64_t var_key = 0;
                    if (var_op->t == mop_S && var_op->s) {
                        var_key = (1ULL << 60) | var_op->s->off;
                    } else if (var_op->t == mop_v) {
                        var_key = (2ULL << 60) | var_op->g;
                    } else if (var_op->t == mop_r) {
                        var_key = (3ULL << 60) | var_op->r;
                    }

                    if (var_key != 0) {
                        var_compare_count[var_key]++;
                        var_constants[var_key].insert(const_val);
                    }
                }
            }
        }
    }

    // Find variables compared against multiple state constants
    for (auto& [var_key, count] : var_compare_count) {
        if (count >= 2 && var_constants[var_key].size() >= 2) {
            StateVariable sv;

            if ((var_key >> 60) == 1) {
                // Stack variable
                sv.is_stack = true;
                sv.stack_offset = var_key & ((1ULL << 60) - 1);
                sv.size = 4;  // Assume 4 bytes
            } else if ((var_key >> 60) == 2) {
                // Global variable
                sv.is_global = true;
                sv.global_addr = var_key & ((1ULL << 60) - 1);
                sv.size = 4;
            }

            if (sv.is_stack || sv.is_global) {
                candidates.push_back(sv);
            }
        }
    }

    return candidates;
}

bool Z3StateSolver::verify_state_variable(mbl_array_t* mba, const StateVariable& var) {
    if (!mba || !var.is_valid())
        return false;

    // Count how many blocks write to this variable
    int write_count = 0;
    int read_count = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        bool has_write = false;
        bool has_read = false;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            // Check for writes
            if (ins->opcode == m_mov || ins->opcode == m_stx) {
                if (var.is_stack && ins->d.t == mop_S && ins->d.s &&
                    ins->d.s->off == var.stack_offset) {
                    has_write = true;
                }
                if (var.is_global && ins->d.t == mop_v &&
                    ins->d.g == var.global_addr) {
                    has_write = true;
                }
            }

            // Check for reads (in conditions)
            if (is_mcode_jcond(ins->opcode)) {
                auto check_op = [&](const mop_t& op) {
                    if (var.is_stack && op.t == mop_S && op.s &&
                        op.s->off == var.stack_offset) {
                        has_read = true;
                    }
                    if (var.is_global && op.t == mop_v &&
                        op.g == var.global_addr) {
                        has_read = true;
                    }
                };
                check_op(ins->l);
                check_op(ins->r);
            }
        }

        if (has_write) write_count++;
        if (has_read) read_count++;
    }

    // A valid state variable should be written in multiple blocks
    // and read in the dispatcher
    return write_count >= 2 && read_count >= 1;
}

std::optional<uint64_t> Z3StateSolver::find_state_write(mblock_t* blk,
                                                         const StateVariable& var) {
    if (!blk || !var.is_valid())
        return std::nullopt;

    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov)
            continue;

        // Check if destination matches state variable
        bool matches = false;
        if (var.is_stack && ins->d.t == mop_S && ins->d.s &&
            ins->d.s->off == var.stack_offset) {
            matches = true;
        }
        if (var.is_global && ins->d.t == mop_v &&
            ins->d.g == var.global_addr) {
            matches = true;
        }

        if (matches && ins->l.t == mop_n && ins->l.nnn) {
            return ins->l.nnn->value;
        }
    }

    return std::nullopt;
}

bool Z3StateSolver::analyze_dispatcher(mbl_array_t* mba, int block_idx,
                                        const StateVariable& var,
                                        DispatcherBlock* out) {
    if (!mba || block_idx < 0 || block_idx >= mba->qty || !out)
        return false;

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk)
        return false;

    out->block_idx = block_idx;
    out->start_addr = blk->start;
    out->state_var = var;

    // Find all state comparisons in this block and its chain
    std::set<int> visited;
    std::queue<int> to_visit;
    to_visit.push(block_idx);

    while (!to_visit.empty()) {
        int curr = to_visit.front();
        to_visit.pop();

        if (visited.count(curr))
            continue;
        visited.insert(curr);

        mblock_t* curr_blk = mba->get_mblock(curr);
        if (!curr_blk)
            continue;

        // Check for state comparisons
        for (minsn_t* ins = curr_blk->head; ins; ins = ins->next) {
            if (!is_mcode_jcond(ins->opcode))
                continue;

            minsn_t* cond = (ins->l.t == mop_d) ? ins->l.d : nullptr;
            if (!cond)
                continue;

            // Look for comparison with state constant
            uint64_t const_val = 0;
            bool found = false;

            if (cond->r.t == mop_n && cond->r.nnn) {
                const_val = cond->r.nnn->value;
                found = true;
            } else if (cond->l.t == mop_n && cond->l.nnn) {
                const_val = cond->l.nnn->value;
                found = true;
            }

            if (found && UnflattenerBase::is_state_constant(const_val)) {
                // This is a state comparison - target block is a case block
                int target = (ins->d.t == mop_b) ? ins->d.b : -1;
                if (target >= 0) {
                    out->state_to_block[const_val] = target;
                    out->case_blocks.insert(target);
                }
            }
        }

        out->dispatcher_chain.insert(curr);

        // Follow fall-through to find chained dispatcher blocks
        if (curr_blk->tail && curr_blk->tail->opcode == m_goto &&
            curr_blk->tail->l.t == mop_b) {
            int fall = curr_blk->tail->l.b;
            if (!visited.count(fall)) {
                to_visit.push(fall);
            }
        }
    }

    out->is_analyzed = true;
    out->is_solvable = !out->state_to_block.empty();

    return out->is_solvable;
}

bool Z3StateSolver::build_state_map(mbl_array_t* mba, DispatcherBlock* disp) {
    return analyze_dispatcher(mba, disp->block_idx, disp->state_var, disp);
}

std::vector<StateTransition> Z3StateSolver::analyze_block_transitions(
    mbl_array_t* mba, int block_idx, const StateVariable& var) {

    std::vector<StateTransition> transitions;

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return transitions;

    // Check cache
    if (transition_cache_.count(block_idx)) {
        return transition_cache_[block_idx];
    }

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk)
        return transitions;

    // Find state writes in this block
    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov)
            continue;

        bool is_state_write = false;
        if (var.is_stack && ins->d.t == mop_S && ins->d.s &&
            ins->d.s->off == var.stack_offset) {
            is_state_write = true;
        }
        if (var.is_global && ins->d.t == mop_v &&
            ins->d.g == var.global_addr) {
            is_state_write = true;
        }

        if (is_state_write && ins->l.t == mop_n && ins->l.nnn) {
            StateTransition trans;
            trans.from_block = block_idx;
            trans.to_state = ins->l.nnn->value;
            trans.transition_addr = ins->ea;
            transitions.push_back(trans);
        }
    }

    // Check for conditional state writes
    auto conditional = analyze_conditional_writes(mba, block_idx, var);
    transitions.insert(transitions.end(), conditional.begin(), conditional.end());

    transition_cache_[block_idx] = transitions;
    return transitions;
}

std::optional<uint64_t> Z3StateSolver::solve_written_state(
    mbl_array_t* mba, int block_idx, const StateVariable& var) {

    auto transitions = analyze_block_transitions(mba, block_idx, var);
    if (transitions.empty())
        return std::nullopt;

    // Return first unconditional transition
    for (auto& t : transitions) {
        if (!t.is_conditional) {
            return t.to_state;
        }
    }

    return std::nullopt;
}

std::vector<StateTransition> Z3StateSolver::analyze_conditional_writes(
    mbl_array_t* mba, int block_idx, const StateVariable& var) {

    std::vector<StateTransition> transitions;

    if (!mba || block_idx < 0 || block_idx >= mba->qty)
        return transitions;

    mblock_t* blk = mba->get_mblock(block_idx);
    if (!blk || !blk->tail)
        return transitions;

    // Check if block ends with a conditional jump
    if (!is_mcode_jcond(blk->tail->opcode))
        return transitions;

    // Get true and false targets
    int true_target = (blk->tail->d.t == mop_b) ? blk->tail->d.b : -1;
    int false_target = -1;

    // Fall-through is the false target
    for (int i = 0; i < blk->nsucc(); i++) {
        int succ = blk->succ(i);
        if (succ != true_target) {
            false_target = succ;
            break;
        }
    }

    // Analyze both branches for state writes
    if (true_target >= 0) {
        auto state = find_state_write(mba->get_mblock(true_target), var);
        if (state.has_value()) {
            StateTransition trans;
            trans.from_block = block_idx;
            trans.to_state = state.value();
            trans.is_conditional = true;
            trans.is_true_branch = true;
            transitions.push_back(trans);
        }
    }

    if (false_target >= 0) {
        auto state = find_state_write(mba->get_mblock(false_target), var);
        if (state.has_value()) {
            StateTransition trans;
            trans.from_block = block_idx;
            trans.to_state = state.value();
            trans.is_conditional = true;
            trans.is_true_branch = false;
            transitions.push_back(trans);
        }
    }

    return transitions;
}

z3::expr Z3StateSolver::state_to_z3(const StateVariable& var) {
    // Create a symbolic variable for the state
    std::string name = "state_";
    if (var.is_stack) {
        name += "stack_" + std::to_string(var.stack_offset);
    } else if (var.is_global) {
        name += "global_" + std::to_string(var.global_addr);
    } else {
        name += "unknown";
    }

    return ctx_.ctx().bv_const(name.c_str(), var.size * 8);
}

std::optional<uint64_t> Z3StateSolver::solve_constant(const z3::expr& expr, int bits) {
    try {
        z3::solver& s = ctx_.solver();
        s.reset();

        // Create a variable for the result
        z3::expr result = ctx_.ctx().bv_const("result", bits);

        // Assert that expr == result
        s.add(expr == result);

        if (s.check() == z3::sat) {
            z3::model m = s.get_model();
            z3::expr val = m.eval(result, true);
            if (val.is_numeral()) {
                return val.as_uint64();
            }
        }
    } catch (...) {
        // Z3 error
    }

    return std::nullopt;
}

bool Z3StateSolver::is_constant_expr(const z3::expr& expr, int bits) {
    try {
        z3::solver& s = ctx_.solver();
        s.reset();

        // Create two different values and check if expr can differ
        z3::expr v1 = ctx_.ctx().bv_const("v1", bits);
        z3::expr v2 = ctx_.ctx().bv_const("v2", bits);

        // If expr depends on any variable, it should be able to take different values
        // This is a simplified check - full check would enumerate all variables

        z3::expr_vector vars(ctx_.ctx());
        // ... would need to extract variables from expr

        // For now, use simplification
        z3::expr simplified = expr.simplify();
        return simplified.is_numeral();
    } catch (...) {
        return false;
    }
}

z3_solver::sat_result_t Z3StateSolver::check_sat(const z3::expr& constraint) {
    try {
        z3::solver& s = ctx_.solver();
        s.reset();
        s.add(constraint);

        switch (s.check()) {
            case z3::sat:   return z3_solver::sat_result_t::SAT;
            case z3::unsat: return z3_solver::sat_result_t::UNSAT;
            default:        return z3_solver::sat_result_t::UNKNOWN;
        }
    } catch (...) {
        return z3_solver::sat_result_t::UNKNOWN;
    }
}

//--------------------------------------------------------------------------
// UnflattenerBase Implementation
//--------------------------------------------------------------------------

UnflattenerBase::UnflattenerBase() {
}

void UnflattenerBase::reset() {
    analysis_complete_ = false;
    dispatchers_.clear();
    transitions_.clear();
    primary_state_var_ = StateVariable();
    if (solver_) {
        solver_->reset();
    }
}

void UnflattenerBase::reset_statistics() {
    functions_unflattened_ = 0;
    edges_recovered_ = 0;
    dispatchers_eliminated_ = 0;
}

Z3StateSolver& UnflattenerBase::solver() {
    if (!solver_) {
        solver_ = std::make_unique<Z3StateSolver>(z3_solver::get_global_context());
    }
    return *solver_;
}

bool UnflattenerBase::is_state_constant(uint64_t val) {
    return is_hikari_constant(val) || is_ollvm_constant(val);
}

bool UnflattenerBase::is_hikari_constant(uint64_t val) {
    // Hikari uses constants like 0xAAAAxxxx, 0xBBBBxxxx, 0xDEADxxxx, etc.
    if (val < 0x10000000 || val > 0xFFFFFFFF)
        return false;

    uint32_t high = (val >> 16) & 0xFFFF;
    switch (high) {
        case 0xAAAA: case 0xBBBB: case 0xCCCC: case 0xDDDD:
        case 0xEEEE: case 0xFFFF:
        case 0xBEEF: case 0xCAFE: case 0xDEAD: case 0xFACE:
        case 0xFEED: case 0xBABE: case 0xC0DE: case 0xD00D:
            return true;
        default:
            return false;
    }
}

bool UnflattenerBase::is_ollvm_constant(uint64_t val) {
    // O-LLVM uses sequential integers or random-looking constants
    // This is a heuristic - O-LLVM constants are often in reasonable ranges
    if (val >= 0x10000000 && val <= 0xFFFFFFFF) {
        // Could be a large constant used as state
        return true;
    }
    // Small sequential integers (0, 1, 2, ...) are also used
    if (val < 1000) {
        return true;
    }
    return false;
}

std::set<uint64_t> UnflattenerBase::find_constants_in_block(const mblock_t* blk) {
    std::set<uint64_t> constants;

    if (!blk)
        return constants;

    for (const minsn_t* ins = blk->head; ins; ins = ins->next) {
        auto check_op = [&](const mop_t& op) {
            if (op.t == mop_n && op.nnn) {
                uint64_t val = op.nnn->value;
                if (is_state_constant(val)) {
                    constants.insert(val);
                }
            }
        };

        check_op(ins->l);
        check_op(ins->r);
        check_op(ins->d);

        // Check nested instructions
        if (ins->l.t == mop_d && ins->l.d) {
            check_op(ins->l.d->l);
            check_op(ins->l.d->r);
        }
    }

    return constants;
}

bool UnflattenerBase::redirect_edge(mbl_array_t* mba, int from_block,
                                     int old_target, int new_target) {
    if (!mba || from_block < 0 || from_block >= mba->qty ||
        new_target < 0 || new_target >= mba->qty)
        return false;

    mblock_t* src = mba->get_mblock(from_block);
    mblock_t* dst = mba->get_mblock(new_target);
    if (!src || !dst)
        return false;

    // Update the instruction target
    minsn_t* tail = src->tail;
    if (!tail)
        return false;

    if (tail->opcode == m_goto) {
        tail->l.make_blkref(new_target);
    } else if (is_mcode_jcond(tail->opcode)) {
        if (tail->d.t == mop_b && tail->d.b == old_target) {
            tail->d.make_blkref(new_target);
        }
    }

    // Update successor list
    for (auto& succ : src->succset) {
        if (succ == old_target) {
            succ = new_target;
            break;
        }
    }

    // Update predecessor lists
    if (old_target >= 0 && old_target < mba->qty) {
        mblock_t* old_dst = mba->get_mblock(old_target);
        if (old_dst) {
            auto it = std::find(old_dst->predset.begin(),
                               old_dst->predset.end(), from_block);
            if (it != old_dst->predset.end()) {
                old_dst->predset.erase(it);
            }
            old_dst->mark_lists_dirty();
        }
    }

    auto it = std::find(dst->predset.begin(), dst->predset.end(), from_block);
    if (it == dst->predset.end()) {
        dst->predset.push_back(from_block);
    }

    src->mark_lists_dirty();
    dst->mark_lists_dirty();

    return true;
}

bool UnflattenerBase::convert_to_goto(mblock_t* blk, int target_block) {
    if (!blk || !blk->tail)
        return false;

    minsn_t* tail = blk->tail;
    ea_t orig_ea = tail->ea;

    // Convert to goto
    tail->opcode = m_goto;
    tail->l.make_blkref(target_block);
    tail->r.erase();
    tail->d.erase();
    tail->ea = orig_ea;

    blk->type = BLT_1WAY;
    blk->mark_lists_dirty();

    return true;
}

bool UnflattenerBase::convert_to_nop(mblock_t* blk, minsn_t* ins) {
    if (!blk || !ins)
        return false;

    ea_t orig_ea = ins->ea;

    ins->opcode = m_nop;
    ins->l.erase();
    ins->r.erase();
    ins->d.erase();
    ins->ea = orig_ea;

    blk->mark_lists_dirty();

    return true;
}

bool UnflattenerBase::remove_dead_stores(mblock_t* blk, const StateVariable& var) {
    if (!blk || !var.is_valid())
        return false;

    bool removed_any = false;

    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (ins->opcode != m_mov)
            continue;

        bool is_state_write = false;
        if (var.is_stack && ins->d.t == mop_S && ins->d.s &&
            ins->d.s->off == var.stack_offset) {
            is_state_write = true;
        }
        if (var.is_global && ins->d.t == mop_v &&
            ins->d.g == var.global_addr) {
            is_state_write = true;
        }

        if (is_state_write) {
            convert_to_nop(blk, ins);
            removed_any = true;
        }
    }

    return removed_any;
}

bool UnflattenerBase::is_exit_block(const mblock_t* blk) {
    if (!blk || !blk->tail)
        return false;

    return blk->tail->opcode == m_ret || blk->type == BLT_STOP;
}

bool UnflattenerBase::is_return_block(const mblock_t* blk) {
    if (!blk || !blk->tail)
        return false;

    return blk->tail->opcode == m_ret;
}

std::vector<int> UnflattenerBase::get_successors(const mblock_t* blk) {
    std::vector<int> succs;
    if (!blk)
        return succs;

    for (int i = 0; i < blk->nsucc(); i++) {
        succs.push_back(blk->succ(i));
    }
    return succs;
}

std::vector<int> UnflattenerBase::get_predecessors(const mblock_t* blk) {
    std::vector<int> preds;
    if (!blk)
        return preds;

    for (int i = 0; i < blk->npred(); i++) {
        preds.push_back(blk->pred(i));
    }
    return preds;
}

int UnflattenerBase::count_state_comparisons(const mblock_t* blk) {
    int count = 0;

    if (!blk)
        return count;

    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (!is_mcode_jcond(ins->opcode))
            continue;

        minsn_t* cond = (ins->l.t == mop_d) ? ins->l.d : nullptr;
        if (!cond)
            continue;

        // Check for comparison with state constant
        if (cond->r.t == mop_n && cond->r.nnn &&
            is_state_constant(cond->r.nnn->value)) {
            count++;
        } else if (cond->l.t == mop_n && cond->l.nnn &&
                   is_state_constant(cond->l.nnn->value)) {
            count++;
        }
    }

    return count;
}

bool UnflattenerBase::has_state_variable_read(const mblock_t* blk,
                                               const StateVariable& var) {
    if (!blk || !var.is_valid())
        return false;

    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        auto check_op = [&](const mop_t& op) -> bool {
            if (var.is_stack && op.t == mop_S && op.s &&
                op.s->off == var.stack_offset) {
                return true;
            }
            if (var.is_global && op.t == mop_v &&
                op.g == var.global_addr) {
                return true;
            }
            return false;
        };

        if (check_op(ins->l) || check_op(ins->r))
            return true;

        // Check nested instructions
        if (ins->l.t == mop_d && ins->l.d) {
            if (check_op(ins->l.d->l) || check_op(ins->l.d->r))
                return true;
        }
    }

    return false;
}

//--------------------------------------------------------------------------
// UnflattenerRegistry Implementation
//--------------------------------------------------------------------------

UnflattenerRegistry& UnflattenerRegistry::instance() {
    static UnflattenerRegistry inst;
    return inst;
}

void UnflattenerRegistry::register_unflattener(
    std::unique_ptr<UnflattenerBase> unflattener) {
    unflatteners_.push_back(std::move(unflattener));

    // Sort by priority (descending)
    std::sort(unflatteners_.begin(), unflatteners_.end(),
              [](const auto& a, const auto& b) {
                  return a->priority() > b->priority();
              });
}

void UnflattenerRegistry::initialize() {
    if (initialized_)
        return;

    unflatteners_.clear();

    // Register built-in unflatteners
    register_unflattener(std::make_unique<HikariUnflattener>());
    register_unflattener(std::make_unique<OLLVMUnflattener>());
    register_unflattener(std::make_unique<JumpTableUnflattener>());
    register_unflattener(std::make_unique<GenericUnflattener>());

    initialized_ = true;
    msg("[chernobog] Unflattener registry initialized (%zu unflatteners)\n",
        unflatteners_.size());
}

UnflattenerBase* UnflattenerRegistry::find_best_match(mbl_array_t* mba) {
    if (!initialized_)
        initialize();

    UnflattenerBase* best = nullptr;
    int best_score = 0;

    for (auto& unflattener : unflatteners_) {
        int score = unflattener->detect(mba);
        if (score > best_score) {
            best_score = score;
            best = unflattener.get();
        }
    }

    return best;
}

UnflattenResult UnflattenerRegistry::unflatten(mbl_array_t* mba, deobf_ctx_t* ctx) {
    UnflattenResult result;

    if (!initialized_)
        initialize();

    UnflattenerBase* unflattener = find_best_match(mba);
    if (!unflattener) {
        result.error_message = "No matching unflattener found";
        return result;
    }

    deobf::log_verbose("[Unflatten] Using %s\n", unflattener->name());

    // Analyze
    if (!unflattener->analyze(mba, ctx)) {
        result.error_message = "Analysis failed";
        return result;
    }

    // Apply
    result = unflattener->apply(mba, ctx);

    if (result.success) {
        unflattener->cleanup(mba, ctx);
    }

    return result;
}

void UnflattenerRegistry::dump_statistics() {
    msg("[chernobog] Unflattener Statistics:\n");
    for (auto& unflattener : unflatteners_) {
        if (unflattener->functions_unflattened() > 0) {
            msg("  %s: %zu functions, %zu edges, %zu dispatchers\n",
                unflattener->name(),
                unflattener->functions_unflattened(),
                unflattener->edges_recovered(),
                unflattener->dispatchers_eliminated());
        }
    }
}

void UnflattenerRegistry::reset_statistics() {
    for (auto& unflattener : unflatteners_) {
        unflattener->reset_statistics();
    }
}

//--------------------------------------------------------------------------
// HikariUnflattener Implementation (delegates to existing deflatten_handler_t)
//--------------------------------------------------------------------------

int HikariUnflattener::detect(mbl_array_t* mba) {
    if (!mba)
        return 0;

    int score = 0;

    // Look for Hikari-style state constants
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        auto constants = find_constants_in_block(blk);
        for (uint64_t c : constants) {
            if (is_hikari_constant(c)) {
                score += 20;
            }
        }

        // Bonus for dispatcher-like blocks
        int state_cmp = count_state_comparisons(blk);
        if (state_cmp >= 2) {
            score += state_cmp * 10;
        }
    }

    return std::min(score, 100);
}

bool HikariUnflattener::analyze(mbl_array_t* mba, deobf_ctx_t* ctx) {
    // Find state variables
    auto candidates = solver().find_state_variables(mba);
    if (candidates.empty())
        return false;

    // Verify and select primary state variable
    for (auto& var : candidates) {
        if (solver().verify_state_variable(mba, var)) {
            primary_state_var_ = var;
            break;
        }
    }

    if (!primary_state_var_.is_valid())
        return false;

    // Find dispatchers
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        if (count_state_comparisons(blk) >= 2) {
            DispatcherBlock disp;
            if (solver().analyze_dispatcher(mba, i, primary_state_var_, &disp)) {
                dispatchers_.push_back(disp);
            }
        }
    }

    if (dispatchers_.empty())
        return false;

    // Analyze transitions for each case block
    for (auto& disp : dispatchers_) {
        for (int case_blk : disp.case_blocks) {
            auto trans = solver().analyze_block_transitions(mba, case_blk,
                                                            primary_state_var_);
            transitions_.insert(transitions_.end(), trans.begin(), trans.end());
        }
    }

    analysis_complete_ = true;
    return true;
}

UnflattenResult HikariUnflattener::apply(mbl_array_t* mba, deobf_ctx_t* ctx) {
    UnflattenResult result;

    if (!analysis_complete_) {
        result.error_message = "Analysis not complete";
        return result;
    }

    // For each transition, redirect the edge
    for (auto& trans : transitions_) {
        if (trans.to_state == 0)
            continue;

        // Find target block for this state
        int target = -1;
        for (auto& disp : dispatchers_) {
            auto it = disp.state_to_block.find(trans.to_state);
            if (it != disp.state_to_block.end()) {
                target = it->second;
                break;
            }
        }

        if (target < 0)
            continue;

        // Find the goto instruction in the source block
        mblock_t* src = mba->get_mblock(trans.from_block);
        if (!src || !src->tail)
            continue;

        if (src->tail->opcode == m_goto) {
            // Get current target (dispatcher)
            int old_target = (src->tail->l.t == mop_b) ? src->tail->l.b : -1;

            if (redirect_edge(mba, trans.from_block, old_target, target)) {
                result.edges_recovered++;
            }
        }
    }

    // Remove state variable assignments
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (blk && remove_dead_stores(blk, primary_state_var_)) {
            result.blocks_modified++;
        }
    }

    result.success = result.edges_recovered > 0;
    result.transitions = transitions_;
    result.dispatchers_eliminated = dispatchers_.size();

    if (result.success) {
        functions_unflattened_++;
        edges_recovered_ += result.edges_recovered;
        dispatchers_eliminated_ += result.dispatchers_eliminated;
    }

    return result;
}

//--------------------------------------------------------------------------
// OLLVMUnflattener Implementation
//--------------------------------------------------------------------------

int OLLVMUnflattener::detect(mbl_array_t* mba) {
    if (!mba)
        return 0;

    int score = 0;

    // O-LLVM patterns:
    // 1. Switch statement in a loop
    // 2. Prologue that initializes state variable
    // 3. State variable comparisons in switch

    if (detect_switch_dispatcher(mba)) {
        score += 50;
    }

    if (detect_prologue_pattern(mba)) {
        score += 30;
    }

    return std::min(score, 100);
}

bool OLLVMUnflattener::detect_switch_dispatcher(mbl_array_t* mba) {
    // Look for m_jtbl instructions
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_jtbl) {
                return true;
            }
        }
    }
    return false;
}

bool OLLVMUnflattener::detect_prologue_pattern(mbl_array_t* mba) {
    // O-LLVM typically initializes state in block 0
    if (mba->qty < 2)
        return false;

    mblock_t* entry = mba->get_mblock(0);
    if (!entry)
        return false;

    // Look for state initialization followed by goto
    for (minsn_t* ins = entry->head; ins; ins = ins->next) {
        if (ins->opcode == m_mov && ins->l.t == mop_n && ins->l.nnn) {
            // Found a constant assignment
            return true;
        }
    }

    return false;
}

bool OLLVMUnflattener::analyze(mbl_array_t* mba, deobf_ctx_t* ctx) {
    // Similar to Hikari but with O-LLVM specific patterns
    auto candidates = solver().find_state_variables(mba);

    for (auto& var : candidates) {
        if (solver().verify_state_variable(mba, var)) {
            primary_state_var_ = var;
            break;
        }
    }

    if (!primary_state_var_.is_valid())
        return false;

    // Find switch-based dispatcher
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        // Look for jtbl or cascading comparisons
        bool has_jtbl = false;
        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode == m_jtbl) {
                has_jtbl = true;
                break;
            }
        }

        if (has_jtbl || count_state_comparisons(blk) >= 2) {
            DispatcherBlock disp;
            if (solver().analyze_dispatcher(mba, i, primary_state_var_, &disp)) {
                dispatchers_.push_back(disp);
            }
        }
    }

    if (dispatchers_.empty())
        return false;

    // Analyze transitions
    for (auto& disp : dispatchers_) {
        for (int case_blk : disp.case_blocks) {
            auto trans = solver().analyze_block_transitions(mba, case_blk,
                                                            primary_state_var_);
            transitions_.insert(transitions_.end(), trans.begin(), trans.end());
        }
    }

    analysis_complete_ = true;
    return true;
}

UnflattenResult OLLVMUnflattener::apply(mbl_array_t* mba, deobf_ctx_t* ctx) {
    // Same application logic as Hikari - implemented inline
    UnflattenResult result;

    if (!analysis_complete_) {
        result.error_message = "Analysis not complete";
        return result;
    }

    // For each transition, redirect the edge
    for (auto& trans : transitions_) {
        if (trans.to_state == 0)
            continue;

        // Find target block for this state
        int target = -1;
        for (auto& disp : dispatchers_) {
            auto it = disp.state_to_block.find(trans.to_state);
            if (it != disp.state_to_block.end()) {
                target = it->second;
                break;
            }
        }

        if (target < 0)
            continue;

        // Find the goto instruction in the source block
        mblock_t* src = mba->get_mblock(trans.from_block);
        if (!src || !src->tail)
            continue;

        if (src->tail->opcode == m_goto) {
            // Get current target (dispatcher)
            int old_target = (src->tail->l.t == mop_b) ? src->tail->l.b : -1;

            if (redirect_edge(mba, trans.from_block, old_target, target)) {
                result.edges_recovered++;
            }
        }
    }

    // Remove state variable assignments
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (blk && remove_dead_stores(blk, primary_state_var_)) {
            result.blocks_modified++;
        }
    }

    result.success = result.edges_recovered > 0;
    result.transitions = transitions_;
    result.dispatchers_eliminated = dispatchers_.size();

    if (result.success) {
        functions_unflattened_++;
        edges_recovered_ += result.edges_recovered;
        dispatchers_eliminated_ += result.dispatchers_eliminated;
    }

    return result;
}

//--------------------------------------------------------------------------
// GenericUnflattener Implementation
//--------------------------------------------------------------------------

int GenericUnflattener::detect(mbl_array_t* mba) {
    if (!mba)
        return 0;

    int score = 0;

    // Generic heuristics:
    // 1. Look for blocks with many conditional jumps
    // 2. Look for variables compared against many constants
    // 3. Look for loop-like structures with state variable

    int max_comparisons = 0;
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (blk) {
            int cmp = score_as_dispatcher(blk);
            max_comparisons = std::max(max_comparisons, cmp);
        }
    }

    if (max_comparisons >= 3) {
        score = max_comparisons * 10;
    }

    return std::min(score, 100);
}

int GenericUnflattener::score_as_dispatcher(const mblock_t* blk) {
    if (!blk)
        return 0;

    int score = 0;

    // Count conditional jumps
    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        if (is_mcode_jcond(ins->opcode)) {
            score++;
        }
    }

    // Bonus for comparing against constants
    auto constants = find_constants_in_block(blk);
    score += constants.size();

    return score;
}

bool GenericUnflattener::detect_state_variable_generic(mbl_array_t* mba) {
    auto candidates = solver().find_state_variables(mba);
    for (auto& var : candidates) {
        if (solver().verify_state_variable(mba, var)) {
            primary_state_var_ = var;
            return true;
        }
    }
    return false;
}

bool GenericUnflattener::analyze(mbl_array_t* mba, deobf_ctx_t* ctx) {
    if (!detect_state_variable_generic(mba))
        return false;

    // Find potential dispatchers
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        if (score_as_dispatcher(blk) >= 2) {
            DispatcherBlock disp;
            if (solver().analyze_dispatcher(mba, i, primary_state_var_, &disp)) {
                dispatchers_.push_back(disp);
            }
        }
    }

    if (dispatchers_.empty())
        return false;

    // Analyze transitions
    for (auto& disp : dispatchers_) {
        for (int case_blk : disp.case_blocks) {
            auto trans = solver().analyze_block_transitions(mba, case_blk,
                                                            primary_state_var_);
            transitions_.insert(transitions_.end(), trans.begin(), trans.end());
        }
    }

    analysis_complete_ = true;
    return true;
}

UnflattenResult GenericUnflattener::apply(mbl_array_t* mba, deobf_ctx_t* ctx) {
    // Same application logic
    UnflattenResult result;

    if (!analysis_complete_) {
        result.error_message = "Analysis not complete";
        return result;
    }

    for (auto& trans : transitions_) {
        if (trans.to_state == 0)
            continue;

        int target = -1;
        for (auto& disp : dispatchers_) {
            auto it = disp.state_to_block.find(trans.to_state);
            if (it != disp.state_to_block.end()) {
                target = it->second;
                break;
            }
        }

        if (target < 0)
            continue;

        mblock_t* src = mba->get_mblock(trans.from_block);
        if (!src || !src->tail)
            continue;

        if (src->tail->opcode == m_goto) {
            int old_target = (src->tail->l.t == mop_b) ? src->tail->l.b : -1;
            if (redirect_edge(mba, trans.from_block, old_target, target)) {
                result.edges_recovered++;
            }
        }
    }

    result.success = result.edges_recovered > 0;
    result.transitions = transitions_;

    if (result.success) {
        functions_unflattened_++;
        edges_recovered_ += result.edges_recovered;
    }

    return result;
}

//--------------------------------------------------------------------------
// JumpTableUnflattener Implementation
//--------------------------------------------------------------------------

int JumpTableUnflattener::detect(mbl_array_t* mba) {
    if (!mba)
        return 0;

    int table_block = -1;
    if (detect_jump_table(mba, &table_block)) {
        return 70;
    }

    return 0;
}

bool JumpTableUnflattener::detect_jump_table(mbl_array_t* mba, int* table_block) {
    // Look for indirect jumps that might be jump tables
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk || !blk->tail)
            continue;

        if (blk->tail->opcode == m_ijmp) {
            if (table_block) *table_block = i;
            return true;
        }
    }

    return false;
}

bool JumpTableUnflattener::analyze_index_computation(mblock_t* blk) {
    // Look for index computation patterns
    // e.g., index = state - base_value
    //       target = table[index]

    if (!blk)
        return false;

    for (minsn_t* ins = blk->head; ins; ins = ins->next) {
        // Look for subtraction that might compute index
        if (ins->opcode == m_sub) {
            if (ins->r.t == mop_n && ins->r.nnn) {
                // Found base subtraction
                return true;
            }
        }
    }

    return false;
}

bool JumpTableUnflattener::analyze(mbl_array_t* mba, deobf_ctx_t* ctx) {
    int table_block = -1;
    if (!detect_jump_table(mba, &table_block))
        return false;

    mblock_t* blk = mba->get_mblock(table_block);
    if (!blk)
        return false;

    // Try to find state variable from index computation
    auto candidates = solver().find_state_variables(mba);
    for (auto& var : candidates) {
        if (solver().verify_state_variable(mba, var)) {
            primary_state_var_ = var;
            break;
        }
    }

    if (!primary_state_var_.is_valid())
        return false;

    // Analyze the jump table structure
    DispatcherBlock disp;
    disp.block_idx = table_block;
    disp.state_var = primary_state_var_;

    // For jump tables, we need to read the table from memory
    // This is complex and depends on the specific structure
    // For now, mark as analyzed but defer full implementation

    dispatchers_.push_back(disp);
    analysis_complete_ = true;

    return true;
}

UnflattenResult JumpTableUnflattener::apply(mbl_array_t* mba, deobf_ctx_t* ctx) {
    UnflattenResult result;
    result.error_message = "Jump table unflattening not fully implemented";

    // TODO: Full implementation would:
    // 1. Read jump table from binary
    // 2. Map index values to target blocks
    // 3. Convert indirect jump to switch or direct jumps

    return result;
}

} // namespace chernobog
