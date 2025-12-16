#include "rules_predicate.h"

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Static member initialization
//--------------------------------------------------------------------------

size_t predicate_optimizer_handler_t::predicates_simplified_ = 0;
size_t predicate_optimizer_handler_t::predicates_to_true_ = 0;
size_t predicate_optimizer_handler_t::predicates_to_false_ = 0;

//--------------------------------------------------------------------------
// PredicateRule helper functions
//--------------------------------------------------------------------------

bool PredicateRule::is_const(const mop_t& op, uint64_t* out) {
    if (op.t != mop_n)
        return false;
    if (out && op.nnn)
        *out = op.nnn->value;
    return true;
}

bool PredicateRule::is_zero(const mop_t& op) {
    uint64_t val;
    if (!is_const(op, &val))
        return false;
    return val == 0;
}

bool PredicateRule::is_all_ones(const mop_t& op) {
    uint64_t val;
    if (!is_const(op, &val))
        return false;

    // Check if all bits are set for the operand size
    uint64_t mask = (op.size >= 8) ? ~0ULL : ((1ULL << (op.size * 8)) - 1);
    return (val & mask) == mask;
}

minsn_t* PredicateRule::get_nested(const mop_t& op) {
    if (op.t != mop_d)
        return nullptr;
    return op.d;
}

bool PredicateRule::operands_equal(const mop_t& a, const mop_t& b) {
    return a.equal_mops(b, EQ_IGNSIZE);
}

bool PredicateRule::is_and_complement(const mop_t& op) {
    minsn_t* ins = get_nested(op);
    if (!ins || ins->opcode != m_and)
        return false;

    // Check for x & ~x or ~x & x
    minsn_t* bnot_l = get_nested(ins->l);
    minsn_t* bnot_r = get_nested(ins->r);

    if (bnot_l && bnot_l->opcode == m_bnot) {
        // ~a & b - check if a == b
        if (bnot_l->l.equal_mops(ins->r, EQ_IGNSIZE))
            return true;
    }
    if (bnot_r && bnot_r->opcode == m_bnot) {
        // a & ~b - check if a == b
        if (bnot_r->l.equal_mops(ins->l, EQ_IGNSIZE))
            return true;
    }

    return false;
}

bool PredicateRule::is_or_complement(const mop_t& op) {
    minsn_t* ins = get_nested(op);
    if (!ins || ins->opcode != m_or)
        return false;

    // Check for x | ~x or ~x | x
    minsn_t* bnot_l = get_nested(ins->l);
    minsn_t* bnot_r = get_nested(ins->r);

    if (bnot_l && bnot_l->opcode == m_bnot) {
        if (bnot_l->l.equal_mops(ins->r, EQ_IGNSIZE))
            return true;
    }
    if (bnot_r && bnot_r->opcode == m_bnot) {
        if (bnot_r->l.equal_mops(ins->l, EQ_IGNSIZE))
            return true;
    }

    return false;
}

bool PredicateRule::is_xor_self(const mop_t& op) {
    minsn_t* ins = get_nested(op);
    if (!ins || ins->opcode != m_xor)
        return false;

    // Check for x ^ x
    return ins->l.equal_mops(ins->r, EQ_IGNSIZE);
}

//--------------------------------------------------------------------------
// Self-Comparison Rules Implementation
//--------------------------------------------------------------------------

// setz x, x -> 1
bool SetzSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setz)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetzSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x == x is always true
}

// setnz x, x -> 0
bool SetnzSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setnz)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetnzSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x != x is always false
}

// setb x, x -> 0
bool SetbSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setb)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetbSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x < x is always false (unsigned)
}

// setae x, x -> 1
bool SetaeSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setae)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetaeSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x >= x is always true (unsigned)
}

// seta x, x -> 0
bool SetaSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_seta)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetaSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x > x is always false (unsigned)
}

// setbe x, x -> 1
bool SetbeSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setbe)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetbeSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x <= x is always true (unsigned)
}

// setl x, x -> 0
bool SetlSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setl)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetlSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x < x is always false (signed)
}

// setge x, x -> 1
bool SetgeSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setge)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetgeSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x >= x is always true (signed)
}

// setg x, x -> 0
bool SetgSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setg)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetgSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x > x is always false (signed)
}

// setle x, x -> 1
bool SetleSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setle)
        return false;
    return operands_equal(ins->l, ins->r);
}

int SetleSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x <= x is always true (signed)
}

//--------------------------------------------------------------------------
// Identity Pattern Rules Implementation
//--------------------------------------------------------------------------

// setz (x & ~x), 0 -> 1
bool SetzAndComplementRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setz)
        return false;

    // Check left operand is x & ~x and right is 0
    if (!is_and_complement(ins->l))
        return false;

    return is_zero(ins->r);
}

int SetzAndComplementRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x & ~x == 0 is always true
}

// setnz (x | ~x), 0 -> 1
bool SetnzOrComplementRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setnz)
        return false;

    if (!is_or_complement(ins->l))
        return false;

    return is_zero(ins->r);
}

int SetnzOrComplementRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x | ~x != 0 is always true (result is -1)
}

// setz (x ^ x), 0 -> 1
bool SetzXorSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setz)
        return false;

    if (!is_xor_self(ins->l))
        return false;

    return is_zero(ins->r);
}

int SetzXorSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x ^ x == 0 is always true
}

// setnz (x ^ x), 0 -> 0
bool SetnzXorSelfRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setnz)
        return false;

    if (!is_xor_self(ins->l))
        return false;

    return is_zero(ins->r);
}

int SetnzXorSelfRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x ^ x != 0 is always false (x ^ x is 0)
}

//--------------------------------------------------------------------------
// Tautology Rules Implementation
//--------------------------------------------------------------------------

// setnz (x | 1), 0 -> 1
bool SetnzOrOneRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setnz)
        return false;

    if (!is_zero(ins->r))
        return false;

    minsn_t* or_ins = get_nested(ins->l);
    if (!or_ins || or_ins->opcode != m_or)
        return false;

    // Check if either operand of OR is an odd constant
    uint64_t val;
    if (is_const(or_ins->l, &val) && (val & 1))
        return true;
    if (is_const(or_ins->r, &val) && (val & 1))
        return true;

    return false;
}

int SetnzOrOneRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x | odd_const != 0 is always true
}

// setz (x & 0), 0 -> 1
bool SetzAndZeroRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setz)
        return false;

    if (!is_zero(ins->r))
        return false;

    minsn_t* and_ins = get_nested(ins->l);
    if (!and_ins || and_ins->opcode != m_and)
        return false;

    // Check if either operand of AND is 0
    if (is_zero(and_ins->l) || is_zero(and_ins->r))
        return true;

    return false;
}

int SetzAndZeroRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x & 0 == 0 is always true
}

// setnz (x | -1), 0 -> 1
bool SetnzOrMinusOneRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setnz)
        return false;

    if (!is_zero(ins->r))
        return false;

    minsn_t* or_ins = get_nested(ins->l);
    if (!or_ins || or_ins->opcode != m_or)
        return false;

    // Check if either operand of OR is all ones
    if (is_all_ones(or_ins->l) || is_all_ones(or_ins->r))
        return true;

    return false;
}

int SetnzOrMinusOneRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x | -1 != 0 is always true
}

// setb x, 0 -> 0 (nothing is below 0 unsigned)
bool SetbZeroRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setb)
        return false;
    return is_zero(ins->r);
}

int SetbZeroRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // x < 0 (unsigned) is always false
}

// setae x, 0 -> 1 (everything is >= 0 unsigned)
bool SetaeZeroRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_setae)
        return false;
    return is_zero(ins->r);
}

int SetaeZeroRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // x >= 0 (unsigned) is always true
}

//--------------------------------------------------------------------------
// Constant Comparison Rule
//--------------------------------------------------------------------------

bool SetConstRule::matches(minsn_t* ins) {
    if (!ins)
        return false;

    // Check for set* opcodes
    if (!is_mcode_set(ins->opcode))
        return false;

    // Both operands must be constants
    return is_const(ins->l, nullptr) && is_const(ins->r, nullptr);
}

int SetConstRule::apply(minsn_t* ins) {
    uint64_t l, r;
    is_const(ins->l, &l);
    is_const(ins->r, &r);

    // Mask to operand size
    int size = ins->l.size > 0 ? ins->l.size : 4;
    uint64_t mask = (size >= 8) ? ~0ULL : ((1ULL << (size * 8)) - 1);
    l &= mask;
    r &= mask;

    hit_count_++;

    switch (ins->opcode) {
        case m_setz:   return (l == r) ? 1 : 0;
        case m_setnz:  return (l != r) ? 1 : 0;
        case m_setb:   return (l < r) ? 1 : 0;
        case m_setae:  return (l >= r) ? 1 : 0;
        case m_seta:   return (l > r) ? 1 : 0;
        case m_setbe:  return (l <= r) ? 1 : 0;

        // Signed comparisons
        case m_setl: {
            int64_t sl = static_cast<int64_t>(l);
            int64_t sr = static_cast<int64_t>(r);
            if (size < 8) {
                // Sign extend
                int shift = 64 - size * 8;
                sl = (sl << shift) >> shift;
                sr = (sr << shift) >> shift;
            }
            return (sl < sr) ? 1 : 0;
        }
        case m_setge: {
            int64_t sl = static_cast<int64_t>(l);
            int64_t sr = static_cast<int64_t>(r);
            if (size < 8) {
                int shift = 64 - size * 8;
                sl = (sl << shift) >> shift;
                sr = (sr << shift) >> shift;
            }
            return (sl >= sr) ? 1 : 0;
        }
        case m_setg: {
            int64_t sl = static_cast<int64_t>(l);
            int64_t sr = static_cast<int64_t>(r);
            if (size < 8) {
                int shift = 64 - size * 8;
                sl = (sl << shift) >> shift;
                sr = (sr << shift) >> shift;
            }
            return (sl > sr) ? 1 : 0;
        }
        case m_setle: {
            int64_t sl = static_cast<int64_t>(l);
            int64_t sr = static_cast<int64_t>(r);
            if (size < 8) {
                int shift = 64 - size * 8;
                sl = (sl << shift) >> shift;
                sr = (sr << shift) >> shift;
            }
            return (sl <= sr) ? 1 : 0;
        }

        default:
            return -1;
    }
}

//--------------------------------------------------------------------------
// Z3-based Predicate Rule
//--------------------------------------------------------------------------

bool SetRuleZ3::matches(minsn_t* ins) {
    if (!ins || !is_mcode_set(ins->opcode))
        return false;

    // Reset cache if different instruction
    if (cached_ins_ != ins) {
        cached_ins_ = ins;
        cached_result_ = -1;

        try {
            z3_solver::predicate_simplifier_t simplifier(z3_solver::get_global_context());

            // Use the appropriate simplifier based on opcode
            switch (ins->opcode) {
                case m_setz: {
                    auto result = simplifier.simplify_setz(ins);
                    if (result.has_value())
                        cached_result_ = result.value() ? 1 : 0;
                    break;
                }
                case m_setnz: {
                    auto result = simplifier.simplify_setnz(ins);
                    if (result.has_value())
                        cached_result_ = result.value() ? 1 : 0;
                    break;
                }
                default: {
                    // For other set* opcodes, try general comparison analysis
                    auto result = simplifier.check_comparison_constant(
                        ins->opcode, ins->l, ins->r);
                    if (result.has_value())
                        cached_result_ = result.value() ? 1 : 0;
                    break;
                }
            }
        } catch (...) {
            cached_result_ = -1;
        }
    }

    return cached_result_ != -1;
}

int SetRuleZ3::apply(minsn_t* ins) {
    hit_count_++;
    return cached_result_;
}

//--------------------------------------------------------------------------
// Logical NOT Rules
//--------------------------------------------------------------------------

// lnot(lnot(x)) - double negation (returns -1 as it's a transformation, not simplification to const)
bool LnotLnotRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_lnot)
        return false;

    minsn_t* inner = get_nested(ins->l);
    if (!inner || inner->opcode != m_lnot)
        return false;

    return true;
}

int LnotLnotRule::apply(minsn_t* ins) {
    // This rule transforms lnot(lnot(x)) but doesn't reduce to a constant
    // Return -1 to indicate no constant simplification
    // The actual transformation should be handled elsewhere
    return -1;
}

// lnot(1) -> 0
bool LnotOneRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_lnot)
        return false;

    uint64_t val;
    if (!is_const(ins->l, &val))
        return false;

    return val != 0;  // lnot of any non-zero value is 0
}

int LnotOneRule::apply(minsn_t* ins) {
    hit_count_++;
    return 0;  // lnot(non-zero) = 0
}

// lnot(0) -> 1
bool LnotZeroRule::matches(minsn_t* ins) {
    if (!ins || ins->opcode != m_lnot)
        return false;

    return is_zero(ins->l);
}

int LnotZeroRule::apply(minsn_t* ins) {
    hit_count_++;
    return 1;  // lnot(0) = 1
}

//--------------------------------------------------------------------------
// PredicateRuleRegistry Implementation
//--------------------------------------------------------------------------

PredicateRuleRegistry& PredicateRuleRegistry::instance() {
    static PredicateRuleRegistry inst;
    return inst;
}

void PredicateRuleRegistry::initialize() {
    if (initialized_)
        return;

    rules_.clear();

    // Self-comparison rules (most common, check first)
    rules_.push_back(std::make_unique<SetzSelfRule>());
    rules_.push_back(std::make_unique<SetnzSelfRule>());
    rules_.push_back(std::make_unique<SetbSelfRule>());
    rules_.push_back(std::make_unique<SetaeSelfRule>());
    rules_.push_back(std::make_unique<SetaSelfRule>());
    rules_.push_back(std::make_unique<SetbeSelfRule>());
    rules_.push_back(std::make_unique<SetlSelfRule>());
    rules_.push_back(std::make_unique<SetgeSelfRule>());
    rules_.push_back(std::make_unique<SetgSelfRule>());
    rules_.push_back(std::make_unique<SetleSelfRule>());

    // Identity pattern rules
    rules_.push_back(std::make_unique<SetzAndComplementRule>());
    rules_.push_back(std::make_unique<SetnzOrComplementRule>());
    rules_.push_back(std::make_unique<SetzXorSelfRule>());
    rules_.push_back(std::make_unique<SetnzXorSelfRule>());

    // Tautology rules
    rules_.push_back(std::make_unique<SetnzOrOneRule>());
    rules_.push_back(std::make_unique<SetzAndZeroRule>());
    rules_.push_back(std::make_unique<SetnzOrMinusOneRule>());
    rules_.push_back(std::make_unique<SetbZeroRule>());
    rules_.push_back(std::make_unique<SetaeZeroRule>());

    // Constant comparison (fast)
    rules_.push_back(std::make_unique<SetConstRule>());

    // Logical NOT rules
    rules_.push_back(std::make_unique<LnotOneRule>());
    rules_.push_back(std::make_unique<LnotZeroRule>());

    // Z3-based rule (last, as it's slowest)
    rules_.push_back(std::make_unique<SetRuleZ3>());

    initialized_ = true;
    msg("[chernobog] Predicate rules initialized (%zu rules)\n", rules_.size());
}

int PredicateRuleRegistry::try_apply(minsn_t* ins) {
    if (!initialized_)
        initialize();

    for (auto& rule : rules_) {
        if (rule->matches(ins)) {
            return rule->apply(ins);
        }
    }

    return -1;  // No rule matched
}

void PredicateRuleRegistry::dump_statistics() {
    msg("[chernobog] Predicate Rule Statistics:\n");
    for (auto& rule : rules_) {
        if (rule->hit_count() > 0) {
            msg("  %s: %zu hits\n", rule->name(), rule->hit_count());
        }
    }
}

void PredicateRuleRegistry::reset_statistics() {
    // Note: would need to add reset method to PredicateRule base class
    // For now, statistics persist across runs
}

//--------------------------------------------------------------------------
// predicate_optimizer_handler_t Implementation
//--------------------------------------------------------------------------

bool predicate_optimizer_handler_t::detect(mbl_array_t* mba) {
    if (!mba)
        return false;

    // Look for set* instructions
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            if (is_mcode_set(ins->opcode))
                return true;
            if (ins->opcode == m_lnot)
                return true;
        }
    }

    return false;
}

int predicate_optimizer_handler_t::run(mbl_array_t* mba, deobf_ctx_t* ctx) {
    if (!mba || !ctx)
        return 0;

    // Initialize rule registry
    PredicateRuleRegistry::instance().initialize();

    int total_changes = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk)
            continue;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            if (is_mcode_set(ins->opcode) || ins->opcode == m_lnot) {
                int changes = simplify_set(blk, ins, ctx);
                total_changes += changes;
            }
        }
    }

    if (total_changes > 0) {
        deobf::log_verbose("[Predicate] Simplified %d predicates\n", total_changes);
    }

    return total_changes;
}

int predicate_optimizer_handler_t::simplify_set(mblock_t* blk, minsn_t* ins, deobf_ctx_t* ctx) {
    if (!blk || !ins)
        return 0;

    int result = PredicateRuleRegistry::instance().try_apply(ins);
    if (result == -1)
        return 0;  // No simplification

    // Convert to mov constant
    ea_t orig_ea = ins->ea;
    int dst_size = ins->d.size > 0 ? ins->d.size : 1;

    // Save destination
    mop_t dst = ins->d;

    // Convert to mov #const, dst
    ins->opcode = m_mov;
    ins->l.make_number(result, dst_size);
    ins->r.erase();
    ins->d = dst;
    ins->ea = orig_ea;

    // Update statistics
    predicates_simplified_++;
    if (result == 1) {
        predicates_to_true_++;
    } else {
        predicates_to_false_++;
    }

    if (ctx) {
        ctx->expressions_simplified++;
    }

    deobf::log_verbose("[Predicate] Simplified set* at %a to %d\n", orig_ea, result);
    return 1;
}

void predicate_optimizer_handler_t::dump_statistics() {
    msg("[chernobog] Predicate Optimizer Statistics:\n");
    msg("  Total simplified: %zu\n", predicates_simplified_);
    msg("  Simplified to true: %zu\n", predicates_to_true_);
    msg("  Simplified to false: %zu\n", predicates_to_false_);

    PredicateRuleRegistry::instance().dump_statistics();
}

void predicate_optimizer_handler_t::reset_statistics() {
    predicates_simplified_ = 0;
    predicates_to_true_ = 0;
    predicates_to_false_ = 0;

    PredicateRuleRegistry::instance().reset_statistics();
}

} // namespace rules
} // namespace chernobog
