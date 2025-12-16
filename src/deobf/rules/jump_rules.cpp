#include "jump_rules.h"

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Helper functions
//--------------------------------------------------------------------------

bool JumpOptimizationRule::is_const(const mop_t& op, uint64_t* out) {
    if (op.t != mop_n)
        return false;
    if (out)
        *out = op.nnn->value;
    return true;
}

bool JumpOptimizationRule::is_zero(const mop_t& op) {
    uint64_t val;
    if (!is_const(op, &val))
        return false;
    return val == 0;
}

bool JumpOptimizationRule::is_all_ones(const mop_t& op) {
    uint64_t val;
    if (!is_const(op, &val))
        return false;

    uint64_t mask = (op.size >= 8) ? ~0ULL : ((1ULL << (op.size * 8)) - 1);
    return (val & mask) == mask;
}

minsn_t* JumpOptimizationRule::get_nested(const mop_t& op) {
    if (op.t != mop_d)
        return nullptr;
    return op.d;
}

//--------------------------------------------------------------------------
// JnzRule1: jnz (-(~x & 1)), x -> always taken
//--------------------------------------------------------------------------

bool JnzRule1::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jnz)
        return false;

    // Pattern: jnz with left operand being result of neg(and(bnot(x), 1))
    minsn_t* inner = get_nested(jcc->l);
    if (!inner || inner->opcode != m_neg)
        return false;

    minsn_t* and_ins = get_nested(inner->l);
    if (!and_ins || and_ins->opcode != m_and)
        return false;

    // Check for (bnot(x) & 1) or (1 & bnot(x))
    uint64_t const_val;
    if (is_const(and_ins->r, &const_val) && const_val == 1) {
        minsn_t* bnot_ins = get_nested(and_ins->l);
        if (bnot_ins && bnot_ins->opcode == m_bnot)
            return true;
    }
    if (is_const(and_ins->l, &const_val) && const_val == 1) {
        minsn_t* bnot_ins = get_nested(and_ins->r);
        if (bnot_ins && bnot_ins->opcode == m_bnot)
            return true;
    }

    return false;
}

int JnzRule1::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 1;  // Always taken
}

//--------------------------------------------------------------------------
// JnzRule2: jnz (~x | 1), 0 -> always taken
//--------------------------------------------------------------------------

bool JnzRule2::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jnz)
        return false;

    // Check if right operand is 0
    if (!is_zero(jcc->r))
        return false;

    minsn_t* or_ins = get_nested(jcc->l);
    if (!or_ins || or_ins->opcode != m_or)
        return false;

    // Check for (~x | 1) or (1 | ~x)
    uint64_t const_val;
    if (is_const(or_ins->r, &const_val) && (const_val & 1)) {
        return true;  // OR with odd number is never 0
    }
    if (is_const(or_ins->l, &const_val) && (const_val & 1)) {
        return true;
    }

    return false;
}

int JnzRule2::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 1;  // Always taken
}

//--------------------------------------------------------------------------
// JzRule1: jz x & ~x -> always taken (result is 0)
//--------------------------------------------------------------------------

bool JzRule1::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jz)
        return false;

    minsn_t* and_ins = get_nested(jcc->l);
    if (!and_ins || and_ins->opcode != m_and)
        return false;

    // Check for x & ~x
    minsn_t* bnot_l = get_nested(and_ins->l);
    minsn_t* bnot_r = get_nested(and_ins->r);

    if (bnot_l && bnot_l->opcode == m_bnot) {
        // ~a & b - check if a == b
        if (bnot_l->l.equal_mops(and_ins->r, EQ_IGNSIZE))
            return true;
    }
    if (bnot_r && bnot_r->opcode == m_bnot) {
        // a & ~b - check if a == b
        if (bnot_r->l.equal_mops(and_ins->l, EQ_IGNSIZE))
            return true;
    }

    return false;
}

int JzRule1::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 1;  // Always taken (x & ~x is always 0)
}

//--------------------------------------------------------------------------
// JnzRule3: jnz x | ~x -> always taken (result is -1)
//--------------------------------------------------------------------------

bool JnzRule3::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jnz)
        return false;

    minsn_t* or_ins = get_nested(jcc->l);
    if (!or_ins || or_ins->opcode != m_or)
        return false;

    // Check for x | ~x
    minsn_t* bnot_l = get_nested(or_ins->l);
    minsn_t* bnot_r = get_nested(or_ins->r);

    if (bnot_l && bnot_l->opcode == m_bnot) {
        if (bnot_l->l.equal_mops(or_ins->r, EQ_IGNSIZE))
            return true;
    }
    if (bnot_r && bnot_r->opcode == m_bnot) {
        if (bnot_r->l.equal_mops(or_ins->l, EQ_IGNSIZE))
            return true;
    }

    return false;
}

int JnzRule3::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 1;  // Always taken (x | ~x is always -1, never 0)
}

//--------------------------------------------------------------------------
// JzRule2: jz x ^ x -> always taken (result is 0)
//--------------------------------------------------------------------------

bool JzRule2::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jz)
        return false;

    minsn_t* xor_ins = get_nested(jcc->l);
    if (!xor_ins || xor_ins->opcode != m_xor)
        return false;

    // Check for x ^ x
    return xor_ins->l.equal_mops(xor_ins->r, EQ_IGNSIZE);
}

int JzRule2::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 1;  // Always taken (x ^ x is always 0)
}

//--------------------------------------------------------------------------
// JnzRule4: jnz x ^ x -> never taken (result is 0)
//--------------------------------------------------------------------------

bool JnzRule4::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jnz)
        return false;

    minsn_t* xor_ins = get_nested(jcc->l);
    if (!xor_ins || xor_ins->opcode != m_xor)
        return false;

    // Check for x ^ x
    return xor_ins->l.equal_mops(xor_ins->r, EQ_IGNSIZE);
}

int JnzRule4::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 0;  // Never taken (x ^ x is always 0)
}

//--------------------------------------------------------------------------
// JbRule1: jb x, x -> never taken (x < x is false)
//--------------------------------------------------------------------------

bool JbRule1::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jb)
        return false;

    // Check if comparing same operand
    return jcc->l.equal_mops(jcc->r, EQ_IGNSIZE);
}

int JbRule1::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 0;  // Never taken
}

//--------------------------------------------------------------------------
// JaeRule1: jae x, x -> always taken (x >= x is true)
//--------------------------------------------------------------------------

bool JaeRule1::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || jcc->opcode != m_jae)
        return false;

    // Check if comparing same operand
    return jcc->l.equal_mops(jcc->r, EQ_IGNSIZE);
}

int JaeRule1::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return 1;  // Always taken
}

//--------------------------------------------------------------------------
// JzConstRule: jz const, const
//--------------------------------------------------------------------------

bool JzConstRule::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc)
        return false;

    if (jcc->opcode != m_jz && jcc->opcode != m_jnz)
        return false;

    return is_const(jcc->l, nullptr) && is_const(jcc->r, nullptr);
}

int JzConstRule::apply(mblock_t* blk, minsn_t* jcc) {
    uint64_t l, r;
    is_const(jcc->l, &l);
    is_const(jcc->r, &r);

    hit_count_++;

    if (jcc->opcode == m_jz) {
        return (l == r) ? 1 : 0;
    } else {  // m_jnz
        return (l != r) ? 1 : 0;
    }
}

//--------------------------------------------------------------------------
// JmpRuleZ3: Z3-based analysis
//--------------------------------------------------------------------------

bool JmpRuleZ3::matches(mblock_t* blk, minsn_t* jcc) {
    if (!jcc || !is_mcode_jcond(jcc->opcode))
        return false;

    // Reset cache if different instruction
    if (cached_jcc_ != jcc) {
        cached_jcc_ = jcc;
        cached_result_ = -1;

        try {
            z3_solver::predicate_simplifier_t simplifier(z3_solver::get_global_context());
            cached_result_ = simplifier.simplify_jcc(jcc);
        } catch (...) {
            cached_result_ = -1;
        }
    }

    return cached_result_ != -1;
}

int JmpRuleZ3::apply(mblock_t* blk, minsn_t* jcc) {
    hit_count_++;
    return cached_result_;
}

//--------------------------------------------------------------------------
// JumpRuleRegistry implementation
//--------------------------------------------------------------------------

JumpRuleRegistry& JumpRuleRegistry::instance() {
    static JumpRuleRegistry inst;
    return inst;
}

void JumpRuleRegistry::initialize() {
    if (initialized_)
        return;

    rules_.clear();

    // Add pattern-based rules first (faster)
    rules_.push_back(std::make_unique<JnzRule1>());
    rules_.push_back(std::make_unique<JnzRule2>());
    rules_.push_back(std::make_unique<JnzRule3>());
    rules_.push_back(std::make_unique<JnzRule4>());
    rules_.push_back(std::make_unique<JzRule1>());
    rules_.push_back(std::make_unique<JzRule2>());
    rules_.push_back(std::make_unique<JbRule1>());
    rules_.push_back(std::make_unique<JaeRule1>());
    rules_.push_back(std::make_unique<JzConstRule>());

    // Add Z3 rule last (slower but more general)
    rules_.push_back(std::make_unique<JmpRuleZ3>());

    initialized_ = true;
    msg("[chernobog] Jump rules initialized (%zu rules)\n", rules_.size());
}

int JumpRuleRegistry::try_apply(mblock_t* blk, minsn_t* jcc) {
    if (!initialized_)
        initialize();

    for (auto& rule : rules_) {
        if (rule->matches(blk, jcc)) {
            return rule->apply(blk, jcc);
        }
    }

    return -1;  // No rule matched
}

void JumpRuleRegistry::dump_statistics() {
    msg("[chernobog] Jump Rule Statistics:\n");
    for (auto& rule : rules_) {
        if (rule->hit_count() > 0) {
            msg("  %s: %zu hits\n", rule->name(), rule->hit_count());
        }
    }
}

void JumpRuleRegistry::reset_statistics() {
    for (auto& rule : rules_) {
        // Reset hit count (need to add reset method to base class)
    }
}

} // namespace rules
} // namespace chernobog
