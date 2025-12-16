#pragma once
#include "../deobf_types.h"
#include "../analysis/z3_solver.h"
#include <memory>
#include <vector>

//--------------------------------------------------------------------------
// Jump Optimization Rules
//
// Rules for simplifying conditional jumps with opaque predicates.
// Each rule detects a specific pattern and determines if the jump is
// always taken, never taken, or depends on runtime values.
//
// Ported from d810-ng's jump optimization rules
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Base class for jump rules
//--------------------------------------------------------------------------
class JumpOptimizationRule {
public:
    virtual ~JumpOptimizationRule() = default;

    // Rule name for logging
    virtual const char* name() const = 0;

    // Check if this rule applies to the conditional jump
    virtual bool matches(mblock_t* blk, minsn_t* jcc) = 0;

    // Apply the optimization
    // Returns: 1 = jump always taken, 0 = jump never taken, -1 = couldn't apply
    virtual int apply(mblock_t* blk, minsn_t* jcc) = 0;

    // Statistics
    size_t hit_count() const { return hit_count_; }
    void increment_hit_count() { hit_count_++; }

protected:
    size_t hit_count_ = 0;

    // Helper: check if operand is constant
    static bool is_const(const mop_t& op, uint64_t* out = nullptr);

    // Helper: check if operand is zero
    static bool is_zero(const mop_t& op);

    // Helper: check if operand is all ones (-1 for size)
    static bool is_all_ones(const mop_t& op);

    // Helper: get nested instruction if operand is mop_d
    static minsn_t* get_nested(const mop_t& op);
};

//--------------------------------------------------------------------------
// Rule: jnz (-(~x & 1)), x -> always taken (x & 1 is always true when tested)
// Pattern: jnz where condition involves negation of masked AND
//--------------------------------------------------------------------------
class JnzRule1 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JnzRule1"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jnz (~x | 1), 0 -> always taken
// Pattern: OR with 1 is never zero
//--------------------------------------------------------------------------
class JnzRule2 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JnzRule2"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jz x & ~x -> always taken (result is always 0)
//--------------------------------------------------------------------------
class JzRule1 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JzRule1"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jnz x | ~x -> always taken (result is always -1, never 0)
//--------------------------------------------------------------------------
class JnzRule3 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JnzRule3"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jz x ^ x -> always taken (result is always 0)
//--------------------------------------------------------------------------
class JzRule2 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JzRule2"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jnz x ^ x -> never taken (result is always 0)
//--------------------------------------------------------------------------
class JnzRule4 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JnzRule4"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jb x, x -> never taken (x < x is always false)
//--------------------------------------------------------------------------
class JbRule1 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JbRule1"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jae x, x -> always taken (x >= x is always true)
//--------------------------------------------------------------------------
class JaeRule1 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JaeRule1"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: jz const, const -> determine based on const values
//--------------------------------------------------------------------------
class JzConstRule : public JumpOptimizationRule {
public:
    const char* name() const override { return "JzConstRule"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;
};

//--------------------------------------------------------------------------
// Rule: Z3-based analysis for complex conditions
// Uses Z3 to prove condition is always true/false
//--------------------------------------------------------------------------
class JmpRuleZ3 : public JumpOptimizationRule {
public:
    const char* name() const override { return "JmpRuleZ3"; }
    bool matches(mblock_t* blk, minsn_t* jcc) override;
    int apply(mblock_t* blk, minsn_t* jcc) override;

private:
    // Cache result for current instruction
    int cached_result_ = -1;
    minsn_t* cached_jcc_ = nullptr;
};

//--------------------------------------------------------------------------
// Jump Rule Registry
//--------------------------------------------------------------------------
class JumpRuleRegistry {
public:
    static JumpRuleRegistry& instance();

    // Initialize all rules
    void initialize();

    // Try to match and apply a rule
    // Returns: 1 = jump always taken, 0 = jump never taken, -1 = no rule matched
    int try_apply(mblock_t* blk, minsn_t* jcc);

    // Get statistics
    void dump_statistics();
    void reset_statistics();

private:
    JumpRuleRegistry() = default;

    std::vector<std::unique_ptr<JumpOptimizationRule>> rules_;
    bool initialized_ = false;
};

} // namespace rules
} // namespace chernobog
