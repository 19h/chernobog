#pragma once
#include "pattern_rule.h"
#include "../deobf_types.h"
#include "../analysis/z3_solver.h"
#include <memory>
#include <vector>

//--------------------------------------------------------------------------
// Predicate Optimization Rules
//
// Rules for simplifying set* instructions (setz, setnz, setb, setae, etc.)
// that evaluate to constants due to opaque predicates or algebraic identities.
//
// Unlike MBA rules which transform complex expressions to simpler ones,
// predicate rules determine if a comparison always produces 0 or 1.
//
// Categories:
//   1. Self-comparison: x == x, x < x, x >= x, etc.
//   2. Identity patterns: (x & ~x) == 0, (x | ~x) != 0, (x ^ x) == 0
//   3. Constant folding: const1 == const2
//   4. Tautologies: (x | 1) != 0, (x & 0) == 0
//   5. Z3-based: complex patterns proven via SMT solving
//
// Ported from d810-ng's predicate simplification rules
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

//--------------------------------------------------------------------------
// Base class for predicate rules
//--------------------------------------------------------------------------
class PredicateRule {
public:
    virtual ~PredicateRule() = default;

    // Rule name for logging and statistics
    virtual const char* name() const = 0;

    // Check if this rule applies to the set* instruction
    // Returns true if the pattern matches
    virtual bool matches(minsn_t* ins) = 0;

    // Apply the optimization
    // Returns: the constant value (0 or 1), or -1 if can't determine
    virtual int apply(minsn_t* ins) = 0;

    // Statistics
    size_t hit_count() const { return hit_count_; }
    void increment_hit_count() { hit_count_++; }

protected:
    size_t hit_count_ = 0;

    //----------------------------------------------------------------------
    // Helper functions
    //----------------------------------------------------------------------

    // Check if operand is a constant
    static bool is_const(const mop_t& op, uint64_t* out = nullptr);

    // Check if operand is zero
    static bool is_zero(const mop_t& op);

    // Check if operand is all ones (-1 for the size)
    static bool is_all_ones(const mop_t& op);

    // Get nested instruction if operand is mop_d
    static minsn_t* get_nested(const mop_t& op);

    // Check if two operands are equal (same value reference)
    static bool operands_equal(const mop_t& a, const mop_t& b);

    // Check for x & ~x pattern (always 0)
    static bool is_and_complement(const mop_t& op);

    // Check for x | ~x pattern (always -1)
    static bool is_or_complement(const mop_t& op);

    // Check for x ^ x pattern (always 0)
    static bool is_xor_self(const mop_t& op);
};

//--------------------------------------------------------------------------
// Self-Comparison Rules
// Patterns where comparing x with x always gives a constant result
//--------------------------------------------------------------------------

// setz x, x -> 1 (x == x is always true)
class SetzSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetzSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setnz x, x -> 0 (x != x is always false)
class SetnzSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetnzSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setb x, x -> 0 (x < x is always false, unsigned)
class SetbSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetbSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setae x, x -> 1 (x >= x is always true, unsigned)
class SetaeSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetaeSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// seta x, x -> 0 (x > x is always false, unsigned)
class SetaSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetaSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setbe x, x -> 1 (x <= x is always true, unsigned)
class SetbeSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetbeSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setl x, x -> 0 (x < x is always false, signed)
class SetlSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetlSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setge x, x -> 1 (x >= x is always true, signed)
class SetgeSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetgeSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setg x, x -> 0 (x > x is always false, signed)
class SetgSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetgSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setle x, x -> 1 (x <= x is always true, signed)
class SetleSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetleSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Identity Pattern Rules
// Patterns involving algebraic identities that always evaluate to constants
//--------------------------------------------------------------------------

// setz (x & ~x), 0 -> 1 (x & ~x is always 0)
class SetzAndComplementRule : public PredicateRule {
public:
    const char* name() const override { return "SetzAndComplementRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setnz (x | ~x), 0 -> 1 (x | ~x is always -1, not 0)
class SetnzOrComplementRule : public PredicateRule {
public:
    const char* name() const override { return "SetnzOrComplementRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setz (x ^ x), 0 -> 1 (x ^ x is always 0)
class SetzXorSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetzXorSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setnz (x ^ x), 0 -> 0 (x ^ x is always 0, not non-zero)
class SetnzXorSelfRule : public PredicateRule {
public:
    const char* name() const override { return "SetnzXorSelfRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Tautology Rules
// Patterns that are always true/false due to bit manipulation properties
//--------------------------------------------------------------------------

// setnz (x | 1), 0 -> 1 (x | 1 is always odd, never 0)
class SetnzOrOneRule : public PredicateRule {
public:
    const char* name() const override { return "SetnzOrOneRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setz (x & 0), 0 -> 1 (x & 0 is always 0)
class SetzAndZeroRule : public PredicateRule {
public:
    const char* name() const override { return "SetzAndZeroRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setnz (x | -1), 0 -> 1 (x | -1 is always -1, never 0)
class SetnzOrMinusOneRule : public PredicateRule {
public:
    const char* name() const override { return "SetnzOrMinusOneRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setb x, 0 -> 0 (nothing is below 0 unsigned)
class SetbZeroRule : public PredicateRule {
public:
    const char* name() const override { return "SetbZeroRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// setae x, 0 -> 1 (everything is >= 0 unsigned)
class SetaeZeroRule : public PredicateRule {
public:
    const char* name() const override { return "SetaeZeroRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Constant Comparison Rules
// Direct evaluation when both operands are constants
//--------------------------------------------------------------------------

class SetConstRule : public PredicateRule {
public:
    const char* name() const override { return "SetConstRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Z3-based Predicate Rule
// Uses Z3 to prove predicates constant when pattern rules don't match
//--------------------------------------------------------------------------

class SetRuleZ3 : public PredicateRule {
public:
    const char* name() const override { return "SetRuleZ3"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;

private:
    // Cache result for current instruction
    minsn_t* cached_ins_ = nullptr;
    int cached_result_ = -1;
};

//--------------------------------------------------------------------------
// Logical NOT Rules
// Patterns involving lnot that can be simplified
//--------------------------------------------------------------------------

// lnot(lnot(x)) can sometimes be simplified to setnz(x, 0)
class LnotLnotRule : public PredicateRule {
public:
    const char* name() const override { return "LnotLnotRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// lnot(1) -> 0
class LnotOneRule : public PredicateRule {
public:
    const char* name() const override { return "LnotOneRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

// lnot(0) -> 1
class LnotZeroRule : public PredicateRule {
public:
    const char* name() const override { return "LnotZeroRule"; }
    bool matches(minsn_t* ins) override;
    int apply(minsn_t* ins) override;
};

//--------------------------------------------------------------------------
// Predicate Rule Registry
//--------------------------------------------------------------------------

class PredicateRuleRegistry {
public:
    static PredicateRuleRegistry& instance();

    // Initialize all predicate rules
    void initialize();

    // Try to match and apply a rule
    // Returns: 0 or 1 if simplified, -1 if no rule matched
    int try_apply(minsn_t* ins);

    // Get statistics
    void dump_statistics();
    void reset_statistics();

private:
    PredicateRuleRegistry() = default;

    std::vector<std::unique_ptr<PredicateRule>> rules_;
    bool initialized_ = false;
};

//--------------------------------------------------------------------------
// Predicate optimization handler
//--------------------------------------------------------------------------

class predicate_optimizer_handler_t {
public:
    // Detect if predicate patterns are present
    static bool detect(mbl_array_t* mba);

    // Run predicate optimization pass
    static int run(mbl_array_t* mba, deobf_ctx_t* ctx);

    // Simplify a single set* instruction
    // Returns 1 if simplified, 0 if not
    static int simplify_set(mblock_t* blk, minsn_t* ins, deobf_ctx_t* ctx);

    // Statistics
    static void dump_statistics();
    static void reset_statistics();

private:
    static size_t predicates_simplified_;
    static size_t predicates_to_true_;
    static size_t predicates_to_false_;
};

} // namespace rules
} // namespace chernobog
