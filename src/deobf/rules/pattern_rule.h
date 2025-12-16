#pragma once
#include "../analysis/ast.h"
#include "../analysis/ast_builder.h"
#include "../analysis/pattern_fuzzer.h"
#include <vector>
#include <string>
#include <map>

//--------------------------------------------------------------------------
// Pattern Matching Rule Base Class
//
// Each MBA simplification rule inherits from this class and defines:
//   - get_pattern(): The obfuscated expression pattern to match
//   - get_replacement(): The simplified replacement pattern
//   - check_candidate() (optional): Extra validation after structural match
//
// The fuzzing system automatically generates all equivalent variants
// of the pattern (commutative reordering, add/sub equivalence, etc.)
//
// Example rule:
//   Pattern: x - (~y + 1)  ->  Replacement: x + y
//   (Two's complement subtraction converted to addition)
//
// Ported from d810-ng's pattern matching rule system
//--------------------------------------------------------------------------

// Forward declaration (global scope - matches deobf_types.h)
struct deobf_ctx_t;

namespace chernobog {
namespace rules {

using namespace ast;

//--------------------------------------------------------------------------
// Base class for all pattern matching rules
//--------------------------------------------------------------------------
class PatternMatchingRule {
public:
    virtual ~PatternMatchingRule() = default;

    //----------------------------------------------------------------------
    // Required overrides
    //----------------------------------------------------------------------

    // Rule name for identification and statistics
    virtual const char* name() const = 0;

    // The pattern to match (obfuscated form)
    virtual AstPtr get_pattern() const = 0;

    // The replacement pattern (simplified form)
    virtual AstPtr get_replacement() const = 0;

    //----------------------------------------------------------------------
    // Optional overrides
    //----------------------------------------------------------------------

    // Whether to generate fuzzed variants (default: false for fast init)
    // TODO: Re-enable after optimizing fuzzer performance
    virtual bool fuzz_pattern() const { return false; }

    // Extra validation after structural match
    // candidate: the matched AST with mops filled in from instruction
    // Return false to reject the match
    virtual bool check_candidate(AstPtr candidate) { return true; }

    // Optional: check constraints on named constants
    // For patterns like "c_minus_2" that must equal -2
    virtual bool check_constants(const std::map<std::string, mop_t>& bindings) {
        return true;
    }

    //----------------------------------------------------------------------
    // Pattern and variant management (called by registry)
    //----------------------------------------------------------------------

    // Get all patterns including fuzzed variants
    std::vector<AstPtr> get_all_patterns();

    // Check if patterns have been generated
    bool patterns_initialized() const { return patterns_initialized_; }

    //----------------------------------------------------------------------
    // Apply replacement
    //----------------------------------------------------------------------

    // Apply the replacement pattern given variable bindings
    // Returns new instruction or nullptr on failure
    minsn_t* apply_replacement(
        const std::map<std::string, mop_t>& bindings,
        mblock_t* blk,
        minsn_t* orig_ins);

    //----------------------------------------------------------------------
    // Statistics
    //----------------------------------------------------------------------

    void increment_hit_count() { hit_count_++; }
    size_t hit_count() const { return hit_count_; }

protected:
    PatternMatchingRule() = default;

private:
    std::vector<AstPtr> all_patterns_;
    bool patterns_initialized_ = false;
    size_t hit_count_ = 0;

    // Generate replacement instruction from pattern
    minsn_t* build_replacement(
        AstPtr replacement,
        const std::map<std::string, mop_t>& bindings,
        mblock_t* blk,
        ea_t ea,
        int size);
};

//--------------------------------------------------------------------------
// Macro for easy rule definition
//--------------------------------------------------------------------------
#define DEFINE_MBA_RULE(ClassName, RuleName, PatternExpr, ReplacementExpr) \
    class ClassName : public PatternMatchingRule { \
    public: \
        const char* name() const override { return RuleName; } \
        AstPtr get_pattern() const override { \
            return PatternExpr; \
        } \
        AstPtr get_replacement() const override { \
            return ReplacementExpr; \
        } \
    }

//--------------------------------------------------------------------------
// Macro for rule with constant validation
//--------------------------------------------------------------------------
#define DEFINE_MBA_RULE_WITH_CHECK(ClassName, RuleName, PatternExpr, ReplacementExpr, CheckFn) \
    class ClassName : public PatternMatchingRule { \
    public: \
        const char* name() const override { return RuleName; } \
        AstPtr get_pattern() const override { \
            return PatternExpr; \
        } \
        AstPtr get_replacement() const override { \
            return ReplacementExpr; \
        } \
        bool check_candidate(AstPtr candidate) override { \
            return CheckFn(candidate); \
        } \
    }

//--------------------------------------------------------------------------
// Utility functions for rule definitions
//--------------------------------------------------------------------------

// Create variable leaves
inline AstPtr x_0() { return make_leaf("x_0"); }
inline AstPtr x_1() { return make_leaf("x_1"); }
inline AstPtr x_2() { return make_leaf("x_2"); }
inline AstPtr x_3() { return make_leaf("x_3"); }

// Create constant leaves
// Note: make_const creates constants with name = stringified value ("0", "1", "2")
// check_const_value calls must use these names, not "c_0", "c_1", "c_2"
inline AstPtr c_0() { return make_const(0); }
inline AstPtr c_1() { return make_const(1); }
inline AstPtr c_2() { return make_const(2); }
inline AstPtr c_minus_1() { return make_named_const("c_minus_1", 0xFFFFFFFFFFFFFFFFULL); }
inline AstPtr c_minus_2() { return make_named_const("c_minus_2", 0xFFFFFFFFFFFFFFFEULL); }

// Shorthand for common operations
inline AstPtr add(AstPtr l, AstPtr r) { return make_node(m_add, l, r); }
inline AstPtr sub(AstPtr l, AstPtr r) { return make_node(m_sub, l, r); }
inline AstPtr mul(AstPtr l, AstPtr r) { return make_node(m_mul, l, r); }
inline AstPtr band(AstPtr l, AstPtr r) { return make_node(m_and, l, r); }
inline AstPtr bor(AstPtr l, AstPtr r) { return make_node(m_or, l, r); }
inline AstPtr bxor(AstPtr l, AstPtr r) { return make_node(m_xor, l, r); }
inline AstPtr bnot(AstPtr o) { return make_unary(m_bnot, o); }
inline AstPtr neg(AstPtr o) { return make_unary(m_neg, o); }

//--------------------------------------------------------------------------
// Validation helpers
//--------------------------------------------------------------------------

// Check if a named constant has the expected value
bool check_const_value(const std::map<std::string, mop_t>& bindings,
                       const std::string& name,
                       uint64_t expected,
                       int size);

// Check if constant equals -2 in two's complement for operand size
bool is_minus_2(const mop_t& mop);

// Check if constant equals -1 (all ones)
bool is_minus_1(const mop_t& mop);

// Get constant value from mop
bool get_const_value(const mop_t& mop, uint64_t* out);

} // namespace rules
} // namespace chernobog
