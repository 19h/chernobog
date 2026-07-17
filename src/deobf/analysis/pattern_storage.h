#pragma once
#include "ast.h"
#include "../../common/simd.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <utility>

//--------------------------------------------------------------------------
// Pattern Storage for Efficient Pattern Matching - OPTIMIZED
//
// Uses simple flat storage indexed by root opcode for fast initialization.
// Patterns are grouped by their root operation for quick lookup during
// matching.
//
// OPTIMIZATIONS:
//   - unordered_map for O(1) opcode lookup
//   - Non-mutating match function eliminates clone per attempt
//
// Ported from d810-ng's handler.py PatternStorage class (simplified)
//--------------------------------------------------------------------------

namespace chernobog {

// Forward declaration from rules namespace
namespace rules {
class PatternMatchingRule;
}

namespace ast {

// Use the rules namespace PatternMatchingRule
using PatternMatchingRule = rules::PatternMatchingRule;

//--------------------------------------------------------------------------
// Pattern-rule association
//--------------------------------------------------------------------------
struct RulePatternInfo {
    PatternMatchingRule* rule;
    AstPtr pattern;

    RulePatternInfo(PatternMatchingRule* r, AstPtr p)
        : rule(r), pattern(std::move(p)) {}
};

//--------------------------------------------------------------------------
// Simple Flat Pattern Storage - OPTIMIZED
// Uses unordered_map for O(1) opcode lookup
//--------------------------------------------------------------------------
class PatternStorage {
public:
    explicit PatternStorage(int depth = 1);

    // Add a pattern for a rule - O(1) operation
    void add_pattern_for_rule(AstPtr pattern, PatternMatchingRule* rule);

    // Find all rules whose patterns match the candidate AST
    // Returns const reference to avoid copy
    const std::vector<RulePatternInfo>& get_matching_rules(AstPtr candidate);

    // Get total number of patterns stored
    size_t pattern_count() const { return total_patterns_; }

    // Debug: print storage structure
    void dump(int indent = 0) const;

private:
    // OPTIMIZED: unordered_map for O(1) lookup
    // Patterns indexed by root opcode (-1 for leaf patterns)
    std::unordered_map<int, std::vector<RulePatternInfo>> patterns_by_opcode_;

    // Empty vector for returning when no patterns match
    static const std::vector<RulePatternInfo> empty_patterns_;

    // Total pattern count
    size_t total_patterns_ = 0;
};

} // namespace ast
} // namespace chernobog
