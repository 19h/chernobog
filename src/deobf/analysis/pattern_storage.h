#pragma once
#include "ast.h"
#include <memory>
#include <vector>
#include <map>
#include <string>

//--------------------------------------------------------------------------
// Hierarchical Pattern Storage for Efficient Pattern Matching
//
// This system provides O(log n) pattern lookup by organizing patterns
// in a multi-level trie-like structure indexed by depth signatures.
//
// Key concepts:
//   - Depth signature: At each tree depth, a signature is generated
//     encoding opcodes ("10"), leaves ("L"), constants ("C"), or none ("N")
//   - Patterns are stored at the depth where they become unique
//   - Matching uses adaptive algorithm: either enumerate signatures
//     or iterate storage depending on density
//
// Ported from d810-ng's handler.py PatternStorage class
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
        : rule(r), pattern(p) {}
};

//--------------------------------------------------------------------------
// Signature utilities
//--------------------------------------------------------------------------
class SignatureUtils {
public:
    // Join signature vector into comma-separated string key
    static std::string join_signature(const std::vector<std::string>& sig);

    // Split signature string back to vector
    static std::vector<std::string> split_signature(const std::string& key);

    // Generate all compatible signatures by replacing non-wildcards with "L"
    // This allows matching patterns with variables against actual constants
    static std::vector<std::vector<std::string>>
    generate_compatible_signatures(const std::vector<std::string>& ref_sig);

    // Check if two signatures are compatible
    // Pattern sig can have "L" (any leaf) or "C" (constant only)
    // Instance sig has actual opcodes
    static bool compatible(const std::vector<std::string>& inst_sig,
                          const std::vector<std::string>& pat_sig);

    // Count non-wildcard elements (not "N" or "L")
    static int count_specific_elements(const std::vector<std::string>& sig);
};

//--------------------------------------------------------------------------
// Hierarchical Pattern Storage
//--------------------------------------------------------------------------
class PatternStorage {
public:
    explicit PatternStorage(int depth = 1);

    // Add a pattern for a rule
    void add_pattern_for_rule(AstPtr pattern, PatternMatchingRule* rule);

    // Find all rules whose patterns match the candidate AST
    std::vector<RulePatternInfo> get_matching_rules(AstPtr candidate);

    // Get total number of patterns stored
    size_t pattern_count() const;

    // Debug: print storage structure
    void dump(int indent = 0) const;

private:
    int depth_;  // Current depth level

    // Next layer patterns: signature -> (split_sig, next_storage)
    struct NextLayerEntry {
        std::vector<std::string> split_sig;
        std::unique_ptr<PatternStorage> storage;
    };
    std::map<std::string, NextLayerEntry> next_layer_patterns_;

    // Rules resolved at this depth (pattern fully matched)
    std::vector<RulePatternInfo> resolved_rules_;

    // Internal: explore patterns at this level and below
    std::vector<RulePatternInfo> explore_one_level(
        AstPtr candidate, int cur_level);
};

//--------------------------------------------------------------------------
// Pattern Matcher - High-level interface for rule matching
//--------------------------------------------------------------------------
class PatternMatcher {
public:
    PatternMatcher() = default;

    // Register a rule with its patterns (including fuzzed variants)
    void register_rule(PatternMatchingRule* rule);

    // Match result
    struct MatchResult {
        PatternMatchingRule* rule;
        AstPtr matched_pattern;
        std::map<std::string, mop_t> bindings;  // Variable name -> operand

        MatchResult() : rule(nullptr) {}
        MatchResult(PatternMatchingRule* r, AstPtr p,
                   const std::map<std::string, mop_t>& b)
            : rule(r), matched_pattern(p), bindings(b) {}

        bool matched() const { return rule != nullptr; }
    };

    // Find first matching rule for an instruction
    MatchResult find_match(const minsn_t* ins);

    // Find all matching rules
    std::vector<MatchResult> find_all_matches(const minsn_t* ins);

    // Statistics
    size_t rule_count() const { return rule_count_; }
    size_t pattern_count() const { return storage_.pattern_count(); }

private:
    PatternStorage storage_;
    size_t rule_count_ = 0;

    // Try to match a single pattern against candidate AST
    bool try_match_pattern(AstPtr pattern, AstPtr candidate,
                          std::map<std::string, mop_t>& bindings);
};

} // namespace ast
} // namespace chernobog
