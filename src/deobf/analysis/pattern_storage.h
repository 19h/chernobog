#pragma once
#include "ast.h"
#include "../../common/simd.h"
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>

//--------------------------------------------------------------------------
// Pattern Storage for Efficient Pattern Matching - OPTIMIZED
//
// Uses simple flat storage indexed by root opcode for fast initialization.
// Patterns are grouped by their root operation for quick lookup during
// matching.
//
// OPTIMIZATIONS:
//   - unordered_map for O(1) opcode lookup
//   - SmallVector for pattern lists to reduce allocations
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
// Pattern structural signature for fast rejection
// Pre-computed at registration time, compared with SIMD before full match
//--------------------------------------------------------------------------
struct alignas(16) PatternStructure {
    uint64_t opcode_hash;      // Hash of opcode tree (depth-first)
    uint16_t depth;            // Tree depth
    uint16_t node_count;       // Number of operation nodes
    uint16_t leaf_count;       // Number of leaf nodes (variables)
    uint16_t const_count;      // Number of constant nodes
    
    static PatternStructure from_ast(const AstBase* node);
    
    // Fast SIMD equality check
    SIMD_FORCE_INLINE bool operator==(const PatternStructure& other) const {
        // Compare as two 64-bit values
        return opcode_hash == other.opcode_hash && 
               *reinterpret_cast<const uint64_t*>(&depth) == 
               *reinterpret_cast<const uint64_t*>(&other.depth);
    }
    
    // Check if candidate could match pattern (pattern may have wildcards)
    SIMD_FORCE_INLINE bool compatible_with(const PatternStructure& candidate) const {
        // Structural counts must match exactly
        if (depth != candidate.depth) return false;
        if (node_count != candidate.node_count) return false;
        // leaf_count can differ (pattern has variables, candidate has actual values)
        return true;
    }
};

//--------------------------------------------------------------------------
// Pattern-rule association with pre-computed signature
//--------------------------------------------------------------------------
struct RulePatternInfo {
    PatternMatchingRule* rule;
    AstPtr pattern;
    PatternStructure structure;  // Pre-computed for O(1) rejection

    RulePatternInfo(PatternMatchingRule* r, AstPtr p)
        : rule(r), pattern(p), structure(PatternStructure::from_ast(p.get())) {}
};

//--------------------------------------------------------------------------
// Signature utilities (kept for compatibility)
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
    int depth_;  // Unused in simplified version, kept for API compatibility

    // OPTIMIZED: unordered_map for O(1) lookup
    // Patterns indexed by root opcode (-1 for leaf patterns)
    std::unordered_map<int, std::vector<RulePatternInfo>> patterns_by_opcode_;

    // Empty vector for returning when no patterns match
    static const std::vector<RulePatternInfo> empty_patterns_;

    // Total pattern count
    size_t total_patterns_ = 0;
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
