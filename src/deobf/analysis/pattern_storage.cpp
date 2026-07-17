#include "pattern_storage.h"

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// PatternStorage implementation - OPTIMIZED
// Uses unordered_map for O(1) lookup, returns const ref to avoid copy
//--------------------------------------------------------------------------

// Static empty vector for when no patterns match
const std::vector<RulePatternInfo> PatternStorage::empty_patterns_;

PatternStorage::PatternStorage(int depth)
{
    (void)depth;
    // Pre-allocate buckets for common opcodes
    patterns_by_opcode_.reserve(32);
}

void PatternStorage::add_pattern_for_rule(AstPtr pattern, PatternMatchingRule* rule) {
    if (SIMD_UNLIKELY(!pattern)) {
        return;
    }

    // Get root opcode (-1 for leaf patterns)
    int opcode = -1;
    if (pattern->is_node()) {
        auto node = std::static_pointer_cast<AstNode>(pattern);
        opcode = static_cast<int>(node->opcode);
    }

    // Simply add to the vector for this opcode - O(1) amortized
    patterns_by_opcode_[opcode].emplace_back(rule, pattern);
    total_patterns_++;
}

const std::vector<RulePatternInfo>& PatternStorage::get_matching_rules(AstPtr candidate) {
    if (SIMD_UNLIKELY(!candidate)) {
        return empty_patterns_;
    }

    // Get candidate's root opcode
    int opcode = -1;
    if (candidate->is_node()) {
        auto node = std::static_pointer_cast<AstNode>(candidate);
        opcode = static_cast<int>(node->opcode);
    }

    // O(1) lookup, return const ref to avoid copy
    auto it = patterns_by_opcode_.find(opcode);
    if (SIMD_LIKELY(it != patterns_by_opcode_.end())) {
        return it->second;
    }

    return empty_patterns_;
}

void PatternStorage::dump(int indent) const {
    std::string prefix(indent * 2, ' ');

    msg("%sPatternStorage (flat):\n", prefix.c_str());
    msg("%s  Total patterns: %zu\n", prefix.c_str(), total_patterns_);

    for (const auto& kv : patterns_by_opcode_) {
        msg("%s  Opcode %d: %zu patterns\n", prefix.c_str(), kv.first, kv.second.size());
    }
}

} // namespace ast
} // namespace chernobog
