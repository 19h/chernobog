#include "pattern_storage.h"
#include "ast_builder.h"
#include <sstream>
#include <algorithm>
#include <cmath>

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// SignatureUtils implementation (kept for compatibility)
//--------------------------------------------------------------------------
std::string SignatureUtils::join_signature(const std::vector<std::string>& sig) {
    std::ostringstream ss;
    for (size_t i = 0; i < sig.size(); i++) {
        if (i > 0) ss << ",";
        ss << sig[i];
    }
    return ss.str();
}

std::vector<std::string> SignatureUtils::split_signature(const std::string& key) {
    std::vector<std::string> result;
    std::istringstream ss(key);
    std::string token;
    while (std::getline(ss, token, ',')) {
        result.push_back(token);
    }
    return result;
}

std::vector<std::vector<std::string>>
SignatureUtils::generate_compatible_signatures(const std::vector<std::string>& ref_sig) {
    std::vector<std::vector<std::string>> result;

    // Start with the original signature
    result.push_back(ref_sig);

    // Generate variants by replacing non-wildcards with "L"
    // This allows matching variable patterns against actual values
    for (size_t i = 0; i < ref_sig.size(); i++) {
        const std::string& elem = ref_sig[i];

        // Only replace elements that are not already wildcards
        if (elem != "N" && elem != "L") {
            // Create variants for all existing results
            size_t current_size = result.size();
            for (size_t j = 0; j < current_size; j++) {
                std::vector<std::string> variant = result[j];
                variant[i] = "L";
                result.push_back(variant);
            }
        }
    }

    return result;
}

bool SignatureUtils::compatible(const std::vector<std::string>& inst_sig,
                                const std::vector<std::string>& pat_sig) {
    if (inst_sig.size() != pat_sig.size()) {
        return false;
    }

    for (size_t i = 0; i < inst_sig.size(); i++) {
        const std::string& inst = inst_sig[i];
        const std::string& pat = pat_sig[i];

        // Wildcards match anything
        if (pat == "L" || pat == "N") {
            continue;
        }

        // "C" matches only constants (also "C" in inst_sig)
        if (pat == "C") {
            if (inst != "C") {
                return false;
            }
            continue;
        }

        // Specific opcode must match exactly
        if (inst != pat) {
            return false;
        }
    }

    return true;
}

int SignatureUtils::count_specific_elements(const std::vector<std::string>& sig) {
    int count = 0;
    for (const auto& s : sig) {
        if (s != "N" && s != "L") {
            count++;
        }
    }
    return count;
}

//--------------------------------------------------------------------------
// PatternStorage implementation - Simple flat storage
//--------------------------------------------------------------------------
PatternStorage::PatternStorage(int depth)
    : depth_(depth)
{
}

void PatternStorage::add_pattern_for_rule(AstPtr pattern, PatternMatchingRule* rule) {
    if (!pattern) {
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

std::vector<RulePatternInfo> PatternStorage::get_matching_rules(AstPtr candidate) {
    if (!candidate) {
        return {};
    }

    // Get candidate's root opcode
    int opcode = -1;
    if (candidate->is_node()) {
        auto node = std::static_pointer_cast<AstNode>(candidate);
        opcode = static_cast<int>(node->opcode);
    }

    // Return all patterns with matching root opcode
    auto it = patterns_by_opcode_.find(opcode);
    if (it != patterns_by_opcode_.end()) {
        return it->second;
    }

    return {};
}

size_t PatternStorage::pattern_count() const {
    return total_patterns_;
}

void PatternStorage::dump(int indent) const {
    std::string prefix(indent * 2, ' ');

    msg("%sPatternStorage (flat):\n", prefix.c_str());
    msg("%s  Total patterns: %zu\n", prefix.c_str(), total_patterns_);

    for (const auto& kv : patterns_by_opcode_) {
        msg("%s  Opcode %d: %zu patterns\n", prefix.c_str(), kv.first, kv.second.size());
    }
}

//--------------------------------------------------------------------------
// PatternMatcher implementation
//--------------------------------------------------------------------------
void PatternMatcher::register_rule(PatternMatchingRule* rule) {
    if (!rule) {
        return;
    }

    // Get all patterns from the rule (including fuzzed variants)
    // This will be implemented after we create the rule base class
    // For now, we'll add a placeholder

    rule_count_++;
}

bool PatternMatcher::try_match_pattern(AstPtr pattern, AstPtr candidate,
                                       std::map<std::string, mop_t>& bindings) {
    if (!pattern || !candidate) {
        return false;
    }

    // Both must be same type (node vs leaf)
    if (pattern->is_node() != candidate->is_node()) {
        return false;
    }

    if (pattern->is_leaf()) {
        auto pat_leaf = std::static_pointer_cast<AstLeaf>(pattern);

        // Constants must match value
        if (pattern->is_constant()) {
            if (!candidate->is_constant()) {
                return false;
            }
            auto pat_const = std::static_pointer_cast<AstConstant>(pattern);
            auto cand_const = std::static_pointer_cast<AstConstant>(candidate);

            // Named constants match by name (will be validated later)
            if (!pat_const->const_name.empty()) {
                bindings[pat_const->const_name] = candidate->mop;
                return true;
            }

            // Value constants must match exactly
            return pat_const->value == cand_const->value;
        }

        // Variable leaf - record binding
        bindings[pat_leaf->name] = candidate->mop;
        return true;
    }

    // Both are nodes
    auto pat_node = std::static_pointer_cast<AstNode>(pattern);
    auto cand_node = std::static_pointer_cast<AstNode>(candidate);

    // Opcode must match
    if (pat_node->opcode != cand_node->opcode) {
        return false;
    }

    // Recurse on children
    if (pat_node->left) {
        if (!cand_node->left) {
            return false;
        }
        if (!try_match_pattern(pat_node->left, cand_node->left, bindings)) {
            return false;
        }
    }

    if (pat_node->right) {
        if (!cand_node->right) {
            return false;
        }
        if (!try_match_pattern(pat_node->right, cand_node->right, bindings)) {
            return false;
        }
    } else if (cand_node->right) {
        // Pattern has no right but candidate does
        return false;
    }

    return true;
}

PatternMatcher::MatchResult PatternMatcher::find_match(const minsn_t* ins) {
    if (!ins) {
        return MatchResult();
    }

    // Convert instruction to AST
    AstPtr candidate = minsn_to_ast(ins);
    if (!candidate) {
        return MatchResult();
    }

    // Get matching rules from storage
    auto matches = storage_.get_matching_rules(candidate);

    // Try each pattern until one matches
    for (const auto& rp : matches) {
        std::map<std::string, mop_t> bindings;

        // Clone pattern for matching (will have mops copied)
        AstPtr pattern_copy = rp.pattern->clone();

        if (pattern_copy->is_node()) {
            auto node = std::static_pointer_cast<AstNode>(pattern_copy);
            if (node->check_pattern_and_copy_mops(candidate)) {
                // Build bindings from matched leaves
                auto leaves = node->get_leafs_by_name();
                for (const auto& kv : leaves) {
                    bindings[kv.first] = kv.second->mop;
                }

                // Check extra validation if rule has one
                if (rp.rule) {
                    // Rule validation will be checked after rule class is implemented
                    return MatchResult(rp.rule, rp.pattern, bindings);
                }
            }
        }
    }

    return MatchResult();
}

std::vector<PatternMatcher::MatchResult> PatternMatcher::find_all_matches(
    const minsn_t* ins) {

    std::vector<MatchResult> results;

    if (!ins) {
        return results;
    }

    // Convert instruction to AST
    AstPtr candidate = minsn_to_ast(ins);
    if (!candidate) {
        return results;
    }

    // Get matching rules from storage
    auto matches = storage_.get_matching_rules(candidate);

    // Try each pattern
    for (const auto& rp : matches) {
        std::map<std::string, mop_t> bindings;

        AstPtr pattern_copy = rp.pattern->clone();

        if (pattern_copy->is_node()) {
            auto node = std::static_pointer_cast<AstNode>(pattern_copy);
            if (node->check_pattern_and_copy_mops(candidate)) {
                auto leaves = node->get_leafs_by_name();
                for (const auto& kv : leaves) {
                    bindings[kv.first] = kv.second->mop;
                }
                results.emplace_back(rp.rule, rp.pattern, bindings);
            }
        }
    }

    return results;
}

} // namespace ast
} // namespace chernobog
