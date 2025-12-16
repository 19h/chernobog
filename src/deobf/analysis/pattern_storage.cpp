#include "pattern_storage.h"
#include "ast_builder.h"
#include <sstream>
#include <algorithm>
#include <cmath>

namespace chernobog {
namespace ast {

//--------------------------------------------------------------------------
// SignatureUtils implementation
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
// PatternStorage implementation
//--------------------------------------------------------------------------
PatternStorage::PatternStorage(int depth)
    : depth_(depth)
{
}

void PatternStorage::add_pattern_for_rule(AstPtr pattern, PatternMatchingRule* rule) {
    if (!pattern) {
        return;
    }

    // Get signature at current depth
    std::vector<std::string> sig = pattern->get_depth_signature(depth_);
    std::string sig_key = SignatureUtils::join_signature(sig);

    // Check if all elements are "N" (tree fully traversed at this depth)
    bool all_none = true;
    for (const auto& s : sig) {
        if (s != "N") {
            all_none = false;
            break;
        }
    }

    if (all_none) {
        // Pattern fully resolved at this depth
        resolved_rules_.emplace_back(rule, pattern);
    } else {
        // Need to go deeper
        auto it = next_layer_patterns_.find(sig_key);
        if (it == next_layer_patterns_.end()) {
            NextLayerEntry entry;
            entry.split_sig = sig;
            entry.storage = std::make_unique<PatternStorage>(depth_ + 1);
            next_layer_patterns_[sig_key] = std::move(entry);
            it = next_layer_patterns_.find(sig_key);
        }

        it->second.storage->add_pattern_for_rule(pattern, rule);
    }
}

std::vector<RulePatternInfo> PatternStorage::get_matching_rules(AstPtr candidate) {
    if (!candidate) {
        return {};
    }

    return explore_one_level(candidate, depth_);
}

std::vector<RulePatternInfo> PatternStorage::explore_one_level(
    AstPtr candidate, int cur_level) {

    std::vector<RulePatternInfo> matched;

    // Add rules resolved at this level
    matched.insert(matched.end(), resolved_rules_.begin(), resolved_rules_.end());

    if (next_layer_patterns_.empty()) {
        return matched;
    }

    // Get candidate's signature at current level
    std::vector<std::string> cand_sig = candidate->get_depth_signature(cur_level);

    // Count specific (non-wildcard) elements
    int specific_count = SignatureUtils::count_specific_elements(cand_sig);

    // Calculate number of possible signatures: 2^specific_count
    int nb_possible_sigs = 1 << specific_count;

    // Choose matching strategy based on density
    if (nb_possible_sigs < static_cast<int>(next_layer_patterns_.size())) {
        // Strategy 1: Generate all possible signatures and look them up
        // More efficient when signature space is smaller than storage
        auto possible_sigs = SignatureUtils::generate_compatible_signatures(cand_sig);

        for (const auto& sig : possible_sigs) {
            std::string sig_key = SignatureUtils::join_signature(sig);
            auto it = next_layer_patterns_.find(sig_key);
            if (it != next_layer_patterns_.end()) {
                // Found matching signature, recurse
                auto sub_matches = it->second.storage->explore_one_level(
                    candidate, cur_level + 1);
                matched.insert(matched.end(), sub_matches.begin(), sub_matches.end());
            }
        }
    } else {
        // Strategy 2: Iterate storage and check compatibility
        // More efficient when storage is sparser
        for (const auto& kv : next_layer_patterns_) {
            if (SignatureUtils::compatible(cand_sig, kv.second.split_sig)) {
                auto sub_matches = kv.second.storage->explore_one_level(
                    candidate, cur_level + 1);
                matched.insert(matched.end(), sub_matches.begin(), sub_matches.end());
            }
        }
    }

    return matched;
}

size_t PatternStorage::pattern_count() const {
    size_t count = resolved_rules_.size();
    for (const auto& kv : next_layer_patterns_) {
        count += kv.second.storage->pattern_count();
    }
    return count;
}

void PatternStorage::dump(int indent) const {
    std::string prefix(indent * 2, ' ');

    msg("%sPatternStorage[depth=%d]:\n", prefix.c_str(), depth_);

    if (!resolved_rules_.empty()) {
        msg("%s  Resolved rules: %zu\n", prefix.c_str(), resolved_rules_.size());
        for (const auto& rp : resolved_rules_) {
            msg("%s    - %s\n", prefix.c_str(),
                rp.pattern ? rp.pattern->to_string().c_str() : "(null)");
        }
    }

    for (const auto& kv : next_layer_patterns_) {
        msg("%s  [%s]:\n", prefix.c_str(), kv.first.c_str());
        kv.second.storage->dump(indent + 2);
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
