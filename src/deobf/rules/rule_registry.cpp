#include "rule_registry.h"
#include "../analysis/ast_builder.h"

namespace chernobog {
namespace rules {

using namespace ast;

//--------------------------------------------------------------------------
// Singleton implementation
//--------------------------------------------------------------------------
RuleRegistry& RuleRegistry::instance() {
    static RuleRegistry instance;
    return instance;
}

//--------------------------------------------------------------------------
// Registration
//--------------------------------------------------------------------------
void RuleRegistry::register_rule(std::unique_ptr<PatternMatchingRule> rule) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (rule) {
        rules_.push_back(std::move(rule));
    }
}

void RuleRegistry::initialize() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (initialized_) {
        return;
    }

    // Build pattern storage from all rules
    storage_ = PatternStorage(1);

    for (auto& rule : rules_) {
        if (!rule) continue;

        // Get all patterns (including fuzzed variants)
        auto patterns = rule->get_all_patterns();

        for (const auto& pattern : patterns) {
            if (pattern) {
                storage_.add_pattern_for_rule(pattern, rule.get());
            }
        }
    }

    initialized_ = true;

    msg("[chernobog] MBA rule registry initialized: %zu rules, %zu patterns\n",
        rules_.size(), pattern_count());
}

void RuleRegistry::reinitialize() {
    std::lock_guard<std::mutex> lock(mutex_);

    initialized_ = false;
    storage_ = PatternStorage(1);

    // Rebuild
    for (auto& rule : rules_) {
        if (!rule) continue;

        auto patterns = rule->get_all_patterns();

        for (const auto& pattern : patterns) {
            if (pattern) {
                storage_.add_pattern_for_rule(pattern, rule.get());
            }
        }
    }

    initialized_ = true;
}

//--------------------------------------------------------------------------
// Matching
//--------------------------------------------------------------------------
RuleRegistry::MatchResult RuleRegistry::find_match(const minsn_t* ins) {
    if (!ins || !initialized_) {
        return MatchResult();
    }

    total_matches_++;

    // Convert instruction to AST
    AstPtr candidate = minsn_to_ast(ins);
    if (!candidate) {
        return MatchResult();
    }

    // Get matching patterns from storage
    auto matches = storage_.get_matching_rules(candidate);

    // Try each match
    for (const auto& rp : matches) {
        if (!rp.rule || !rp.pattern) {
            continue;
        }

        std::map<std::string, mop_t> bindings;

        // Clone pattern for matching
        AstPtr pattern_copy = rp.pattern->clone();

        if (pattern_copy->is_node()) {
            auto node = std::static_pointer_cast<AstNode>(pattern_copy);

            if (node->check_pattern_and_copy_mops(candidate)) {
                // Extract bindings
                auto leaves = node->get_leafs_by_name();
                for (const auto& kv : leaves) {
                    bindings[kv.first] = kv.second->mop;
                }

                // Check extra validation
                if (!rp.rule->check_candidate(pattern_copy)) {
                    continue;
                }

                // Check constant constraints
                if (!rp.rule->check_constants(bindings)) {
                    continue;
                }

                // Success!
                successful_matches_++;
                rp.rule->increment_hit_count();

                MatchResult result;
                result.rule = rp.rule;
                result.matched_pattern = rp.pattern;
                result.bindings = bindings;
                return result;
            }
        }
    }

    return MatchResult();
}

std::vector<RuleRegistry::MatchResult> RuleRegistry::find_all_matches(
    const minsn_t* ins) {

    std::vector<MatchResult> results;

    if (!ins || !initialized_) {
        return results;
    }

    // Convert instruction to AST
    AstPtr candidate = minsn_to_ast(ins);
    if (!candidate) {
        return results;
    }

    // Get matching patterns
    auto matches = storage_.get_matching_rules(candidate);

    for (const auto& rp : matches) {
        if (!rp.rule || !rp.pattern) {
            continue;
        }

        std::map<std::string, mop_t> bindings;
        AstPtr pattern_copy = rp.pattern->clone();

        if (pattern_copy->is_node()) {
            auto node = std::static_pointer_cast<AstNode>(pattern_copy);

            if (node->check_pattern_and_copy_mops(candidate)) {
                auto leaves = node->get_leafs_by_name();
                for (const auto& kv : leaves) {
                    bindings[kv.first] = kv.second->mop;
                }

                if (!rp.rule->check_candidate(pattern_copy)) {
                    continue;
                }

                if (!rp.rule->check_constants(bindings)) {
                    continue;
                }

                MatchResult result;
                result.rule = rp.rule;
                result.matched_pattern = rp.pattern;
                result.bindings = bindings;
                results.push_back(result);
            }
        }
    }

    return results;
}

//--------------------------------------------------------------------------
// Statistics
//--------------------------------------------------------------------------
size_t RuleRegistry::pattern_count() const {
    return storage_.pattern_count();
}

std::map<std::string, size_t> RuleRegistry::get_hit_statistics() const {
    std::map<std::string, size_t> stats;

    for (const auto& rule : rules_) {
        if (rule) {
            stats[rule->name()] = rule->hit_count();
        }
    }

    return stats;
}

void RuleRegistry::clear_statistics() {
    total_matches_ = 0;
    successful_matches_ = 0;

    // Note: Rule hit counts are not cleared as they're per-rule statistics
}

//--------------------------------------------------------------------------
// Debug
//--------------------------------------------------------------------------
void RuleRegistry::dump() const {
    msg("[chernobog] MBA Rule Registry:\n");
    msg("  Rules: %zu\n", rules_.size());
    msg("  Patterns: %zu\n", pattern_count());
    msg("  Total matches attempted: %zu\n", total_matches_);
    msg("  Successful matches: %zu\n", successful_matches_);

    msg("  Rule list:\n");
    for (const auto& rule : rules_) {
        if (rule) {
            msg("    - %s (hits: %zu)\n", rule->name(), rule->hit_count());
        }
    }
}

std::vector<std::string> RuleRegistry::list_rules() const {
    std::vector<std::string> names;
    for (const auto& rule : rules_) {
        if (rule) {
            names.push_back(rule->name());
        }
    }
    return names;
}

//--------------------------------------------------------------------------
// Initialization helper
//--------------------------------------------------------------------------
void initialize_mba_rules() {
    RuleRegistry::instance().initialize();
}

} // namespace rules
} // namespace chernobog
