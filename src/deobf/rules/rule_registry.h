#pragma once
#include "pattern_rule.h"
#include "../analysis/pattern_storage.h"
#include <memory>
#include <vector>
#include <map>
#include <mutex>

//--------------------------------------------------------------------------
// Rule Registry - Central management of all MBA simplification rules
//
// Features:
//   - Singleton pattern for global access
//   - Automatic rule registration via REGISTER_MBA_RULE macro
//   - Pattern storage integration for O(log n) matching
//   - Statistics tracking per rule
//
// Usage:
//   1. Rules register themselves at static initialization
//   2. Call RuleRegistry::instance().initialize() to build pattern index
//   3. Use find_match() to find applicable rules for an instruction
//--------------------------------------------------------------------------

namespace chernobog {
namespace rules {

using namespace ast;

//--------------------------------------------------------------------------
// Rule Registry Singleton
//--------------------------------------------------------------------------
class RuleRegistry {
public:
    // Singleton access
    static RuleRegistry& instance();

    // Delete copy/move
    RuleRegistry(const RuleRegistry&) = delete;
    RuleRegistry& operator=(const RuleRegistry&) = delete;

    //----------------------------------------------------------------------
    // Registration
    //----------------------------------------------------------------------

    // Register a rule (called by REGISTER_MBA_RULE macro)
    void register_rule(std::unique_ptr<PatternMatchingRule> rule);

    // Initialize pattern storage (must be called before matching)
    void initialize();

    // Check if initialized
    bool is_initialized() const { return initialized_; }

    // Re-initialize (e.g., after configuration change)
    void reinitialize();

    //----------------------------------------------------------------------
    // Matching
    //----------------------------------------------------------------------

    struct MatchResult {
        PatternMatchingRule* rule;
        AstPtr matched_pattern;
        std::map<std::string, mop_t> bindings;

        MatchResult() : rule(nullptr) {}
        bool matched() const { return rule != nullptr; }
    };

    // Find first matching rule for instruction
    MatchResult find_match(const minsn_t* ins);

    // Find all matching rules
    std::vector<MatchResult> find_all_matches(const minsn_t* ins);

    //----------------------------------------------------------------------
    // Statistics
    //----------------------------------------------------------------------

    // Number of registered rules
    size_t rule_count() const { return rules_.size(); }

    // Number of patterns (including fuzzed variants)
    size_t pattern_count() const;

    // Get rule hit statistics
    std::map<std::string, size_t> get_hit_statistics() const;

    // Total matches performed
    size_t total_matches() const { return total_matches_; }
    size_t successful_matches() const { return successful_matches_; }

    // Clear statistics
    void clear_statistics();

    //----------------------------------------------------------------------
    // Debug
    //----------------------------------------------------------------------

    // Dump registry state
    void dump() const;

    // List all rules
    std::vector<std::string> list_rules() const;

private:
    RuleRegistry() = default;

    std::vector<std::unique_ptr<PatternMatchingRule>> rules_;
    PatternStorage storage_;
    bool initialized_ = false;
    mutable std::mutex mutex_;

    // Statistics
    size_t total_matches_ = 0;
    size_t successful_matches_ = 0;

    // Internal matching helper
    bool try_match_pattern(AstPtr pattern, AstPtr candidate,
                          std::map<std::string, mop_t>& bindings);
};

//--------------------------------------------------------------------------
// Registration macro for automatic rule registration
//--------------------------------------------------------------------------
#define REGISTER_MBA_RULE(RuleClass) \
    namespace { \
        static bool _registered_##RuleClass = []() { \
            ::chernobog::rules::RuleRegistry::instance().register_rule( \
                std::make_unique<RuleClass>()); \
            return true; \
        }(); \
    }

//--------------------------------------------------------------------------
// Initialization helper (call from plugin init)
//--------------------------------------------------------------------------
void initialize_mba_rules();

} // namespace rules
} // namespace chernobog
