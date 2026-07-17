#include "rule_registry.h"
#include "rule_verifier.h"
#include "../analysis/ast_builder.h"

namespace chernobog {
namespace rules {

using namespace ast;

//--------------------------------------------------------------------------
// Singleton implementation
//--------------------------------------------------------------------------
RuleRegistry& RuleRegistry::instance()
{
    // CRITICAL: Use heap-allocated singleton that intentionally leaks on exit.
    // This is necessary because the RuleRegistry contains AST nodes with mop_t
    // members, and mop_t's destructor calls IDA functions. During static
    // destruction at exit, IDA's library is already unloaded, so calling any
    // mop_t method (including the destructor) causes a crash.
    //
    // By using a heap-allocated singleton that never gets deleted, we avoid
    // the destructor being called during exit. The memory leak is intentional
    // and harmless since the process is exiting anyway.
    static RuleRegistry* instance = new RuleRegistry();
    return *instance;
}

//--------------------------------------------------------------------------
// Registration
//--------------------------------------------------------------------------
void RuleRegistry::register_rule(std::unique_ptr<PatternMatchingRule> rule)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if ( rule )
    {
        rules_.push_back(std::move(rule));
    }
}

void RuleRegistry::initialize()
{
    std::lock_guard<std::mutex> lock(mutex_);

    if ( initialized_ )
    {
        return;
    }

    rebuild_storage_locked();

#if !defined(CHERNOBOG_CATALOG_TEST)
    msg("[chernobog] MBA rule registry initialized: %zu registered, "
        "%zu verified, %zu rejected, %zu patterns\n",
        rules_.size(), verified_rule_count_, rejected_rule_count_, pattern_count());
#endif
}

void RuleRegistry::reinitialize()
{
    std::lock_guard<std::mutex> lock(mutex_);

    rebuild_storage_locked();
}

void RuleRegistry::rebuild_storage_locked()
{
    initialized_ = false;
    storage_ = PatternStorage(1);
    semantic_roots_.clear();
    verified_rule_count_ = 0;
    rejected_rule_count_ = 0;

    RuleVerifier verifier;
    for ( auto& rule : rules_ )
    {
        if ( !rule )
            continue;

        AstPtr pattern = rule->get_pattern();
        AstPtr replacement = rule->get_replacement();
        semantic_roots_.push_back(replacement);
        RuleVerificationResult verification = verifier.verify(pattern, replacement);
        if ( !verification.verified() )
        {
            ++rejected_rule_count_;
#if !defined(CHERNOBOG_CATALOG_TEST)
            msg("[chernobog] rejected MBA rule '%s': %s at %u bits (%s)\n",
                rule->name(), rule_verification_status_name(verification.status),
                verification.bit_width, verification.detail.c_str());
#endif
            continue;
        }

        ++verified_rule_count_;
        storage_.add_pattern_for_rule(pattern, rule.get());
    }

    initialized_ = true;
}

void RuleRegistry::clear()
{
    std::lock_guard<std::mutex> lock(mutex_);

    // Clear pattern storage first (it has shared_ptrs to patterns)
    storage_ = PatternStorage(1);

    // Destroy retained certification trees while IDA/Hex-Rays is still live.
    semantic_roots_.clear();

    // Clear rules (this destroys the rule objects)
    rules_.clear();

    // Reset state
    initialized_ = false;
    total_matches_ = 0;
    successful_matches_ = 0;
    verified_rule_count_ = 0;
    rejected_rule_count_ = 0;
}

//--------------------------------------------------------------------------
// Matching - OPTIMIZED
// Uses non-mutating match path to eliminate pattern cloning per attempt.
// Uses stack-allocated MatchBindings to avoid heap allocations.
//--------------------------------------------------------------------------
RuleRegistry::MatchResult RuleRegistry::find_match(const minsn_t* ins)
{
    if ( SIMD_UNLIKELY( !ins || !initialized_ ) )
    {
        return MatchResult();
    }

    ++total_matches_;

    // Convert instruction to AST
    AstPtr candidate = minsn_to_ast(ins);
    if ( SIMD_UNLIKELY( !candidate ) )
    {
        return MatchResult();
    }

    // Get matching patterns from storage - const ref, no copy
    const auto& matches = storage_.get_matching_rules(candidate);

    // Stack-allocated bindings - NO HEAP ALLOCATION PER MATCH ATTEMPT
    MatchBindings match_bindings;

    // Try each match
    for ( const auto& rp : matches )
    {
        if ( SIMD_UNLIKELY( !rp.rule || !rp.pattern ) )
        {
            continue;
        }

        // OPTIMIZED: Non-mutating match - NO PATTERN CLONING
        // match_pattern() doesn't modify pattern, just fills bindings
        if ( match_pattern(rp.pattern.get(), candidate.get(), match_bindings) )
        {
            // Only convert to std::map when we have a structural match
            // This moves the allocation cost to the success path
            std::map<std::string, mop_t> bindings;
            for ( size_t i = 0; i < match_bindings.count; ++i )
            {
                bindings[match_bindings.bindings[i].name] = match_bindings.bindings[i].mop;
            }

            // Check extra validation - pass candidate (unchanged)
            if ( !rp.rule->check_candidate(candidate) )
            {
                continue;
            }

            // Check constant constraints
            if ( !rp.rule->check_constants(bindings) )
            {
                continue;
            }

            // Success!
            ++successful_matches_;
            rp.rule->increment_hit_count();

            // Debug: log successful match
#if !defined(CHERNOBOG_CATALOG_TEST)
            deobf::log_verbose("[chernobog] MBA rule '%s' matched\n",
                               rp.rule->name());
#endif

            MatchResult result;
            result.rule = rp.rule;
            result.matched_pattern = rp.pattern;
            result.bindings = std::move(bindings);
            return result;
        }
    }

    return MatchResult();
}

std::vector<RuleRegistry::MatchResult> RuleRegistry::find_all_matches(
    const minsn_t* ins)
{
    std::vector<MatchResult> results;

    if ( SIMD_UNLIKELY( !ins || !initialized_ ) )
    {
        return results;
    }

    // Convert instruction to AST
    AstPtr candidate = minsn_to_ast(ins);
    if ( SIMD_UNLIKELY( !candidate ) )
    {
        return results;
    }

    // Get matching patterns - const ref, no copy
    const auto& matches = storage_.get_matching_rules(candidate);

    // Reserve for typical case
    results.reserve(4);

    // Stack-allocated bindings - NO HEAP ALLOCATION PER MATCH ATTEMPT
    MatchBindings match_bindings;

    for ( const auto& rp : matches )
    {
        if ( SIMD_UNLIKELY( !rp.rule || !rp.pattern ) )
        {
            continue;
        }

        // OPTIMIZED: Non-mutating match - NO PATTERN CLONING
        if ( match_pattern(rp.pattern.get(), candidate.get(), match_bindings) )
        {
            // Convert bindings only on successful structural match
            std::map<std::string, mop_t> bindings;
            for ( size_t i = 0; i < match_bindings.count; ++i )
            {
                bindings[match_bindings.bindings[i].name] = match_bindings.bindings[i].mop;
            }

            if ( !rp.rule->check_candidate(candidate) )
            {
                continue;
            }

            if ( !rp.rule->check_constants(bindings) )
            {
                continue;
            }

            MatchResult result;
            result.rule = rp.rule;
            result.matched_pattern = rp.pattern;
            result.bindings = std::move(bindings);
            results.push_back(std::move(result));
        }
    }

    return results;
}

//--------------------------------------------------------------------------
// Statistics
//--------------------------------------------------------------------------
size_t RuleRegistry::pattern_count() const
{
    return storage_.pattern_count();
}

std::map<std::string, size_t> RuleRegistry::get_hit_statistics() const
{
    std::map<std::string, size_t> stats;

    for ( const auto& p : rules_ )
    {
        if ( p )
        {
            stats[p->name()] = p->hit_count();
        }
    }

    return stats;
}

void RuleRegistry::clear_statistics()
{
    total_matches_ = 0;
    successful_matches_ = 0;

    // Note: Rule hit counts are not cleared as they're per-rule statistics
}

//--------------------------------------------------------------------------
// Debug
//--------------------------------------------------------------------------
void RuleRegistry::dump() const
{
    msg("[chernobog] MBA Rule Registry:\n");
    msg("  Rules: %zu\n", rules_.size());
    msg("  Verified rules: %zu\n", verified_rule_count_);
    msg("  Rejected rules: %zu\n", rejected_rule_count_);
    msg("  Patterns: %zu\n", pattern_count());
    msg("  Total matches attempted: %zu\n", total_matches_);
    msg("  Successful matches: %zu\n", successful_matches_);

    msg("  Rule list:\n");
    for ( const auto& p : rules_ )
    {
        if ( p )
        {
            msg("    - %s (hits: %zu)\n", p->name(), p->hit_count());
        }
    }
}

std::vector<std::string> RuleRegistry::list_rules() const
{
    std::vector<std::string> names;
    for ( const auto& p : rules_ )
    {
        if ( p )
        {
            names.push_back(p->name());
        }
    }
    return names;
}

//--------------------------------------------------------------------------
// Initialization helper
//--------------------------------------------------------------------------
void initialize_mba_rules()
{
    RuleRegistry::instance().initialize();
}

} // namespace rules
} // namespace chernobog
