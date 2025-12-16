#pragma once
#include "../deobf_types.h"
#include "../rules/rule_registry.h"

//--------------------------------------------------------------------------
// MBA Simplify Handler
//
// This handler replaces the old substitution_handler_t with the new
// AST-based pattern matching system. It provides:
//
//   - 90+ MBA simplification rules (vs 12 in old handler)
//   - Pattern fuzzing for robust matching
//   - O(log n) hierarchical pattern lookup
//   - Statistics tracking per rule
//
// The handler integrates with IDA's microcode optimization through
// both instruction-level (optinsn_t) and block-level passes.
//--------------------------------------------------------------------------

class mba_simplify_handler_t {
public:
    //----------------------------------------------------------------------
    // Standard handler interface
    //----------------------------------------------------------------------

    // Detect if MBA obfuscation is present
    static bool detect(mbl_array_t *mba);

    // Run the deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    //----------------------------------------------------------------------
    // Instruction-level simplification (for optinsn_t callback)
    //----------------------------------------------------------------------

    // Try to simplify a single instruction
    // Returns 1 if simplified, 0 otherwise
    static int simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx);

    //----------------------------------------------------------------------
    // Initialization
    //----------------------------------------------------------------------

    // Initialize the rule registry (call once at plugin startup)
    static void initialize();

    // Check if initialized
    static bool is_initialized();

    //----------------------------------------------------------------------
    // Statistics
    //----------------------------------------------------------------------

    static size_t total_simplifications();
    static void reset_statistics();
    static void dump_statistics();

private:
    static bool initialized_;
    static size_t total_simplified_;

    // Internal simplification helpers
    static int try_simplify_instruction(mblock_t *blk, minsn_t *ins);
    static int apply_match(mblock_t *blk, minsn_t *ins,
                          const chernobog::rules::RuleRegistry::MatchResult &match);
};
