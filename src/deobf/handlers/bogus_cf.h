#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Bogus Control Flow Removal Handler
//
// Hikari's bogus CF inserts:
//   - Opaque predicates (always-true/false conditions)
//   - Unreachable "altered" blocks with junk code
//   - Fake branches that never execute
//
// Detection:
//   - Conditions comparing constants (e.g., 1 == 1)
//   - Conditions using (x * (x+1)) % 2 == 0 pattern
//   - Blocks with no real predecessors
//   - Duplicate/modified code blocks
//
// Reversal:
//   1. Identify opaque predicates
//   2. Evaluate to determine always-true/false
//   3. Remove dead branches
//   4. Delete unreachable blocks
//   5. Simplify remaining CFG
//--------------------------------------------------------------------------
class bogus_cf_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    // Find all opaque predicates
    struct opaque_info_t {
        int block_idx;
        minsn_t *cond_insn;
        bool always_true;
        int live_target;    // Target to keep
        int dead_target;    // Target to remove
    };

    static std::vector<opaque_info_t> find_opaque_predicates(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Check if a condition is opaque
    static bool is_opaque_predicate(minsn_t *cond, bool *is_true);

    // Check specific opaque patterns
    static bool check_const_comparison(minsn_t *insn, bool *result);
    static bool check_math_identity(minsn_t *insn, bool *result);  // x*(x+1) % 2 == 0
    static bool check_global_var_pattern(minsn_t *insn, bool *result);

    // Find unreachable blocks
    static std::set<int> find_dead_blocks(mbl_array_t *mba, const std::vector<opaque_info_t> &opaques);

    // Remove dead code
    static int remove_dead_branches(mbl_array_t *mba, const std::vector<opaque_info_t> &opaques);
    static int remove_dead_blocks(mbl_array_t *mba, const std::set<int> &dead_blocks);

    // Simplify junk instructions in remaining blocks
    static int simplify_junk_instructions(mbl_array_t *mba, deobf_ctx_t *ctx);
};
