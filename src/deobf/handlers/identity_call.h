#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Identity Call Resolution Handler
//
// This obfuscation pattern uses:
//   1. An identity function: __int64 identity(__int64 a1) { return a1; }
//   2. Global pointers to code locations: off_XXX = &loc_YYY
//   3. Indirect calls: identity(off_XXX)() which hides the real target
//
// Example:
//   v4 = identity_func(off_1008B8B80);  // Returns the pointer value
//   return v4();                         // Calls the target
//
// Detection:
//   - Functions that just return their argument (identity functions)
//   - Calls to identity functions with global pointer arguments
//   - Indirect calls through the result
//
// Reversal:
//   1. Identify identity functions
//   2. Find calls through identity functions
//   3. Read the actual target from the global pointer
//   4. Replace indirect call with direct call
//--------------------------------------------------------------------------
class identity_call_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Check if a function is an identity function
    static bool is_identity_function(ea_t func_ea);

private:
    // Identity call pattern info
    struct identity_call_t {
        int block_idx;
        minsn_t *call_insn;     // The call to identity function
        ea_t identity_func;      // Address of identity function
        ea_t global_ptr;         // Address of global pointer
        ea_t resolved_target;    // Actual target address
    };

    // Find all identity call patterns
    static std::vector<identity_call_t> find_identity_calls(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Analyze a potential identity function
    static bool analyze_identity_func(ea_t ea);

    // Resolve the target from global pointer
    static ea_t resolve_global_pointer(ea_t ptr_addr);

    // Replace identity call with direct call
    static int replace_identity_call(mbl_array_t *mba, mblock_t *blk,
                                     const identity_call_t &ic, deobf_ctx_t *ctx);

    // Cache of known identity functions
    static std::set<ea_t> s_identity_funcs;
    static std::set<ea_t> s_non_identity_funcs;
};
