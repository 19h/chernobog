#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Identity Call Resolution Handler
//
// This obfuscation pattern uses:
//   1. An identity function: __int64 identity(__int64 a1) { return a1; }
//   2. Global pointers to code locations: off_XXX = &loc_YYY
//   3. Indirect calls/jumps: identity(off_XXX)() or jmp identity(off_XXX)
//
// Pattern A (indirect call):
//   v4 = identity_func(off_1008B8B80);  // Returns the pointer value
//   return v4();                         // Calls the target
//
// Pattern B (indirect jump - Hikari style):
//   mov rdi, cs:off_10095FB68           // Load pointer into arg1
//   call sub_1007260C0                  // Call identity function
//   jmp rax                             // Jump to returned address
//
// The targets themselves may follow the same pattern, creating a CHAIN:
//   off_A -> loc_B (which loads off_C and jumps) -> loc_D (actual code)
//
// Detection:
//   - Functions that just return their argument (identity functions)
//   - Calls to identity functions with global pointer arguments
//   - Followed by indirect jump (m_ijmp) or indirect call (m_icall)
//
// Reversal (Two-Phase Approach):
//   Phase 1 (Maturity 0 - hxe_microcode):
//     - Identify identity functions
//     - Find call patterns with ijmp/icall
//     - Resolve pointer chains to final targets
//     - Store analysis results for later
//
//   Phase 2 (MMAT_LOCOPT - optblock handler):
//     - Apply deferred transformations
//     - Convert indirect jumps to direct calls
//     - Proper microcode instruction building
//--------------------------------------------------------------------------

// Forward declaration
struct deferred_identity_call_t;

class identity_call_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass (Phase 1 - analysis at maturity 0)
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Phase 2 - apply deferred transformations (called from optblock at MMAT_LOCOPT)
    static int apply_deferred(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Check if we have pending analysis for a function
    static bool has_pending_analysis(ea_t func_ea);

    // Clear deferred analysis for a function
    static void clear_deferred(ea_t func_ea);

    // Check if a function is an identity function
    static bool is_identity_function(ea_t func_ea);

    // Resolve pointer chain recursively (public for use by other handlers)
    static ea_t resolve_trampoline_chain(ea_t start_addr, int max_depth = 32);

    // Resolve a global pointer to get actual target address
    static ea_t resolve_global_pointer(ea_t ptr_addr);

    // Resolve an indexed table access - returns both entries if different
    // Returns: pair<entry0_target, entry1_target>
    // If both resolve to same target, second will equal first
    // If resolution fails, returns BADADDR
    struct table_resolution_t {
        ea_t table_base;
        ea_t entry0_target;   // Final resolved target for index 0
        ea_t entry1_target;   // Final resolved target for index 1
        bool both_same;       // True if both entries resolve to same target
        bool is_cff_dispatcher; // True if targets loop back (CFF pattern)
    };
    static table_resolution_t resolve_indexed_table(ea_t table_base, ea_t func_ea = BADADDR);

    // Deferred analysis storage (public for clearing on refresh)
    static std::map<ea_t, std::vector<deferred_identity_call_t>> s_deferred_analysis;

private:
    // Identity call pattern info (used during detection)
    struct identity_call_t {
        int block_idx;
        minsn_t *call_insn;      // The call to identity function
        minsn_t *ijmp_insn;      // The subsequent ijmp instruction
        ea_t identity_func;       // Address of identity function
        ea_t global_ptr;          // Address of global pointer
        ea_t resolved_target;     // Immediate target address
        ea_t final_target;        // Final target after following chain
        ea_t call_ea;             // Address of call instruction (stable across maturities)
        ea_t ijmp_ea;             // Address of ijmp instruction (stable across maturities)
        bool is_ijmp_pattern;     // True if followed by m_ijmp (vs m_icall)
    };

    // Find all identity call patterns
    static std::vector<identity_call_t> find_identity_calls(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Analyze a potential identity function
    static bool analyze_identity_func(ea_t ea);

    // Check if a code location is a trampoline (loads ptr, calls identity, jumps)
    static bool is_trampoline_code(ea_t addr, ea_t *next_ptr_out = nullptr);

    // Transform identity call at MMAT_LOCOPT (proper microcode building)
    static int transform_identity_call(mbl_array_t *mba, const deferred_identity_call_t &dc, deobf_ctx_t *ctx);

    // Create a proper call instruction
    static minsn_t *create_call_insn(mbl_array_t *mba, ea_t target, ea_t source_ea);

    // Cache of known identity functions
    static std::set<ea_t> s_identity_funcs;
    static std::set<ea_t> s_non_identity_funcs;

    // Cache of resolved trampolines: trampoline_addr -> final_target
    static std::map<ea_t, ea_t> s_trampoline_cache;
};

// Deferred analysis record - stored between maturity 0 and MMAT_LOCOPT
struct deferred_identity_call_t {
    ea_t call_ea;             // Address of call instruction
    ea_t ijmp_ea;             // Address of ijmp instruction
    ea_t identity_func;       // Address of identity function
    ea_t global_ptr;          // Address of global pointer
    ea_t final_target;        // Resolved final target
    qstring target_name;      // Name of target function (for annotation)
    bool is_ijmp_pattern;     // True if followed by m_ijmp
};
