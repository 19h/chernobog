#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Hikari Function Wrapper Resolution Handler
//
// Hikari creates wrapper functions to hide API calls:
//   - Functions named HikariFunctionWrapper_XXX
//   - Typically call objc_msgSend, dlsym, or other APIs internally
//   - Take Class reference and selector string as arguments (Obj-C)
//   - Or take function pointer and forward arguments
//
// Example:
//   v5 = HikariFunctionWrapper_390(&OBJC_CLASS___NSDictionary,
//                                   "dictionaryWithContentsOfFile:", *v191);
//   // Actually calls: [NSDictionary dictionaryWithContentsOfFile:v191]
//
// Detection:
//   - Function names matching HikariFunctionWrapper_* or similar patterns
//   - Short functions that just forward to objc_msgSend/dlsym
//   - Functions taking Class + selector string arguments
//
// Reversal:
//   1. Identify wrapper functions
//   2. Analyze what they actually call
//   3. Rename wrappers to indicate the real target
//   4. Annotate call sites with the resolved API name
//--------------------------------------------------------------------------
class hikari_wrapper_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Clear address-keyed analysis between databases.
    static void clear_cache();

private:
    // Wrapper function info
    struct wrapper_info_t {
        ea_t func_ea = BADADDR;     // Wrapper function address
        qstring original_name;       // Original name (e.g., HikariFunctionWrapper_390)
        qstring resolved_name;       // Resolved name (e.g., NSDictionary_dictionaryWithContentsOfFile)
        qstring target_class;        // For Obj-C: class name
        qstring target_selector;     // For Obj-C: selector
        ea_t target_func = BADADDR; // For direct calls: target function
        bool is_objc = false;       // True if Obj-C message send
    };

    // Call site info
    struct call_site_t {
        int block_idx = -1;
        minsn_t *call_insn = nullptr;
        wrapper_info_t wrapper;
        qstring class_arg;          // Class argument if determinable
        qstring selector_arg;       // Selector argument if determinable
    };

    // Analyze a single wrapper function
    static bool analyze_wrapper(ea_t func_ea, wrapper_info_t *out);
    static bool get_wrapper_info(ea_t func_ea, wrapper_info_t *out);

    // Check if function is a wrapper (by name pattern)
    static bool is_wrapper_by_name(ea_t func_ea);

    // Check if function is a wrapper (by code pattern)
    static bool is_wrapper_by_pattern(ea_t func_ea);

    // Find call sites to wrappers in the current function
    static std::vector<call_site_t> find_wrapper_calls(mbl_array_t *mba);

    // Try to resolve class/selector arguments at a call site
    static bool resolve_call_args(call_site_t *call);

    // Annotate a call site
    static void annotate_call_site(const call_site_t &call);

    // Check for objc_msgSend pattern
    static bool has_objc_msgsend(ea_t func_ea);

    // Check for dlsym pattern
    static bool has_dlsym_call(ea_t func_ea);

    // Cache of analyzed wrappers
    static std::map<ssize_t, std::map<ea_t, wrapper_info_t>> s_wrapper_cache;
    static std::map<ssize_t, std::set<ea_t>> s_non_wrapper_cache;
    static std::map<ea_t, wrapper_info_t> &wrapper_cache();
    static std::set<ea_t> &non_wrapper_cache();
};
