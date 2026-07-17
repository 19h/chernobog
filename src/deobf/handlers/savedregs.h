#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Saved-register stack-slot resolver
//
// Resolves indirect call targets and string arguments at each call site using
// conservative reaching-definition tracing. Results are database annotations;
// this handler does not mutate microcode.
//--------------------------------------------------------------------------
class savedregs_handler_t {
public:
    static bool detect(mbl_array_t *mba);
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    struct resolved_call_t {
        ea_t call_addr = BADADDR;
        ea_t target_func = BADADDR;
        qstring target_name;
        qstring selector;
        std::vector<qstring> args;  // Preserves original call-argument indices.
        bool is_objc = false;
    };

    static bool is_savedregs_ref(const mop_t& operand, sval_t *offset);
    static bool is_objc_msgsend(ea_t address);
    static bool resolve_indirect_call(mblock_t *block, minsn_t *call,
                                      resolved_call_t *out);
    static void extract_call_args(mblock_t *block, minsn_t *call,
                                  resolved_call_t *out);
    static void annotate_call(const resolved_call_t& resolved);
};
