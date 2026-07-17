#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Conservative indirect-branch resolution.
//
// An m_ijmp stores its selector in r and its offset expression in d.  This
// handler rewrites the branch only when that actual offset expression is an
// exact constant and names the start of an existing microblock.  In
// particular, it does not infer a jump table from unrelated loads, symbols,
// constants, or arithmetic elsewhere in the function.
//--------------------------------------------------------------------------
class indirect_branch_handler_t {
public:
    static bool detect(mbl_array_t *mba);
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);
};
