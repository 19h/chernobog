#pragma once

#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Long select-chain collapse
//
// LLVM lowers cascaded integer select operations to repeated conditional-move
// diamonds on x86.  Very long cascades can exceed Hex-Rays' ctree structural
// limits even though their data flow is linear.  This handler recognizes only
// dense sets of exact diamonds with atomic predicates and replaces each
// conditional register assignment with an equivalent fixed-width branchless
// expression before ctree construction.
//--------------------------------------------------------------------------
class select_chain_handler_t
{
public:
    static bool detect(mbl_array_t *mba);
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);
};
