#pragma once

#include "../deobf_types.h"

// Neutralize pure call-site expressions in ABI registers that a recurrent,
// statically closed resolver thunk provably does not observe. Physical ABI
// slots are retained, so later live register arguments cannot shift position.
// This is a MMAT_CALLS-only microcode transformation.
class resolver_call_args_handler_t
{
public:
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);
};
