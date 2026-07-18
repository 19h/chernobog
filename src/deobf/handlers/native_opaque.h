#pragma once

#include "../deobf_types.h"

struct native_opaque_stats_t
{
    int functions_scanned = 0;
    int blocks_scanned = 0;
    int conditional_branches = 0;
    int predicates_proved = 0;
    int branches_patched = 0;
};

// Resolve AArch64 conditional branches before Hex-Rays lifts a function. The
// evaluator is deliberately bounded to one native basic block and admits
// memory only through global_const_handler_t's exact scalar proof.
class native_opaque_handler_t
{
public:
    static int mode();
    static native_opaque_stats_t run();
};
