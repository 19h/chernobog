#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Ctree-level switch folder
//
// Handles switches where the switch expression evaluates to a constant,
// making all but one case unreachable. This is common in flattened code
// where the state variable (often in high bits via HIDWORD) controls flow.
//
// Patterns detected:
//   1. switch(HIDWORD(x)) where HIDWORD is always a specific constant
//   2. switch(x >> N) where the shifted bits are always constant
//   3. switch on variables that are always assigned the same value
//
// This runs after the initial decompilation as a ctree transformation.
//--------------------------------------------------------------------------
class ctree_switch_fold_handler_t {
public:
    // Main entry point - transforms the ctree
    static int run(cfunc_t *cfunc);
};
