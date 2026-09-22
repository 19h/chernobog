#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Ctree-level constant folder
//
// At the ctree level, global references are resolved. This handler finds
// XOR expressions where one operand is a global variable and folds them
// to constants by reading the actual value from the binary.
//
// This is particularly useful for Hikari string decryption where:
//   byte_1000146C5 = byte_100014695 ^ 0x84;
// Can be folded to:
//   byte_1000146C5 = 0xD1;
//
// This runs after the initial decompilation as a ctree transformation.
//--------------------------------------------------------------------------
class ctree_const_fold_handler_t
{
  public:
    // Main entry point - transforms the ctree
    static int run(cfunc_t *cfunc);
};
