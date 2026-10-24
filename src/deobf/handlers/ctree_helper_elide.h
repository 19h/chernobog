#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Ctree-level ARM64e helper elision
//
// The arm64e decoder models pointer authentication, signing, stripping and
// generic instructions as helper calls. Their results stay opaque to
// Hex-Rays, which therefore keeps a standalone call statement even when the
// authenticated value is a literal that was only used as a value, never as a
// pointer.
//
// This removes those statements when the helper is one of the value-only
// ARM64e intrinsics and every argument is a constant. Authenticating a
// constant is invariant, so discarding the result also discards the call.
//--------------------------------------------------------------------------
class ctree_helper_elide_handler_t
{
  public:
    // Main entry point - removes discarded constant helper statements
    static int run(cfunc_t *cfunc);
};
