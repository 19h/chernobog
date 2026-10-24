#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Ctree-level direct call rendering
//
// A call to an address that is known statically can still reach the ctree as
// a cast of the function object when the object's type does not describe the
// call. Hex-Rays prints such a call as a casted function pointer call, even
// though nothing about the target is unknown.
//
// Rewriting the callee to the object, typed with the prototype the call was
// already written against, prints the ordinary direct call form. The argument
// list is untouched; only the type of the callee expression changes.
//--------------------------------------------------------------------------
class ctree_direct_call_handler_t
{
  public:
    // Main entry point - turns casted calls to known targets into direct calls
    static int run(cfunc_t *cfunc);
};
