#pragma once

#include "../deobf_types.h"

// Replace indirect accesses only when every incoming path proves the same
// stack address at the access. No native bytes or function boundaries change.
namespace stack_alias
{
int run(mbl_array_t *mba);
}
