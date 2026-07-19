#pragma once

#include "../deobf_types.h"
#include "../analysis/pattern_match.h"

namespace recurrent_switch {

// Recover and remove an encoded recurrent switch before ctree construction.
// Returns the number of CFG edges rewritten. A zero result is fail-closed and
// leaves the microcode unchanged.
int run(mbl_array_t *mba,
        const pattern_match::flatten_info_t &pattern,
        deobf_ctx_t *ctx);

} // namespace recurrent_switch
