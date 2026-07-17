#pragma once
#include "../deobf_types.h"

// Control-flow flattening detection shared by the deflattening handler.
namespace pattern_match {

struct flatten_info_t {
    int dispatcher_block = -1;
    int loop_entry_block = -1;
    int loop_end_block = -1;
    mop_t state_var;
    std::map<uint64_t, int> state_to_block;
};

bool detect_flatten_pattern(mbl_array_t *mba, flatten_info_t *out);

} // namespace pattern_match
