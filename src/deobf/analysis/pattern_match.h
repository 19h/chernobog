#pragma once
#include "../deobf_types.h"
#include "switch_dispatch_classifier.hpp"

// Control-flow flattening detection shared by the deflattening handler.
namespace pattern_match {

enum class flatten_pattern_kind_t {
    unknown,
    constant_state,
    indexed_jump_table,
    recurrent_switch,
};

struct flatten_info_t {
    flatten_pattern_kind_t kind = flatten_pattern_kind_t::unknown;
    int dispatcher_block = -1;
    int switch_block = -1;
    int loop_entry_block = -1;
    int loop_end_block = -1;
    std::size_t case_count = 0;
    std::size_t returning_target_count = 0;
    std::size_t direct_return_target_count = 0;
    std::size_t return_frontier_count = 0;
    unsigned confidence_score = 0;
    std::set<int> dispatcher_blocks;
    mop_t state_var;
    std::map<uint64_t, int> state_to_block;
};

bool detect_flatten_pattern(mbl_array_t *mba, flatten_info_t *out);

} // namespace pattern_match
