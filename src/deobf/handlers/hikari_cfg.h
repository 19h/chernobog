#pragma once

#include "../deobf_types.h"

struct hikari_cfg_stats_t {
    int root_state_slots = 0;
    int terminal_indirect_branches = 0;
    int recovered_dispatchers = 0;
    int patched_dispatchers = 0;
    int reachable_functions = 0;
};

// Recover Hikari's cross-function ARM64 two-way dispatch encoding.  The pass
// is explicitly opt-in because it adds IDB control-flow references and tier 2
// also applies reversible instruction patches inside proven compact tails.
class hikari_cfg_handler_t {
public:
    // 0: disabled; 1: annotate exact edges; 2: also patch compact tails.
    static int mode();
    static hikari_cfg_stats_t run();
};
