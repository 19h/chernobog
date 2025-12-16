#pragma once
#include "../deobf_types.h"
#include "../rules/jump_rules.h"

//--------------------------------------------------------------------------
// Jump Optimizer Handler
//
// Detects and simplifies opaque predicates in conditional jumps.
// Uses both pattern matching and Z3-based analysis to determine if
// conditional jumps are always taken or never taken.
//
// When a jump is always taken:  Convert to unconditional goto
// When a jump is never taken:   Convert to nop / remove
//--------------------------------------------------------------------------

namespace chernobog {

class jump_optimizer_handler_t {
public:
    // Detect if opaque jump patterns are present
    static bool detect(mbl_array_t* mba);

    // Run jump optimization pass
    static int run(mbl_array_t* mba, deobf_ctx_t* ctx);

    // Instruction-level optimization
    static int simplify_jcc(mblock_t* blk, minsn_t* jcc, deobf_ctx_t* ctx);

    // Statistics
    static void dump_statistics();
    static void reset_statistics();

private:
    // Apply optimization based on rule result
    // result: 1 = always taken, 0 = never taken
    static int apply_optimization(mblock_t* blk, minsn_t* jcc, int result);

    static size_t jumps_simplified_;
    static size_t jumps_converted_goto_;
    static size_t jumps_removed_;
};

} // namespace chernobog
