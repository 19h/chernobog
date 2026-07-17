#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Use-site virtual stack tracing
//
// Resolves a direct stack-slot value only when a reaching definition can be
// established by scanning backward from the use through a chain of unique
// predecessors. Ambiguous joins, cycles, overlapping writes, calls, and
// potentially aliasing stores terminate the trace.
//--------------------------------------------------------------------------
class stack_tracker_t {
public:
    static std::optional<ea_t> trace_address(mblock_t *block,
                                             const minsn_t *before,
                                             sval_t offset,
                                             int size);

private:
    static std::optional<mop_t> trace_source(mblock_t *block,
                                             const minsn_t *before,
                                             sval_t offset,
                                             int size);
    static std::optional<ea_t> source_address(const mop_t& source);
};
