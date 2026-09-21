#pragma once

#include "native_classifier.hpp"

#include <cstddef>
#include <optional>

struct insn_t;

namespace chernobog::ida_analysis {

// Decode and classify one x86 direct-call get-PC construction. The returned
// proof is address-exact and rejects alternate entries, register aliases, and
// unmodeled return-stack mutations.
std::optional<classifier::get_pc_candidate_t> classify_ida_get_pc_call(
    const insn_t &call,
    size_t maximum_depth,
    bool reject_other_entries = true);

std::optional<classifier::stack_transfer_t> classify_ida_push_return(
    const insn_t &push, int register_scan_depth);

} // namespace chernobog::ida_analysis
