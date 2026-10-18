#pragma once

#include "native_classifier.hpp"
#include "stack_stub.hpp"

#include <cstddef>
#include <optional>

class insn_t;

namespace chernobog::ida_analysis
{

// Decode and classify one x86 direct-call get-PC construction. The returned
// proof is address-exact and rejects alternate entries, register aliases, and
// unmodeled return-stack mutations.
std::optional<classifier::get_pc_candidate_t>
classify_ida_get_pc_call(const insn_t &call, size_t maximum_depth,
                         bool reject_other_entries = true);

std::optional<classifier::stack_transfer_t> classify_ida_push_return(const insn_t &push,
                                                                     int register_scan_depth);

std::optional<classifier::push_get_pc_t> classify_ida_push_get_pc(const insn_t &push);

// Exact loaded bytes plus current IDA instruction boundaries and entry topology.
std::optional<classifier::stack_stub_t> classify_ida_stack_stub32(uint64_t start);
std::optional<classifier::stack_stub_t> find_ida_stack_stub32(uint64_t return_ea);

} // namespace chernobog::ida_analysis
