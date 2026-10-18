#pragma once

#include "native_classifier.hpp"
#include <utility>

namespace chernobog::ida_analysis::classifier
{

struct stack_stub_t
{
    uint64_t start = 0, end = 0, transfer = 0;
    uint32_t handler = 0, continuation = 0;
    uint8_t saved_register = 0; // Architectural x86 encoding, never ESP.
    uint16_t return_adjustment = 0;
    int64_t stack_delta_bytes = -4; // At handler entry, relative to stub entry.
    std::vector<std::pair<uint64_t, uint16_t>> instructions;
    std::vector<stack_access_t> stack_accesses;
};

constexpr size_t stack_stub_maximum_bytes = 128;
constexpr size_t stack_stub_maximum_instructions = 32;

// Exact unprefixed PE32-style stack stubs: two saved copies, two LEA address
// pairs and either PUSH/MOV/RET 4 or XCHG [ESP],reg/RET. Parsing is O(bytes)
// with bounded storage. No code ownership, entry topology or executable-target
// claim is made here; the IDA adapter must establish those separately.
std::optional<stack_stub_t> classify_stack_stub32(const uint8_t *bytes, size_t size,
                                                  uint64_t start);

} // namespace chernobog::ida_analysis::classifier
