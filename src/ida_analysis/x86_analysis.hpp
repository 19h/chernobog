#pragma once

#include "../common/x86_abstract.h"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

struct insn_t;
struct op_t;

namespace chernobog::ida_analysis {

enum class X86ConditionUse : uint8_t { branch, set_byte, conditional_move };
struct X86Condition
{
    x86_abstract::Condition condition;
    X86ConditionUse use;
};

std::optional<X86Condition> x86_condition(uint16_t instruction_type);

// Reads only the current contiguous single-entry basic-block prefix. Unknown
// effects invalidate facts; no dynamic witnesses or writable memory are folded.
x86_abstract::Flags analyze_x86_flags_before(const insn_t &instruction, size_t depth);

struct X86RegisterFact
{
    std::optional<uint64_t> value;
    std::vector<uint64_t> support;
};
X86RegisterFact analyze_x86_register_before(
    const insn_t &instruction, const op_t &operand, size_t depth);

} // namespace chernobog::ida_analysis
