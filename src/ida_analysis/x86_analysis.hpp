#pragma once

#include "../common/x86_abstract.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

struct insn_t;
struct op_t;

namespace chernobog::ida_analysis
{

enum class X86ConditionUse : uint8_t
{
    branch,
    set_byte,
    conditional_move
};
struct X86Condition
{
    x86_abstract::Condition condition;
    X86ConditionUse use;
};

std::optional<X86Condition> x86_condition(uint16_t instruction_type);

// Bounded owned-function must-analysis with architectural direct successors and
// conservative joins. Incomplete/unsupported graphs fall back to the contiguous
// single-entry prefix. No dynamic witnesses or writable memory are folded.
x86_abstract::Flags analyze_x86_flags_before(const insn_t &instruction, size_t depth);

struct X86FlagFact
{
    x86_abstract::Flags flags;
    std::vector<uint64_t> support;
};
X86FlagFact analyze_x86_flag_fact_before(const insn_t &instruction, size_t depth);

struct X86RegisterFact
{
    std::optional<uint64_t> value;
    std::vector<uint64_t> support;
};
X86RegisterFact analyze_x86_register_before(const insn_t &instruction, const op_t &operand,
                                            size_t depth);

// Recomputed facts for an exact existing ownerless root, before the first
// unrepresented transfer. No IDB mutation, automatic ownership or publication.
// Calls clear state at their syntactic continuation under normal return.
struct X86RegionInspection
{
    bool available = false, converged = false, truncated = false;
    int64_t database = -1;
    uint64_t context = 0, root = 0;
    unsigned address_bits = 0;
    size_t incoming_examined = 0;
    std::string reason;
    std::vector<std::map<std::string, std::string>> nodes, edges, records;
};

// Budgets are clamped to 64 nodes, 128 rounds and 256 incoming references per
// instruction (including interior bytes). Resource or structural failures
// retain diagnostics but return no facts. The root input is unknown.
X86RegionInspection analyze_x86_region(uint64_t root, size_t node_limit = 64,
                                       size_t round_limit = 128);

} // namespace chernobog::ida_analysis
