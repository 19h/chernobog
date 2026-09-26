#pragma once

#include "../common/x86_abstract.h"
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

class insn_t;
class op_t;

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
// single-entry prefix. No dynamic witnesses or initial writable bytes are
// folded; only bounded local MOV stores and register/memory exchanges can
// establish writable facts. Exact MOV, MOVZX, MOVSX, and MOVSXD register loads
// may consume those facts.
// Exact value queries retry joins with at most eight correlated alternatives;
// overflow joins all alternatives conservatively. Only a value shared by
// every represented input is returned, with the complete graph support.
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

// Reads only a complete machine word at the current tracked SP. Unknown
// initial stack bytes, intervening writes, and incomplete paths abstain.
X86RegisterFact analyze_x86_stack_top_before(const insn_t &instruction, size_t depth);

// A writable address starts unknown. A complete word is available only when
// every byte is known on every admitted path after modeled writes and joins.
X86RegisterFact analyze_x86_memory_before(const insn_t &instruction, uint64_t address,
                                          size_t depth);

// A complete cover contains the destination of every represented normal
// completion. It does not assert that any member is reachable, and does not
// authorize unconditional edges or publication. Recomputed from current bytes.
struct X86TargetCover
{
    bool available = false, complete = false, widened = false;
    size_t unknown_inputs = 0;
    std::vector<uint64_t> values, support;
    std::string reason;
};
X86TargetCover analyze_x86_push_targets_before(const insn_t &instruction, size_t depth);
void append_x86_target_cover(std::map<std::string, std::string> &row, const X86TargetCover &cover);

// Recomputed facts for an exact existing ownerless root, before the first
// unrepresented transfer. No IDB mutation, automatic ownership or publication.
// Calls clear state at their syntactic continuation under normal return.
struct X86RegionInspection
{
    bool available = false, converged = false, truncated = false, candidate_decode = false;
    int64_t database = -1;
    uint64_t context = 0, root = 0;
    unsigned address_bits = 0;
    size_t incoming_examined = 0;
    std::string reason;
    std::vector<std::map<std::string, std::string>> nodes, edges, records;
};

// Budgets are clamped to 128 nodes, 128 rounds and 256 incoming references per
// instruction (including interior bytes). Resource or structural failures
// retain diagnostics but return no facts. The root input is unknown. Explicit
// candidate decoding reads a data-head root in an executable segment without
// changing IDB items and labels every fact conditional on that byte decode.
X86RegionInspection analyze_x86_region(uint64_t root, size_t node_limit = 128,
                                       size_t round_limit = 128, bool candidate_decode = false);

} // namespace chernobog::ida_analysis
