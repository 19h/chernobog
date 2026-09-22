/*
 * Small IDA-independent classifiers used by the native and Hex-Rays adapters.
 *
 * Keeping the state machine independent of IDA makes semantic boundary cases
 * executable in the ordinary CTest suite.  The host adapter remains
 * responsible for decoding instructions, canonicalizing register aliases, and
 * identifying alternate CFG predecessors.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace chernobog::ida_analysis::classifier
{

constexpr uint64_t k_bad_address = ~uint64_t(0);

struct register_slice_t
{
    int32_t reg = -1;
    uint16_t bit_offset = 0;
    uint16_t bit_width = 0;

    bool valid() const { return reg >= 0 && bit_width != 0; }
    bool same(const register_slice_t &other) const;
    bool overlaps(const register_slice_t &other) const;
};

enum class instruction_kind_t : uint8_t
{
    other = 0,
    direct_call,
    indirect_call,
    direct_jump,
    indirect_jump,
    conditional_branch,
    return_instruction,
    pop_register,
    push_register,
    push_immediate,
    push_memory,
    read_stack_top,
    add_stack_top_immediate,
    adjust_stack_pointer_immediate,
    add_register_immediate,
    sub_register_immediate,
    register_write,
    stack_mutation,
    load_pc_relative_address,
    exchange_stack_top_register,
};

struct instruction_t
{
    uint64_t address = k_bad_address;
    uint16_t size = 0;
    instruction_kind_t kind = instruction_kind_t::other;
    register_slice_t destination;
    register_slice_t source;
    uint64_t immediate = 0;
    uint64_t target = k_bad_address;
    uint16_t stack_width_bits = 0;
    bool alternate_predecessor = false;
    bool far_transfer = false;
    bool destination_is_stack_pointer = false;
    bool source_is_stack_pointer = false;
    bool preserves_flags = false;

    uint64_t end() const;
};

enum class get_pc_mode_t : uint8_t
{
    pop_return_address = 0,
    read_return_address,
    adjust_return_address,
    discard_return_address,
};

enum class stack_access_kind_t : uint8_t
{
    read,
    write,
    read_modify_write
};
struct stack_access_t
{
    uint64_t instruction = k_bad_address;
    int64_t offset_bytes = 0; // Relative to SP before the CALL/PUSH sequence.
    unsigned width_bits = 0;
    stack_access_kind_t kind = stack_access_kind_t::read;
    std::optional<uint64_t> value_before;
    std::optional<uint64_t> value_after;
    bool implicit_lock = false;
};

struct get_pc_candidate_t
{
    uint64_t call = k_bad_address;
    uint64_t gadget = k_bad_address;
    uint64_t pushed_return = k_bad_address;
    uint64_t return_instruction = k_bad_address;
    std::optional<uint64_t> resumed_at;
    std::optional<uint64_t> register_value_at_return;
    register_slice_t pc_register;
    int64_t delta = 0;
    get_pc_mode_t mode = get_pc_mode_t::pop_return_address;
    std::vector<uint64_t> support;
    uint64_t summary_end = k_bad_address;
    unsigned width_bits = 0;
    int64_t stack_delta_bytes = 0;
    bool flags_preserved = false;
    std::vector<stack_access_t> stack_accesses;
};

struct push_get_pc_t
{
    uint64_t start = k_bad_address;
    uint64_t end = k_bad_address;
    uint64_t address_value = k_bad_address;
    unsigned width_bits = 0;
    int64_t stack_delta_bytes = 0;
    register_slice_t restored_register;
    bool flags_preserved = true;
    std::vector<uint64_t> support;
    std::vector<stack_access_t> stack_accesses;
};

// Exact metadata summaries. The x64 form retains both stack writes and the
// implicit lock on XCHG; it does not authorize replacing the native sequence.
std::optional<push_get_pc_t> classify_push_get_pc(const std::vector<instruction_t> &sequence,
                                                  unsigned execution_mode_bits);

// The gadget vector starts at the direct call target and is in exact physical
// address order. `other_callers` includes any alternate control-flow entry to
// the first gadget instruction.
std::optional<get_pc_candidate_t> classify_get_pc_gadget(const instruction_t &call,
                                                         const std::vector<instruction_t> &gadget,
                                                         bool other_callers, size_t maximum_depth);

enum class target_proof_kind_t : uint8_t
{
    unresolved,
    immediate,
    register_definition,
    immutable_memory,
};

struct memory_dependency_t
{
    uint64_t address = k_bad_address;
    std::vector<uint8_t> bytes;
};

struct target_proof_t
{
    target_proof_kind_t kind = target_proof_kind_t::unresolved;
    std::optional<uint64_t> value;
    std::vector<uint64_t> definitions;
    std::vector<register_slice_t> registers;
    std::vector<memory_dependency_t> memory;
};

struct stack_transfer_t
{
    uint64_t push = k_bad_address;
    uint64_t transfer = k_bad_address;
    unsigned width_bits = 0;
    int stack_delta_bytes = 0;
    int stack_write_offset_bytes = 0;
    unsigned stack_write_bytes = 0;
    target_proof_t target;
};

// Metadata summary only: a zero net SP delta does not remove the stack write.
// The caller proves target facts and memory dependencies before supplying them.
std::optional<stack_transfer_t> classify_push_return(const instruction_t &push,
                                                     const instruction_t &ret,
                                                     unsigned execution_mode_bits,
                                                     const target_proof_t &target);

} // namespace chernobog::ida_analysis::classifier
