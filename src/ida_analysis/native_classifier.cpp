#include "native_classifier.hpp"

#include <algorithm>
#include <limits>

namespace chernobog::ida_analysis::classifier
{
namespace
{

bool add_address(uint64_t base, int64_t delta, uint64_t *result)
{
    if (result == nullptr)
        return false;
    if (delta >= 0)
    {
        const uint64_t amount = static_cast<uint64_t>(delta);
        if (base > std::numeric_limits<uint64_t>::max() - amount)
            return false;
        *result = base + amount;
    }
    else
    {
        const uint64_t amount = static_cast<uint64_t>(-(delta + 1)) + 1;
        if (base < amount)
            return false;
        *result = base - amount;
    }
    return *result != k_bad_address;
}

bool add_delta(int64_t *value, int64_t delta)
{
    if (value == nullptr)
        return false;
    if ((delta > 0 && *value > std::numeric_limits<int64_t>::max() - delta) ||
        (delta < 0 && *value < std::numeric_limits<int64_t>::min() - delta))
    {
        return false;
    }
    *value += delta;
    return true;
}

bool add_word_address(uint64_t base, int64_t delta, unsigned width, uint64_t *result)
{
    if (width == 32)
    {
        *result = (base + uint64_t(delta)) & UINT32_MAX;
        return true;
    }
    return add_address(base, delta, result);
}

bool is_control_transfer(instruction_kind_t kind)
{
    return kind == instruction_kind_t::direct_call || kind == instruction_kind_t::indirect_call ||
           kind == instruction_kind_t::direct_jump || kind == instruction_kind_t::indirect_jump ||
           kind == instruction_kind_t::conditional_branch;
}

bool is_unmodeled_stack_mutation(instruction_kind_t kind)
{
    return kind == instruction_kind_t::push_immediate || kind == instruction_kind_t::push_memory ||
           kind == instruction_kind_t::pop_register ||
           kind == instruction_kind_t::add_stack_top_immediate ||
           kind == instruction_kind_t::adjust_stack_pointer_immediate ||
           kind == instruction_kind_t::stack_mutation;
}

} // namespace

bool register_slice_t::same(const register_slice_t &other) const
{
    return valid() && other.valid() && reg == other.reg && bit_offset == other.bit_offset &&
           bit_width == other.bit_width;
}

bool register_slice_t::overlaps(const register_slice_t &other) const
{
    if (!valid() || !other.valid() || reg != other.reg)
        return false;
    const uint32_t end = uint32_t(bit_offset) + uint32_t(bit_width);
    const uint32_t other_end = uint32_t(other.bit_offset) + uint32_t(other.bit_width);
    return uint32_t(bit_offset) < other_end && uint32_t(other.bit_offset) < end;
}

uint64_t instruction_t::end() const
{
    if (address == k_bad_address || size == 0 ||
        address > std::numeric_limits<uint64_t>::max() - size)
    {
        return k_bad_address;
    }
    return address + size;
}

std::optional<push_get_pc_t> classify_push_get_pc(const std::vector<instruction_t> &sequence,
                                                  unsigned mode)
{
    if ((mode != 32 && mode != 64) || sequence.empty() ||
        (mode == 32 ? sequence.size() != 1 : sequence.size() != 3))
        return std::nullopt;
    for (size_t i = 0; i < sequence.size(); ++i)
    {
        const auto &insn = sequence[i];
        if (insn.end() == k_bad_address || insn.stack_width_bits != mode || insn.far_transfer ||
            (i != 0 && (insn.alternate_predecessor || sequence[i - 1].end() != insn.address)) ||
            (mode == 32 && insn.end() > UINT32_MAX))
            return std::nullopt;
    }
    const auto &push = sequence.front();
    push_get_pc_t result;
    result.start = push.address;
    result.end = sequence.back().end();
    result.width_bits = mode;
    result.stack_delta_bytes = -int64_t(mode / 8);
    for (const auto &insn : sequence)
        result.support.push_back(insn.address);
    if (mode == 32)
    {
        // A literal equal to this PUSH's continuation is an address fact even if
        // its original producer was not a protector-generated CALL replacement.
        if (push.kind != instruction_kind_t::push_immediate || push.immediate != push.end())
            return std::nullopt;
        result.address_value = push.immediate;
        result.stack_accesses.push_back({push.address, -4, 32, stack_access_kind_t::write,
                                         std::nullopt, push.immediate, false});
        return result;
    }
    const auto &lea = sequence[1];
    const auto &exchange = sequence[2];
    if (push.kind != instruction_kind_t::push_register || !push.source.valid() ||
        push.source.bit_width != 64 || push.source.bit_offset != 0 ||
        push.source_is_stack_pointer || lea.destination_is_stack_pointer ||
        lea.kind != instruction_kind_t::load_pc_relative_address ||
        !lea.destination.same(push.source) || lea.target == k_bad_address ||
        exchange.kind != instruction_kind_t::exchange_stack_top_register ||
        !exchange.source.same(push.source))
        return std::nullopt;
    result.address_value = lea.target;
    result.restored_register = push.source;
    result.stack_accesses.push_back(
        {push.address, -8, 64, stack_access_kind_t::write, std::nullopt, std::nullopt, false});
    result.stack_accesses.push_back({exchange.address, -8, 64,
                                     stack_access_kind_t::read_modify_write, std::nullopt,
                                     lea.target, true});
    return result;
}

std::optional<stack_transfer_t> classify_push_return(const instruction_t &push,
                                                     const instruction_t &ret, unsigned mode,
                                                     const target_proof_t &target)
{
    if ((mode != 32 && mode != 64) || push.stack_width_bits != mode ||
        ret.stack_width_bits != mode || ret.kind != instruction_kind_t::return_instruction ||
        ret.far_transfer || ret.immediate != 0 || ret.alternate_predecessor ||
        push.end() == k_bad_address || push.end() != ret.address || ret.end() == k_bad_address ||
        (push.kind != instruction_kind_t::push_immediate &&
         push.kind != instruction_kind_t::push_register &&
         push.kind != instruction_kind_t::push_memory))
        return std::nullopt;
    if (push.kind == instruction_kind_t::push_register &&
        (!push.source.valid() || push.source.bit_width != mode || push.source.bit_offset != 0))
        return std::nullopt;
    if (target.value.has_value() != (target.kind != target_proof_kind_t::unresolved))
        return std::nullopt;
    if (target.value && (mode == 32 && *target.value > UINT32_MAX))
        return std::nullopt;
    if (target.kind == target_proof_kind_t::immediate &&
        push.kind != instruction_kind_t::push_immediate)
        return std::nullopt;
    if (target.kind == target_proof_kind_t::register_definition &&
        (push.kind != instruction_kind_t::push_register || target.definitions.empty() ||
         target.registers.empty()))
        return std::nullopt;
    if (target.stack_top_source &&
        (push.kind != instruction_kind_t::push_memory || !push.source_is_stack_pointer))
        return std::nullopt;
    if (target.kind == target_proof_kind_t::stack_definition &&
        (!target.stack_top_source || target.definitions.empty() || !target.memory.empty()))
        return std::nullopt;
    if (target.kind == target_proof_kind_t::immutable_memory &&
        (push.kind != instruction_kind_t::push_memory || target.memory.size() != 1 ||
         target.memory.front().bytes.size() != mode / 8 ||
         target.memory.front().address == k_bad_address ||
         target.memory.front().address > k_bad_address - mode / 8))
        return std::nullopt;
    if (target.kind == target_proof_kind_t::immutable_memory)
    {
        uint64_t decoded = 0;
        for (unsigned i = 0; i < mode / 8; ++i)
            decoded |= uint64_t(target.memory.front().bytes[i]) << (i * 8);
        if (decoded != *target.value)
            return std::nullopt;
    }
    stack_transfer_t result;
    result.push = push.address;
    result.transfer = ret.address;
    result.width_bits = mode;
    result.stack_write_bytes = mode / 8;
    result.stack_write_offset_bytes = -int(mode / 8);
    result.target = target;
    return result;
}

std::optional<get_pc_candidate_t> classify_get_pc_gadget(const instruction_t &call,
                                                         const std::vector<instruction_t> &gadget,
                                                         bool other_callers, size_t maximum_depth)
{
    const uint64_t call_end = call.end();
    if (call.kind != instruction_kind_t::direct_call || call.size == 0 ||
        call.address == k_bad_address || call_end == k_bad_address ||
        call.target == k_bad_address || call.far_transfer || gadget.empty() ||
        gadget.front().address != call.target || other_callers ||
        gadget.front().alternate_predecessor || maximum_depth == 0 ||
        (call.stack_width_bits != 32 && call.stack_width_bits != 64) ||
        (call.stack_width_bits == 32 && (call_end > UINT32_MAX || call.target > UINT32_MAX)))
    {
        return std::nullopt;
    }

    get_pc_candidate_t result;
    result.call = call.address;
    result.gadget = call.target;
    result.pushed_return = call_end;
    result.support = {call.address, gadget.front().address};
    result.width_bits = call.stack_width_bits;
    const int64_t word_bytes = call.stack_width_bits / 8;
    result.stack_delta_bytes = -word_bytes;
    result.flags_preserved = true;
    result.stack_accesses.push_back({call.address, -word_bytes, result.width_bits,
                                     stack_access_kind_t::write, std::nullopt, call_end, false});

    const instruction_t &entry = gadget.front();
    if (entry.end() == k_bad_address || (call.stack_width_bits == 32 && entry.end() > UINT32_MAX))
        return std::nullopt;
    bool register_known = false;
    bool stack_target_adjusted = false;
    bool pushed_tracked_register = false;
    int64_t pushed_register_delta = 0;
    switch (entry.kind)
    {
    case instruction_kind_t::pop_register:
        if (!entry.destination.valid() || entry.destination_is_stack_pointer ||
            entry.stack_width_bits != call.stack_width_bits || entry.destination.bit_offset != 0 ||
            entry.destination.bit_width != call.stack_width_bits)
            return std::nullopt;
        result.mode = get_pc_mode_t::pop_return_address;
        result.pc_register = entry.destination;
        register_known = true;
        result.stack_delta_bytes = 0;
        result.stack_accesses.push_back({entry.address, -word_bytes, result.width_bits,
                                         stack_access_kind_t::read, call_end, std::nullopt, false});
        break;
    case instruction_kind_t::read_stack_top:
        if (!entry.destination.valid() || entry.destination_is_stack_pointer ||
            entry.destination.bit_offset != 0 ||
            entry.destination.bit_width != call.stack_width_bits)
            return std::nullopt;
        result.mode = get_pc_mode_t::read_return_address;
        result.pc_register = entry.destination;
        register_known = true;
        result.stack_accesses.push_back({entry.address, -word_bytes, result.width_bits,
                                         stack_access_kind_t::read, call_end, std::nullopt, false});
        break;
    case instruction_kind_t::add_stack_top_immediate:
        if (entry.stack_width_bits != call.stack_width_bits)
            return std::nullopt;
        result.mode = get_pc_mode_t::adjust_return_address;
        result.delta = static_cast<int64_t>(entry.immediate);
        stack_target_adjusted = true;
        result.flags_preserved = false;
        {
            uint64_t adjusted = 0;
            if (!add_word_address(call_end, result.delta, result.width_bits, &adjusted))
                return std::nullopt;
            result.stack_accesses.push_back({entry.address, -word_bytes, result.width_bits,
                                             stack_access_kind_t::read_modify_write, call_end,
                                             adjusted, false});
        }
        break;
    case instruction_kind_t::adjust_stack_pointer_immediate:
        if (entry.stack_width_bits != call.stack_width_bits ||
            entry.immediate != call.stack_width_bits / 8)
            return std::nullopt;
        result.mode = get_pc_mode_t::discard_return_address;
        result.stack_delta_bytes = 0;
        result.flags_preserved = false;
        // The return address has been consumed completely. Execution continues
        // at the instruction after this exact stack adjustment; later branches
        // are application control flow, not part of the proof obligation.
        result.resumed_at = entry.end();
        result.summary_end = entry.end();
        if (*result.resumed_at == k_bad_address)
            return std::nullopt;
        return result;
    default:
        return std::nullopt;
    }

    uint64_t expected = entry.end();
    if (expected == k_bad_address)
        return std::nullopt;
    const size_t count = gadget.size() <= maximum_depth ? gadget.size() : maximum_depth + 1;
    for (size_t index = 1; index < count; ++index)
    {
        const instruction_t &instruction = gadget[index];
        if (instruction.address != expected || instruction.alternate_predecessor ||
            instruction.destination_is_stack_pointer)
            return std::nullopt;
        expected = instruction.end();
        if (expected == k_bad_address)
            return std::nullopt;
        if (result.width_bits == 32 && expected > UINT32_MAX)
            return std::nullopt;
        result.support.push_back(instruction.address);

        if (instruction.kind == instruction_kind_t::return_instruction)
        {
            if (instruction.far_transfer || instruction.immediate != 0 ||
                instruction.stack_width_bits != result.width_bits)
                return std::nullopt;
            result.return_instruction = instruction.address;
            if (stack_target_adjusted || pushed_tracked_register)
            {
                const int64_t return_delta =
                    pushed_tracked_register ? pushed_register_delta : result.delta;
                uint64_t resumed = 0;
                if (!add_word_address(result.pushed_return, return_delta, result.width_bits,
                                      &resumed))
                    return std::nullopt;
                result.resumed_at = resumed;
                // Re-entering the summarized body requires a new logical stack/register
                // state. A single context-free RET edge cannot represent that loop.
                if (resumed >= entry.address && resumed < instruction.end())
                    return std::nullopt;
            }
            if (register_known)
            {
                uint64_t value = 0;
                if (!add_word_address(result.pushed_return, result.delta, result.width_bits,
                                      &value))
                    return std::nullopt;
                result.register_value_at_return = value;
            }
            // A plain read/pop followed by RET consumes an unrelated stack value.
            if ((result.mode == get_pc_mode_t::read_return_address ||
                 result.mode == get_pc_mode_t::pop_return_address) &&
                !pushed_tracked_register)
            {
                return std::nullopt;
            }
            result.stack_accesses.push_back({instruction.address, result.stack_delta_bytes,
                                             result.width_bits, stack_access_kind_t::read,
                                             result.resumed_at, std::nullopt, false});
            if (!add_delta(&result.stack_delta_bytes, word_bytes))
                return std::nullopt;
            result.summary_end = instruction.end();
            return result;
        }

        if (is_control_transfer(instruction.kind))
        {
            // A pop-entry gadget has already consumed the CALL's return address.
            // If the captured value remains exact up to the next control transfer,
            // retain the physical inline continuation without speculating past it.
            if (result.mode == get_pc_mode_t::pop_return_address && register_known)
            {
                result.resumed_at = entry.end();
                result.register_value_at_return = result.pushed_return;
                result.summary_end = entry.end();
                result.stack_delta_bytes = 0;
                result.flags_preserved = true;
                result.support.resize(2);
                result.stack_accesses.resize(2);
                return result;
            }
            return std::nullopt;
        }
        if (is_unmodeled_stack_mutation(instruction.kind))
        {
            return std::nullopt;
        }

        if (instruction.kind != instruction_kind_t::push_register && !instruction.preserves_flags)
            result.flags_preserved = false;

        if (register_known && instruction.destination.overlaps(result.pc_register))
        {
            int64_t adjustment = 0;
            if (instruction.destination.same(result.pc_register) &&
                instruction.source.same(result.pc_register) &&
                instruction.kind == instruction_kind_t::add_register_immediate)
            {
                adjustment = static_cast<int64_t>(instruction.immediate);
            }
            else if (instruction.destination.same(result.pc_register) &&
                     instruction.source.same(result.pc_register) &&
                     instruction.kind == instruction_kind_t::sub_register_immediate)
            {
                const int64_t value = static_cast<int64_t>(instruction.immediate);
                if (value == std::numeric_limits<int64_t>::min())
                    return std::nullopt;
                adjustment = -value;
            }
            else
            {
                register_known = false;
            }
            if (register_known && !add_delta(&result.delta, adjustment))
                return std::nullopt;
        }

        if (instruction.kind == instruction_kind_t::push_register && register_known &&
            instruction.source.same(result.pc_register))
        {
            if (instruction.source.bit_width != result.width_bits ||
                instruction.stack_width_bits != result.width_bits)
                return std::nullopt;
            pushed_tracked_register = true;
            pushed_register_delta = result.delta;
            uint64_t value = 0;
            if (!add_word_address(result.pushed_return, result.delta, result.width_bits, &value) ||
                !add_delta(&result.stack_delta_bytes, -word_bytes))
                return std::nullopt;
            result.stack_accesses.push_back({instruction.address, result.stack_delta_bytes,
                                             result.width_bits, stack_access_kind_t::write,
                                             std::nullopt, value, false});
        }
        else if (instruction.kind == instruction_kind_t::push_register)
        {
            return std::nullopt;
        }
    }

    // A bounded pop-entry scan may reach its limit before a control transfer.
    // The CALL is still an intra-function transfer if the popped PC register
    // remains exact throughout the scanned prefix.
    if (result.mode == get_pc_mode_t::pop_return_address && register_known)
    {
        result.resumed_at = entry.end();
        result.register_value_at_return = result.pushed_return;
        result.summary_end = entry.end();
        result.stack_delta_bytes = 0;
        result.flags_preserved = true;
        result.support.resize(2);
        result.stack_accesses.resize(2);
        return result;
    }
    return std::nullopt;
}

} // namespace chernobog::ida_analysis::classifier
