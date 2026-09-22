#include "get_pc_ida.hpp"
#include "ida_sdk_compat.hpp"
#include "x86_analysis.hpp"
#include "../common/x86_abstract.h"

#include "../common/warn_off.h"
#include <bytes.hpp>
#include <funcs.hpp>
#include <idp.hpp>
#include <intel.hpp>
#include <segment.hpp>
#include <ua.hpp>
#include <xref.hpp>
#include "../common/warn_on.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <string>
#include <vector>

namespace chernobog::ida_analysis
{
namespace
{

using classifier::instruction_kind_t;
using classifier::instruction_t;
using classifier::register_slice_t;

bool stack_pointer_deref(const insn_t &instruction, const op_t &operand)
{
    if (!natad(instruction) || instruction.segpref != 0)
        return false;
    if (operand.type != o_phrase && operand.type != o_displ)
        return false;
    if (operand.type == o_displ && operand.addr != 0)
        return false;
    // Decode the ModRM/SIB form explicitly. `op_t::reg` aliases other operand
    // fields and does not prove that RSP is the sole address component.
    return x86_base_reg(instruction, operand) == R_sp &&
           x86_index_reg(instruction, operand) == R_none;
}

register_slice_t slice_from_operand(const op_t &operand)
{
    register_slice_t result;
    if (operand.type != o_reg)
        return result;
    size_t width = get_dtype_size(operand.dtype);
    if (width == 0 || width > 64)
        return result;
    qstring name;
    if (get_reg_name(&name, operand.reg, width) <= 0)
        return result;
    bitrange_t range;
    const char *main_name = PH.get_reg_info(name.c_str(), &range);
    if (main_name == nullptr)
        return result;
    result.reg = str2reg(main_name);
    if (result.reg < 0)
        return register_slice_t{};
    result.bit_offset = static_cast<uint16_t>(range.empty() ? 0 : range.bitoff());
    const size_t bit_width = range.empty() ? width * 8 : range.bitsize();
    if (bit_width == 0 || bit_width > std::numeric_limits<uint16_t>::max())
        return register_slice_t{};
    result.bit_width = static_cast<uint16_t>(bit_width);
    return result;
}

register_slice_t slice_from_access(const reg_access_t &access, const insn_t &instruction)
{
    register_slice_t result;
    result.reg = access.regnum;
    result.bit_offset = static_cast<uint16_t>(access.range.empty() ? 0 : access.range.bitoff());
    size_t bits = access.range.empty() ? 0 : access.range.bitsize();
    if (bits == 0 && access.opnum < UA_MAXOP)
    {
        const size_t width = get_dtype_size(instruction.ops[access.opnum].dtype);
        if (width <= std::numeric_limits<uint16_t>::max() / 8)
            bits = width * 8;
    }
    if (bits == 0)
        bits = inf_is_64bit() ? 64 : inf_is_32bit_exactly() ? 32 : 16;
    if (bits > std::numeric_limits<uint16_t>::max())
        return register_slice_t{};
    result.bit_width = static_cast<uint16_t>(bits);
    return result;
}

std::vector<register_slice_t> written_registers(const insn_t &instruction)
{
    std::vector<register_slice_t> result;
    reg_accesses_t accesses;
    if (PH.get_reg_accesses(&accesses, instruction, 0) > 0)
    {
        for (const reg_access_t &access : accesses)
        {
            if ((access.access_type & WRITE_ACCESS) == 0)
                continue;
            const register_slice_t slice = slice_from_access(access, instruction);
            if (slice.valid())
                result.push_back(slice);
        }
        return result;
    }

    const uint32_t features = instruction.get_canon_feature(PH);
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        const op_t &operand = instruction.ops[index];
        if (operand.type == o_void)
            break;
        if (operand.type == o_reg && has_cf_chg(features, index))
        {
            const register_slice_t slice = slice_from_operand(operand);
            if (slice.valid())
                result.push_back(slice);
        }
    }
    return result;
}

bool is_stack_pointer_register(const register_slice_t &candidate)
{
    if (!candidate.valid())
        return false;
    static constexpr std::array<const char *, 3> names = {{"rsp", "esp", "sp"}};
    for (const char *name : names)
    {
        bitrange_t range;
        const char *main_name = PH.get_reg_info(name, &range);
        if (main_name != nullptr && str2reg(main_name) == candidate.reg)
            return true;
    }
    return false;
}

bool writes_stack_pointer(const insn_t &instruction)
{
    const std::vector<register_slice_t> writes = written_registers(instruction);
    return std::any_of(writes.begin(), writes.end(), is_stack_pointer_register);
}

bool has_alternate_inbound_flow(ea_t address, ea_t expected_source)
{
    xrefblk_t xref;
    for (bool ok = xref.first_to(address, XREF_FLOW); ok; ok = xref.next_to())
    {
        if (xref.from != expected_source)
            return true;
    }
    return false;
}

bool has_other_entry(ea_t address, ea_t call_ea)
{
    return has_alternate_inbound_flow(address, call_ea);
}

bool same_owner_and_segment(ea_t address, const func_t *owner, const segment_t *segment)
{
    if (segment == nullptr || getseg(address) != segment)
        return false;
    const func_t *candidate = get_func(address);
    return owner == nullptr ? candidate == nullptr : candidate == owner;
}

instruction_t translate_instruction(const insn_t &instruction, const register_slice_t &tracked)
{
    instruction_t result;
    result.address = instruction.ea;
    result.size = instruction.size;
    result.target = classifier::k_bad_address;
    result.stack_width_bits = op64(instruction) ? 64 : op32(instruction) ? 32 : 16;
    result.preserves_flags = instruction.itype == NN_mov || instruction.itype == NN_movzx ||
                             instruction.itype == NN_movsx || instruction.itype == NN_movsxd ||
                             instruction.itype == NN_lea || instruction.itype == NN_xchg ||
                             instruction.itype == NN_nop || instruction.itype == NN_bswap;

    if (is_ret_insn(instruction))
    {
        result.kind = instruction_kind_t::return_instruction;
        result.far_transfer = instruction.itype != NN_retn;
        result.immediate = instruction.Op1.type == o_imm ? instruction.Op1.value : 0;
        return result;
    }
    if (is_call_insn(instruction))
    {
        const bool direct = instruction.Op1.type == o_near || instruction.Op1.type == o_far;
        result.kind = direct ? instruction_kind_t::direct_call : instruction_kind_t::indirect_call;
        if (direct)
            result.target = instruction.Op1.addr;
        result.far_transfer = instruction.Op1.type == o_far;
        return result;
    }
    if (instruction.itype == NN_jmp)
    {
        const bool direct = instruction.Op1.type == o_near || instruction.Op1.type == o_far;
        result.kind = direct ? instruction_kind_t::direct_jump : instruction_kind_t::indirect_jump;
        if (direct)
            result.target = instruction.Op1.addr;
        return result;
    }
    if (is_basic_block_end(instruction, false))
    {
        result.kind = instruction_kind_t::conditional_branch;
        for (int index = 0; index < UA_MAXOP; ++index)
        {
            if (instruction.ops[index].type == o_near || instruction.ops[index].type == o_far)
            {
                result.target = instruction.ops[index].addr;
                break;
            }
        }
        return result;
    }

    if (instruction.itype == NN_pop && instruction.Op1.type == o_reg)
    {
        result.kind = instruction_kind_t::pop_register;
        result.destination = slice_from_operand(instruction.Op1);
        result.destination_is_stack_pointer = is_stack_pointer_register(result.destination);
        return result;
    }
    if (instruction.itype == NN_push)
    {
        if (instruction.Op1.type == o_reg)
        {
            result.kind = instruction_kind_t::push_register;
            result.source = slice_from_operand(instruction.Op1);
        }
        else if (instruction.Op1.type == o_imm)
        {
            result.kind = instruction_kind_t::push_immediate;
        }
        else
            result.kind = instruction_kind_t::push_memory;
        return result;
    }
    if (instruction.itype == NN_mov && instruction.Op1.type == o_reg &&
        stack_pointer_deref(instruction, instruction.Op2))
    {
        result.kind = instruction_kind_t::read_stack_top;
        result.destination = slice_from_operand(instruction.Op1);
        result.destination_is_stack_pointer = is_stack_pointer_register(result.destination);
        return result;
    }
    if (instruction.itype == NN_add && stack_pointer_deref(instruction, instruction.Op1) &&
        instruction.Op2.type == o_imm)
    {
        result.kind = instruction_kind_t::add_stack_top_immediate;
        result.immediate = instruction.Op2.value;
        result.stack_width_bits = static_cast<uint16_t>(get_dtype_size(instruction.Op1.dtype) * 8);
        return result;
    }
    if (instruction.itype == NN_add && instruction.Op1.type == o_reg &&
        instruction.Op1.reg == R_sp && instruction.Op2.type == o_imm)
    {
        result.kind = instruction_kind_t::adjust_stack_pointer_immediate;
        result.immediate = instruction.Op2.value;
        result.stack_width_bits = static_cast<uint16_t>(get_dtype_size(instruction.Op1.dtype) * 8);
        return result;
    }

    // Unknown aliases can modify an outstanding return slot even when the
    // addressing expression does not spell SP. Account for these before tracked
    // register writes (e.g. XCHG RAX,RSP writes both).
    if (writes_stack_pointer(instruction))
    {
        result.kind = instruction_kind_t::stack_mutation;
        return result;
    }
    const uint32_t features = instruction.get_canon_feature(PH);
    for (int index = 0; index < UA_MAXOP; ++index)
    {
        const auto type = instruction.ops[index].type;
        if (has_cf_chg(features, index) && (type == o_mem || type == o_displ || type == o_phrase))
        {
            result.kind = instruction_kind_t::stack_mutation;
            return result;
        }
    }

    switch (instruction.itype)
    {
    case NN_nop:
    case NN_mov:
    case NN_movzx:
    case NN_movsx:
    case NN_movsxd:
    case NN_lea:
    case NN_xchg:
    case NN_bswap:
    case NN_add:
    case NN_sub:
    case NN_adc:
    case NN_sbb:
    case NN_inc:
    case NN_dec:
    case NN_and:
    case NN_or:
    case NN_xor:
    case NN_not:
    case NN_neg:
    case NN_cmp:
    case NN_test:
    case NN_shl:
    case NN_shr:
    case NN_sar:
    case NN_rol:
    case NN_ror:
    case NN_clc:
    case NN_stc:
    case NN_cmc:
        break;
    default:
        result.kind = instruction_kind_t::stack_mutation;
        return result;
    }

    register_slice_t destination;
    const std::vector<register_slice_t> writes = written_registers(instruction);
    for (const register_slice_t &write : writes)
    {
        if (tracked.valid() && write.overlaps(tracked))
        {
            destination = write;
            break;
        }
    }
    if (destination.valid())
    {
        result.destination = destination;
        if (instruction.Op1.type == o_reg)
            result.source = slice_from_operand(instruction.Op1);
        if ((instruction.itype == NN_add || instruction.itype == NN_sub) &&
            instruction.Op2.type == o_imm && result.destination.same(result.source))
        {
            result.kind = instruction.itype == NN_add ? instruction_kind_t::add_register_immediate
                                                      : instruction_kind_t::sub_register_immediate;
            result.immediate = instruction.Op2.value;
            return result;
        }
        if ((instruction.itype == NN_inc || instruction.itype == NN_dec) &&
            result.destination.same(result.source))
        {
            result.kind = instruction.itype == NN_inc ? instruction_kind_t::add_register_immediate
                                                      : instruction_kind_t::sub_register_immediate;
            result.immediate = 1;
            return result;
        }
        if (instruction.itype == NN_lea && instruction.Op1.type == o_reg &&
            instruction.Op2.type == o_displ &&
            x86_index_reg(instruction, instruction.Op2) == R_none)
        {
            // Resolve the sole address-base register at the destination width.
            op_t base = instruction.Op1;
            base.reg = x86_base_reg(instruction, instruction.Op2);
            result.source = slice_from_operand(base);
            if (result.destination.same(result.source))
            {
                const sval_t displacement = static_cast<sval_t>(instruction.Op2.addr);
                result.kind = displacement < 0 ? instruction_kind_t::sub_register_immediate
                                               : instruction_kind_t::add_register_immediate;
                result.immediate =
                    displacement < 0 ? uint64_t(-(displacement + 1)) + 1 : uint64_t(displacement);
                return result;
            }
        }
        result.kind = instruction_kind_t::register_write;
        return result;
    }

    return result;
}

} // namespace

std::optional<classifier::push_get_pc_t> classify_ida_push_get_pc(const insn_t &push)
{
    using namespace classifier;
    if (PH.id != PLFM_386 || push.itype != NN_push || push.size == 0 ||
        (!mode32(push) && !mode64(push)) || !natad(push))
        return std::nullopt;
    const unsigned mode = mode64(push) ? 64 : 32;
    instruction_t first = translate_instruction(push, {});
    if (first.stack_width_bits != mode)
        return std::nullopt;
    if (mode == 32)
    {
        if (push.Op1.type != o_imm)
            return std::nullopt;
        first.immediate = uint32_t(push.Op1.value);
        return classify_push_get_pc({first}, mode);
    }
    if (push.Op1.type != o_reg)
        return std::nullopt;
    first.source_is_stack_pointer = is_stack_pointer_register(first.source);
    const auto *owner = get_func(push.ea);
    const auto *segment = getseg(push.ea);
    insn_t lea, exchange;
    if (first.end() == k_bad_address || decode_insn(&lea, ea_t(first.end())) <= 0 ||
        lea.itype != NN_lea || !mode64(lea) || !op64(lea) || !natad(lea) || lea.Op1.type != o_reg ||
        lea.Op2.type != o_mem || lea.Op2.hasSIB ||
        !same_owner_and_segment(lea.ea, owner, segment) ||
        has_alternate_inbound_flow(lea.ea, push.ea) || lea.ea > BADADDR - lea.size)
        return std::nullopt;
    if (decode_insn(&exchange, lea.ea + lea.size) <= 0 || exchange.itype != NN_xchg ||
        !mode64(exchange) || !op64(exchange) || !natad(exchange) ||
        !same_owner_and_segment(exchange.ea, owner, segment) ||
        has_alternate_inbound_flow(exchange.ea, lea.ea))
        return std::nullopt;
    const op_t *reg = nullptr, *memory = nullptr;
    if (exchange.Op1.type == o_reg)
    {
        reg = &exchange.Op1;
        memory = &exchange.Op2;
    }
    else if (exchange.Op2.type == o_reg)
    {
        reg = &exchange.Op2;
        memory = &exchange.Op1;
    }
    if (reg == nullptr || !stack_pointer_deref(exchange, *memory) ||
        get_dtype_size(memory->dtype) != 8)
        return std::nullopt;
    instruction_t address, swap;
    address.address = lea.ea;
    address.size = lea.size;
    address.stack_width_bits = 64;
    address.kind = instruction_kind_t::load_pc_relative_address;
    address.destination = slice_from_operand(lea.Op1);
    address.destination_is_stack_pointer = is_stack_pointer_register(address.destination);
    address.target = lea.Op2.addr;
    swap.address = exchange.ea;
    swap.size = exchange.size;
    swap.stack_width_bits = 64;
    swap.kind = instruction_kind_t::exchange_stack_top_register;
    swap.source = slice_from_operand(*reg);
    return classify_push_get_pc({first, address, swap}, mode);
}

std::optional<classifier::stack_transfer_t> classify_ida_push_return(const insn_t &push,
                                                                     int register_scan_depth)
{
    using namespace classifier;
    if (PH.id != PLFM_386 || push.itype != NN_push || push.size == 0 ||
        (!mode32(push) && !mode64(push)) || !natad(push))
        return std::nullopt;
    const unsigned mode = mode64(push) ? 64 : 32;
    const unsigned push_width = op64(push) ? 64 : op16(push) ? 16 : 32;
    if (push_width != mode || push.ea > BADADDR - push.size)
        return std::nullopt;
    insn_t ret;
    if (decode_insn(&ret, push.ea + push.size) <= 0 || ret.itype != NN_retn ||
        mode64(ret) != mode64(push) || mode32(ret) != mode32(push) ||
        (mode == 64 ? !op64(ret) : !op32(ret)) || has_alternate_inbound_flow(ret.ea, push.ea) ||
        getseg(ret.ea) != getseg(push.ea) || get_func(ret.ea) != get_func(push.ea))
        return std::nullopt;
    instruction_t p, r;
    p.address = push.ea;
    p.size = push.size;
    p.stack_width_bits = uint16_t(mode);
    r.address = ret.ea;
    r.size = ret.size;
    r.stack_width_bits = uint16_t(mode);
    r.kind = instruction_kind_t::return_instruction;
    if (ret.Op1.type != o_void && ret.Op1.type != o_imm)
        return std::nullopt;
    r.immediate = ret.Op1.type == o_imm ? ret.Op1.value : 0;
    target_proof_t proof;
    auto tracked = [&](const op_t &operand) -> std::optional<uint64_t>
    {
        const size_t bytes = get_dtype_size(operand.dtype);
        if (operand.type != o_reg || bytes != mode / 8)
            return std::nullopt;
        // Independently replay a bounded, single-entry instruction prefix. This
        // never converts initial writable-memory bytes into a register constant.
        const auto fact = analyze_x86_register_before(
            push, operand, register_scan_depth > 0 ? size_t(register_scan_depth) : size_t(64));
        // An unresolved value still depends on the inspected prefix. Retain that
        // dependency so restoring a defining instruction requeues this consumer.
        proof.definitions.insert(proof.definitions.end(), fact.support.begin(), fact.support.end());
        if (!fact.value || fact.support.empty())
            return std::nullopt;
        proof.registers.push_back(slice_from_operand(operand));
        return *fact.value & x86_abstract::mask(mode);
    };
    if (push.Op1.type == o_imm)
    {
        p.kind = instruction_kind_t::push_immediate;
        proof.kind = target_proof_kind_t::immediate;
        // Architectural PUSH in 64-bit mode sign-extends its immediate encoding.
        proof.value = mode == 64 ? uint64_t(int64_t(int32_t(push.Op1.value)))
                                 : uint64_t(uint32_t(push.Op1.value));
    }
    else if (push.Op1.type == o_reg)
    {
        p.kind = instruction_kind_t::push_register;
        p.source = slice_from_operand(push.Op1);
        proof.value = tracked(push.Op1);
        if (proof.value)
            proof.kind = target_proof_kind_t::register_definition;
    }
    else if (push.Op1.type == o_mem || push.Op1.type == o_displ || push.Op1.type == o_phrase)
    {
        p.kind = instruction_kind_t::push_memory;
        // Segment overrides require segment-base evidence, especially FS/GS.
        if (push.segpref != 0)
            return classify_push_return(p, r, mode, proof);
        std::optional<uint64_t> address;
        const op_t &mem = push.Op1;
        if (mem.type == o_mem && !mem.hasSIB)
            address = mem.addr;
        else
        {
            uint64_t a = mem.type == o_displ || mem.type == o_mem ? mem.addr : 0;
            bool complete = true;
            const int base = x86_base_reg(push, mem), index = x86_index_reg(push, mem);
            for (const auto &part :
                 {std::make_pair(base, 0), std::make_pair(index, x86_scale(mem))})
            {
                if (part.first == R_none)
                    continue;
                op_t reg;
                reg.type = o_reg;
                reg.reg = uint16_t(part.first);
                reg.dtype = mode == 64 ? dt_qword : dt_dword;
                const auto value = tracked(reg);
                if (!value || part.second < 0 || part.second > 3)
                {
                    complete = false;
                    break;
                }
                a += *value << unsigned(part.second);
            }
            if (complete)
                address = a & x86_abstract::mask(mode);
        }
        if (address && *address <= BADADDR - mode / 8)
        {
            const segment_t *segment = getseg(ea_t(*address));
            const ea_t end = ea_t(*address + mode / 8 - 1);
            bool immutable = segment && getseg(end) == segment && segment->type != SEG_XTRN &&
                             (segment->perm & SEGPERM_READ) && !(segment->perm & SEGPERM_WRITE);
            memory_dependency_t memory;
            memory.address = *address;
            uint64_t value = 0;
            for (unsigned i = 0; immutable && i < mode / 8; ++i)
            {
                const ea_t at = ea_t(*address + i);
                if (!is_loaded(at))
                {
                    immutable = false;
                    break;
                }
                xrefblk_t xref;
                for (bool ok = xref.first_to(at, XREF_DATA); ok; ok = xref.next_to())
                    if ((xref.type & XREF_MASK) == dr_W)
                        immutable = false;
                const uint8_t byte = get_byte(at);
                memory.bytes.push_back(byte);
                value |= uint64_t(byte) << (8 * i);
            }
            if (immutable)
            {
                proof.value = value;
                proof.kind = target_proof_kind_t::immutable_memory;
                proof.memory.push_back(std::move(memory));
            }
        }
    }
    else
        return std::nullopt;
    return classify_push_return(p, r, mode, proof);
}

std::optional<classifier::get_pc_candidate_t>
classify_ida_get_pc_call(const insn_t &call, size_t maximum_depth, bool reject_other_entries)
{
    if (PH.id != PLFM_386 || maximum_depth == 0 || call.itype != NN_call ||
        call.Op1.type != o_near || call.size == 0 || (!mode32(call) && !mode64(call)) ||
        !natad(call) || (mode64(call) ? !op64(call) : !op32(call)) || call.ea > BADADDR - call.size)
    {
        return std::nullopt;
    }
    const ea_t target = call.Op1.addr;
    if (target == BADADDR)
        return std::nullopt;
    const segment_t *segment = getseg(target);
    const func_t *owner = get_func(target);
    if (segment == nullptr || !is_mapped(target))
        return std::nullopt;

    std::vector<instruction_t> gadget;
    gadget.reserve(maximum_depth + 1);
    ea_t cursor = target;
    register_slice_t tracked;
    ea_t previous = call.ea;
    for (size_t index = 0; index <= maximum_depth; ++index)
    {
        if (!same_owner_and_segment(cursor, owner, segment))
            return std::nullopt;
        insn_t decoded;
        if (decode_insn(&decoded, cursor) <= 0 || decoded.size == 0)
            break;
        if (mode64(decoded) != mode64(call) || mode32(decoded) != mode32(call) || !natad(decoded))
            return std::nullopt;
        instruction_t translated = translate_instruction(decoded, tracked);
        translated.alternate_predecessor =
            index != 0 && has_alternate_inbound_flow(cursor, previous);
        if (index == 0)
        {
            if (translated.kind == instruction_kind_t::pop_register ||
                translated.kind == instruction_kind_t::read_stack_top)
            {
                tracked = translated.destination;
            }
        }
        gadget.push_back(translated);
        previous = cursor;
        if (cursor > BADADDR - decoded.size)
            break;
        cursor += decoded.size;
        if (translated.kind == instruction_kind_t::return_instruction ||
            translated.kind == instruction_kind_t::direct_jump ||
            translated.kind == instruction_kind_t::indirect_jump ||
            translated.kind == instruction_kind_t::conditional_branch ||
            translated.kind == instruction_kind_t::direct_call ||
            translated.kind == instruction_kind_t::indirect_call)
            break;
    }

    instruction_t core_call;
    core_call.address = call.ea;
    core_call.size = call.size;
    core_call.kind = instruction_kind_t::direct_call;
    core_call.target = target;
    core_call.stack_width_bits = mode64(call) ? 64 : 32;
    const bool other_entries = reject_other_entries && has_other_entry(target, call.ea);
    const auto result =
        classifier::classify_get_pc_gadget(core_call, gadget, other_entries, maximum_depth);
    qstring trace;
    if (qgetenv("CHERNOBOG_IDA_GET_PC_TRACE", &trace) && !trace.empty() && trace[0] != '0' &&
        !gadget.empty() &&
        (gadget.front().kind == instruction_kind_t::pop_register ||
         gadget.front().kind == instruction_kind_t::read_stack_top ||
         gadget.front().kind == instruction_kind_t::add_stack_top_immediate ||
         gadget.front().kind == instruction_kind_t::adjust_stack_pointer_immediate))
    {
        msg("[chernobog][ida-analysis][get-pc-trace] call=%a target=%a "
            "other-entry=%d result=%s count=%zu\n",
            call.ea, target, other_entries ? 1 : 0, result ? "accepted" : "rejected",
            gadget.size());
        for (const instruction_t &item : gadget)
        {
            msg("[chernobog][ida-analysis][get-pc-trace]   ea=%a size=%u "
                "kind=%u dst={%d,%u,%u} src={%d,%u,%u} imm=%llu alt=%d\n",
                ea_t(item.address), unsigned(item.size), unsigned(item.kind), item.destination.reg,
                unsigned(item.destination.bit_offset), unsigned(item.destination.bit_width),
                item.source.reg, unsigned(item.source.bit_offset), unsigned(item.source.bit_width),
                static_cast<unsigned long long>(item.immediate),
                item.alternate_predecessor ? 1 : 0);
        }
    }
    return result;
}

} // namespace chernobog::ida_analysis
