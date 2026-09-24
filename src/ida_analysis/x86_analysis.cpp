#include "x86_analysis.hpp"
#include "native_classifier.hpp"
#include "../common/bounded_dataflow.h"

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
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <sstream>
#include <vector>

namespace chernobog::ida_analysis
{

std::optional<X86Condition> x86_condition(uint16_t type)
{
    using C = x86_abstract::Condition;
    using U = X86ConditionUse;
#define CONDITION(j, s, m, c)                                                                      \
    case j:                                                                                        \
        return X86Condition{C::c, U::branch};                                                      \
    case s:                                                                                        \
        return X86Condition{C::c, U::set_byte};                                                    \
    case m:                                                                                        \
        return X86Condition { C::c, U::conditional_move }
    switch (type)
    {
        CONDITION(NN_jo, NN_seto, NN_cmovo, overflow);
        CONDITION(NN_jno, NN_setno, NN_cmovno, not_overflow);
        CONDITION(NN_jb, NN_setb, NN_cmovb, below);
        CONDITION(NN_jnb, NN_setnb, NN_cmovnb, above_equal);
        CONDITION(NN_jz, NN_setz, NN_cmovz, equal);
        CONDITION(NN_jnz, NN_setnz, NN_cmovnz, not_equal);
        CONDITION(NN_jbe, NN_setbe, NN_cmovbe, below_equal);
        CONDITION(NN_ja, NN_seta, NN_cmova, above);
        CONDITION(NN_js, NN_sets, NN_cmovs, sign);
        CONDITION(NN_jns, NN_setns, NN_cmovns, not_sign);
        CONDITION(NN_jp, NN_setp, NN_cmovp, parity);
        CONDITION(NN_jnp, NN_setnp, NN_cmovnp, not_parity);
        CONDITION(NN_jl, NN_setl, NN_cmovl, less);
        CONDITION(NN_jnl, NN_setge, NN_cmovge, greater_equal);
        CONDITION(NN_jle, NN_setle, NN_cmovle, less_equal);
        CONDITION(NN_jnle, NN_setg, NN_cmovg, greater);
    case NN_jc:
    case NN_jnae:
        return X86Condition{C::below, U::branch};
    case NN_jae:
    case NN_jnc:
        return X86Condition{C::above_equal, U::branch};
    case NN_je:
        return X86Condition{C::equal, U::branch};
    case NN_jne:
        return X86Condition{C::not_equal, U::branch};
    case NN_jna:
        return X86Condition{C::below_equal, U::branch};
    case NN_jnbe:
        return X86Condition{C::above, U::branch};
    case NN_jpe:
        return X86Condition{C::parity, U::branch};
    case NN_jpo:
        return X86Condition{C::not_parity, U::branch};
    case NN_jnge:
        return X86Condition{C::less, U::branch};
    case NN_jge:
        return X86Condition{C::greater_equal, U::branch};
    case NN_jng:
        return X86Condition{C::less_equal, U::branch};
    case NN_jg:
        return X86Condition{C::greater, U::branch};
    case NN_setc:
    case NN_setnae:
        return X86Condition{C::below, U::set_byte};
    case NN_setae:
    case NN_setnc:
        return X86Condition{C::above_equal, U::set_byte};
    case NN_sete:
        return X86Condition{C::equal, U::set_byte};
    case NN_setne:
        return X86Condition{C::not_equal, U::set_byte};
    case NN_setna:
        return X86Condition{C::below_equal, U::set_byte};
    case NN_setnbe:
        return X86Condition{C::above, U::set_byte};
    case NN_setpe:
        return X86Condition{C::parity, U::set_byte};
    case NN_setpo:
        return X86Condition{C::not_parity, U::set_byte};
    case NN_setnge:
        return X86Condition{C::less, U::set_byte};
    case NN_setnl:
        return X86Condition{C::greater_equal, U::set_byte};
    case NN_setng:
        return X86Condition{C::less_equal, U::set_byte};
    case NN_setnle:
        return X86Condition{C::greater, U::set_byte};
    default:
        return std::nullopt;
    }
#undef CONDITION
}

namespace
{
using namespace x86_abstract;

struct Slice
{
    int reg = -1;
    unsigned width = 0;
    unsigned offset = 0;
};

Slice register_slice(const op_t &operand)
{
    if (operand.type != o_reg)
        return {};
    const size_t bytes = get_dtype_size(operand.dtype);
    if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
        return {};
    qstring name;
    if (get_reg_name(&name, operand.reg, bytes) <= 0)
        return {};
    static const char *const names[16][4] = {
        {"al", "ax", "eax", "rax"},      {"cl", "cx", "ecx", "rcx"},
        {"dl", "dx", "edx", "rdx"},      {"bl", "bx", "ebx", "rbx"},
        {"spl", "sp", "esp", "rsp"},     {"bpl", "bp", "ebp", "rbp"},
        {"sil", "si", "esi", "rsi"},     {"dil", "di", "edi", "rdi"},
        {"r8b", "r8w", "r8d", "r8"},     {"r9b", "r9w", "r9d", "r9"},
        {"r10b", "r10w", "r10d", "r10"}, {"r11b", "r11w", "r11d", "r11"},
        {"r12b", "r12w", "r12d", "r12"}, {"r13b", "r13w", "r13d", "r13"},
        {"r14b", "r14w", "r14d", "r14"}, {"r15b", "r15w", "r15d", "r15"},
    };
    for (int reg = 0; reg < 16; ++reg)
        for (unsigned part = 0; part < 4; ++part)
            if (name == names[reg][part])
                return {reg, 8u << part, 0};
    static const char *const high[4] = {"ah", "ch", "dh", "bh"};
    for (int reg = 0; reg < 4; ++reg)
        if (name == high[reg])
            return {reg, 8, 8};
    return {};
}

Operation operation(uint16_t type)
{
    switch (type)
    {
    case NN_add:
        return Operation::add;
    case NN_adc:
        return Operation::adc;
    case NN_sub:
        return Operation::sub;
    case NN_sbb:
        return Operation::sbb;
    case NN_cmp:
        return Operation::compare;
    case NN_inc:
        return Operation::increment;
    case NN_dec:
        return Operation::decrement;
    case NN_neg:
        return Operation::negate;
    case NN_and:
        return Operation::bit_and;
    case NN_or:
        return Operation::bit_or;
    case NN_xor:
        return Operation::bit_xor;
    case NN_test:
        return Operation::test;
    case NN_not:
        return Operation::bit_not;
    case NN_shl:
    case NN_sal:
        return Operation::shift_left;
    case NN_shr:
        return Operation::shift_right;
    case NN_sar:
        return Operation::arithmetic_right;
    case NN_clc:
        return Operation::clear_carry;
    case NN_stc:
        return Operation::set_carry;
    case NN_cmc:
        return Operation::complement_carry;
    default:
        return Operation::unknown;
    }
}

struct State
{
    Flags flags;
    std::array<Word, 16> regs{};
    // Only words established by this single-entry replay are retained. No
    // initial stack memory or absolute stack address is assumed known.
    std::vector<Word> stack;
    // Only bytes written within this replay are retained. Initial image bytes
    // in writable segments never enter this map.
    std::map<uint64_t, uint8_t> memory;

    void join(const State &other)
    {
        flags.join(other.flags);
        for (size_t i = 0; i < regs.size(); ++i)
            regs[i].join(other.regs[i]);
        // Both vectors describe a suffix above otherwise unknown stack bytes.
        const size_t count = std::min(stack.size(), other.stack.size());
        std::vector<Word> suffix(count);
        for (size_t i = 0; i < count; ++i)
        {
            suffix[i] = stack[stack.size() - count + i];
            suffix[i].join(other.stack[other.stack.size() - count + i]);
        }
        stack = std::move(suffix);
        for (auto it = memory.begin(); it != memory.end();)
        {
            const auto peer = other.memory.find(it->first);
            if (peer == other.memory.end() || it->second != peer->second)
                it = memory.erase(it);
            else
                ++it;
        }
    }

    bool operator==(const State &other) const
    {
        if (flags.known != other.flags.known || flags.value != other.flags.value ||
            stack.size() != other.stack.size() || memory.size() != other.memory.size())
            return false;
        for (size_t i = 0; i < stack.size(); ++i)
            if (stack[i].known != other.stack[i].known || stack[i].value != other.stack[i].value)
                return false;
        for (size_t i = 0; i < regs.size(); ++i)
            if (regs[i].known != other.regs[i].known || regs[i].value != other.regs[i].value)
                return false;
        return memory == other.memory;
    }

    static bool stack_top(const insn_t &insn, const op_t &operand)
    {
        return natad(insn) && insn.segpref == 0 &&
               (operand.type == o_phrase || (operand.type == o_displ && operand.addr == 0)) &&
               get_dtype_size(operand.dtype) == (mode64(insn) ? 8 : 4) &&
               x86_base_reg(insn, operand) == R_sp && x86_index_reg(insn, operand) == R_none;
    }

    void adjust_sp(int64_t delta, bool is64)
    {
        const unsigned bits = is64 ? 64 : 32;
        auto value = regs[4].read(bits, 0);
        if (value)
            *value = (*value + uint64_t(delta)) & mask(bits);
        regs[4].write(bits, 0, value, is64);
    }

    std::optional<uint64_t> read(const op_t &operand, unsigned target_width = 0) const
    {
        if (operand.type == o_imm)
        {
            uint64_t value = operand.value;
            const unsigned bits = unsigned(get_dtype_size(operand.dtype) * 8);
            if (valid_width(bits) && bits < target_width)
            {
                value &= mask(bits);
                if (value & (uint64_t{1} << (bits - 1)))
                    value |= ~mask(bits);
            }
            return value;
        }
        const Slice s = register_slice(operand);
        return s.reg < 0 ? std::nullopt : regs[size_t(s.reg)].read(s.width, s.offset);
    }

    std::optional<uint64_t> read_stack_top(unsigned bits) const
    {
        return stack.empty() ? std::nullopt : stack.back().read(bits);
    }

    std::optional<uint64_t> memory_address(const insn_t &insn, const op_t &operand) const
    {
        if (!natad(insn) || insn.segpref != 0 ||
            (operand.type != o_mem && operand.type != o_displ && operand.type != o_phrase))
            return std::nullopt;
        const unsigned bits = mode64(insn) ? 64 : mode32(insn) ? 32 : 0;
        if (!bits)
            return std::nullopt;
        if (operand.type == o_mem && !operand.hasSIB)
            return operand.addr & mask(bits);
        uint64_t address = operand.type == o_phrase ? 0 : operand.addr;
        for (const auto &part : {std::make_pair(x86_base_reg(insn, operand), 0),
                                 std::make_pair(x86_index_reg(insn, operand), x86_scale(operand))})
        {
            if (part.first == R_none)
                continue;
            if (part.second < 0 || part.second > 3)
                return std::nullopt;
            op_t reg;
            reg.type = o_reg;
            reg.reg = uint16_t(part.first);
            reg.dtype = bits == 64 ? dt_qword : dt_dword;
            const auto value = read(reg);
            if (!value)
                return std::nullopt;
            address += *value << unsigned(part.second);
        }
        return address & mask(bits);
    }

    static bool writable_range(uint64_t address, size_t bytes, unsigned address_bits)
    {
        if ((bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) ||
            (address_bits != 32 && address_bits != 64) || address > BADADDR - bytes ||
            (address_bits == 32 && address > UINT32_MAX - (bytes - 1)))
            return false;
        const auto *segment = getseg(ea_t(address));
        return segment && getseg(ea_t(address + bytes - 1)) == segment &&
               segment->type != SEG_XTRN && (segment->perm & SEGPERM_READ) &&
               (segment->perm & SEGPERM_WRITE);
    }

    static bool writable_word(uint64_t address, unsigned bits)
    {
        return (bits == 32 || bits == 64) && writable_range(address, bits / 8, bits);
    }

    std::optional<uint64_t> read_memory(uint64_t address, unsigned bits) const
    {
        if (!valid_width(bits) || address > BADADDR - bits / 8)
            return std::nullopt;
        uint64_t value = 0;
        for (unsigned i = 0; i < bits / 8; ++i)
        {
            const auto found = memory.find(address + i);
            if (found == memory.end())
                return std::nullopt;
            value |= uint64_t(found->second) << (i * 8);
        }
        return value;
    }

    void invalidate_memory(std::optional<uint64_t> address, size_t bytes)
    {
        if (!address || bytes == 0 || *address > BADADDR - bytes)
        {
            memory.clear();
            return;
        }
        auto it = memory.lower_bound(*address);
        while (it != memory.end() && it->first < *address + bytes)
            it = memory.erase(it);
    }

    void store_memory(uint64_t address, unsigned bits, uint64_t value)
    {
        for (unsigned i = 0; i < bits / 8; ++i)
        {
            if (memory.size() == 128 && !memory.count(address + i))
                memory.erase(memory.begin());
            memory[address + i] = uint8_t(value >> (8 * i));
        }
    }

    void write(const op_t &operand, std::optional<uint64_t> value, bool mode64)
    {
        const Slice s = register_slice(operand);
        if (s.reg >= 0)
        {
            if (s.reg == 4)
                stack.clear();
            regs[size_t(s.reg)].write(s.width, s.offset, value, mode64);
        }
    }

    void step(const insn_t &insn)
    {
        const bool is64 = mode64(insn);
        const unsigned width = unsigned(get_dtype_size(insn.Op1.dtype) * 8);
        const unsigned word_bits = is64 ? 64 : 32;
        const auto algebra = operation(insn.itype);
        const auto memory_operand = [](const op_t &operand)
        { return operand.type == o_mem || operand.type == o_displ || operand.type == o_phrase; };
        const auto algebra_address =
            algebra != Operation::unknown && memory_operand(insn.Op1) && valid_width(width)
                ? memory_address(insn, insn.Op1)
                : std::nullopt;
        const auto algebra_read = [&](const op_t &operand) -> std::optional<uint64_t>
        {
            if (!memory_operand(operand))
                return read(operand, width);
            if (unsigned(get_dtype_size(operand.dtype) * 8) != width || !valid_width(width))
                return std::nullopt;
            const auto address = memory_address(insn, operand);
            return address && writable_range(*address, width / 8, word_bits)
                       ? read_memory(*address, width)
                       : std::nullopt;
        };
        // Capture both operands before the canonical memory-write invalidation.
        // An RMW instruction reads the old bytes before it writes the result.
        const auto algebra_left =
            algebra == Operation::unknown ? std::nullopt : algebra_read(insn.Op1);
        const auto algebra_right =
            algebra == Operation::unknown ? std::nullopt : algebra_read(insn.Op2);
        const bool local_memory_store =
            insn.itype == NN_mov &&
            (insn.Op1.type == o_mem || insn.Op1.type == o_displ || insn.Op1.type == o_phrase) &&
            valid_width(width);
        const auto store_address =
            local_memory_store ? memory_address(insn, insn.Op1) : std::nullopt;
        const auto store_value = local_memory_store ? read(insn.Op2, width) : std::nullopt;
        const unsigned load_width = unsigned(get_dtype_size(insn.Op2.dtype) * 8);
        const Slice load_register = register_slice(insn.Op1);
        const bool local_memory_load =
            (insn.itype == NN_mov || insn.itype == NN_movzx || insn.itype == NN_movsx ||
             insn.itype == NN_movsxd) &&
            insn.Op1.type == o_reg &&
            (insn.Op2.type == o_mem || insn.Op2.type == o_displ || insn.Op2.type == o_phrase) &&
            valid_width(width) && valid_width(load_width) &&
            (insn.itype == NN_mov ? load_width == width : load_width < width) &&
            load_register.reg >= 0 && load_register.reg != 4 && load_register.width == width;
        std::optional<uint64_t> load_value;
        if (local_memory_load)
        {
            const auto address = memory_address(insn, insn.Op2);
            if (address && writable_range(*address, load_width / 8, word_bits))
                load_value = read_memory(*address, load_width);
        }
        const op_t *exchange_reg = nullptr;
        const op_t *memory_exchange_reg = nullptr;
        std::optional<uint64_t> memory_exchange_address;
        std::optional<uint64_t> memory_exchange_old;
        std::optional<uint64_t> memory_exchange_new;
        unsigned memory_exchange_width = 0;
        if (insn.itype == NN_xchg)
        {
            if (insn.Op1.type == o_reg && stack_top(insn, insn.Op2))
                exchange_reg = &insn.Op1;
            if (insn.Op2.type == o_reg && stack_top(insn, insn.Op1))
                exchange_reg = &insn.Op2;
            if (exchange_reg != nullptr)
            {
                const auto slice = register_slice(*exchange_reg);
                if (slice.reg < 0 || slice.reg == 4 || slice.width != word_bits)
                    exchange_reg = nullptr;
            }
            if (exchange_reg == nullptr)
            {
                const op_t *mem = nullptr;
                if (insn.Op1.type == o_reg && memory_operand(insn.Op2))
                {
                    memory_exchange_reg = &insn.Op1;
                    mem = &insn.Op2;
                }
                else if (insn.Op2.type == o_reg && memory_operand(insn.Op1))
                {
                    memory_exchange_reg = &insn.Op2;
                    mem = &insn.Op1;
                }
                if (mem != nullptr)
                {
                    memory_exchange_width = unsigned(get_dtype_size(mem->dtype) * 8);
                    const Slice reg = register_slice(*memory_exchange_reg);
                    if (!valid_width(memory_exchange_width) || reg.reg < 0 || reg.reg == 4 ||
                        reg.width != memory_exchange_width)
                        memory_exchange_reg = nullptr;
                    else
                    {
                        memory_exchange_address = memory_address(insn, *mem);
                        if (memory_exchange_address &&
                            writable_range(*memory_exchange_address, memory_exchange_width / 8,
                                           word_bits))
                        {
                            memory_exchange_old =
                                read_memory(*memory_exchange_address, memory_exchange_width);
                            memory_exchange_new = read(*memory_exchange_reg);
                        }
                        else
                            memory_exchange_reg = nullptr;
                    }
                }
            }
        }
        const uint32_t features = insn.get_canon_feature(PH);
        for (int index = 0; index < UA_MAXOP; ++index)
        {
            const auto type = insn.ops[index].type;
            if (has_cf_chg(features, index) && type == o_reg &&
                register_slice(insn.ops[index]).reg < 0)
                stack.clear();
            if (exchange_reg == nullptr && has_cf_chg(features, index) &&
                (type == o_mem || type == o_displ || type == o_phrase))
                stack.clear();
            if (has_cf_chg(features, index) &&
                (type == o_mem || type == o_displ || type == o_phrase))
                invalidate_memory(memory_address(insn, insn.ops[index]),
                                  get_dtype_size(insn.ops[index].dtype));
        }
        const auto cond = x86_condition(insn.itype);
        if (cond && cond->use != X86ConditionUse::branch)
        {
            const auto result = evaluate(cond->condition, flags);
            if (cond->use == X86ConditionUse::set_byte)
                write(insn.Op1, result ? std::optional<uint64_t>(*result ? 1 : 0) : std::nullopt,
                      is64);
            else
            {
                // CMOV always writes the architectural destination width; a
                // false 32-bit CMOV in 64-bit mode still clears its upper half.
                const auto v = result ? read(*result ? insn.Op2 : insn.Op1) : std::nullopt;
                write(insn.Op1, v, is64);
            }
            return;
        }
        switch (insn.itype)
        {
        case NN_mov:
        {
            std::optional<uint64_t> move_value;
            if (stack_top(insn, insn.Op2))
                move_value = stack.empty() ? std::nullopt : stack.back().read(word_bits);
            else if (local_memory_load)
                move_value = load_value;
            else
                move_value = read(insn.Op2, width);
            write(insn.Op1, move_value, is64);
            if (store_address && store_value &&
                writable_range(*store_address, width / 8, word_bits))
                store_memory(*store_address, width, *store_value);
            return;
        }
        case NN_movzx:
        case NN_movsx:
        case NN_movsxd:
        {
            auto v = local_memory_load ? load_value : read(insn.Op2);
            const unsigned source_width = unsigned(get_dtype_size(insn.Op2.dtype) * 8);
            if (v && valid_width(source_width) && source_width < width)
            {
                *v &= mask(source_width);
                if (insn.itype != NN_movzx && (*v & (uint64_t{1} << (source_width - 1))))
                    *v |= ~mask(source_width);
            }
            else
                v.reset();
            write(insn.Op1, v, is64);
            return;
        }
        case NN_lea:
        {
            std::optional<uint64_t> result;
            const op_t &mem = insn.Op2;
            const unsigned address_width = ad64(insn) ? 64 : ad32(insn) ? 32 : 16;
            if (address_width != 16 && mem.type == o_mem && !mem.hasSIB)
                result = mem.addr & mask(address_width);
            else if (address_width != 16 &&
                     (mem.type == o_displ || mem.type == o_phrase || mem.type == o_mem))
            {
                uint64_t value = mem.type == o_phrase ? 0 : mem.addr;
                bool complete = true;
                const int base = x86_base_reg(insn, mem), index = x86_index_reg(insn, mem);
                for (const auto &part :
                     {std::make_pair(base, 0), std::make_pair(index, x86_scale(mem))})
                {
                    if (part.first == R_none)
                        continue;
                    op_t reg;
                    reg.type = o_reg;
                    reg.reg = uint16_t(part.first);
                    reg.dtype = address_width == 64 ? dt_qword : dt_dword;
                    const auto v = read(reg);
                    if (!v || part.second < 0 || part.second > 3)
                    {
                        complete = false;
                        break;
                    }
                    value += *v << unsigned(part.second);
                }
                if (complete)
                    result = value & mask(address_width);
            }
            write(insn.Op1, result, is64);
            return;
        }
        case NN_xchg:
        {
            if (exchange_reg != nullptr)
            {
                const auto value = read(*exchange_reg);
                const auto old_top = stack.empty() ? std::nullopt : stack.back().read(word_bits);
                Word replacement;
                replacement.write(word_bits, 0, value, is64);
                if (stack.empty())
                    stack.push_back(replacement);
                else
                    stack.back() = replacement;
                write(*exchange_reg, old_top, is64);
                return;
            }
            if (memory_exchange_reg != nullptr)
            {
                invalidate_memory(memory_exchange_address, memory_exchange_width / 8);
                write(*memory_exchange_reg, memory_exchange_old, is64);
                if (memory_exchange_new)
                    store_memory(*memory_exchange_address, memory_exchange_width,
                                 *memory_exchange_new);
                return;
            }
            const auto a = read(insn.Op1), b = read(insn.Op2);
            write(insn.Op1, b, is64);
            write(insn.Op2, a, is64);
            return;
        }
        case NN_push:
        {
            memory.clear();
            if (!natad(insn) || (is64 ? !op64(insn) : !op32(insn)))
            {
                stack.clear();
                regs[4] = {};
                return;
            }
            auto value = stack_top(insn, insn.Op1)
                             ? (stack.empty() ? std::nullopt : stack.back().read(word_bits))
                             : read(insn.Op1, word_bits);
            // A long-mode PUSH has no imm64 encoding. Normalize the
            // decoder's immediate representation to its signed imm32
            // architectural value after any imm8 extension in read().
            if (value && is64 && insn.Op1.type == o_imm)
                *value = uint64_t(int64_t(int32_t(*value)));
            if (value)
                *value &= mask(word_bits);
            if (stack.size() == 64)
                stack.erase(stack.begin());
            Word pushed;
            pushed.write(word_bits, 0, value, is64);
            stack.push_back(pushed);
            adjust_sp(-int64_t(word_bits / 8), is64);
            return;
        }
        case NN_pushf:
        case NN_pushfd:
        case NN_pushfq:
        {
            memory.clear();
            if (!natad(insn) || (is64 ? !op64(insn) : !op32(insn)))
            {
                stack.clear();
                regs[4] = {};
                return;
            }
            Word pushed;
            for (const auto [abstract_bit, architectural_bit] :
                 {std::pair<uint8_t, unsigned>{CF, 0},
                  {PF, 2},
                  {AF, 4},
                  {ZF, 6},
                  {SF, 7},
                  {OF, 11}})
            {
                if (const auto bit = flags.get(abstract_bit))
                {
                    pushed.known |= uint64_t{1} << architectural_bit;
                    if (*bit)
                        pushed.value |= uint64_t{1} << architectural_bit;
                }
            }
            if (stack.size() == 64)
                stack.erase(stack.begin());
            stack.push_back(pushed);
            adjust_sp(-int64_t(word_bits / 8), is64);
            return;
        }
        case NN_pop:
        {
            memory.clear();
            if (insn.Op1.type != o_reg || !natad(insn) || (is64 ? !op64(insn) : !op32(insn)))
            {
                stack.clear();
                write(insn.Op1, std::nullopt, is64);
                regs[4] = {};
                return;
            }
            const auto value = stack.empty() ? std::nullopt : stack.back().read(word_bits);
            if (!stack.empty())
                stack.pop_back();
            adjust_sp(int64_t(word_bits / 8), is64);
            write(insn.Op1, value, is64);
            return;
        }
        case NN_popf:
        case NN_popfd:
        case NN_popfq:
        {
            memory.clear();
            if (!natad(insn) || (is64 ? !op64(insn) : !op32(insn)))
            {
                stack.clear();
                regs[4] = {};
                flags = {};
                return;
            }
            const Word popped = stack.empty() ? Word{} : stack.back();
            if (!stack.empty())
                stack.pop_back();
            adjust_sp(int64_t(word_bits / 8), is64);
            flags = {};
            for (const auto [abstract_bit, architectural_bit] :
                 {std::pair<uint8_t, unsigned>{CF, 0},
                  {PF, 2},
                  {AF, 4},
                  {ZF, 6},
                  {SF, 7},
                  {OF, 11}})
                if (popped.known & (uint64_t{1} << architectural_bit))
                    flags.set(abstract_bit,
                              (popped.value & (uint64_t{1} << architectural_bit)) != 0);
            return;
        }
        case NN_nop:
        case NN_cld:
        case NN_std:
            // DF is outside this state; the six tracked status flags are unchanged.
            return;
        case NN_movs:
            // MOVS, including REP MOVS, leaves the six status flags unchanged.
            // The implicit destination may alias any retained memory or stack
            // word. After a normally completed, natural-address-size REP MOVS,
            // the full count register is zero, regardless of its input value.
            stack.clear();
            memory.clear();
            regs[6] = {};
            regs[7] = {};
            if (insn.auxpref & (aux_rep | aux_repne))
            {
                regs[1] = {};
                if ((insn.auxpref & aux_rep) && !(insn.auxpref & aux_repne) && natad(insn))
                    regs[1].write(word_bits, 0, 0, is64);
            }
            return;
        case NN_stos:
            // The implicit destination may alias every retained byte. STOS
            // reads but does not change the accumulator or status flags.
            stack.clear();
            memory.clear();
            regs[7] = {};
            if (insn.auxpref & (aux_rep | aux_repne))
                regs[1] = {};
            return;
        case NN_lods:
            // LODS reads memory without writing it or the status flags. Even
            // a byte load invalidates the accumulator's known full value.
            regs[0] = {};
            regs[6] = {};
            if (insn.auxpref & (aux_rep | aux_repne))
                regs[1] = {};
            return;
        case NN_bswap:
        {
            const auto input = read(insn.Op1);
            std::optional<uint64_t> output;
            if (input && (width == 32 || width == 64))
            {
                uint64_t value = 0;
                for (unsigned i = 0; i < width / 8; ++i)
                    value = (value << 8) | ((*input >> (8 * i)) & 255);
                output = value;
            }
            write(insn.Op1, output, is64);
            return;
        }
        case NN_pusha:
        case NN_popa:
            stack.clear();
            memory.clear();
            regs = {};
            return;
        default:
            break;
        }
        if (algebra == Operation::unknown)
        {
            // Covers implicit writes, calls, and unsupported instructions.
            // No assumption about a destination list's completeness is needed.
            *this = {};
            return;
        }
        const Slice a = register_slice(insn.Op1), b = register_slice(insn.Op2);
        const bool same =
            a.reg >= 0 && a.reg == b.reg && a.width == b.width && a.offset == b.offset;
        const auto result = transfer(algebra, width, algebra_left, algebra_right, same, flags);
        if (algebra != Operation::compare && algebra != Operation::test &&
            algebra != Operation::clear_carry && algebra != Operation::set_carry &&
            algebra != Operation::complement_carry)
        {
            write(insn.Op1, result, is64);
            if (result && algebra_address && writable_range(*algebra_address, width / 8, word_bits))
                store_memory(*algebra_address, width, *result);
        }
    }
};

bool alternative_entry(ea_t address, ea_t previous)
{
    xrefblk_t xref;
    for (bool ok = xref.first_to(address, XREF_ALL); ok; ok = xref.next_to())
        if (xref.iscode && (xref.from != previous || (xref.type & XREF_MASK) != fl_F))
            return true;
    return false;
}

bool only_fallthrough(ea_t source, ea_t target)
{
    bool found = false;
    xrefblk_t xref;
    for (bool ok = xref.first_from(source, XREF_ALL); ok; ok = xref.next_from())
    {
        if (!xref.iscode)
            continue;
        if (xref.to != target || (xref.type & XREF_MASK) != fl_F)
            return false;
        found = true;
    }
    return found;
}

std::vector<insn_t> prefix_before(const insn_t &insn, size_t depth)
{
    if (PH.id != PLFM_386 || (!mode32(insn) && !mode64(insn)))
        return {};
    depth = std::min<size_t>(depth, 64);
    std::vector<insn_t> prefix;
    prefix.reserve(depth);
    ea_t cursor = insn.ea;
    const auto *segment = getseg(cursor);
    const auto *owner = get_func(cursor);
    for (size_t i = 0; i < depth; ++i)
    {
        const ea_t previous = prev_head(cursor, segment ? segment->start_ea : 0);
        if (previous == BADADDR || !is_code(get_flags(previous)) || getseg(previous) != segment ||
            get_func(previous) != owner || alternative_entry(cursor, previous))
            break;
        insn_t decoded;
        if (decode_insn(&decoded, previous) <= 0 || decoded.size == 0 ||
            previous > BADADDR - decoded.size || previous + decoded.size != cursor ||
            is_call_insn(decoded) || mode64(decoded) != mode64(insn) ||
            mode32(decoded) != mode32(insn))
            break;
        // IDA marks PUSH-next as a block end in 32-bit code even when its sole
        // code edge is ordinary fallthrough. Include this architectural PUSH
        // as the first replayed instruction, without scanning across the
        // marked boundary or admitting a second outgoing edge.
        const bool boundary = is_basic_block_end(decoded, false);
        if (boundary && (decoded.itype != NN_push || !natad(decoded) ||
                         (mode64(decoded) ? !op64(decoded) : !op32(decoded)) ||
                         !only_fallthrough(previous, cursor)))
            break;
        prefix.push_back(decoded);
        if (boundary)
            break;
        cursor = previous;
    }
    return prefix;
}

struct FlowFact
{
    State state;
    std::vector<uint64_t> support;
};

std::optional<FlowFact> flow_before(const insn_t &insn, size_t depth)
{
    if (PH.id != PLFM_386 || (!mode32(insn) && !mode64(insn)))
        return std::nullopt;
    auto *owner = get_func(insn.ea);
    if (!owner)
        return std::nullopt;
    const size_t limit = std::min<size_t>(depth, 64);
    std::vector<insn_t> code;
    std::map<ea_t, size_t> index;
    func_item_iterator_t iterator;
    if (!iterator.set(owner))
        return std::nullopt;
    do
    {
        const ea_t ea = iterator.current();
        if (!is_code(get_flags(ea)))
            continue;
        insn_t decoded;
        if (code.size() >= limit || get_func(ea) != owner || decode_insn(&decoded, ea) <= 0 ||
            decoded.size == 0 || ea > BADADDR - decoded.size || mode64(decoded) != mode64(insn) ||
            mode32(decoded) != mode32(insn))
            return std::nullopt;
        index.emplace(ea, code.size());
        code.push_back(decoded);
    } while (iterator.next_code());
    if (!index.count(insn.ea) || !index.count(owner->start_ea))
        return std::nullopt;
    std::vector<FlowNode> graph(code.size());
    graph[index.at(owner->start_ea)].unknown_entry = true;
    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto &instruction = code[i];
        const auto condition = x86_condition(instruction.itype);
        const bool branch = condition && condition->use == X86ConditionUse::branch;
        const bool jump = instruction.itype == NN_jmp;
        const bool call = is_call_insn(instruction);
        if (!jump && !branch && !call && instruction.itype != NN_retn)
        {
            if (is_indirect_jump_insn(instruction))
                return std::nullopt;
            for (const auto &operand : instruction.ops)
                if (operand.type == o_near || operand.type == o_far)
                    return std::nullopt;
        }
        const auto add_edge = [&](ea_t target)
        {
            const auto found = index.find(target);
            if (found == index.end())
                return false;
            graph[found->second].predecessors.push_back(i);
            return true;
        };
        // Reconstruct both architectural Jcc successors from bytes, including
        // edges suppressed by earlier native analysis. Never propagate over a
        // guessed return/indirect/far destination or incomplete inventory.
        if (jump || branch)
        {
            if (instruction.Op1.type != o_near || !add_edge(instruction.Op1.addr))
                return std::nullopt;
        }
        if (!jump && instruction.itype != NN_retn)
        {
            if ((!branch && !call && (instruction.get_canon_feature(PH) & CF_STOP)) ||
                !add_edge(instruction.ea + instruction.size))
                return std::nullopt;
        }
        if (call && instruction.Op1.type == o_near && index.count(instruction.Op1.addr))
            graph[index.at(instruction.Op1.addr)].unknown_entry = true;
        xrefblk_t xref;
        size_t references = 0;
        for (bool ok = xref.first_to(instruction.ea, XREF_ALL); ok; ok = xref.next_to())
        {
            if (++references > 256)
                return std::nullopt;
            if (!xref.iscode)
                continue;
            const auto source = index.find(xref.from);
            const int type = xref.type & XREF_MASK;
            if (source == index.end() || (type != fl_F && type != fl_JN))
                graph[i].unknown_entry = true;
            else
            {
                const auto &from = code[source->second];
                const auto from_condition = x86_condition(from.itype);
                const bool from_branch =
                    from_condition && from_condition->use == X86ConditionUse::branch;
                const bool matches =
                    type == fl_F ? from.ea + from.size == instruction.ea && from.itype != NN_jmp &&
                                       from.itype != NN_retn
                                 : (from.itype == NN_jmp || from_branch) &&
                                       from.Op1.type == o_near && from.Op1.addr == instruction.ea;
                if (!matches)
                    graph[i].unknown_entry = true;
            }
        }
    }
    const auto states =
        bounded_dataflow<State>(graph, 64, 128,
                                [&](size_t i, State state)
                                {
                                    const auto condition = x86_condition(code[i].itype);
                                    if (code[i].itype != NN_jmp &&
                                        !(condition && condition->use == X86ConditionUse::branch))
                                        state.step(code[i]);
                                    return state;
                                });
    if (!states)
        return std::nullopt;
    FlowFact result;
    result.state = (*states)[index.at(insn.ea)];
    for (const auto &instruction : code)
        if (instruction.ea != insn.ea)
            result.support.push_back(instruction.ea);
    return result;
}
} // namespace

x86_abstract::Flags analyze_x86_flags_before(const insn_t &insn, size_t depth)
{
    return analyze_x86_flag_fact_before(insn, depth).flags;
}

X86FlagFact analyze_x86_flag_fact_before(const insn_t &insn, size_t depth)
{
    if (const auto flow = flow_before(insn, depth))
        return {flow->state.flags, flow->support};
    const auto prefix = prefix_before(insn, depth);
    State state;
    X86FlagFact result;
    for (auto it = prefix.rbegin(); it != prefix.rend(); ++it)
    {
        state.step(*it);
        result.support.push_back(it->ea);
    }
    result.flags = state.flags;
    return result;
}

X86RegisterFact analyze_x86_register_before(const insn_t &insn, const op_t &operand, size_t depth)
{
    if (const auto flow = flow_before(insn, depth))
        return {flow->state.read(operand), flow->support};
    const auto prefix = prefix_before(insn, depth);
    State state;
    X86RegisterFact result;
    for (auto it = prefix.rbegin(); it != prefix.rend(); ++it)
    {
        state.step(*it);
        result.support.push_back(it->ea);
    }
    result.value = state.read(operand);
    return result;
}

X86RegisterFact analyze_x86_stack_top_before(const insn_t &insn, size_t depth)
{
    const unsigned bits = mode64(insn) ? 64 : mode32(insn) ? 32 : 0;
    if (!bits || !natad(insn))
        return {};
    if (const auto flow = flow_before(insn, depth))
        return {flow->state.read_stack_top(bits), flow->support};
    const auto prefix = prefix_before(insn, depth);
    State state;
    X86RegisterFact result;
    for (auto it = prefix.rbegin(); it != prefix.rend(); ++it)
    {
        state.step(*it);
        result.support.push_back(it->ea);
    }
    result.value = state.read_stack_top(bits);
    return result;
}

X86RegisterFact analyze_x86_memory_before(const insn_t &insn, uint64_t address, size_t depth)
{
    const unsigned bits = mode64(insn) ? 64 : mode32(insn) ? 32 : 0;
    if (!bits || !natad(insn) || !State::writable_word(address, bits))
        return {};
    if (const auto flow = flow_before(insn, depth))
        return {flow->state.read_memory(address, bits), flow->support};
    const auto prefix = prefix_before(insn, depth);
    State state;
    X86RegisterFact result;
    for (auto it = prefix.rbegin(); it != prefix.rend(); ++it)
    {
        state.step(*it);
        result.support.push_back(it->ea);
    }
    result.value = state.read_memory(address, bits);
    return result;
}

X86RegionInspection analyze_x86_region(uint64_t root, size_t node_limit, size_t round_limit)
{
    X86RegionInspection result;
    result.root = root;
    node_limit = std::min<size_t>(node_limit, 128);
    round_limit = std::min<size_t>(round_limit, 128);
    const auto hex = [](uint64_t value)
    {
        std::ostringstream out;
        out << "0x" << std::hex << value;
        return out.str();
    };
    const auto bytes_at = [](ea_t address, size_t size)
    {
        static const char digits[] = "0123456789abcdef";
        std::string bytes;
        for (size_t i = 0; i < size; ++i)
        {
            const auto value = get_byte(address + i);
            bytes += digits[value >> 4];
            bytes += digits[value & 15];
        }
        return bytes;
    };
    if (PH.id != PLFM_386 || root == BADADDR || uint64_t(ea_t(root)) != root)
    {
        result.reason = "unsupported_request";
        return result;
    }
    const auto *segment = getseg(ea_t(root));
    if (!segment || segment->type == SEG_XTRN || !(segment->perm & SEGPERM_EXEC))
    {
        result.reason = "nonexecutable_or_external";
        return result;
    }
    if (segment->bitness != 1 && segment->bitness != 2)
    {
        result.reason = "unsupported_mode";
        return result;
    }
    result.address_bits = segment->bitness == 2 ? 64 : 32;
    const auto decode = [&](ea_t address, insn_t &instruction) -> std::string
    {
        if (address == BADADDR || getseg(address) != segment)
            return "segment_boundary";
        if (get_func(address))
            return "owned_code";
        const auto flags = get_flags(address);
        if (!is_code(flags) || !is_head(flags))
            return is_tail(flags) && is_code(get_flags(get_item_head(address)))
                       ? "interior_instruction_target"
                       : "not_existing_code_head";
        if (decode_insn(&instruction, address) <= 0 || !instruction.size || instruction.size > 15 ||
            address > BADADDR - instruction.size || address + instruction.size > segment->end_ea ||
            get_item_end(address) != address + instruction.size)
            return "invalid_instruction_span";
        if ((result.address_bits == 64 && !mode64(instruction)) ||
            (result.address_bits == 32 &&
             (!mode32(instruction) ||
              uint64_t(address) + instruction.size > uint64_t(UINT32_MAX) + 1)))
            return "mode_boundary";
        for (size_t offset = 0; offset < instruction.size; ++offset)
        {
            if (get_func(address + offset))
                return "owned_code";
            if (!is_loaded(address + offset) || get_item_head(address + offset) != address)
                return "invalid_instruction_span";
        }
        return {};
    };
    insn_t entry;
    result.reason = decode(ea_t(root), entry);
    if (!result.reason.empty())
        return result;
    result.available = true;
    if (!node_limit || !round_limit)
    {
        result.truncated = true;
        result.reason = !node_limit ? "node_limit" : "round_limit";
        return result;
    }
    struct Control
    {
        bool branch = false, jump = false, call = false, ret = false;
        std::string stop;
    };
    const auto control = [](const insn_t &instruction)
    {
        Control flow;
        const auto condition = x86_condition(instruction.itype);
        flow.branch = condition && condition->use == X86ConditionUse::branch;
        flow.jump = instruction.itype == NN_jmp;
        flow.call = is_call_insn(instruction);
        flow.ret = instruction.itype == NN_retn;
        if (instruction.itype == NN_bswap && get_dtype_size(instruction.Op1.dtype) != 4 &&
            get_dtype_size(instruction.Op1.dtype) != 8)
            flow.stop = "unsupported_bswap_width";
        else if (instruction.Op1.type == o_far || instruction.itype == NN_callfi ||
                 instruction.itype == NN_jmpfi || (is_ret_insn(instruction) && !flow.ret) ||
                 instruction.itype == NN_int || instruction.itype == NN_int3 ||
                 instruction.itype == NN_into || instruction.itype == NN_syscall ||
                 instruction.itype == NN_sysenter || instruction.itype == NN_sysexit ||
                 instruction.itype == NN_sysret || instruction.itype == NN_xbegin ||
                 instruction.itype == NN_hlt || instruction.itype == NN_ud2)
            flow.stop = "unsupported_control";
        else if (flow.jump && instruction.Op1.type != o_near)
            flow.stop = "indirect_target";
        else if (flow.branch && instruction.Op1.type != o_near)
            flow.stop = "unsupported_control";
        else if (!flow.jump && !flow.branch && !flow.call && !flow.ret)
        {
            if (instruction.get_canon_feature(PH) & (CF_CALL | CF_JUMP | CF_STOP))
                flow.stop = "unsupported_control";
            for (const auto &operand : instruction.ops)
                if (operand.type == o_near || operand.type == o_far)
                    flow.stop = "unsupported_control";
        }
        return flow;
    };
    struct Link
    {
        ea_t source, target;
        std::string kind;
    };
    std::map<ea_t, insn_t> code{{entry.ea, entry}};
    std::deque<ea_t> pending{entry.ea};
    std::vector<Link> links;
    bool failed = false;
    const auto failure = [&](const std::string &reason, bool truncated)
    {
        if (!failed)
            result.reason = reason;
        failed = true;
        result.truncated |= truncated;
    };
    const auto frontier = [&](ea_t source, ea_t target, const std::string &reason)
    {
        result.edges.push_back({{"source", hex(source)},
                                {"target", hex(target)},
                                {"kind", "frontier"},
                                {"reason", reason}});
    };
    const auto successor = [&](ea_t source, ea_t target, const std::string &kind)
    {
        if (!code.count(target))
        {
            insn_t next;
            const auto reason = decode(target, next);
            if (!reason.empty())
            {
                frontier(source, target, reason);
                if (reason == "interior_instruction_target" || reason == "invalid_instruction_span")
                    failure(reason, false);
                return;
            }
            const auto after = code.lower_bound(target);
            if ((after != code.end() && target + next.size > after->first) ||
                (after != code.begin() &&
                 std::prev(after)->first + std::prev(after)->second.size > target))
            {
                frontier(source, target, "overlapping_instructions");
                failure("overlapping_instructions", false);
                return;
            }
            if (code.size() >= node_limit)
            {
                frontier(source, target, "node_limit");
                failure("node_limit", true);
                return;
            }
            code.emplace(target, next);
            pending.push_back(target);
        }
        links.push_back({source, target, kind});
        result.edges.push_back(
            {{"source", hex(source)}, {"target", hex(target)}, {"kind", kind}, {"reason", ""}});
    };
    while (!pending.empty())
    {
        const auto &instruction = code.at(pending.front());
        pending.pop_front();
        const auto flow = control(instruction);
        if (!flow.stop.empty())
        {
            frontier(instruction.ea, instruction.ea, flow.stop);
            continue;
        }
        if (flow.ret)
        {
            frontier(instruction.ea, instruction.ea, "return_target");
            continue;
        }
        if (flow.jump || flow.branch)
            successor(instruction.ea, to_ea(instruction.cs, instruction.Op1.addr),
                      flow.jump ? "direct-jump" : "conditional-taken");
        if (flow.call)
        {
            frontier(instruction.ea,
                     instruction.Op1.type == o_near ? to_ea(instruction.cs, instruction.Op1.addr)
                                                    : instruction.ea,
                     "call_target_not_followed");
            successor(instruction.ea, instruction.ea + instruction.size, "call-return");
        }
        else if (!flow.jump)
            successor(instruction.ea, instruction.ea + instruction.size, "fallthrough");
    }
    std::map<ea_t, size_t> index;
    std::vector<insn_t> instructions;
    for (const auto &[address, instruction] : code)
    {
        index.emplace(address, instructions.size());
        instructions.push_back(instruction);
    }
    std::vector<FlowNode> graph(code.size());
    graph[index.at(entry.ea)].unknown_entry = true;
    for (const auto &link : links)
    {
        auto &predecessors = graph[index.at(link.target)].predecessors;
        const auto source = index.at(link.source);
        if (std::find(predecessors.begin(), predecessors.end(), source) == predecessors.end())
            predecessors.push_back(source);
    }
    std::string support;
    for (const auto &instruction : instructions)
    {
        if (!support.empty())
            support += ';';
        support += hex(instruction.ea);
        auto &node = graph[index.at(instruction.ea)];
        std::set<std::pair<ea_t, int>> incoming;
        size_t examined = 0;
        bool exhausted = false;
        for (size_t offset = 0; offset < instruction.size && !exhausted; ++offset)
        {
            xrefblk_t xref;
            for (bool more = xref.first_to(instruction.ea + offset, XREF_ALL); more;
                 more = xref.next_to())
            {
                if (examined == 256)
                {
                    failure("incoming_reference_limit", true);
                    exhausted = true;
                    break;
                }
                ++examined;
                ++result.incoming_examined;
                incoming.emplace(xref.from, xref.type);
                if (!xref.iscode)
                    continue;
                if (offset)
                {
                    failure("interior_code_entry", false);
                    continue;
                }
                const int type = xref.type & XREF_MASK;
                const bool compatible = std::any_of(
                    links.begin(), links.end(),
                    [&](const Link &link)
                    {
                        return link.source == xref.from && link.target == instruction.ea &&
                               ((type == fl_F &&
                                 (link.kind == "fallthrough" || link.kind == "call-return")) ||
                                (type == fl_JN &&
                                 (link.kind == "direct-jump" || link.kind == "conditional-taken")));
                    });
                if (!compatible)
                    node.unknown_entry = true;
            }
        }
        std::string adjacency = "unknown", adjacent_bytes;
        const ea_t previous = prev_head(instruction.ea, segment->start_ea);
        const bool admitted_fallthrough =
            std::any_of(links.begin(), links.end(),
                        [&](const Link &link)
                        {
                            return link.source == previous && link.target == instruction.ea &&
                                   (link.kind == "fallthrough" || link.kind == "call-return");
                        });
        if (previous != BADADDR && !admitted_fallthrough && is_code(get_flags(previous)) &&
            is_head(get_flags(previous)))
        {
            insn_t before;
            if (decode_insn(&before, previous) > 0 && before.size &&
                previous <= BADADDR - before.size && previous + before.size == instruction.ea)
            {
                // A modeling frontier can still have architectural fallthrough
                // (for example LOOP or unsupported-width BSWAP). Its unknown
                // input must not disappear merely because that instruction
                // would not be propagated by this inspector.
                const bool fallthrough =
                    is_call_insn(before) ||
                    (!is_ret_insn(before) && before.itype != NN_jmp && before.itype != NN_jmpfi &&
                     !(before.get_canon_feature(PH) & CF_STOP));
                if (fallthrough)
                {
                    node.unknown_entry = true;
                    adjacency = hex(previous);
                    adjacent_bytes = bytes_at(previous, before.size);
                }
            }
        }
        std::string references;
        for (const auto &[source, type] : incoming)
        {
            if (!references.empty())
                references += ';';
            references += hex(source) + ':' + std::to_string(type);
        }
        result.nodes.push_back({{"site", hex(instruction.ea)},
                                {"size", std::to_string(instruction.size)},
                                {"bytes", bytes_at(instruction.ea, instruction.size)},
                                {"owner", "unknown"},
                                {"segment_start", hex(segment->start_ea)},
                                {"segment_end", hex(segment->end_ea)},
                                {"permissions", std::to_string(segment->perm)},
                                {"segment_bitness", std::to_string(segment->bitness)},
                                {"unknown_entry", node.unknown_entry ? "true" : "false"},
                                {"incoming", references},
                                {"adjacent", adjacency},
                                {"adjacent_bytes", adjacent_bytes},
                                {"flags_known", "0x0"},
                                {"flags_value", "0x0"}});
    }
    if (failed)
        return result;
    const auto states = bounded_dataflow<State>(graph, node_limit, round_limit,
                                                [&](size_t i, State state)
                                                {
                                                    const auto flow = control(instructions[i]);
                                                    if (!flow.stop.empty() || flow.call || flow.ret)
                                                        return State{};
                                                    if (!flow.jump && !flow.branch)
                                                        state.step(instructions[i]);
                                                    return state;
                                                });
    if (!states)
    {
        result.reason = "nonconvergence";
        return result;
    }
    result.converged = true;
    result.reason = "complete_bounded_region";
    for (size_t i = 0; i < instructions.size(); ++i)
    {
        const auto &instruction = instructions[i];
        const auto &state = (*states)[i];
        const auto known = hex(state.flags.known), value = hex(state.flags.value);
        result.nodes[i]["flags_known"] = known;
        result.nodes[i]["flags_value"] = value;
        const auto condition = x86_condition(instruction.itype);
        if (condition && control(instruction).stop.empty())
        {
            const auto outcome = evaluate(condition->condition, state.flags);
            std::map<std::string, std::string> row{
                {"site", hex(instruction.ea)},
                {"truth", "static-region-fact"},
                {"status", outcome ? "proved" : "unresolved"},
                {"outcome", outcome ? (*outcome ? "true" : "false") : "unknown"},
                {"kind", condition->use == X86ConditionUse::branch     ? "branch-condition"
                         : condition->use == X86ConditionUse::set_byte ? "setcc-value"
                                                                       : "cmov-condition"},
                {"flags_known", known},
                {"flags_value", value},
                {"support", support}};
            if (condition->use == X86ConditionUse::branch)
            {
                row["taken"] = hex(to_ea(instruction.cs, instruction.Op1.addr));
                row["fallthrough"] = hex(instruction.ea + instruction.size);
                row["target"] = !outcome ? "unknown" : row[*outcome ? "taken" : "fallthrough"];
            }
            if (condition->use == X86ConditionUse::set_byte)
            {
                row["value"] = !outcome ? "unknown" : (*outcome ? "0x1" : "0x0");
                row["width_bits"] = "8";
            }
            result.records.push_back(std::move(row));
        }
        if (instruction.itype != NN_push || !natad(instruction) ||
            (result.address_bits == 64 ? !op64(instruction) : !op32(instruction)))
            continue;
        const auto next = index.find(instruction.ea + instruction.size);
        if (next == index.end())
            continue;
        const auto &ret = instructions[next->second];
        if (ret.itype != NN_retn || !natad(ret) ||
            (result.address_bits == 64 ? !op64(ret) : !op32(ret)) ||
            (ret.Op1.type != o_void && ret.Op1.type != o_imm))
            continue;
        classifier::instruction_t push_model, ret_model;
        push_model.address = instruction.ea;
        push_model.size = instruction.size;
        push_model.stack_width_bits = uint16_t(result.address_bits);
        ret_model.address = ret.ea;
        ret_model.size = ret.size;
        ret_model.stack_width_bits = uint16_t(result.address_bits);
        ret_model.kind = classifier::instruction_kind_t::return_instruction;
        ret_model.immediate = ret.Op1.type == o_imm ? ret.Op1.value : 0;
        const auto &ret_node = graph[next->second];
        ret_model.alternate_predecessor = ret_node.unknown_entry ||
                                          ret_node.predecessors.size() != 1 ||
                                          ret_node.predecessors.front() != i;
        classifier::target_proof_t target;
        if (instruction.Op1.type == o_imm)
        {
            push_model.kind = classifier::instruction_kind_t::push_immediate;
            target.kind = classifier::target_proof_kind_t::immediate;
            const auto immediate = state.read(instruction.Op1, result.address_bits);
            if (!immediate)
                continue;
            target.value = result.address_bits == 64 ? uint64_t(int64_t(int32_t(*immediate)))
                                                     : uint64_t(uint32_t(*immediate));
        }
        else if (instruction.Op1.type == o_reg)
        {
            const auto slice = register_slice(instruction.Op1);
            push_model.kind = classifier::instruction_kind_t::push_register;
            push_model.source = {slice.reg, uint16_t(slice.offset), uint16_t(slice.width)};
            target.value = state.read(instruction.Op1);
            if (target.value)
            {
                target.kind = classifier::target_proof_kind_t::register_definition;
                target.registers.push_back(push_model.source);
                for (const auto &definition : instructions)
                    target.definitions.push_back(definition.ea);
            }
        }
        else if (instruction.Op1.type == o_mem || instruction.Op1.type == o_displ ||
                 instruction.Op1.type == o_phrase)
        {
            push_model.kind = classifier::instruction_kind_t::push_memory;
            if (State::stack_top(instruction, instruction.Op1))
            {
                push_model.source_is_stack_pointer = true;
                target.stack_top_source = true;
                target.value = state.read_stack_top(result.address_bits);
                if (target.value)
                {
                    target.kind = classifier::target_proof_kind_t::stack_definition;
                    for (const auto &definition : instructions)
                        target.definitions.push_back(definition.ea);
                }
            }
            else if (const auto address = state.memory_address(instruction, instruction.Op1);
                     address && State::writable_word(*address, result.address_bits))
            {
                target.source_address = *address;
                target.value = state.read_memory(*address, result.address_bits);
                if (target.value)
                {
                    target.kind = classifier::target_proof_kind_t::memory_definition;
                    for (const auto &definition : instructions)
                        target.definitions.push_back(definition.ea);
                }
            }
        }
        else
            continue;
        const auto transfer =
            classifier::classify_push_return(push_model, ret_model, result.address_bits, target);
        if (!transfer)
            continue;
        result.records.push_back(
            {{"site", hex(instruction.ea)},
             {"kind", "push-return"},
             {"truth", "static-region-fact"},
             {"status", target.value ? "proved" : "unresolved"},
             {"transfer", hex(ret.ea)},
             {"target", target.value ? hex(*target.value) : "unknown"},
             {"target_proof", target.kind == classifier::target_proof_kind_t::immediate
                                  ? "immediate"
                              : target.kind == classifier::target_proof_kind_t::register_definition
                                  ? "register-definition"
                              : target.kind == classifier::target_proof_kind_t::stack_definition
                                  ? "stack-definition"
                              : target.kind == classifier::target_proof_kind_t::memory_definition
                                  ? "memory-definition"
                                  : "unresolved"},
             {"width_bits", std::to_string(transfer->width_bits)},
             {"stack_delta_bytes", std::to_string(transfer->stack_delta_bytes)},
             {"stack_write_bytes", std::to_string(transfer->stack_write_bytes)},
             {"stack_write_offset_bytes", std::to_string(transfer->stack_write_offset_bytes)},
             {"flags_known", known},
             {"flags_value", value},
             {"support", support}});
    }
    return result;
}

} // namespace chernobog::ida_analysis
