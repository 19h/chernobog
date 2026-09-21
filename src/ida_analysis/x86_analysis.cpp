#include "x86_analysis.hpp"

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
#include <vector>

namespace chernobog::ida_analysis {

std::optional<X86Condition> x86_condition(uint16_t type)
{
    using C = x86_abstract::Condition;
    using U = X86ConditionUse;
#define CONDITION(j, s, m, c) \
    case j: return X86Condition{C::c, U::branch}; \
    case s: return X86Condition{C::c, U::set_byte}; \
    case m: return X86Condition{C::c, U::conditional_move}
    switch ( type )
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
        case NN_jc: case NN_jnae: return X86Condition{C::below, U::branch};
        case NN_jae: case NN_jnc: return X86Condition{C::above_equal, U::branch};
        case NN_je: return X86Condition{C::equal, U::branch};
        case NN_jne: return X86Condition{C::not_equal, U::branch};
        case NN_jna: return X86Condition{C::below_equal, U::branch};
        case NN_jnbe: return X86Condition{C::above, U::branch};
        case NN_jpe: return X86Condition{C::parity, U::branch};
        case NN_jpo: return X86Condition{C::not_parity, U::branch};
        case NN_jnge: return X86Condition{C::less, U::branch};
        case NN_jge: return X86Condition{C::greater_equal, U::branch};
        case NN_jng: return X86Condition{C::less_equal, U::branch};
        case NN_jg: return X86Condition{C::greater, U::branch};
        case NN_setc: case NN_setnae: return X86Condition{C::below, U::set_byte};
        case NN_setae: case NN_setnc: return X86Condition{C::above_equal, U::set_byte};
        case NN_sete: return X86Condition{C::equal, U::set_byte};
        case NN_setne: return X86Condition{C::not_equal, U::set_byte};
        case NN_setna: return X86Condition{C::below_equal, U::set_byte};
        case NN_setnbe: return X86Condition{C::above, U::set_byte};
        case NN_setpe: return X86Condition{C::parity, U::set_byte};
        case NN_setpo: return X86Condition{C::not_parity, U::set_byte};
        case NN_setnge: return X86Condition{C::less, U::set_byte};
        case NN_setnl: return X86Condition{C::greater_equal, U::set_byte};
        case NN_setng: return X86Condition{C::less_equal, U::set_byte};
        case NN_setnle: return X86Condition{C::greater, U::set_byte};
        default: return std::nullopt;
    }
#undef CONDITION
}

namespace {
using namespace x86_abstract;

struct Slice { int reg = -1; unsigned width = 0; unsigned offset = 0; };

Slice register_slice(const op_t &operand)
{
    if ( operand.type != o_reg ) return {};
    const size_t bytes = get_dtype_size(operand.dtype);
    if ( bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8 ) return {};
    qstring name;
    if ( get_reg_name(&name, operand.reg, bytes) <= 0 ) return {};
    static const char *const names[16][4] = {
        {"al", "ax", "eax", "rax"}, {"cl", "cx", "ecx", "rcx"},
        {"dl", "dx", "edx", "rdx"}, {"bl", "bx", "ebx", "rbx"},
        {"spl", "sp", "esp", "rsp"}, {"bpl", "bp", "ebp", "rbp"},
        {"sil", "si", "esi", "rsi"}, {"dil", "di", "edi", "rdi"},
        {"r8b", "r8w", "r8d", "r8"}, {"r9b", "r9w", "r9d", "r9"},
        {"r10b", "r10w", "r10d", "r10"}, {"r11b", "r11w", "r11d", "r11"},
        {"r12b", "r12w", "r12d", "r12"}, {"r13b", "r13w", "r13d", "r13"},
        {"r14b", "r14w", "r14d", "r14"}, {"r15b", "r15w", "r15d", "r15"},
    };
    for ( int reg = 0; reg < 16; ++reg )
        for ( unsigned part = 0; part < 4; ++part )
            if ( name == names[reg][part] ) return {reg, 8u << part, 0};
    static const char *const high[4] = {"ah", "ch", "dh", "bh"};
    for ( int reg = 0; reg < 4; ++reg )
        if ( name == high[reg] ) return {reg, 8, 8};
    return {};
}

Operation operation(uint16_t type)
{
    switch ( type )
    {
        case NN_add: return Operation::add;
        case NN_adc: return Operation::adc;
        case NN_sub: return Operation::sub;
        case NN_sbb: return Operation::sbb;
        case NN_cmp: return Operation::compare;
        case NN_inc: return Operation::increment;
        case NN_dec: return Operation::decrement;
        case NN_neg: return Operation::negate;
        case NN_and: return Operation::bit_and;
        case NN_or: return Operation::bit_or;
        case NN_xor: return Operation::bit_xor;
        case NN_test: return Operation::test;
        case NN_not: return Operation::bit_not;
        case NN_shl: case NN_sal: return Operation::shift_left;
        case NN_shr: return Operation::shift_right;
        case NN_sar: return Operation::arithmetic_right;
        case NN_clc: return Operation::clear_carry;
        case NN_stc: return Operation::set_carry;
        case NN_cmc: return Operation::complement_carry;
        default: return Operation::unknown;
    }
}

struct State
{
    Flags flags;
    std::array<Word, 16> regs{};
    // Only words established by this single-entry replay are retained. No
    // initial stack memory or absolute stack address is assumed known.
    std::vector<std::optional<uint64_t>> stack;

    static bool stack_top(const insn_t &insn, const op_t &operand)
    {
        return natad(insn) && insn.segpref == 0
            && (operand.type == o_phrase || (operand.type == o_displ && operand.addr == 0))
            && get_dtype_size(operand.dtype) == (mode64(insn) ? 8 : 4)
            && x86_base_reg(insn, operand) == R_sp
            && x86_index_reg(insn, operand) == R_none;
    }

    void adjust_sp(int64_t delta, bool is64)
    {
        const unsigned bits = is64 ? 64 : 32;
        auto value = regs[4].read(bits, 0);
        if ( value ) *value = (*value + uint64_t(delta)) & mask(bits);
        regs[4].write(bits, 0, value, is64);
    }

    std::optional<uint64_t> read(const op_t &operand, unsigned target_width = 0) const
    {
        if ( operand.type == o_imm )
        {
            uint64_t value = operand.value;
            const unsigned bits = unsigned(get_dtype_size(operand.dtype) * 8);
            if ( valid_width(bits) && bits < target_width )
            {
                value &= mask(bits);
                if ( value & (uint64_t{1} << (bits - 1)) ) value |= ~mask(bits);
            }
            return value;
        }
        const Slice s = register_slice(operand);
        return s.reg < 0 ? std::nullopt : regs[size_t(s.reg)].read(s.width, s.offset);
    }

    void write(const op_t &operand, std::optional<uint64_t> value, bool mode64)
    {
        const Slice s = register_slice(operand);
        if ( s.reg >= 0 )
        {
            if ( s.reg == 4 ) stack.clear();
            regs[size_t(s.reg)].write(s.width, s.offset, value, mode64);
        }
    }

    void step(const insn_t &insn)
    {
        const bool is64 = mode64(insn);
        const unsigned width = unsigned(get_dtype_size(insn.Op1.dtype) * 8);
        const unsigned word_bits = is64 ? 64 : 32;
        const op_t *exchange_reg = nullptr;
        if ( insn.itype == NN_xchg )
        {
            if ( insn.Op1.type == o_reg && stack_top(insn, insn.Op2) ) exchange_reg = &insn.Op1;
            if ( insn.Op2.type == o_reg && stack_top(insn, insn.Op1) ) exchange_reg = &insn.Op2;
            if ( exchange_reg != nullptr )
            {
                const auto slice = register_slice(*exchange_reg);
                if ( slice.reg < 0 || slice.reg == 4 || slice.width != word_bits ) exchange_reg = nullptr;
            }
        }
        const uint32_t features = insn.get_canon_feature(PH);
        for ( int index = 0; index < UA_MAXOP; ++index )
        {
            const auto type = insn.ops[index].type;
            if ( has_cf_chg(features, index) && type == o_reg
              && register_slice(insn.ops[index]).reg < 0 ) stack.clear();
            if ( exchange_reg == nullptr && has_cf_chg(features, index)
                 && (type == o_mem || type == o_displ || type == o_phrase) ) stack.clear();
        }
        const auto cond = x86_condition(insn.itype);
        if ( cond && cond->use != X86ConditionUse::branch )
        {
            const auto result = evaluate(cond->condition, flags);
            if ( cond->use == X86ConditionUse::set_byte )
                write(insn.Op1, result ? std::optional<uint64_t>(*result ? 1 : 0)
                                      : std::nullopt, is64);
            else
            {
                // CMOV always writes the architectural destination width; a
                // false 32-bit CMOV in 64-bit mode still clears its upper half.
                const auto v = result ? read(*result ? insn.Op2 : insn.Op1) : std::nullopt;
                write(insn.Op1, v, is64);
            }
            return;
        }
        switch ( insn.itype )
        {
            case NN_mov:
                write(insn.Op1, stack_top(insn, insn.Op2)
                      ? (stack.empty() ? std::nullopt : stack.back())
                      : read(insn.Op2, width), is64);
                return;
            case NN_movzx: case NN_movsx: case NN_movsxd:
            {
                auto v = read(insn.Op2);
                const unsigned source_width = unsigned(get_dtype_size(insn.Op2.dtype) * 8);
                if ( v && valid_width(source_width) && source_width < width )
                {
                    *v &= mask(source_width);
                    if ( insn.itype != NN_movzx
                         && (*v & (uint64_t{1} << (source_width - 1))) )
                        *v |= ~mask(source_width);
                }
                else v.reset();
                write(insn.Op1, v, is64);
                return;
            }
            case NN_lea:
            {
                std::optional<uint64_t> result;
                const op_t &mem = insn.Op2;
                const unsigned address_width = ad64(insn) ? 64 : ad32(insn) ? 32 : 16;
                if ( address_width != 16 && mem.type == o_mem && !mem.hasSIB )
                    result = mem.addr & mask(address_width);
                else if ( address_width != 16 && (mem.type == o_displ || mem.type == o_phrase
                                                  || mem.type == o_mem) )
                {
                    uint64_t value = mem.type == o_phrase ? 0 : mem.addr;
                    bool complete = true;
                    const int base = x86_base_reg(insn, mem), index = x86_index_reg(insn, mem);
                    for ( const auto &part : {std::make_pair(base, 0), std::make_pair(index, x86_scale(mem))} )
                    {
                        if ( part.first == R_none ) continue;
                        op_t reg;
                        reg.type = o_reg; reg.reg = uint16_t(part.first);
                        reg.dtype = address_width == 64 ? dt_qword : dt_dword;
                        const auto v = read(reg);
                        if ( !v || part.second < 0 || part.second > 3 ) { complete = false; break; }
                        value += *v << unsigned(part.second);
                    }
                    if ( complete ) result = value & mask(address_width);
                }
                write(insn.Op1, result, is64);
                return;
            }
            case NN_xchg:
            {
                if ( exchange_reg != nullptr )
                {
                    const auto value = read(*exchange_reg);
                    const auto old_top = stack.empty() ? std::nullopt : stack.back();
                    if ( stack.empty() ) stack.push_back(value);
                    else stack.back() = value;
                    write(*exchange_reg, old_top, is64);
                    return;
                }
                const auto a = read(insn.Op1), b = read(insn.Op2);
                write(insn.Op1, b, is64);
                write(insn.Op2, a, is64);
                return;
            }
            case NN_push:
            {
                if ( !natad(insn) || (is64 ? !op64(insn) : !op32(insn)) )
                {
                    stack.clear(); regs[4] = {}; return;
                }
                auto value = stack_top(insn, insn.Op1)
                           ? (stack.empty() ? std::nullopt : stack.back())
                           : read(insn.Op1, word_bits);
                // A long-mode PUSH has no imm64 encoding. Normalize the
                // decoder's immediate representation to its signed imm32
                // architectural value after any imm8 extension in read().
                if ( value && is64 && insn.Op1.type == o_imm )
                    *value = uint64_t(int64_t(int32_t(*value)));
                if ( value ) *value &= mask(word_bits);
                if ( stack.size() == 64 ) stack.erase(stack.begin());
                stack.push_back(value);
                adjust_sp(-int64_t(word_bits / 8), is64);
                return;
            }
            case NN_pushf: case NN_pushfd: case NN_pushfq:
                stack.clear();
                regs[4] = {};
                return;
            case NN_pop:
            {
                if ( insn.Op1.type != o_reg || !natad(insn)
                  || (is64 ? !op64(insn) : !op32(insn)) )
                {
                    stack.clear(); write(insn.Op1, std::nullopt, is64); regs[4] = {}; return;
                }
                const auto value = stack.empty() ? std::nullopt : stack.back();
                if ( !stack.empty() ) stack.pop_back();
                adjust_sp(int64_t(word_bits / 8), is64);
                write(insn.Op1, value, is64);
                return;
            }
            case NN_nop:
                return;
            case NN_bswap:
            {
                const auto input = read(insn.Op1);
                std::optional<uint64_t> output;
                if ( input && (width == 32 || width == 64) )
                {
                    uint64_t value = 0;
                    for ( unsigned i = 0; i < width / 8; ++i )
                        value = (value << 8) | ((*input >> (8 * i)) & 255);
                    output = value;
                }
                write(insn.Op1, output, is64);
                return;
            }
            case NN_pusha: case NN_popa:
                stack.clear();
                regs = {};
                return;
            default:
                break;
        }
        const auto op = operation(insn.itype);
        if ( op == Operation::unknown )
        {
            // Covers implicit writes, calls, POPF, and unsupported instructions.
            // No assumption about a destination list's completeness is needed.
            *this = {};
            return;
        }
        const Slice a = register_slice(insn.Op1), b = register_slice(insn.Op2);
        const bool same = a.reg >= 0 && a.reg == b.reg
                       && a.width == b.width && a.offset == b.offset;
        const auto result = transfer(op, width, read(insn.Op1), read(insn.Op2, width), same, flags);
        if ( op != Operation::compare && op != Operation::test
             && op != Operation::clear_carry && op != Operation::set_carry
             && op != Operation::complement_carry )
            write(insn.Op1, result, is64);
    }
};

bool alternative_entry(ea_t address, ea_t previous)
{
    xrefblk_t xref;
    for ( bool ok = xref.first_to(address, XREF_ALL); ok; ok = xref.next_to() )
        if ( xref.iscode && (xref.from != previous || (xref.type & XREF_MASK) != fl_F) )
            return true;
    return false;
}

bool only_fallthrough(ea_t source, ea_t target)
{
    bool found = false;
    xrefblk_t xref;
    for ( bool ok = xref.first_from(source, XREF_ALL); ok; ok = xref.next_from() )
    {
        if ( !xref.iscode ) continue;
        if ( xref.to != target || (xref.type & XREF_MASK) != fl_F ) return false;
        found = true;
    }
    return found;
}

std::vector<insn_t> prefix_before(const insn_t &insn, size_t depth)
{
    if ( PH.id != PLFM_386 || (!mode32(insn) && !mode64(insn)) ) return {};
    depth = std::min<size_t>(depth, 64);
    std::vector<insn_t> prefix;
    prefix.reserve(depth);
    ea_t cursor = insn.ea;
    const auto *segment = getseg(cursor);
    const auto *owner = get_func(cursor);
    for ( size_t i = 0; i < depth; ++i )
    {
        const ea_t previous = prev_head(cursor, segment ? segment->start_ea : 0);
        if ( previous == BADADDR || !is_code(get_flags(previous))
             || getseg(previous) != segment || get_func(previous) != owner
             || alternative_entry(cursor, previous) ) break;
        insn_t decoded;
        if ( decode_insn(&decoded, previous) <= 0 || decoded.size == 0
             || previous > BADADDR - decoded.size || previous + decoded.size != cursor
             || is_call_insn(decoded)
             || mode64(decoded) != mode64(insn) || mode32(decoded) != mode32(insn) ) break;
        // IDA marks PUSH-next as a block end in 32-bit code even when its sole
        // code edge is ordinary fallthrough. Include this architectural PUSH
        // as the first replayed instruction, without scanning across the
        // marked boundary or admitting a second outgoing edge.
        const bool boundary = is_basic_block_end(decoded, false);
        if ( boundary && (decoded.itype != NN_push || !natad(decoded)
          || (mode64(decoded) ? !op64(decoded) : !op32(decoded))
          || !only_fallthrough(previous, cursor)) ) break;
        prefix.push_back(decoded);
        if ( boundary ) break;
        cursor = previous;
    }
    return prefix;
}
} // namespace

x86_abstract::Flags analyze_x86_flags_before(const insn_t &insn, size_t depth)
{
    return analyze_x86_flag_fact_before(insn, depth).flags;
}

X86FlagFact analyze_x86_flag_fact_before(const insn_t &insn, size_t depth)
{
    const auto prefix = prefix_before(insn, depth);
    State state;
    X86FlagFact result;
    for ( auto it = prefix.rbegin(); it != prefix.rend(); ++it )
    {
        state.step(*it);
        result.support.push_back(it->ea);
    }
    result.flags = state.flags;
    return result;
}

X86RegisterFact analyze_x86_register_before(const insn_t &insn, const op_t &operand, size_t depth)
{
    const auto prefix = prefix_before(insn, depth);
    State state;
    X86RegisterFact result;
    for ( auto it = prefix.rbegin(); it != prefix.rend(); ++it )
    {
        state.step(*it);
        result.support.push_back(it->ea);
    }
    result.value = state.read(operand);
    return result;
}

} // namespace chernobog::ida_analysis
