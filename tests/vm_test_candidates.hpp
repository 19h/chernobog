#pragma once
#include "vm/region.hpp"
#include <stdexcept>
namespace vm_test
{
using namespace chernobog::vm;
inline Operand reg(int index, unsigned bits)
{
    Operand o;
    o.kind = Kind::reg;
    o.reg = index;
    o.bits = bits;
    return o;
}
inline Operand imm(uint64_t v)
{
    Operand o;
    o.kind = Kind::immediate;
    o.value = v;
    return o;
}
inline Operand mem(int base, unsigned bits, unsigned mode, int index = -1, unsigned scale = 1)
{
    Operand o;
    o.kind = Kind::memory;
    o.base = base;
    o.bits = bits;
    o.address_bits = mode;
    o.index = index;
    o.scale = scale;
    return o;
}
inline void layout_path(std::vector<Instruction> &code)
{
    uint64_t at = 0x8000;
    for (auto &i : code)
    {
        i.address = at;
        i.size = 4;
        at += 4;
        if (i.op == Op::direct_jump)
        {
            at -= 0x1000;
            i.dst.value = at;
        }
    }
}
inline Candidate candidate(unsigned mode, bool backward, bool relative, bool keyed, int vip = 6,
                           int value = 0, int key = 3, int base = 7)
{
    std::vector<Instruction> code;
    auto add = [&](Op op, Operand a, Operand b = Operand{})
    { code.push_back({0x1000 + code.size() * 4, 4, op, a, b, false}); };
    const unsigned bits = relative ? 32 : 8;
    if (backward)
        add(Op::sub, reg(vip, mode), imm(bits / 8));
    add(Op::load, reg(value, 32), mem(vip, bits, mode));
    if (!backward)
        add(Op::add, reg(vip, mode), imm(bits / 8));
    if (keyed)
    {
        add(Op::bit_xor, reg(value, bits), reg(key, bits));
        add(Op::rotate_left, reg(value, bits), imm(3));
        add(Op::add, reg(value, bits), imm(7));
        if (mode == 64 && relative)
        {
            add(Op::push, reg(key, 64));
            add(Op::bit_xor, mem(4, 32, 64), reg(value, 32));
            add(Op::pop, reg(key, 64));
        }
        else
            add(Op::bit_xor, reg(key, bits), reg(value, bits));
    }
    if (relative)
    {
        if (mode == 64)
            add(Op::sign_extend, reg(value, 64), reg(value, 32));
        add(Op::add, reg(base, mode), reg(value, mode));
        add(Op::jump, reg(base, mode));
    }
    else
        add(Op::jump, mem(mode == 64 ? base : -1, mode, mode, value, mode / 8));
    auto result = recognize(code, mode);
    if (!result)
        throw std::runtime_error("test candidate rejected");
    return *result;
}
inline Candidate path_candidate(unsigned mode, bool backward, int vip = 6, int value = 0,
                                int key = 3, int base = 7)
{
    const auto original = candidate(mode, backward, true, true, vip, value, key, base);
    std::vector<Instruction> code;
    auto add = [&](Op op, Operand dst = {}, Operand src = {})
    { code.push_back({0, 4, op, dst, src, false}); };
    for (const auto &i : original.support)
    {
        code.push_back(i);
        if (backward && i.address == original.start)
        {
            add(Op::rotate_right, reg(value, 32), imm(8));
            add(Op::scan_forward, reg(value, 16), reg(2, 16));
        }
        if (i.op == Op::load)
        {
            auto high = reg(value, 8);
            high.bit_offset = 8;
            add(Op::compare, high, imm(0xaa));
        }
        if (i.op == Op::rotate_left)
        {
            auto target = imm(0);
            target.bits = mode;
            add(Op::direct_jump, target);
            add(Op::carry_set);
            add(Op::carry_toggle);
        }
        if (i.op == Op::push)
        {
            add(Op::bit_xor, reg(key, 16), reg(9, 16));
            add(Op::load, reg(key, 16), reg(value, 8));
        }
        if (i.dst.kind == Kind::memory)
            add(Op::negate, reg(key, mode));
        if (i.op == Op::pop)
            add(Op::test, reg(2, 16), imm(0x8fe7));
    }
    layout_path(code);
    const auto result = recognize(code, mode);
    if (!result)
        throw std::runtime_error("path candidate rejected");
    return *result;
}
inline Candidate stack_candidate(const Candidate &original, bool split = false)
{
    auto code = original.support;
    if (code.back().op != Op::jump)
        throw std::runtime_error("expected jump source");
    code.back().op = Op::push;
    if (split)
    {
        auto target = imm(0);
        target.bits = original.address_bits;
        code.push_back({0, 4, Op::direct_jump, target, {}, false});
    }
    code.push_back({0, 4, Op::near_return, {}, {}, false, original.address_bits});
    layout_path(code);
    auto result = recognize(code, original.address_bits);
    if (!result)
        throw std::runtime_error("push/return candidate rejected");
    return *result;
}
}
