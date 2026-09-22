#include "region.hpp"
#include <sstream>
#include <algorithm>

namespace chernobog::vm
{
namespace
{
bool reg(const Operand &o, int r, unsigned bits)
{
    return o.kind == Kind::reg && o.reg == r && o.bits == bits && o.bit_offset == 0;
}
bool valid_reg(int r, unsigned mode) { return r >= 0 && r < (mode == 64 ? 16 : 8) && r != 4; }
bool arithmetic(Op op) { return op == Op::add || op == Op::sub || op == Op::bit_xor; }
bool memory(const Operand &o, int base, unsigned bits, unsigned mode)
{
    return o.kind == Kind::memory && o.base == base && o.index == -1 && o.value == 0 &&
           o.bits == bits && o.address_bits == mode;
}
bool advance(const Instruction &i, int vip, unsigned bits, unsigned mode, Op op)
{
    return i.op == op && reg(i.dst, vip, mode) && i.src.kind == Kind::immediate &&
           i.src.value == bits / 8;
}
} // namespace

static std::optional<Candidate> recognize_core(const std::vector<Instruction> &code, unsigned mode)
{
    if ((mode != 32 && mode != 64) || code.size() < 3 || code.size() > 128)
        return {};
    for (size_t i = 0; i < code.size(); ++i)
        if (code[i].address == bad_address || !code[i].size || code[i].size > 15 ||
            code[i].address > UINT64_MAX - code[i].size)
            return {};
    const bool backwards = code[0].op == Op::sub;
    const auto &load = code[backwards ? 1 : 0];
    if (load.op != Op::load || load.dst.kind != Kind::reg || load.src.kind != Kind::memory ||
        (load.src.bits != 8 && load.src.bits != 32) || load.dst.bits != 32 ||
        !valid_reg(load.dst.reg, mode) || !valid_reg(load.src.base, mode) ||
        load.dst.reg == load.src.base || !memory(load.src, load.src.base, load.src.bits, mode))
        return {};
    if (!advance(code[backwards ? 0 : 1], load.src.base, load.src.bits, mode,
                 backwards ? Op::sub : Op::add))
        return {};
    Candidate c;
    c.start = code.front().address;
    c.end = code.back().address + code.back().size;
    c.read = load.address;
    c.dispatch = code.back().address;
    c.address_bits = mode;
    c.read_bits = load.src.bits;
    c.direction = backwards ? Direction::backward : Direction::forward;
    c.vip = load.src.base;
    c.value = load.dst.reg;
    size_t cursor = 2;
    // Stateful source-emitted decode: value OP key, bounded immediate/unary
    // transforms, then key OP value (including the x64 low-dword stack idiom).
    if (cursor < code.size() && arithmetic(code[cursor].op) &&
        reg(code[cursor].dst, c.value, c.read_bits) && code[cursor].src.kind == Kind::reg)
    {
        const auto &mix = code[cursor++];
        c.key = mix.src.reg;
        if (!valid_reg(c.key, mode) || c.key == c.vip || c.key == c.value ||
            mix.src.bits != c.read_bits)
            return {};
        while (cursor < code.size())
        {
            const auto &i = code[cursor];
            if (!reg(i.dst, c.value, c.read_bits))
                break;
            const bool immediate =
                (arithmetic(i.op) || i.op == Op::rotate_left || i.op == Op::rotate_right) &&
                i.src.kind == Kind::immediate;
            const bool unary =
                (i.op == Op::negate || i.op == Op::bit_not || i.op == Op::increment ||
                 i.op == Op::decrement || (i.op == Op::byte_swap && c.read_bits == 32)) &&
                i.src.kind == Kind::none;
            if (!immediate && !unary)
                break;
            ++cursor;
        }
        if (cursor == code.size())
            return {};
        if (mode == 64 && c.read_bits == 32)
        {
            if (cursor + 2 >= code.size())
                return {};
            const auto &push = code[cursor], &update = code[cursor + 1], &pop = code[cursor + 2];
            if (push.op != Op::push || !reg(push.dst, c.key, 64) || update.op != mix.op ||
                !memory(update.dst, 4, 32, 64) || !reg(update.src, c.value, 32) ||
                pop.op != Op::pop || !reg(pop.dst, c.key, 64))
                return {};
            c.stack_key_update = true;
            cursor += 3;
        }
        else
        {
            const auto &update = code[cursor++];
            if (update.op != mix.op || !reg(update.dst, c.key, c.read_bits) ||
                !reg(update.src, c.value, c.read_bits))
                return {};
        }
    }
    if (c.read_bits == 8)
    {
        if (cursor + 1 != code.size())
            return {};
        const auto &jump = code[cursor];
        const auto &target = jump.dst;
        if (jump.op != Op::jump || target.kind != Kind::memory || target.bits != mode ||
            target.address_bits != mode || target.index != c.value || target.scale != mode / 8)
            return {};
        if (mode == 64 && (!valid_reg(target.base, mode) || target.base == c.vip ||
                           target.base == c.value || target.base == c.key || target.value != 0))
            return {};
        if (mode == 32 && target.base != -1)
            return {};
        c.dispatch_kind = Dispatch::indexed_table;
        c.dispatch_base = target.base;
        c.table_displacement = target.value;
    }
    else
    {
        if (mode == 64)
        {
            if (cursor >= code.size() || code[cursor].op != Op::sign_extend ||
                !reg(code[cursor].dst, c.value, 64) || !reg(code[cursor].src, c.value, 32))
                return {};
            ++cursor;
        }
        if (cursor + 2 != code.size())
            return {};
        const auto &add = code[cursor], &jump = code[cursor + 1];
        if (add.op != Op::add || add.dst.kind != Kind::reg || !valid_reg(add.dst.reg, mode) ||
            add.dst.reg == c.vip || add.dst.reg == c.value || add.dst.reg == c.key ||
            add.dst.bits != mode || !reg(add.src, c.value, mode) || jump.op != Op::jump ||
            !reg(jump.dst, add.dst.reg, mode))
            return {};
        c.dispatch_kind = Dispatch::relative_register;
        c.dispatch_base = add.dst.reg;
    }
    c.support = code;
    return c;
}

namespace
{
bool register_operand(const Operand &o, unsigned mode)
{
    return o.kind == Kind::reg && o.reg >= 0 && o.reg < (mode == 64 ? 16 : 8) &&
           !(mode == 32 && o.bits == 8 && o.reg >= 4) &&
           (o.bits == 8 || o.bits == 16 || o.bits == 32 || (mode == 64 && o.bits == 64)) &&
           (o.bit_offset == 0 || (o.bit_offset == 8 && o.bits == 8 && o.reg < 4));
}
bool register_effect(const Instruction &i, unsigned mode)
{
    if (!register_operand(i.dst, mode) || i.dst.reg == 4)
        return false;
    const bool source = i.src.kind == Kind::immediate ||
                        (register_operand(i.src, mode) && i.src.bits == i.dst.bits);
    if (arithmetic(i.op))
        return source;
    if (i.op == Op::rotate_left || i.op == Op::rotate_right)
        return i.src.kind == Kind::immediate;
    if (i.op == Op::negate || i.op == Op::bit_not || i.op == Op::increment || i.op == Op::decrement)
        return i.src.kind == Kind::none;
    if (i.op == Op::byte_swap)
        return i.dst.bits == 32 && i.src.kind == Kind::none;
    if (i.op == Op::load || i.op == Op::sign_extend)
        return register_operand(i.src, mode) && i.src.bits <= i.dst.bits;
    return i.op == Op::scan_forward && i.dst.bits >= 16 && register_operand(i.src, mode) &&
           i.src.bits == i.dst.bits;
}
bool flag_effect(const Instruction &i, unsigned mode)
{
    if (i.op == Op::carry_set || i.op == Op::carry_clear || i.op == Op::carry_toggle)
        return i.dst.kind == Kind::none && i.src.kind == Kind::none;
    return (i.op == Op::compare || i.op == Op::test) && register_operand(i.dst, mode) &&
           (i.src.kind == Kind::immediate ||
            (register_operand(i.src, mode) && i.src.bits == i.dst.bits));
}
}

std::optional<Candidate> recognize(const std::vector<Instruction> &code, unsigned mode)
{
    if ((mode != 32 && mode != 64) || code.size() < 3 || code.size() > 128 ||
        (code.back().op != Op::jump && code.back().op != Op::near_return))
        return {};
    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto &current = code[i];
        if (current.address == bad_address || current.size == 0 || current.size > 15 ||
            current.address > UINT64_MAX - current.size)
            return {};
        for (const auto &operand : {current.dst, current.src})
            if ((operand.kind == Kind::reg && !register_operand(operand, mode)) ||
                (operand.kind != Kind::reg && operand.bit_offset != 0))
                return {};
        if (i)
        {
            const auto &previous = code[i - 1];
            const uint64_t next = previous.op == Op::direct_jump ? previous.dst.value
                                                                 : previous.address + previous.size;
            if (current.alternate_entry || current.address != next)
                return {};
        }
        for (size_t j = 0; j < i; ++j)
            if (current.address < code[j].address + code[j].size &&
                code[j].address < current.address + current.size)
                return {};
    }
    std::vector<Instruction> core;
    for (size_t index = 0; index < code.size(); ++index)
    {
        const auto &i = code[index];
        if (i.op == Op::direct_jump)
        {
            if (index + 1 == code.size() || i.dst.kind != Kind::immediate || i.dst.bits != mode ||
                i.src.kind != Kind::none)
                return {};
            continue;
        }
        if (flag_effect(i, mode))
            continue;
        core.push_back(i);
    }
    // Pre-read writes to the subsequently zero-extended value register remain
    // fully modeled, but do not prevent recognizing a backward VIP advance.
    if (core.size() > 2 && core.front().op == Op::sub)
    {
        size_t load = 1;
        while (load < core.size() && register_effect(core[load], mode))
            ++load;
        if (load < core.size() && core[load].op == Op::load && core[load].src.kind == Kind::memory)
        {
            for (size_t i = 1; i < load; ++i)
                if (core[i].dst.reg != core[load].dst.reg)
                    return {};
            core.erase(core.begin() + 1, core.begin() + load);
        }
    }
    // Scratch writes to a saved key cannot change its restored value. Preserve
    // those writes in support and summarize them, including partial registers.
    for (size_t at = 0; at < core.size(); ++at)
    {
        if (core[at].op != Op::push || core[at].dst.kind != Kind::reg)
            continue;
        const int key = core[at].dst.reg;
        size_t end = at + 1;
        for (; end < core.size() && core[end].op != Op::pop; ++end)
        {
        }
        if (end == core.size() || core[end].dst.kind != Kind::reg || core[end].dst.reg != key)
            continue;
        for (size_t i = at + 1; i < end;)
        {
            if (register_effect(core[i], mode) && core[i].dst.reg == key)
            {
                core.erase(core.begin() + i);
                --end;
            }
            else
                ++i;
        }
        at = end;
    }
    const bool stack_dispatch = !core.empty() && core.back().op == Op::near_return;
    if (stack_dispatch)
    {
        const auto &ret = core.back();
        if (core.size() < 2 || ret.stack_bits != mode || ret.dst.kind != Kind::none ||
            ret.src.kind != Kind::none)
            return {};
        const auto &push = core[core.size() - 2];
        if (push.op != Op::push || push.dst.bits != mode || push.src.kind != Kind::none)
            return {};
        // Pattern selection uses the original target operand. Evaluation retains
        // both instructions and their ordered stack accesses in the full support.
        core.pop_back();
        core.back().op = Op::jump;
    }
    auto result = recognize_core(core, mode);
    if (!result)
        return {};
    result->start = code.front().address;
    result->end = code.back().address + code.back().size;
    result->dispatch = code.back().address;
    result->stack_dispatch = stack_dispatch;
    result->support = code;
    return result;
}

bool same_logical_state(const LogicalState &a, const LogicalState &b, bool stateful)
{
    return a.publication != 0 && a.publication == b.publication && a.native != bad_address &&
           a.native == b.native && a.context != 0 && a.context == b.context &&
           a.memory_epoch != 0 && a.memory_epoch == b.memory_epoch && a.vip && a.vip == b.vip &&
           a.virtual_stack && a.virtual_stack == b.virtual_stack && a.dispatch_base &&
           a.dispatch_base == b.dispatch_base && (!stateful || (a.key && a.key == b.key));
}

std::string normalized_shape(const Candidate &c)
{
    std::ostringstream out;
    out << c.address_bits << ':' << c.read_bits << ':' << int(c.direction) << ':'
        << int(c.dispatch_kind);
    const auto role = [&](int r)
    {
        return r == -1                ? -1
               : r == c.vip           ? 0
               : r == c.value         ? 1
               : r == c.key           ? 2
               : r == c.dispatch_base ? 3
               : r == 4               ? 4
                                      : 5 + r;
    };
    for (const auto &i : c.support)
    {
        if (i.op == Op::direct_jump)
        {
            out << ";direct-next";
            continue;
        }
        out << ';' << int(i.op) << ':' << i.stack_bits;
        for (const auto &o : {i.dst, i.src})
            out << ',' << int(o.kind) << '/' << role(o.reg) << '/' << role(o.base) << '/'
                << role(o.index) << '/' << o.bits << '/' << o.address_bits << '/' << o.scale << '/'
                << o.value << '/' << o.bit_offset;
    }
    return out.str();
}
} // namespace chernobog::vm
