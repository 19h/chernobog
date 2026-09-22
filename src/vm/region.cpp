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

namespace
{
struct ReadStage
{
    uint64_t read = bad_address;
    unsigned bits = 0;
    int vip = -1, value = -1, key = -1;
    Direction direction = Direction::forward;
    bool stack_key_update = false;
};
std::optional<ReadStage> read_stage(const std::vector<Instruction> &code, size_t &cursor,
                                    unsigned mode)
{
    if (cursor + 1 >= code.size())
        return {};
    const bool backwards = code[cursor].op == Op::sub;
    const auto &load = code[cursor + (backwards ? 1 : 0)];
    const auto bits = load.src.bits;
    if (load.op != Op::load || load.dst.kind != Kind::reg || load.src.kind != Kind::memory ||
        (bits != 8 && bits != 16 && bits != 32 && !(mode == 64 && bits == 64)) ||
        load.dst.bits != std::max(32u, bits) || load.dst.bit_offset != 0 ||
        !valid_reg(load.dst.reg, mode) || !valid_reg(load.src.base, mode) ||
        load.dst.reg == load.src.base || !memory(load.src, load.src.base, bits, mode) ||
        !advance(code[cursor + (backwards ? 0 : 1)], load.src.base, bits, mode,
                 backwards ? Op::sub : Op::add))
        return {};
    ReadStage stage;
    stage.read = load.address;
    stage.bits = bits;
    stage.vip = load.src.base;
    stage.value = load.dst.reg;
    stage.direction = backwards ? Direction::backward : Direction::forward;
    cursor += 2;
    if (cursor < code.size() && arithmetic(code[cursor].op) &&
        reg(code[cursor].dst, stage.value, bits) && code[cursor].src.kind == Kind::reg)
    {
        const auto &mix = code[cursor++];
        stage.key = mix.src.reg;
        if (!valid_reg(stage.key, mode) || stage.key == stage.vip || stage.key == stage.value ||
            !reg(mix.src, stage.key, bits))
            return {};
        while (cursor < code.size())
        {
            const auto &i = code[cursor];
            if (!reg(i.dst, stage.value, bits))
                break;
            const bool immediate =
                (arithmetic(i.op) || i.op == Op::rotate_left || i.op == Op::rotate_right) &&
                i.src.kind == Kind::immediate;
            const bool unary =
                (i.op == Op::negate || i.op == Op::bit_not || i.op == Op::increment ||
                 i.op == Op::decrement || (i.op == Op::byte_swap && (bits == 32 || bits == 64))) &&
                i.src.kind == Kind::none;
            if (!immediate && !unary)
                break;
            ++cursor;
        }
        if (cursor == code.size())
            return {};
        if (mode == 64 && bits == 32)
        {
            if (cursor + 2 >= code.size())
                return {};
            const auto &push = code[cursor], &update = code[cursor + 1], &pop = code[cursor + 2];
            if (push.op != Op::push || !reg(push.dst, stage.key, 64) ||
                push.src.kind != Kind::none || update.op != mix.op ||
                !memory(update.dst, 4, 32, 64) || !reg(update.src, stage.value, 32) ||
                pop.op != Op::pop || !reg(pop.dst, stage.key, 64) || pop.src.kind != Kind::none)
                return {};
            stage.stack_key_update = true;
            cursor += 3;
        }
        else
        {
            const auto &update = code[cursor++];
            if (update.op != mix.op || !reg(update.dst, stage.key, bits) ||
                !reg(update.src, stage.value, bits))
                return {};
        }
    }
    return stage;
}
bool stack_check(const std::vector<Instruction> &code, size_t &cursor, Candidate &c)
{
    if (cursor + 2 >= code.size())
        return false;
    const auto &lea = code[cursor], &cmp = code[cursor + 1], &branch = code[cursor + 2];
    const auto mode = c.address_bits;
    const auto &source = lea.src;
    if (lea.op != Op::address || lea.dst.kind != Kind::reg || !valid_reg(lea.dst.reg, mode) ||
        !reg(lea.dst, lea.dst.reg, mode) || source.kind != Kind::memory || source.base != 4 ||
        source.index != -1 || source.bits != mode || source.address_bits != mode ||
        source.scale != 1 ||
        (source.value != (mode == 64 ? 256u : 96u) && source.value != (mode == 64 ? 320u : 128u)) ||
        cmp.op != Op::compare || !reg(cmp.dst, c.virtual_stack, mode) ||
        !reg(cmp.src, lea.dst.reg, mode) || branch.op != Op::jump_above ||
        branch.dst.kind != Kind::immediate || branch.dst.bits != mode ||
        branch.src.kind != Kind::none)
        return false;
    c.stack_check = true;
    c.stack_check_branch = branch.address;
    c.stack_check_offset = source.value;
    c.stack_check_value = lea.dst.reg;
    cursor += 3;
    return true;
}
} // namespace

static std::optional<Candidate> recognize_core(const std::vector<Instruction> &code, unsigned mode)
{
    if ((mode != 32 && mode != 64) || code.size() < 3 || code.size() > instruction_limit)
        return {};
    size_t cursor = 0;
    auto stage = read_stage(code, cursor, mode);
    if (!stage)
        return {};
    Candidate c;
    c.start = code.front().address;
    c.end = code.back().address + code.back().size;
    c.dispatch = code.back().address;
    c.address_bits = mode;
    c.vip = stage->vip;
    c.direction = stage->direction;
    c.key = stage->key;
    c.stack_key_update = stage->stack_key_update;
    if (cursor + 1 < code.size() && code[cursor].op == Op::sub && code[cursor + 1].op == Op::load &&
        code[cursor + 1].dst.kind == Kind::memory)
    {
        const auto &adjust = code[cursor++], &store = code[cursor++];
        c.payload_read = stage->read;
        c.payload_bits = stage->bits;
        c.stored_bits = std::max(16u, c.payload_bits);
        c.payload_value = stage->value;
        c.virtual_stack = adjust.dst.reg;
        c.payload_store = store.address;
        if (!valid_reg(c.virtual_stack, mode) || c.virtual_stack == c.vip ||
            c.virtual_stack == c.key || c.virtual_stack == c.payload_value ||
            !advance(adjust, c.virtual_stack, c.stored_bits, mode, Op::sub) ||
            !memory(store.dst, c.virtual_stack, c.stored_bits, mode) ||
            !reg(store.src, c.payload_value, c.stored_bits))
            return {};
        if (cursor < code.size() && code[cursor].op == Op::address && !stack_check(code, cursor, c))
            return {};
        stage = read_stage(code, cursor, mode);
        if (!stage || stage->vip != c.vip || stage->direction != c.direction ||
            (stage->key >= 0 && c.key >= 0 && stage->key != c.key))
            return {};
        if (stage->key >= 0)
            c.key = stage->key;
        c.stack_key_update = c.stack_key_update || stage->stack_key_update;
    }
    c.read = stage->read;
    c.read_bits = stage->bits;
    c.value = stage->value;
    if (c.read_bits == 8)
    {
        if (cursor + 1 != code.size())
            return {};
        const auto &jump = code[cursor];
        const auto &target = jump.dst;
        if (jump.op != Op::jump || jump.src.kind != Kind::none || target.kind != Kind::memory ||
            target.bits != mode || target.address_bits != mode || target.index != c.value ||
            target.scale != mode / 8)
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
    else if (c.read_bits == 32)
    {
        // Advanced handlers compute the relative target before their stack check.
        if (c.stack_check)
            return {};
        if (mode == 64)
        {
            if (cursor >= code.size() || code[cursor].op != Op::sign_extend ||
                !reg(code[cursor].dst, c.value, 64) || !reg(code[cursor].src, c.value, 32))
                return {};
            ++cursor;
        }
        if (cursor >= code.size())
            return {};
        const auto &add = code[cursor++];
        if (add.op != Op::add || add.dst.kind != Kind::reg || !valid_reg(add.dst.reg, mode) ||
            add.dst.reg == c.vip || add.dst.reg == c.value || add.dst.reg == c.key ||
            !reg(add.dst, add.dst.reg, mode) || !reg(add.src, c.value, mode))
            return {};
        c.dispatch_kind = Dispatch::relative_register;
        c.dispatch_base = add.dst.reg;
        if (c.payload_bits && cursor < code.size() && code[cursor].op == Op::address &&
            !stack_check(code, cursor, c))
            return {};
        if (cursor + 1 != code.size() || code[cursor].op != Op::jump ||
            !reg(code[cursor].dst, c.dispatch_base, mode) || code[cursor].src.kind != Kind::none)
            return {};
    }
    else
        return {};
    if (c.payload_bits)
    {
        for (int role : {c.vip, c.key, c.dispatch_base, c.value})
            if (role >= 0 && role == c.virtual_stack)
                return {};
        for (int role : {c.vip, c.key, c.dispatch_base})
            if (role >= 0 && (role == c.payload_value || role == c.value ||
                              (c.stack_check && role == c.stack_check_value)))
                return {};
        if (c.stack_check && c.stack_check_value == c.virtual_stack)
            return {};
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
        return (i.dst.bits == 32 || i.dst.bits == 64) && i.src.kind == Kind::none;
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
    if ((mode != 32 && mode != 64) || code.size() < 3 || code.size() > instruction_limit ||
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
            const uint64_t next = previous.op == Op::direct_jump || previous.op == Op::jump_above
                                      ? previous.dst.value
                                      : previous.address + previous.size;
            if (current.alternate_entry || current.address != next)
                return {};
        }
        for (size_t j = 0; j < i; ++j)
            if (current.address < code[j].address + code[j].size &&
                code[j].address < current.address + current.size)
                return {};
    }
    const bool guarded = std::any_of(code.begin(), code.end(),
                                     [](const Instruction &i) { return i.op == Op::jump_above; });
    std::vector<Instruction> core;
    for (size_t index = 0; index < code.size(); ++index)
    {
        const auto &i = code[index];
        if (i.op == Op::direct_jump || i.op == Op::jump_above)
        {
            if (index + 1 == code.size() || i.dst.kind != Kind::immediate || i.dst.bits != mode ||
                i.src.kind != Kind::none || (mode == 32 && i.dst.value > UINT32_MAX))
                return {};
            if (i.op == Op::direct_jump)
                continue;
        }
        if (!guarded && flag_effect(i, mode))
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
        << int(c.dispatch_kind) << ':' << c.payload_bits << ':' << c.stored_bits << ':'
        << c.stack_check;
    const auto role = [&](int r)
    {
        return r == -1                    ? -1
               : r == c.vip               ? 0
               : r == c.value             ? 1
               : r == c.key               ? 2
               : r == c.dispatch_base     ? 3
               : r == 4                   ? 4
               : r == c.virtual_stack     ? 5
               : r == c.payload_value     ? 6
               : r == c.stack_check_value ? 7
                                          : 8 + r;
    };
    for (const auto &i : c.support)
    {
        if (i.op == Op::direct_jump)
        {
            out << ";direct-next";
            continue;
        }
        if (i.op == Op::jump_above)
        {
            out << ";above-next";
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
