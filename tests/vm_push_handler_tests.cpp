#include "vm/semantics.hpp"
#include "vm/transition.hpp"
#include "vm_test_candidates.hpp"
#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <map>
#include <string>

using namespace chernobog::vm;
namespace
{
size_t checks = 0, concrete_cases = 0;
std::string scenario;
void require(bool good, const char *label)
{
    ++checks;
    if (!good)
    {
        std::cerr << label << "; " << scenario << '\n';
        std::exit(1);
    }
}
uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }
uint64_t arithmetic(Op op, uint64_t a, uint64_t b, unsigned bits)
{
    return (op == Op::add ? a + b : op == Op::sub ? a - b : a ^ b) & mask(bits);
}
uint64_t rotate(uint64_t value, unsigned bits)
{
    return ((value << 3) | (value >> (bits - 3))) & mask(bits);
}
struct Config
{
    unsigned mode = 64, payload_bits = 32, keys = 3;
    bool backward = false, relative = true, shared_value = false;
    bool guarded = false;
    Op payload_mix = Op::bit_xor, dispatch_mix = Op::bit_xor;
    int vip = 6, value = 0, key = 3, base = 7, virtual_stack = 5, payload_value = 2;
    int guard_value = 1;
    uint64_t guard_offset = 0;
};
struct Stage
{
    unsigned bits = 0;
    size_t read = 0, stride = 0, mix = SIZE_MAX, constant = SIZE_MAX;
    size_t push = SIZE_MAX, feedback = SIZE_MAX, pop = SIZE_MAX;
};
struct Fixture
{
    Config config;
    std::vector<Instruction> code;
    Stage payload, dispatch;
    size_t stack_adjust = 0, store = 0;
    size_t guard_link = SIZE_MAX, guard_address = SIZE_MAX, guard_compare = SIZE_MAX;
    size_t guard_branch = SIZE_MAX;
};
Fixture make(Config config)
{
    using namespace vm_test;
    if (config.shared_value)
        config.payload_value = config.value;
    if (config.guarded && !config.guard_offset)
        config.guard_offset = config.mode == 64 ? 256 : 96;
    Fixture result;
    result.config = config;
    const auto &c = result.config;
    auto add = [&](Op op, Operand dst, Operand src = Operand{})
    {
        const auto index = result.code.size();
        result.code.push_back({0x1000 + index * 4, 4, op, dst, src, false});
        return index;
    };
    auto stage = [&](unsigned bits, int value, bool keyed, Op mix)
    {
        Stage s;
        s.bits = bits;
        if (c.backward)
            s.stride = add(Op::sub, reg(c.vip, c.mode), imm(bits / 8));
        s.read = add(Op::load, reg(value, bits == 64 ? 64 : 32), mem(c.vip, bits, c.mode));
        if (!c.backward)
            s.stride = add(Op::add, reg(c.vip, c.mode), imm(bits / 8));
        if (keyed)
        {
            s.mix = add(mix, reg(value, bits), reg(c.key, bits));
            add(Op::rotate_left, reg(value, bits), imm(3));
            s.constant = add(Op::add, reg(value, bits), imm(7));
            if (c.mode == 64 && bits == 32)
            {
                s.push = add(Op::push, reg(c.key, 64));
                s.feedback = add(mix, mem(4, 32, 64), reg(value, 32));
                s.pop = add(Op::pop, reg(c.key, 64));
            }
            else
                s.feedback = add(mix, reg(c.key, bits), reg(value, bits));
        }
        return s;
    };
    auto guard = [&]()
    {
        auto target = imm(0);
        target.bits = c.mode;
        result.guard_link = add(Op::direct_jump, target);
        auto stack_limit = mem(4, c.mode, c.mode);
        stack_limit.value = c.guard_offset;
        result.guard_address = add(Op::address, reg(c.guard_value, c.mode), stack_limit);
        result.guard_compare =
            add(Op::compare, reg(c.virtual_stack, c.mode), reg(c.guard_value, c.mode));
        result.guard_branch = add(Op::jump_above, target);
    };
    result.payload = stage(c.payload_bits, c.payload_value, c.keys & 1, c.payload_mix);
    result.stack_adjust =
        add(Op::sub, reg(c.virtual_stack, c.mode), imm(std::max(2u, c.payload_bits / 8)));
    const auto stored = std::max(16u, c.payload_bits);
    result.store =
        add(Op::load, mem(c.virtual_stack, stored, c.mode), reg(c.payload_value, stored));
    if (c.guarded && !c.relative)
        guard();
    result.dispatch = stage(c.relative ? 32 : 8, c.value, c.keys & 2, c.dispatch_mix);
    if (c.relative)
    {
        if (c.mode == 64)
            add(Op::sign_extend, reg(c.value, 64), reg(c.value, 32));
        add(Op::add, reg(c.base, c.mode), reg(c.value, c.mode));
        if (c.guarded)
            guard();
        add(Op::jump, reg(c.base, c.mode));
    }
    else
        add(Op::jump, mem(c.mode == 64 ? c.base : -1, c.mode, c.mode, c.value, c.mode / 8));
    if (c.guarded)
    {
        for (size_t index = 0; index < result.code.size(); ++index)
            result.code[index].address += (index > result.guard_link ? 0x1000 : 0) +
                                          (index > result.guard_branch ? 0x100 : 0);
        result.code[result.guard_link].dst.value = result.code[result.guard_link + 1].address;
        result.code[result.guard_branch].dst.value = result.code[result.guard_branch + 1].address;
    }
    return result;
}
Candidate recognized(const Fixture &fixture)
{
    auto candidate = recognize(fixture.code, fixture.config.mode);
    require(bool(candidate), "complete push handler recognized");
    const auto &c = fixture.config;
    require(candidate->start == fixture.code.front().address &&
                candidate->end == fixture.code.back().address + fixture.code.back().size &&
                candidate->support.size() == fixture.code.size(),
            "complete support retained");
    require(candidate->payload_read == fixture.code[fixture.payload.read].address &&
                candidate->read == fixture.code[fixture.dispatch.read].address &&
                candidate->payload_read != candidate->read,
            "payload and dispatch read provenance distinct");
    require(candidate->payload_bits == c.payload_bits &&
                candidate->stored_bits == std::max(16u, c.payload_bits) &&
                candidate->read_bits == (c.relative ? 32u : 8u),
            "payload, store and dispatch widths retained");
    require(candidate->vip == c.vip && candidate->value == c.value &&
                candidate->payload_value == c.payload_value &&
                candidate->virtual_stack == c.virtual_stack &&
                candidate->key == (c.keys ? c.key : -1),
            "complete handler register roles");
    require(candidate->direction == (c.backward ? Direction::backward : Direction::forward),
            "full handler direction");
    require(candidate->stack_check == c.guarded, "guard presence retained");
    if (c.guarded)
        require(candidate->stack_check_branch == fixture.code[fixture.guard_branch].address &&
                    candidate->stack_check_value == c.guard_value &&
                    candidate->stack_check_offset == c.guard_offset &&
                    candidate->payload_store == fixture.code[fixture.store].address,
                "stack-check provenance, scratch and threshold retained");
    return *candidate;
}
struct ConcreteAccess
{
    bool write;
    unsigned bits;
    uint64_t address, value, site;
};
using Memory = std::map<uint64_t, uint8_t>;
void write_bytes(Memory &memory, uint64_t address, uint64_t value, unsigned bits, unsigned mode)
{
    for (unsigned byte = 0; byte < bits / 8; ++byte)
        memory[(address + byte) & mask(mode)] = uint8_t(value >> (byte * 8));
}
uint64_t read_bytes(const Memory &memory, uint64_t address, unsigned bits, unsigned mode)
{
    uint64_t value = 0;
    for (unsigned byte = 0; byte < bits / 8; ++byte)
    {
        const auto found = memory.find((address + byte) & mask(mode));
        if (found != memory.end())
            value |= uint64_t(found->second) << (byte * 8);
    }
    return value;
}
uint64_t number(z3::model &model, const z3::expr &expr)
{
    return model.eval(expr, true).get_numeral_uint64();
}
std::array<bool, 6> flags(Op op, unsigned bits, uint64_t a, uint64_t b)
{
    a &= mask(bits);
    b &= mask(bits);
    const auto result = arithmetic(op, a, b, bits);
    unsigned population = 0;
    for (unsigned bit = 0; bit < 8; ++bit)
        population += unsigned((result >> bit) & 1);
    const bool logical = op == Op::bit_xor, subtract = op == Op::sub;
    const auto overflow = (subtract ? a ^ b : ~(a ^ b)) & (a ^ result);
    return {{!logical && (subtract ? a < b : result < a), (population & 1) == 0,
             !logical && ((a ^ b ^ result) & 16) != 0, result == 0,
             ((result >> (bits - 1)) & 1) != 0, !logical && ((overflow >> (bits - 1)) & 1) != 0}};
}
// Independent concrete formulas operate on a byte map. Neither recognition,
// Evaluator, x86_abstract nor symbolic terms determine expected effects.
void concrete(const Fixture &fixture, unsigned alias, unsigned vector)
{
    const auto &c = fixture.config;
    const auto candidate = recognized(fixture);
    z3::context ctx;
    const auto summary = summarize(ctx, candidate);
    require(bool(summary), "complete handler summary built");
    require(summary->roles[c.virtual_stack] == "virtual_stack" &&
                summary->roles[c.payload_value] == (c.shared_value ? "value" : "payload_value"),
            "new input roles explicit");
    const uint64_t encoded_payload[] = {0, UINT64_MAX, UINT64_C(0x80017fffab0080fe)};
    const uint64_t encoded_dispatch[] = {0x80000000, 0x7fffffff, 0x810000fe};
    const uint64_t initial_keys[] = {0, UINT64_MAX, UINT64_C(0x9a785634a581f03c)};
    const auto payload_bytes = c.payload_bits / 8;
    const auto dispatch_bits = c.relative ? 32u : 8u;
    const auto dispatch_bytes = dispatch_bits / 8;
    const uint64_t payload_at = 0x2000 + (c.backward ? dispatch_bytes : 0);
    const uint64_t dispatch_at = 0x2000 + (c.backward ? 0 : payload_bytes);
    const auto slot = std::max(2u, payload_bytes);
    const auto base = uint64_t{0x10000};
    std::vector<uint64_t> registers(summary->registers.size());
    for (size_t i = 0; i < registers.size(); ++i)
        registers[i] = (UINT64_C(0x13579bdf24680000) + i * 0x101) & mask(c.mode);
    registers[c.vip] = c.backward ? payload_at + payload_bytes : payload_at;
    registers[c.virtual_stack] = alias & 1 ? dispatch_at + slot : 0x5000;
    registers[4] = alias & 2 ? dispatch_at + c.mode / 8 : c.guarded ? 0x1000 : 0x8000;
    if (c.keys)
        registers[c.key] = initial_keys[vector] & mask(c.mode);
    if (candidate.dispatch_base >= 0)
        registers[c.base] = base;
    const auto inputs = registers;
    Memory input_memory;
    write_bytes(input_memory, payload_at, encoded_payload[vector], c.payload_bits, c.mode);
    write_bytes(input_memory, dispatch_at, encoded_dispatch[vector], dispatch_bits, c.mode);
    auto memory = input_memory;
    std::vector<ConcreteAccess> accesses;
    auto read = [&](uint64_t address, unsigned bits, size_t index)
    {
        const auto value = read_bytes(memory, address, bits, c.mode);
        accesses.push_back({false, bits, address, value, fixture.code[index].address});
        return value;
    };
    auto write = [&](uint64_t address, uint64_t value, unsigned bits, size_t index)
    {
        value &= mask(bits);
        accesses.push_back({true, bits, address, value, fixture.code[index].address});
        write_bytes(memory, address, value, bits, c.mode);
    };
    Op final_op = Op::sub;
    unsigned final_bits = c.mode;
    uint64_t final_a = 0, final_b = 0;
    auto decode = [&](const Stage &stage, int value_reg, bool keyed, Op mix)
    {
        const auto before = registers[c.vip];
        if (c.backward)
            registers[c.vip] = (before - stage.bits / 8) & mask(c.mode);
        auto value = read(registers[c.vip], stage.bits, stage.read);
        if (!c.backward)
            registers[c.vip] = (before + stage.bits / 8) & mask(c.mode);
        final_op = c.backward ? Op::sub : Op::add;
        final_bits = c.mode;
        final_a = before;
        final_b = stage.bits / 8;
        if (keyed)
        {
            const auto key = registers[c.key];
            value = (rotate(arithmetic(mix, value, key, stage.bits), stage.bits) + 7) &
                    mask(stage.bits);
            if (c.mode == 64 && stage.bits == 32)
            {
                registers[4] -= 8;
                write(registers[4], key, 64, stage.push);
                const auto low = read(registers[4], 32, stage.feedback);
                write(registers[4], arithmetic(mix, low, value, 32), 32, stage.feedback);
                registers[c.key] = read(registers[4], 64, stage.pop);
                registers[4] += 8;
            }
            else
                registers[c.key] =
                    ((key & ~mask(stage.bits)) | arithmetic(mix, key, value, stage.bits)) &
                    mask(c.mode);
            final_op = mix;
            final_bits = stage.bits;
            final_a = key;
            final_b = value;
        }
        registers[value_reg] = value;
    };
    auto execute_guard = [&]()
    {
        registers[c.guard_value] = (registers[4] + c.guard_offset) & mask(c.mode);
        final_op = Op::sub;
        final_bits = c.mode;
        final_a = registers[c.virtual_stack];
        final_b = registers[c.guard_value];
        require(final_a > final_b, "independent concrete input takes unsigned stack guard");
    };
    decode(fixture.payload, c.payload_value, c.keys & 1, c.payload_mix);
    registers[c.virtual_stack] = (registers[c.virtual_stack] - slot) & mask(c.mode);
    write(registers[c.virtual_stack], registers[c.payload_value], std::max(16u, c.payload_bits),
          fixture.store);
    if (c.guarded && !c.relative)
        execute_guard();
    decode(fixture.dispatch, c.value, c.keys & 2, c.dispatch_mix);
    uint64_t next = 0;
    if (c.relative)
    {
        if (c.mode == 64 && (registers[c.value] & 0x80000000))
            registers[c.value] |= UINT64_C(0xffffffff00000000);
        final_op = Op::add;
        final_bits = c.mode;
        final_a = registers[c.base];
        final_b = registers[c.value];
        registers[c.base] = (final_a + final_b) & mask(c.mode);
        next = registers[c.base];
        if (c.guarded)
            execute_guard();
    }
    else
    {
        const auto address =
            ((c.mode == 64 ? base : 0) + registers[c.value] * c.mode / 8) & mask(c.mode);
        const auto target = (UINT64_C(0xfedcba9876540000) + registers[c.value] * 17) & mask(c.mode);
        require(address + c.mode / 8 <= 0x2000 || address >= 0x200c,
                "chosen oracle table does not overlap source");
        write_bytes(input_memory, address, target, c.mode, c.mode);
        write_bytes(memory, address, target, c.mode, c.mode);
        next = read(address, c.mode, fixture.code.size() - 1);
    }
    z3::solver solver(ctx);
    for (size_t i = 0; i < inputs.size(); ++i)
        solver.add(ctx.bv_const(("input_" + summary->roles[i]).c_str(), c.mode) ==
                   ctx.bv_val(inputs[i], c.mode));
    auto symbolic_memory = z3::const_array(ctx.bv_sort(c.mode), ctx.bv_val(0, 8));
    for (const auto &entry : input_memory)
        symbolic_memory = z3::store(symbolic_memory, ctx.bv_val(entry.first, c.mode),
                                    ctx.bv_val(entry.second, 8));
    solver.add(ctx.constant("input_memory", symbolic_memory.get_sort()) == symbolic_memory);
    require(solver.check() == z3::sat, "independent concrete inputs satisfiable");
    auto model = solver.get_model();
    require(model.eval(summary->domain, true).is_true(),
            "concrete input belongs to summary domain");
    for (size_t i = 0; i < registers.size(); ++i)
        require(number(model, summary->registers[i]) == registers[i], "complete register oracle");
    require(number(model, summary->next_pc) == next, "independent next-PC oracle");
    require(summary->accesses.size() == accesses.size(), "exact ordered access count");
    for (size_t i = 0; i < accesses.size(); ++i)
    {
        const auto &actual = summary->accesses[i];
        const auto &expected = accesses[i];
        require(actual.write == expected.write && actual.bits == expected.bits &&
                    actual.site == expected.site &&
                    number(model, actual.address) == expected.address &&
                    number(model, actual.value) == expected.value,
                "independent ordered access and provenance oracle");
    }
    auto expected_memory = z3::const_array(ctx.bv_sort(c.mode), ctx.bv_val(0, 8));
    for (const auto &entry : memory)
        expected_memory = z3::store(expected_memory, ctx.bv_val(entry.first, c.mode),
                                    ctx.bv_val(entry.second, 8));
    solver.push();
    solver.add(summary->memory != expected_memory);
    require(solver.check() == z3::unsat, "complete final memory agrees, including aliased writes");
    solver.pop();
    const auto expected_flags = flags(final_op, final_bits, final_a, final_b);
    for (unsigned i = 0; i < expected_flags.size(); ++i)
    {
        const bool defined = i != 2 || final_op != Op::bit_xor;
        require(summary->defined[i] == defined, "independent final flag definedness");
        if (defined)
            require(model.eval(summary->flags[i], true).is_true() == expected_flags[i],
                    "independent final flag value");
    }
    if (alias & 1)
        require(accesses.front().site == candidate.payload_read && memory.count(dispatch_at) != 0,
                "payload overwrite followed by dispatch read retained");
    if (c.guarded && alias == 0)
    {
        using namespace chernobog;
        hybrid::StatePoint entry, output;
        entry.pc = candidate.start;
        entry.source = 0x800;
        entry.sequence = 1;
        entry.run_id = 2;
        entry.seed = 19;
        output = entry;
        output.pc = next;
        output.source = candidate.dispatch;
        output.sequence = 1000;
        for (size_t i = 0; i < registers.size(); ++i)
        {
            const int id = c.mode == 64 ? RAX_X86_GPR64(i) : RAX_X86_GPR32(i);
            entry.regs.push_back({id, inputs[i], uint8_t(c.mode / 8)});
            output.regs.push_back({id, registers[i], uint8_t(c.mode / 8)});
        }
        const int flags_id = c.mode == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS;
        uint64_t output_flags = 2;
        const unsigned flag_bits[] = {0, 2, 4, 6, 7, 11};
        for (unsigned i = 0; i < expected_flags.size(); ++i)
            if (expected_flags[i])
                output_flags |= uint64_t{1} << flag_bits[i];
        entry.regs.push_back({flags_id, 0x202, uint8_t(c.mode / 8)});
        output.regs.push_back({flags_id, output_flags, uint8_t(c.mode / 8)});
        std::vector<hybrid::DataAcc> observed;
        for (size_t i = 0; i < accesses.size(); ++i)
        {
            const auto &access = accesses[i];
            observed.push_back({access.site, access.address, access.value, access.bits / 8,
                                access.write ? RAX_MEM_WRITE : RAX_MEM_READ,
                                hybrid::DataScope::OTHER, 10 + i, 2, 19});
        }
        auto transition = check_transition(candidate, entry, output, observed, 1000, 2000000);
        require(transition.result == TransitionResult::corroborated && transition.queries == 2,
                "independent observed fast-path transition corroborated");
        output.regs[c.guard_value].value ^= 1;
        require(check_transition(candidate, entry, output, observed, 1000, 2000000).result ==
                    TransitionResult::different,
                "guard scratch output remains observable");
        output.regs[c.guard_value].value ^= 1;
        if (c.relative)
        {
            output.regs.back().value ^= uint64_t{1} << 6;
            require(check_transition(candidate, entry, output, observed, 1000, 2000000).result ==
                        TransitionResult::different,
                    "advanced guard final CMP flags remain observable");
            output.regs.back().value ^= uint64_t{1} << 6;
        }
        for (unsigned below = 0; below < 2; ++below)
        {
            auto outside = entry;
            outside.regs[c.virtual_stack].value =
                (inputs[4] + c.guard_offset + slot - below) & mask(c.mode);
            transition = check_transition(candidate, outside, output, observed, 1000, 2000000);
            require(transition.result == TransitionResult::inconsistent && transition.queries == 1,
                    "equality and below-threshold inputs cannot corroborate the taken fast path");
        }
    }
    ++concrete_cases;
}
void negatives(const Fixture &fixture)
{
    using namespace vm_test;
    const auto &c = fixture.config;
    auto reject = [&](std::vector<Instruction> code, const char *label)
    {
        require(!recognize(code, c.mode), label);
        Candidate forged;
        forged.address_bits = c.mode;
        forged.support = std::move(code);
        z3::context ctx;
        require(!summarize(ctx, forged), "re-recognition rejects malformed summary support");
    };
    for (size_t i = 1; i < fixture.code.size(); ++i)
    {
        auto bad = fixture.code;
        bad[i].alternate_entry = true;
        reject(std::move(bad), "interior alternate entry rejected");
    }
    for (unsigned change = 0; change < 20; ++change)
    {
        auto bad = fixture.code;
        auto &read = bad[fixture.payload.read], &stride = bad[fixture.payload.stride];
        auto &adjust = bad[fixture.stack_adjust], &store = bad[fixture.store];
        switch (change)
        {
        case 0:
            read.src.bits = 24;
            break;
        case 1:
            read.dst.bits = 16;
            break;
        case 2:
            read.src.address_bits = 16;
            break;
        case 3:
            read.src.index = c.value;
            break;
        case 4:
            read.src.value = 1;
            break;
        case 5:
            ++stride.src.value;
            break;
        case 6:
            stride.dst.bits = 16;
            break;
        case 7:
            ++adjust.src.value;
            break;
        case 8:
            adjust.op = Op::add;
            break;
        case 9:
            adjust.dst.bits = 16;
            break;
        case 10:
            store.dst.bits = 8;
            break;
        case 11:
            store.src.bits = 8;
            break;
        case 12:
            store.dst.value = 1;
            break;
        case 13:
            store.dst.index = c.value;
            break;
        case 14:
            store.dst.address_bits = 16;
            break;
        case 15:
            store.src.reg = c.vip;
            break;
        case 16:
            bad[fixture.dispatch.stride].op = c.backward ? Op::add : Op::sub;
            break;
        case 17:
            bad[fixture.dispatch.read].src.base = c.virtual_stack;
            break;
        case 18:
            store.op = Op::bit_xor;
            break;
        case 19:
            store.dst.base = 4;
            break;
        }
        reject(std::move(bad), "malformed width, stride, store or direction rejected");
    }
    for (int alias : {c.vip, c.value, c.key, c.base, c.payload_value, 4})
    {
        if (alias == c.base && !c.relative && c.mode == 32)
            continue;
        if (alias == c.key && !c.keys)
            continue;
        auto bad = fixture.code;
        bad[fixture.stack_adjust].dst.reg = alias;
        bad[fixture.store].dst.base = alias;
        reject(std::move(bad), "virtual stack cannot alias logical registers or native SP");
    }
    if ((c.keys & 3) == 3)
    {
        auto bad = fixture.code;
        // Keep each stage internally well formed, but give the dispatch an
        // otherwise unused key register. A suffix-only check cannot reject this.
        const int separate_key = 1;
        bad[fixture.dispatch.mix].src.reg = separate_key;
        if (fixture.dispatch.push != SIZE_MAX)
        {
            bad[fixture.dispatch.push].dst.reg = separate_key;
            bad[fixture.dispatch.pop].dst.reg = separate_key;
        }
        else
            bad[fixture.dispatch.feedback].dst.reg = separate_key;
        reject(std::move(bad), "separate dispatch key violates shared key role");
    }
}
void comparisons(Config c)
{
    const auto original = make(c);
    const bool guard_value_alias = c.guard_value == original.config.value;
    const bool guard_payload_alias = c.guard_value == original.config.payload_value;
    c.vip = 5;
    c.value = 2;
    c.key = 1;
    c.base = 6;
    c.virtual_stack = 7;
    c.payload_value = 0;
    c.guard_value = guard_value_alias ? c.value : guard_payload_alias ? c.payload_value : 3;
    auto renamed = make(c);
    for (auto &instruction : renamed.code)
    {
        instruction.address += 0x20000;
        if (instruction.op == Op::direct_jump || instruction.op == Op::jump_above)
            instruction.dst.value += 0x20000;
    }
    const auto a = recognized(original), b = recognized(renamed);
    require(normalized_shape(a) == normalized_shape(b), "full handler shape role normalization");
    z3::context ctx;
    auto sa = summarize(ctx, a), sb = summarize(ctx, b);
    require(bool(sa) && bool(sb), "role-renamed summaries built");
    require(compare(*sa, *sb, 1000, 2000000).result == Equivalence::equivalent,
            "role-renamed full memory effects equivalent");
    if (c.guarded)
    {
        auto changed = original;
        changed.config.guard_offset = c.mode == 64 ? 320 : 128;
        changed.code[changed.guard_address].src.value = changed.config.guard_offset;
        auto sc = summarize(ctx, recognized(changed));
        require(bool(sc) && compare(*sa, *sc, 1000, 2000000).result == Equivalence::different,
                "different stack-check domains cannot share a semantic summary");
    }
    if (original.config.keys & 1)
    {
        auto changed = original;
        ++changed.code[changed.payload.constant].src.value;
        const auto different = recognized(changed);
        auto sc = summarize(ctx, different);
        require(bool(sc), "changed payload remains valid handler");
        require(compare(*sa, *sc, 1000, 2000000).result == Equivalence::different,
                "changed pushed payload rejected by semantic equivalence");
    }
    auto forged = a;
    forged.payload_read = bad_address;
    forged.payload_bits = 8;
    forged.stored_bits = 64;
    forged.virtual_stack = 4;
    forged.payload_value = forged.vip;
    auto repaired = summarize(ctx, forged);
    require(bool(repaired) && repaired->candidate.payload_read == a.payload_read &&
                repaired->candidate.payload_bits == a.payload_bits &&
                repaired->candidate.stored_bits == a.stored_bits &&
                repaired->candidate.virtual_stack == a.virtual_stack &&
                repaired->candidate.payload_value == a.payload_value &&
                compare(*sa, *repaired).result == Equivalence::equivalent,
            "summary derives roles and widths from support rather than caller metadata");
}
void relayout(std::vector<Instruction> &code)
{
    std::map<uint64_t, uint64_t> relocated;
    uint64_t address = 0x1000;
    for (auto &instruction : code)
    {
        if (instruction.address != bad_address)
            require(relocated.emplace(instruction.address, address).second,
                    "test support addresses unique before relocation");
        instruction.address = address;
        address += instruction.size;
        if (instruction.op == Op::direct_jump || instruction.op == Op::jump_above)
            address += 0x100;
    }
    for (auto &instruction : code)
        if (instruction.op == Op::direct_jump || instruction.op == Op::jump_above)
            instruction.dst.value = relocated.at(instruction.dst.value);
}
void guarded_controls(Config c)
{
    const auto fixture = make(c);
    c = fixture.config;
    const auto candidate = recognized(fixture);
    z3::context ctx;
    const auto summary = summarize(ctx, candidate);
    require(bool(summary), "guarded domain model available");
    const auto stack = ctx.bv_const("input_virtual_stack", c.mode);
    const auto native_stack = ctx.bv_const("input_sp", c.mode);
    const auto slot = std::max(2u, c.payload_bits / 8);
    for (uint64_t sp : {uint64_t{0x1000}, mask(c.mode) - c.guard_offset / 2})
        for (int delta : {-1, 0, 1})
        {
            const auto boundary = (sp + c.guard_offset) & mask(c.mode);
            z3::solver solver(ctx);
            solver.add(native_stack == ctx.bv_val(sp, c.mode));
            solver.add(stack == ctx.bv_val((boundary + slot + delta) & mask(c.mode), c.mode));
            solver.add(summary->domain != ctx.bool_val(delta > 0));
            require(solver.check() == z3::unsat,
                    "strict unsigned JA domain below/equal/above with modular LEA");
        }
    for (unsigned change = 0; change < 12; ++change)
    {
        auto bad = fixture.code;
        auto &address = bad[fixture.guard_address], &comparison = bad[fixture.guard_compare];
        auto &branch = bad[fixture.guard_branch];
        switch (change)
        {
        case 0:
            address.src.value = c.mode == 64 ? 128 : 256;
            break;
        case 1:
            address.src.base = c.virtual_stack;
            break;
        case 2:
            address.src.index = c.value;
            break;
        case 3:
            address.dst.bits = 16;
            break;
        case 4:
            comparison.op = Op::test;
            break;
        case 5:
            std::swap(comparison.dst, comparison.src);
            break;
        case 6:
            branch.op = Op::direct_jump;
            break;
        case 7:
            branch.dst.value = branch.address + branch.size;
            break;
        case 8:
            branch.dst.bits = 16;
            break;
        case 9:
            address.dst.reg = c.vip;
            comparison.src.reg = c.vip;
            break;
        case 10:
            address.dst.reg = 4;
            comparison.src.reg = 4;
            break;
        case 11:
            // The observed continuation takes fallthrough into the relocation
            // arm instead of the modeled JA target. Do not summarize it as fast.
            bad[fixture.guard_branch + 1].address = branch.address + branch.size;
            bad[fixture.guard_branch + 1].op = Op::unsupported;
            break;
        }
        require(!recognize(bad, c.mode), "malformed guard or slow relocation path rejected");
    }
    // A complete source-sized pair of cryptors exceeds the old 128-instruction
    // dispatch-only budget. This remains grammar coverage, not source attestation.
    std::vector<Instruction> expanded;
    for (size_t index = 0; index < fixture.code.size(); ++index)
    {
        expanded.push_back(fixture.code[index]);
        if (index == fixture.payload.mix + 1 || index == fixture.dispatch.mix + 1)
            for (unsigned repeat = 0; repeat < 99; ++repeat)
            {
                auto transform = fixture.code[index];
                transform.address = bad_address;
                expanded.push_back(transform);
            }
    }
    require(expanded.size() > 128 && expanded.size() < 256,
            "two 101-transform cryptors fit the complete-handler budget");
    relayout(expanded);
    auto bounded = recognize(expanded, c.mode);
    require(bool(bounded) && bounded->support.size() == expanded.size() &&
                bool(summarize(ctx, *bounded)),
            "both 101-transform cryptors retained in complete semantic support");
    auto padding = fixture.code[fixture.payload.mix + 1];
    padding.address = bad_address;
    while (expanded.size() < 256)
        expanded.insert(expanded.begin() + fixture.payload.mix + 2, padding);
    relayout(expanded);
    bounded = recognize(expanded, c.mode);
    require(bool(bounded) && bounded->support.size() == 256,
            "exact complete-handler instruction budget admitted");
    expanded.insert(expanded.begin() + fixture.payload.mix + 2, padding);
    relayout(expanded);
    require(!recognize(expanded, c.mode), "complete-handler instruction overflow rejected");
}
} // namespace
int main()
{
    for (unsigned mode : {32u, 64u})
        for (unsigned payload_bits : {8u, 16u, 32u, 64u})
        {
            if (payload_bits > mode)
                continue;
            for (bool backward : {false, true})
                for (bool relative : {false, true})
                    for (unsigned keys = 0; keys < 4; ++keys)
                        for (bool shared : {false, true})
                        {
                            Config c;
                            c.mode = mode;
                            c.payload_bits = payload_bits;
                            c.backward = backward;
                            c.relative = relative;
                            c.keys = keys;
                            c.shared_value = shared;
                            scenario = "mode=" + std::to_string(mode) +
                                       ";payload=" + std::to_string(payload_bits) +
                                       ";back=" + std::to_string(backward) +
                                       ";relative=" + std::to_string(relative) +
                                       ";keys=" + std::to_string(keys) +
                                       ";shared=" + std::to_string(shared);
                            const auto fixture = make(c);
                            for (unsigned alias = 0; alias < 4; ++alias)
                                concrete(fixture, alias, (keys + alias) % 3);
                            if (!shared && keys == 3)
                                negatives(fixture);
                            if (keys == 1 || keys == 3)
                                comparisons(c);
                        }
        }
    for (Op payload_mix : {Op::bit_xor, Op::add, Op::sub})
        for (Op dispatch_mix : {Op::bit_xor, Op::add, Op::sub})
            for (unsigned payload_bits : {8u, 16u, 32u, 64u})
            {
                Config c;
                c.payload_bits = payload_bits;
                c.payload_mix = payload_mix;
                c.dispatch_mix = dispatch_mix;
                scenario = "independent arithmetic mixes;payload=" + std::to_string(payload_bits) +
                           ";mix=" + std::to_string(unsigned(payload_mix)) + "," +
                           std::to_string(unsigned(dispatch_mix));
                for (unsigned vector = 0; vector < 3; ++vector)
                    concrete(make(c), 3, vector);
            }
    for (unsigned mode : {32u, 64u})
        for (unsigned payload_bits : {8u, 16u, 32u, 64u})
        {
            if (payload_bits > mode)
                continue;
            for (bool backward : {false, true})
                for (bool relative : {false, true})
                    for (unsigned scratch = 0; scratch < 4; ++scratch)
                    {
                        Config c;
                        c.mode = mode;
                        c.payload_bits = payload_bits;
                        c.backward = backward;
                        c.relative = relative;
                        c.guarded = true;
                        c.shared_value = scratch == 3;
                        if (scratch == 1 || scratch == 3)
                            c.guard_value = c.value;
                        else if (scratch == 2)
                            c.guard_value = c.payload_value;
                        scenario =
                            "observed source fast-path grammar;mode=" + std::to_string(mode) +
                            ";payload=" + std::to_string(payload_bits) +
                            ";back=" + std::to_string(backward) +
                            ";advanced=" + std::to_string(relative) +
                            ";scratch=" + std::to_string(scratch);
                        for (unsigned alias = 0; alias < 3; ++alias)
                            concrete(make(c), alias, alias);
                        comparisons(c);
                        if (scratch == 0)
                            guarded_controls(c);
                    }
        }
    std::cout << "VM push-handler checks=" << checks << "; concrete cases=" << concrete_cases
              << '\n';
}
