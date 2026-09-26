#include "vm_test_candidates.hpp"
#include "vm/native_observations.hpp"
#include "common/solver_evidence.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <set>
#include <sstream>
#include <stdexcept>

using namespace chernobog;
namespace
{
unsigned checks = 0;
std::string last_projection;
void check(bool value, const char *name)
{
    ++checks;
    if (!value)
        throw std::runtime_error(name);
}
uint64_t add_flags(uint64_t before)
{
    const uint64_t after = before + 1;
    unsigned parity = 0;
    for (unsigned bit = 0; bit < 8; ++bit)
        parity += unsigned((after >> bit) & 1);
    return 0x202 | (parity % 2 == 0 ? 4 : 0) | ((before ^ 1 ^ after) & 16);
}
struct Fixture
{
    hybrid::ProgramImage image;
    vm::NativeRegion region;
    std::map<uint64_t, vm::Instruction> instructions;
    hybrid::EmuEvents events;
    hybrid::EmuOutcome outcome;
};
Fixture fixture(unsigned mode, bool split = false, unsigned repeats = 1)
{
    using namespace hybrid;
    using namespace vm;
    Fixture f;
    auto candidate = vm_test::candidate(mode, false, false, false);
    if (split)
    {
        auto code = candidate.support;
        auto target = vm_test::imm(0x1200);
        target.bits = mode;
        code.insert(code.begin() + 1, {0x1004, 4, Op::direct_jump, target, {}});
        code[2].address = 0x1200;
        code[3].address = 0x1204;
        candidate = *recognize(code, mode);
    }
    f.image.arch = mode == 64 ? HybridArch::X86_64 : HybridArch::X86_32;
    f.image.lo = 0x1000;
    f.image.hi = 0x4000;
    f.image.generation = 9;
    SegImage segment;
    segment.start = 0x1000;
    segment.end = 0x4000;
    segment.bitness = mode == 64 ? 2 : 1;
    segment.perm = uint32_t(HybridSegPerm::READ) | uint32_t(HybridSegPerm::EXEC);
    segment.bytes.assign(0x3000, 0x90);
    segment.mask.assign(0x600, 0xff);
    f.image.segs.push_back(segment);
    for (const auto &i : candidate.support)
        f.instructions.emplace(i.address, i);
    const NativeDecoder decoder = [&](uint64_t ea, const uint8_t *, size_t, rax_decoded &out)
    {
        const auto found = f.instructions.find(ea);
        if (found == f.instructions.end())
            return false;
        out = {};
        out.valid = 1;
        out.size = 4;
        out.flow = found->second.op == Op::jump          ? RAX_FLOW_INDIRECT_JUMP
                   : found->second.op == Op::direct_jump ? RAX_FLOW_BRANCH
                                                         : RAX_FLOW_FALLTHROUGH;
        if (found->second.op == Op::direct_jump)
        {
            out.has_target = 1;
            out.target = found->second.dst.value;
        }
        return true;
    };
    f.region = plan_native_region(f.image, nullptr, 0x1000, 4096, decoder);
    StatePoint state;
    state.kind = StatePoint::Kind::NativeInstructionEntry;
    state.run_id = 2;
    state.seed = 19;
    for (int i = 0; i < (mode == 64 ? 16 : 8); ++i)
        state.regs.push_back({mode == 64 ? RAX_X86_GPR64(i) : RAX_X86_GPR32(i), uint64_t(0x100 + i),
                              uint8_t(mode / 8)});
    state.regs[6].value = 0x2000;
    state.regs[7].value = 0x3000;
    state.regs[4].value = 0x8000;
    state.regs.push_back(
        {mode == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS, 0x202, uint8_t(mode / 8)});
    uint64_t sequence = 0;
    for (unsigned visit = 0; visit < repeats; ++visit)
    {
        for (const auto &i : candidate.support)
        {
            state.pc = i.address;
            state.sequence = sequence;
            f.events.states.push_back(state);
            f.events.execution.push_back({i.address, 4, sequence, 2, 19});
            if (i.op == Op::load)
            {
                f.events.data.push_back({i.address, state.regs[6].value, 2, 1, RAX_MEM_READ,
                                         DataScope::IMAGE, sequence + 1, 2, 19});
                state.regs[0].value = 2;
            }
            if (i.op == Op::add)
            {
                state.regs.back().value = add_flags(state.regs[6].value);
                ++state.regs[6].value;
            }
            if (i.op == Op::direct_jump)
            {
                auto output = state;
                output.kind = StatePoint::Kind::TransferTarget;
                output.pc = i.dst.value;
                output.source = i.address;
                output.sequence = sequence + 10;
                f.events.states.push_back(output);
                f.events.edges.push_back(
                    {i.address, i.dst.value, 2, 19, ExecEdge::Kind::Jump, sequence + 10});
            }
            if (i.op == Op::jump)
            {
                const uint64_t target = visit + 1 < repeats ? candidate.start : 0x1800;
                f.events.data.push_back({i.address, (mode == 64 ? 0x3000 : 0) + 2 * (mode / 8),
                                         target, mode / 8, RAX_MEM_READ, DataScope::IMAGE,
                                         sequence + 1, 2, 19});
                auto output = state;
                output.kind = StatePoint::Kind::TransferTarget;
                output.pc = target;
                output.source = i.address;
                output.sequence = sequence + 10;
                f.events.states.push_back(output);
                f.events.edges.push_back(
                    {i.address, target, 2, 19, ExecEdge::Kind::Jump, sequence + 10});
            }
            sequence += 10;
        }
    }
    f.outcome.native_region = true;
    f.outcome.region_identity = f.region.identity();
    f.outcome.stop_valid = true;
    f.outcome.data_trace_complete = true;
    f.outcome.native_state_capture_requested = true;
    f.outcome.native_state_capture_complete = true;
    return f;
}
uint64_t arithmetic_flags(uint64_t a, uint64_t b, unsigned bits, bool subtract)
{
    const auto mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
    a &= mask;
    b &= mask;
    const auto result = (subtract ? a - b : a + b) & mask;
    const auto sign = uint64_t{1} << (bits - 1);
    uint64_t flags = 0x202 | ((subtract ? a < b : result < a) ? 1 : 0);
    unsigned parity = 0;
    for (unsigned bit = 0; bit < 8; ++bit)
        parity += unsigned((result >> bit) & 1);
    if (parity % 2 == 0)
        flags |= 4;
    if ((a ^ b ^ result) & 16)
        flags |= 16;
    if (!result)
        flags |= 64;
    if (result & sign)
        flags |= 128;
    if (((subtract ? a ^ b : ~(a ^ b)) & (a ^ result)) & sign)
        flags |= 2048;
    return flags;
}
Fixture guarded_fixture(unsigned mode, bool relative, bool backward, bool equality = false)
{
    using namespace hybrid;
    using namespace vm;
    using namespace vm_test;
    auto f = fixture(mode);
    f.instructions.clear();
    f.events = {};
    std::vector<Instruction> code;
    auto add = [&](Op op, Operand dst, Operand src = Operand{})
    { code.push_back({0, 4, op, dst, src, false}); };
    if (backward)
        add(Op::sub, reg(6, mode), imm(1));
    add(Op::load, reg(0, 32), mem(6, 8, mode));
    if (!backward)
        add(Op::add, reg(6, mode), imm(1));
    add(Op::sub, reg(5, mode), imm(2));
    add(Op::load, mem(5, 16, mode), reg(0, 16));
    size_t direct = 0, branch = 0;
    auto guard = [&]()
    {
        auto target = imm(0);
        target.bits = mode;
        direct = code.size();
        add(Op::direct_jump, target);
        auto limit = mem(4, mode, mode);
        limit.value = mode == 64 ? 256 : 96;
        add(Op::address, reg(1, mode), limit);
        add(Op::compare, reg(5, mode), reg(1, mode));
        branch = code.size();
        add(Op::jump_above, target);
    };
    const auto suffix = vm_test::candidate(mode, backward, relative, false).support;
    if (!relative)
        guard();
    code.insert(code.end(), suffix.begin(), suffix.end() - 1);
    if (relative)
        guard();
    code.push_back(suffix.back());
    for (size_t index = 0; index < code.size(); ++index)
        code[index].address =
            0x1000 + index * 4 + (index > direct ? 0x100 : 0) + (index > branch ? 0x100 : 0);
    code[direct].dst.value = code[direct + 1].address;
    code[branch].dst.value = code[branch + 1].address;
    const auto candidate = recognize(code, mode);
    check(bool(candidate) && candidate->stack_check && candidate->payload_bits == 8,
          "guarded native fixture recognized");
    for (const auto &instruction : code)
        f.instructions.emplace(instruction.address, instruction);
    const NativeDecoder decoder = [&](uint64_t pc, const uint8_t *, size_t, rax_decoded &out)
    {
        const auto found = f.instructions.find(pc);
        if (found == f.instructions.end())
            return false;
        out = {};
        out.valid = 1;
        out.size = 4;
        const auto op = found->second.op;
        out.flow = op == Op::jump          ? RAX_FLOW_INDIRECT_JUMP
                   : op == Op::direct_jump ? RAX_FLOW_BRANCH
                   : op == Op::jump_above  ? RAX_FLOW_COND_BRANCH
                                           : RAX_FLOW_FALLTHROUGH;
        if (op == Op::direct_jump || op == Op::jump_above)
        {
            out.has_target = 1;
            out.target = found->second.dst.value;
        }
        return true;
    };
    f.region = plan_native_region(f.image, nullptr, 0x1000, 4096, decoder);
    check(f.region.available() && f.region.heads().size() == code.size(),
          "guarded native plan admits the complete taken path");
    StatePoint state;
    state.kind = StatePoint::Kind::NativeInstructionEntry;
    state.run_id = 2;
    state.seed = 19;
    for (int index = 0; index < (mode == 64 ? 16 : 8); ++index)
        state.regs.push_back({mode == 64 ? RAX_X86_GPR64(index) : RAX_X86_GPR32(index),
                              uint64_t(0x100 + index), uint8_t(mode / 8)});
    const uint64_t mask = mode == 64 ? UINT64_MAX : UINT32_MAX;
    const uint64_t dispatch_bytes = relative ? 4 : 1;
    const uint64_t payload_at = 0x2000 + (backward ? dispatch_bytes : 0);
    const uint64_t dispatch_at = 0x2000 + (backward ? 0 : 1);
    state.regs[6].value = backward ? payload_at + 1 : payload_at;
    state.regs[4].value = 0x3000;
    state.regs[5].value = equality ? 0x3000 + candidate->stack_check_offset + 2 : 0x5000;
    state.regs[7].value = 0x9000;
    state.regs[0].value = 0xabc;
    state.regs[1].value = 0x123;
    state.regs.push_back(
        {mode == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS, 0x202, uint8_t(mode / 8)});
    // Concrete instruction effects are computed independently of summarize().
    // The equality fixture intentionally records a contradictory taken JA.
    for (size_t index = 0; index < code.size(); ++index)
    {
        const auto &instruction = code[index];
        const uint64_t sequence = index * 10;
        state.pc = instruction.address;
        state.sequence = sequence;
        f.events.states.push_back(state);
        f.events.execution.push_back({instruction.address, 4, sequence, 2, 19});
        if (instruction.op == Op::load && instruction.dst.kind == Kind::reg)
        {
            const auto address = state.regs[instruction.src.base].value;
            check(address == payload_at || address == dispatch_at,
                  "independent guarded read belongs to selected bytecode");
            const uint64_t value = address == payload_at ? 0x5a : 3;
            state.regs[instruction.dst.reg].value = value;
            f.events.data.push_back({instruction.address, address, value, instruction.src.bits / 8,
                                     RAX_MEM_READ, DataScope::IMAGE, sequence + 1, 2, 19});
        }
        else if (instruction.op == Op::load)
        {
            f.events.data.push_back({instruction.address, state.regs[instruction.dst.base].value,
                                     state.regs[instruction.src.reg].value & 0xffff, 2,
                                     RAX_MEM_WRITE, DataScope::STACK, sequence + 1, 2, 19});
        }
        else if (instruction.op == Op::add || instruction.op == Op::sub)
        {
            auto &value = state.regs[instruction.dst.reg].value;
            const auto source = instruction.src.kind == Kind::immediate
                                    ? instruction.src.value
                                    : state.regs[instruction.src.reg].value;
            const bool subtract = instruction.op == Op::sub;
            state.regs.back().value = arithmetic_flags(value, source, mode, subtract);
            value = (subtract ? value - source : value + source) & mask;
        }
        else if (instruction.op == Op::address)
            state.regs[instruction.dst.reg].value =
                (state.regs[4].value + instruction.src.value) & mask;
        else if (instruction.op == Op::compare)
            state.regs.back().value =
                arithmetic_flags(state.regs[instruction.dst.reg].value,
                                 state.regs[instruction.src.reg].value, mode, true);
        else if (instruction.op == Op::sign_extend)
        {
            check(state.regs[instruction.src.reg].value == 3,
                  "independent positive relative displacement");
        }
        if (instruction.op == Op::direct_jump || instruction.op == Op::jump_above ||
            instruction.op == Op::jump)
        {
            uint64_t target = instruction.dst.value;
            if (instruction.op == Op::jump)
            {
                target = relative ? state.regs[7].value : 0xa000;
                if (!relative)
                    f.events.data.push_back(
                        {instruction.address, (mode == 64 ? 0x9000 : 0) + 3 * (mode / 8), target,
                         mode / 8, RAX_MEM_READ, DataScope::IMAGE, sequence + 1, 2, 19});
            }
            auto output = state;
            output.kind = StatePoint::Kind::TransferTarget;
            output.source = instruction.address;
            output.pc = target;
            output.sequence = sequence + 10;
            f.events.states.push_back(output);
            f.events.edges.push_back(
                {instruction.address, target, 2, 19, ExecEdge::Kind::Jump, sequence + 10});
        }
        state.source = instruction.address;
    }
    f.outcome.region_identity = f.region.identity();
    return f;
}
vm::NativeObservationView project(const Fixture &f, bool validate = true, uint64_t capture = 7)
{
    const auto started = std::chrono::steady_clock::now();
    auto view = vm::project_native_observations(f.region, f.instructions, f.events, f.outcome,
                                                f.region.address_bits(), capture, 0x1000, validate);
    const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - started);
    std::ostringstream detail;
    detail << "last projection: mode=" << f.region.address_bits() << "; capture=" << capture
           << "; validate=" << validate << "; instructions=" << f.instructions.size()
           << "; entered=" << f.events.execution.size() << "; elapsed_us=" << elapsed.count()
           << "; available=" << view.available << "; records=" << view.records.size()
           << "; visits=" << view.candidate_visits << "; omitted=" << view.omitted
           << "; attempts=" << view.transition_attempts << "; queries=" << view.queries
           << "; reason=" << view.reason << '\n';
    for (const auto &row : view.records)
    {
        for (const char *key : {"vm_state", "transition_check", "transition_queries",
                                "semantic_validation", "transition_reason"})
            if (const auto found = row.find(key); found != row.end())
                detail << key << '=' << found->second << "; ";
        detail << '\n';
    }
    last_projection = detail.str();
    return view;
}
const vm::ObservationView::Row *full_push_row(const vm::NativeObservationView &view)
{
    for (const auto &row : view.records)
        if (row.at("site") == "0x1000" && row.at("payload_bits") == "8")
            return &row;
    return nullptr;
}
void guarded_controls(unsigned mode, bool relative, bool backward)
{
    using namespace hybrid;
    const auto fixture = guarded_fixture(mode, relative, backward);
    auto view = project(fixture);
    const auto *row = full_push_row(view);
    check(view.available && row &&
              row->at("semantic_validation") == "corroborated for captured transition" &&
              row->at("transition_queries") == "2" &&
              row->at("internal_transfers") == "exact captured witnesses" &&
              row->at("path") == "complete captured native path",
          "independent native guarded push transition corroborated");
    check(row->at("payload_value_register") == "0" && row->at("virtual_stack_register") == "5" &&
              row->at("stack_check_register") == "1" && row->at("stack_check") == "true" &&
              row->at("stored_bits") == "16" && row->at("payload_read") != row->at("read"),
          "native payload and guard metadata retained");
    check(row->at("entry_virtual_stack") == "0x5000" &&
              row->at("output_virtual_stack") == "0x4ffe" &&
              row->at("entry_payload_register") == "0xabc" &&
              row->at("output_payload_register") == "0x3" &&
              row->at("entry_stack_check_register") == "0x123" &&
              row->at("output_stack_check_register") == (mode == 64 ? "0x3100" : "0x3060"),
          "native payload, VSP and guard input/output snapshots retained");
    check(row->at("payload_register_scope").find("stored payload is the ordered store value") !=
                  std::string::npos &&
              fixture.events.data[1].kind == RAX_MEM_WRITE &&
              fixture.events.data[1].value == 0x5a && fixture.events.data[1].size == 2,
          "native final payload register is distinct from the stored payload");
    check(row->at("logical_state_complete") == "false" && row->at("memory_epoch") == "unknown" &&
              row->at("vm_context") == "unknown" && row->at("merge") == "not admitted",
          "native VSP hypothesis does not establish context or memory identity");
    auto unchecked = project(fixture, false);
    check(full_push_row(unchecked) && unchecked.queries == 0 && unchecked.transition_attempts == 0,
          "guarded native projection remains optionally solver-free");
    auto find = [&](const auto &items, auto predicate)
    {
        const auto found = std::find_if(items.begin(), items.end(), predicate);
        check(found != items.end(), "guarded native control witness exists");
        return size_t(found - items.begin());
    };
    const auto transfer =
        find(fixture.events.states,
             [&](const auto &state)
             {
                 return state.kind == StatePoint::Kind::TransferTarget &&
                        fixture.instructions.at(state.source).op == vm::Op::jump_above;
             });
    const auto sequence = fixture.events.states[transfer].sequence;
    const auto entered = find(fixture.events.states,
                              [&](const auto &state)
                              {
                                  return state.kind == StatePoint::Kind::NativeInstructionEntry &&
                                         state.sequence == sequence;
                              });
    const auto guard_edge =
        find(fixture.events.edges, [&](const auto &edge) { return edge.sequence == sequence; });
    const auto direct_transfer =
        find(fixture.events.states,
             [&](const auto &state)
             {
                 return state.kind == StatePoint::Kind::TransferTarget &&
                        fixture.instructions.at(state.source).op == vm::Op::direct_jump;
             });
    auto rejected = [&](const Fixture &bad)
    {
        const auto result = project(bad);
        const auto *full = full_push_row(result);
        check(!result.available ||
                  (full && full->at("internal_transfers") == "missing or inconsistent witness" &&
                   full->at("semantic_validation") == "transition not checked" &&
                   full->count("transition_queries") == 0 && full->count("transition_check") == 0),
              "corrupt intermediate native witness cannot corroborate the full handler");
    };
    for (unsigned change = 0; change < 25; ++change)
    {
        auto bad = fixture;
        auto &states = bad.events.states;
        auto &edges = bad.events.edges;
        switch (change)
        {
        case 0:
            states.erase(states.begin() + transfer);
            break;
        case 1:
            states.push_back(states[transfer]);
            break;
        case 2:
            ++states[transfer].source;
            break;
        case 3:
            ++states[transfer].pc;
            break;
        case 4:
            --states[transfer].sequence;
            break;
        case 5:
            ++states[transfer].run_id;
            break;
        case 6:
            ++states[transfer].seed;
            break;
        case 7:
            states[transfer].kind = StatePoint::Kind::NativeInstructionEntry;
            break;
        case 8:
            edges.erase(edges.begin() + guard_edge);
            break;
        case 9:
            edges.push_back(edges[guard_edge]);
            break;
        case 10:
            ++edges[guard_edge].from;
            break;
        case 11:
            ++edges[guard_edge].to;
            break;
        case 12:
            edges[guard_edge].kind = ExecEdge::Kind::Call;
            break;
        case 13:
            ++edges[guard_edge].run_id;
            break;
        case 14:
            ++edges[guard_edge].seed;
            break;
        case 15:
            --edges[guard_edge].sequence;
            break;
        case 16:
            states[transfer].regs.erase(states[transfer].regs.begin());
            break;
        case 17:
            states[transfer].regs[0].width = 2;
            break;
        case 18:
        {
            auto conflict = states[transfer].regs[0];
            ++conflict.value;
            states[transfer].regs.push_back(conflict);
            break;
        }
        case 19:
            states[transfer].regs.back().width = 2;
            break;
        case 20:
            states[entered].regs[0].value ^= 1;
            break;
        case 21:
            states.erase(states.begin() + direct_transfer);
            break;
        case 22:
            edges.front().kind = ExecEdge::Kind::Return;
            break;
        case 23:
        case 24:
        {
            const auto &next = bad.events.execution[1];
            auto unexpected =
                *std::find_if(states.begin(), states.end(),
                              [&](const auto &state)
                              {
                                  return state.kind == StatePoint::Kind::NativeInstructionEntry &&
                                         state.sequence == next.sequence;
                              });
            unexpected.kind = StatePoint::Kind::TransferTarget;
            unexpected.source = bad.events.execution[0].pc;
            if (change == 23)
                states.push_back(unexpected);
            edges.push_back(
                {unexpected.source, unexpected.pc, 2, 19, ExecEdge::Kind::Jump, next.sequence});
            std::sort(edges.begin(), edges.end(),
                      [](const auto &a, const auto &b) { return a.sequence < b.sequence; });
            break;
        }
        }
        rejected(bad);
    }
    for (size_t reg = 0; reg < fixture.events.states[transfer].regs.size(); ++reg)
    {
        auto bad = fixture;
        bad.events.states[transfer].regs[reg].value ^= 1;
        rejected(bad);
    }
    view = project(guarded_fixture(mode, relative, backward, true));
    row = full_push_row(view);
    check(view.available && row && row->at("path") == "complete captured native path" &&
              row->at("semantic_validation") == "inconsistent captured inputs" &&
              row->at("transition_queries") == "1",
          "native taken-JA equality contradiction rejected before output mismatch");
}
struct Collector : solver_evidence::Collector
{
    std::vector<solver_evidence::Origin> origins;
    bool accepts(const solver_evidence::Origin &) override { return true; }
    void publish(const solver_evidence::Origin &origin, solver_evidence::Row) override
    {
        origins.push_back(origin);
    }
};
void check_repeated_verdicts(const vm::NativeObservationView &view, size_t different = SIZE_MAX)
{
    size_t expected_queries = 0;
    for (size_t i = 0; i < view.records.size(); ++i)
    {
        const auto &row = view.records[i];
        if (i < 16)
        {
            const auto &verdict = row.at("semantic_validation");
            const bool completed =
                verdict == (i == different ? "modeled transition counterexample"
                                           : "corroborated for captured transition");
            // A bounded solver may abstain under load; the one-visit controls
            // separately require completed positive and counterexample results.
            const auto &reason = row.at("transition_reason");
            const bool bounded_unknown =
                verdict == "solver unresolved" && (reason == "canceled" || reason == "timeout" ||
                                                   reason == "max. resource limit reached");
            const auto &queries = row.at("transition_queries");
            check((completed && queries == "2" ||
                   bounded_unknown && (queries == "1" || queries == "2")) &&
                      !row.at("transition_check").empty(),
                  "each attempted visit retains its own semantic verdict");
            expected_queries += queries == "2" ? 2 : 1;
        }
        else
            check(row.at("semantic_validation") == "transition not checked" &&
                      row.at("transition_reason") == "transition attempt budget exhausted" &&
                      row.count("transition_queries") == 0 && row.count("transition_check") == 0,
                  "every over-budget visit remains unchecked");
    }
    check(view.queries == expected_queries, "native query total equals per-visit query counts");
}
}
int main()
{
    try
    {
        for (unsigned mode : {32u, 64u})
            for (bool relative : {false, true})
                for (bool backward : {false, true})
                    guarded_controls(mode, relative, backward);
        for (unsigned mode : {32u, 64u})
            for (bool split : {false, true})
            {
                auto f = fixture(mode, split);
                auto v = project(f);
                check(v.available && v.records.size() == 1 && v.transition_attempts == 1 &&
                          v.queries == 2 &&
                          v.records[0].at("semantic_validation") ==
                              "corroborated for captured transition",
                      "native captured table transition");
                check(v.records[0].at("virtual_stack") == "unknown" &&
                          v.records[0].at("vm_context") == "unknown" &&
                          v.records[0].at("memory_epoch") == "unknown" &&
                          v.records[0].at("merge") == "not admitted",
                      "partial VM state never promoted");
                check(project(f, false).queries == 0 && project(f, false).transition_attempts == 0,
                      "solver-free projection");
                check(!project(f, true, 0).available, "zero capture identity rejected");
                auto bad = f;
                bad.outcome.native_region = false;
                check(!project(bad).available, "ordinary outcome rejected");
                bad = f;
                ++bad.outcome.region_identity;
                check(!project(bad).available, "wrong region identity rejected");
                bad = f;
                bad.outcome.native_state_capture_complete = false;
                check(!project(bad).available, "incomplete native samples rejected");
                bad = f;
                bad.events.execution[1].sequence = 0;
                check(!project(bad).available, "duplicate execution sequence rejected");
                bad = f;
                bad.events.states.erase(bad.events.states.begin());
                check(!project(bad).available, "missing instruction sample rejected");
                bad = f;
                bad.events.states.push_back(bad.events.states.back());
                check(!project(bad).available, "duplicate output sample rejected");
                bad = f;
                ++bad.instructions.begin()->second.size;
                check(!project(bad).available, "semantic instruction size mismatch rejected");
                bad = f;
                bad.events.data[0].sequence = 0;
                check(!project(bad).available, "read before instruction rejected");
                bad = f;
                ++bad.events.data[0].from;
                check(!project(bad).available, "read source differs from entered instruction");
                bad = f;
                ++bad.events.states.back().regs[0].value;
                v = project(bad);
                check(v.records[0].at("semantic_validation") ==
                              "modeled transition counterexample" &&
                          v.queries == 2,
                      "corrupted final GPR produces counterexample");
                bad = f;
                bad.outcome.data_trace_complete = false;
                v = project(bad);
                check(v.queries == 0 && v.records[0].at("transition_reason") ==
                                            "complete direct data trace required",
                      "incomplete data vetoes check");
                bad = f;
                bad.events.data.insert(
                    bad.events.data.begin() + 1,
                    {0x1000, 0x1000, 0x90, 1, RAX_MEM_WRITE, hybrid::DataScope::IMAGE, 2, 2, 19});
                v = project(bad);
                check(v.queries == 0 &&
                          v.records[0].at("transition_reason") == "recorded candidate code write",
                      "code write vetoes check");
                bad = f;
                bad.events.data.resize(4097);
                check(!project(bad).available, "data input quota");
                check(!vm::project_native_observations(f.region, f.instructions, f.events,
                                                       f.outcome, mode == 32 ? 64 : 32, 7, 0x1000)
                           .available,
                      "mode bound to native plan");
                bad = f;
                ++bad.events.edges.back().to;
                v = project(bad);
                check(v.queries == 0 && v.records[0].at("transition_reason") ==
                                            "complete dispatch observation required",
                      "mismatched edge cannot support dispatch check");
                bad = f;
                bad.events.states.front().regs.clear();
                v = project(bad);
                check(v.records[0].at("semantic_validation") == "transition not checked" &&
                          v.queries == 0,
                      "missing entry register cannot corroborate");
                auto many = fixture(mode, split, 17);
                v = project(many);
                check(v.records.size() == 17 && v.transition_attempts == 16 && v.queries >= 16 &&
                          v.queries <= 32 &&
                          v.records.back().at("transition_reason") ==
                              "transition attempt budget exhausted",
                      "separate repeated visits and solver budget");
                check_repeated_verdicts(v);
                auto different = many;
                unsigned dispatch_visit = 0;
                for (auto &state : different.events.states)
                    if (state.kind == hybrid::StatePoint::Kind::TransferTarget &&
                        different.instructions.at(state.source).op == vm::Op::jump &&
                        dispatch_visit++ == 8)
                        state.regs[1].value ^= 1;
                const auto different_view = project(different);
                check(different_view.records.size() == 17 &&
                          different_view.transition_attempts == 16 &&
                          different_view.queries >= 16 && different_view.queries <= 32,
                      "one later counterexample preserves visit and query counts");
                check_repeated_verdicts(different_view, 8);
                std::set<std::string> identities;
                for (const auto &row : v.records)
                    identities.insert(row.at("vm_state"));
                check(identities.size() == 17,
                      "repeated native address retains distinct visit identity");
                Collector collector;
                solver_evidence::collector = &collector;
                v = project(f);
                solver_evidence::collector = nullptr;
                check(collector.origins.size() == 2 && collector.origins[0].capture_revision == 7 &&
                          std::string(collector.origins[0].phase) ==
                              "vm-native-observed-transition" &&
                          collector.origins[0].transition_check ==
                              collector.origins[1].transition_check,
                      "actual SMT queries retain native capture and check provenance");
            }
        {
            auto repeated = fixture(64, false, 130);
            auto view = project(repeated);
            check(view.records.size() == 128 && view.omitted == 2 && view.candidate_visits == 130 &&
                      view.transition_attempts == 16 && view.queries >= 16 && view.queries <= 32,
                  "native row and solver quotas remain separate");
            check_repeated_verdicts(view);
            auto dense = fixture(64);
            const auto sample = dense.events.states.front();
            dense.instructions.clear();
            dense.events = {};
            auto &segment = dense.image.segs[0];
            segment.end = 0x5000;
            segment.bytes.assign(0x4000, 0x90);
            segment.mask.assign(0x800, 0xff);
            dense.image.hi = 0x5000;
            for (uint64_t index = 0; index < 4096; ++index)
            {
                const uint64_t address = 0x1000 + 4 * index, sequence = 10 * index;
                dense.instructions.emplace(address, vm::Instruction{address, 4, vm::Op::load,
                                                                    vm_test::reg(0, 32),
                                                                    vm_test::mem(6, 8, 64)});
                dense.events.execution.push_back({address, 4, sequence, 2, 19});
                auto state = sample;
                state.pc = address;
                state.sequence = sequence;
                dense.events.states.push_back(state);
            }
            const vm::NativeDecoder decode =
                [](uint64_t, const uint8_t *, size_t count, rax_decoded &out)
            {
                if (count < 4)
                    return false;
                out = {};
                out.valid = 1;
                out.size = 4;
                out.flow = RAX_FLOW_FALLTHROUGH;
                return true;
            };
            dense.region = vm::plan_native_region(dense.image, nullptr, 0x1000, 4096, decode);
            dense.outcome.region_identity = dense.region.identity();
            view = project(dense);
            check(
                view.available && view.path_limited && view.path_steps == 8192 &&
                    view.path_length_stops == 32 && view.starts_examined == 33 &&
                    view.records.empty() && view.queries == 0,
                "native semantic scan reports exact global and local path exhaustion without a partial model");
        }
        std::cout << "native observation checks: " << checks << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "native observation failure at check " << checks << ": " << error.what()
                  << '\n'
                  << last_projection << '\n';
        return 1;
    }
}
