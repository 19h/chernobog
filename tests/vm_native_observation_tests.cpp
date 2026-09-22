#include "vm_test_candidates.hpp"
#include "vm/native_observations.hpp"
#include "common/solver_evidence.hpp"
#include <iostream>
#include <set>
#include <stdexcept>

using namespace chernobog;
namespace
{
unsigned checks = 0;
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
vm::NativeObservationView project(const Fixture &f, bool validate = true, uint64_t capture = 7)
{
    return vm::project_native_observations(f.region, f.instructions, f.events, f.outcome,
                                           f.region.address_bits(), capture, 0x1000, validate);
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
}
int main()
{
    try
    {
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
                check(v.records.size() == 17 && v.transition_attempts == 16 && v.queries == 32 &&
                          v.records.back().at("transition_reason") ==
                              "transition attempt budget exhausted",
                      "separate repeated visits and solver budget");
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
                      view.transition_attempts == 16 && view.queries == 32,
                  "native row and solver quotas remain separate");
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
                    view.path_length_stops == 64 && view.starts_examined == 65 &&
                    view.records.empty() && view.queries == 0,
                "native semantic scan reports exact global and local path exhaustion without a partial model");
        }
        std::cout << "native observation checks: " << checks << '\n';
        return 0;
    }
    catch (const std::exception &error)
    {
        std::cerr << "native observation failure: " << error.what() << '\n';
        return 1;
    }
}
