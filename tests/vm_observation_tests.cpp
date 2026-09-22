#include "vm_test_candidates.hpp"
#include "vm/observations.hpp"
#include "hybrid/evidence.hpp"
#include <algorithm>
#include <iostream>
#include <set>
#include <stdexcept>
using namespace chernobog;
namespace
{
unsigned checks = 0;
void check(bool condition, const char *name)
{
    ++checks;
    if (!condition)
        throw std::runtime_error(name);
}
hybrid::StatePoint state(const vm::Candidate &c, uint64_t seq, uint64_t vip)
{
    hybrid::StatePoint s;
    s.pc = c.start;
    s.source = 0x800;
    s.sequence = seq;
    s.run_id = 1;
    s.seed = 9;
    for (int i = 0; i < (c.address_bits == 64 ? 16 : 8); ++i)
        s.regs.push_back({c.address_bits == 64 ? RAX_X86_GPR64(i) : RAX_X86_GPR32(i),
                          i == c.vip ? vip : uint64_t(i), uint8_t(c.address_bits / 8)});
    s.regs.push_back({c.address_bits == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS, 0x202,
                      uint8_t(c.address_bits / 8)});
    return s;
}
hybrid::TargetEvidence fixture(const vm::Candidate &c)
{
    hybrid::TargetEvidence e;
    e.architecture = c.address_bits == 64 ? hybrid::HybridArch::X86_64 : hybrid::HybridArch::X86_32;
    e.scope.function_start = 0x800;
    e.scope.generation = 17;
    hybrid::RunObservation r;
    r.ran = true;
    r.provenance = e.scope;
    r.provenance.run_id = 1;
    r.provenance.seed = 9;
    e.runs.push_back(r);
    for (unsigned visit = 0; visit < 3; ++visit)
    {
        const uint64_t sequence = 10 + visit * 100;
        auto s = state(c, sequence, 0x2000 + visit);
        e.events.states.push_back(s);
        e.events.edges.push_back({s.source, s.pc, 1, 9, hybrid::ExecEdge::Kind::Jump, sequence});
        for (size_t j = 0; j < c.support.size(); ++j)
        {
            e.events.execution.push_back(
                {c.support[j].address, c.support[j].size, sequence + j * 2, 1, 9});
            if (j && c.support[j].address != c.support[j - 1].address + c.support[j - 1].size)
            {
                auto transfer = s;
                transfer.source = c.support[j - 1].address;
                transfer.pc = c.support[j].address;
                transfer.sequence = sequence + j * 2;
                e.events.states.push_back(transfer);
                e.events.edges.push_back({transfer.source, transfer.pc, 1, 9,
                                          hybrid::ExecEdge::Kind::Jump, transfer.sequence});
            }
        }
        s.source = c.dispatch;
        s.pc = 0x1800;
        s.sequence = sequence + 50;
        for (auto &reg : s.regs)
            if (reg.reg == RAX_X86_GPR64(c.vip) || reg.reg == RAX_X86_GPR32(c.vip))
                ++reg.value;
        e.events.states.push_back(s);
        e.events.edges.push_back(
            {s.source, s.pc, 1, 9,
             c.stack_dispatch ? hybrid::ExecEdge::Kind::Return : hybrid::ExecEdge::Kind::Jump,
             s.sequence});
        e.events.data.push_back({c.read, 0x2000 + visit, 0x25, 1, RAX_MEM_READ,
                                 hybrid::DataScope::IMAGE, sequence + 1, 1, 9});
    }
    return e;
}
vm::ObservationView project(const vm::Candidate &c, const hybrid::TargetEvidence &e)
{
    return vm::project_observations({c}, e, 0x800, 12, true);
}
vm::Candidate guarded_candidate(unsigned mode, bool relative, bool backward)
{
    using namespace vm;
    using namespace vm_test;
    std::vector<Instruction> code;
    size_t link = 0, branch = 0;
    auto add = [&](Op op, Operand dst, Operand src = Operand{})
    { code.push_back({0, 4, op, dst, src, false}); };
    auto read = [&](unsigned bits)
    {
        if (backward)
            add(Op::sub, reg(6, mode), imm(bits / 8));
        add(Op::load, reg(0, 32), mem(6, bits, mode));
        if (!backward)
            add(Op::add, reg(6, mode), imm(bits / 8));
    };
    auto guard = [&]()
    {
        auto target = imm(0);
        target.bits = mode;
        link = code.size();
        add(Op::direct_jump, target);
        auto limit = mem(4, mode, mode);
        limit.value = mode == 64 ? 256 : 96;
        add(Op::address, reg(1, mode), limit);
        add(Op::compare, reg(5, mode), reg(1, mode));
        branch = code.size();
        add(Op::jump_above, target);
    };
    read(8);
    add(Op::sub, reg(5, mode), imm(2));
    add(Op::load, mem(5, 16, mode), reg(0, 16));
    if (!relative)
        guard();
    read(relative ? 32 : 8);
    if (relative)
    {
        if (mode == 64)
            add(Op::sign_extend, reg(0, 64), reg(0, 32));
        add(Op::add, reg(7, mode), reg(0, mode));
        guard();
        add(Op::jump, reg(7, mode));
    }
    else
        add(Op::jump, mem(mode == 64 ? 7 : -1, mode, mode, 0, mode / 8));
    for (size_t i = 0; i < code.size(); ++i)
        code[i].address = 0x1000 + i * 4 + (i > link ? 0x100 : 0) + (i > branch ? 0x100 : 0);
    code[link].dst.value = code[link + 1].address;
    code[branch].dst.value = code[branch + 1].address;
    const auto candidate = recognize(code, mode);
    check(bool(candidate), "guarded observation fixture recognized");
    return *candidate;
}
uint64_t arithmetic_flags(uint64_t a, uint64_t b, unsigned bits, bool subtract)
{
    const auto mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
    a &= mask;
    b &= mask;
    const auto result = (subtract ? a - b : a + b) & mask;
    const auto sign = uint64_t{1} << (bits - 1);
    uint64_t flags = (subtract ? a < b : result < a) ? 1 : 0;
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
    return flags | 2;
}
hybrid::TargetEvidence guarded_fixture(const vm::Candidate &c)
{
    auto evidence = fixture(c);
    const bool backward = c.direction == vm::Direction::backward;
    const bool relative = c.dispatch_kind == vm::Dispatch::relative_register;
    auto &outcome = evidence.runs[0].outcome;
    outcome.data_trace_complete = true;
    outcome.memory_observation_available = true;
    evidence.events.data.clear();
    for (unsigned visit = 0; visit < 3; ++visit)
    {
        const uint64_t sequence = 10 + visit * 100, data = 0x2000 + visit * 0x100;
        const uint64_t dispatch_bytes = c.read_bits / 8;
        const uint64_t vip = backward ? data + 1 + dispatch_bytes : data;
        const uint64_t virtual_stack = 0x5000 + visit * 0x10, native_stack = 0x3000;
        const uint64_t base = 0x9000, decoded = 3, payload = 0x5a + visit;
        const uint64_t limit = native_stack + c.stack_check_offset;
        const uint64_t after_payload = backward ? vip - 1 : vip + 1;
        const uint64_t after_dispatch = backward ? data : vip + 1 + dispatch_bytes;
        const uint64_t target = relative ? base + decoded : 0xa000 + visit * 0x100;
        const uint64_t payload_at = backward ? after_payload : vip;
        const uint64_t dispatch_at = backward ? data : after_payload;
        for (auto &s : evidence.events.states)
        {
            if (s.sequence < sequence || s.sequence > sequence + 50)
                continue;
            const bool entry = s.sequence == sequence;
            const bool output = s.source == c.dispatch;
            const bool checked = s.source == c.stack_check_branch || output;
            s.regs[c.vip].value = entry ? vip : output || relative ? after_dispatch : after_payload;
            s.regs[c.virtual_stack].value = entry ? virtual_stack : virtual_stack - 2;
            s.regs[4].value = native_stack;
            s.regs[0].value = entry ? 0xabc : output || relative ? decoded : payload;
            s.regs[1].value = checked ? limit : 0x123;
            s.regs[7].value = relative && !entry ? base + decoded : base;
            uint64_t flags = 0x202;
            if (!entry)
                flags = checked ? arithmetic_flags(virtual_stack - 2, limit, c.address_bits, true)
                        : relative ? arithmetic_flags(base, decoded, c.address_bits, false)
                                   : arithmetic_flags(virtual_stack, 2, c.address_bits, true);
            if (output && !relative)
                flags = arithmetic_flags(after_payload, dispatch_bytes, c.address_bits, backward);
            s.regs.back().value = flags;
            if (output)
                s.pc = target;
        }
        auto sequence_for = [&](uint64_t site)
        {
            const auto found = std::find_if(c.support.begin(), c.support.end(),
                                            [&](const auto &i) { return i.address == site; });
            check(found != c.support.end(), "guarded data source belongs to support");
            return sequence + uint64_t(found - c.support.begin()) * 2 + 1;
        };
        evidence.events.data.push_back({c.payload_read, payload_at, payload, 1, RAX_MEM_READ,
                                        hybrid::DataScope::IMAGE, sequence_for(c.payload_read), 1,
                                        9});
        evidence.events.data.push_back({c.payload_store, virtual_stack - 2, payload, 2,
                                        RAX_MEM_WRITE, hybrid::DataScope::STACK,
                                        sequence_for(c.payload_store), 1, 9});
        evidence.events.data.push_back({c.read, dispatch_at, decoded, unsigned(dispatch_bytes),
                                        RAX_MEM_READ, hybrid::DataScope::IMAGE,
                                        sequence_for(c.read), 1, 9});
        if (!relative)
            evidence.events.data.push_back(
                {c.dispatch, (c.address_bits == 64 ? base : 0) + decoded * (c.address_bits / 8),
                 target, c.address_bits / 8, RAX_MEM_READ, hybrid::DataScope::IMAGE,
                 sequence_for(c.dispatch), 1, 9});
    }
    for (auto &edge : evidence.events.edges)
        for (const auto &s : evidence.events.states)
            if (edge.sequence == s.sequence)
                edge.to = s.pc;
    return evidence;
}
void guarded_observations(unsigned mode, bool relative, bool backward)
{
    const auto candidate = guarded_candidate(mode, relative, backward);
    const auto evidence = guarded_fixture(candidate);
    auto view = vm::project_observations({candidate}, evidence, 0x800, 12, true, true);
    check(view.records.size() == 3 && view.transition_attempts == 3 && view.queries == 6,
          "three guarded transitions reach the complete local model");
    for (const auto &row : view.records)
    {
        check(row.at("path") == "sampled local address/size path" &&
                  row.at("internal_transfers") == "2",
              "guarded association traverses exact direct and JA witnesses");
        check(row.at("semantic_validation") == "corroborated for captured transition",
              "independent guarded ordinary transition corroborated");
        check(row.at("payload_value_register") == "0" && row.at("virtual_stack_register") == "5" &&
                  row.at("stack_check_register") == "1" && row.at("stack_check") == "true" &&
                  row.at("payload_bits") == "8" && row.at("stored_bits") == "16",
              "payload, virtual stack and guard register hypotheses exposed");
        check(row.at("output_payload_register") == "0x3" &&
                  row.at("access_1_value_low64") != "0x3" &&
                  row.at("payload_contract").find("final register may be overwritten") !=
                      std::string::npos,
              "stored payload distinguished from final decoded register");
        check(row.at("entry_virtual_stack") != row.at("output_virtual_stack") &&
                  row.at("entry_stack_check_register") == "0x123" &&
                  row.at("output_stack_check_register") == (mode == 64 ? "0x3100" : "0x3060"),
              "guard and virtual-stack pre/post snapshots retained");
        check(row.at("vm_context") == "unknown" && row.at("memory_epoch") == "unknown" &&
                  row.at("logical_state_complete") == "false" && row.at("merge") == "not admitted",
              "captured stack register does not establish complete logical identity");
    }
    auto shuffled = evidence;
    std::reverse(shuffled.events.states.begin(), shuffled.events.states.end());
    std::reverse(shuffled.events.execution.begin(), shuffled.events.execution.end());
    std::reverse(shuffled.events.edges.begin(), shuffled.events.edges.end());
    std::reverse(shuffled.events.data.begin(), shuffled.events.data.end());
    check(project(candidate, shuffled).records == project(candidate, evidence).records,
          "guarded association independent of input container ordering");
    auto target_entered = evidence;
    const auto first_output =
        std::find_if(target_entered.events.states.begin(), target_entered.events.states.end(),
                     [&](const auto &s) { return s.source == candidate.dispatch; });
    check(first_output != target_entered.events.states.end(), "guarded output target present");
    target_entered.events.execution.push_back(
        {first_output->pc, 4, first_output->sequence, first_output->run_id, first_output->seed});
    check(project(candidate, target_entered).records.front().at("path") ==
              "sampled local address/size path",
          "matching entered output target retained outside candidate support");
    ++target_entered.events.execution.back().pc;
    check(project(candidate, target_entered).records.front().at("path").find("unresolved") == 0,
          "output state must match an available entered target");
    --target_entered.events.execution.back().pc;
    target_entered.events.execution.push_back(target_entered.events.execution.back());
    check(project(candidate, target_entered).records.front().at("path").find("unresolved") == 0,
          "duplicate entered output target rejected");
    auto extra_execution = evidence;
    extra_execution.events.execution.push_back({0xdead, 4, 59, 1, 9});
    check(project(candidate, extra_execution).records.front().at("path").find("unresolved") == 0,
          "instructions between dispatch and claimed output cannot be skipped");
    auto equal_guard = evidence;
    auto &equal_entry = equal_guard.events.states.front();
    equal_entry.regs[candidate.virtual_stack].value =
        equal_entry.regs[4].value + candidate.stack_check_offset + 2;
    view = vm::project_observations({candidate}, equal_guard, 0x800, 12, true, true);
    check(view.records.front().at("path") == "sampled local address/size path" &&
              view.records.front().at("semantic_validation") == "inconsistent captured inputs" &&
              view.records.front().at("transition_queries") == "1",
          "ordinary transition input consistency includes strict fast-path domain");
    const auto state_at = [&](const auto &items, auto predicate)
    {
        const auto found = std::find_if(items.begin(), items.end(), predicate);
        check(found != items.end(), "guarded negative control witness present");
        return size_t(found - items.begin());
    };
    const auto guard_state =
        state_at(evidence.events.states, [&](const auto &s)
                 { return s.sequence < 60 && s.source == candidate.stack_check_branch; });
    const auto guard_edge =
        state_at(evidence.events.edges, [&](const auto &e)
                 { return e.sequence < 60 && e.from == candidate.stack_check_branch; });
    const auto guard_execution =
        state_at(evidence.events.execution, [&](const auto &e)
                 { return e.sequence < 60 && e.pc == candidate.stack_check_branch; });
    for (unsigned change = 0; change < 27; ++change)
    {
        auto bad = evidence;
        auto &states = bad.events.states;
        auto &edges = bad.events.edges;
        auto &execution = bad.events.execution;
        switch (change)
        {
        case 0:
            states.erase(states.begin() + guard_state);
            break;
        case 1:
            states.push_back(states[guard_state]);
            break;
        case 2:
            ++states[guard_state].source;
            break;
        case 3:
            ++states[guard_state].pc;
            break;
        case 4:
            --states[guard_state].sequence;
            break;
        case 5:
            ++states[guard_state].run_id;
            break;
        case 6:
            ++states[guard_state].seed;
            break;
        case 7:
            states[guard_state].kind = hybrid::StatePoint::Kind::NativeInstructionEntry;
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
            edges[guard_edge].kind = hybrid::ExecEdge::Kind::Call;
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
        {
            auto extra = states[guard_state];
            extra.sequence = execution[guard_execution].sequence + 1;
            states.push_back(extra);
            break;
        }
        case 17:
            states.erase(states.begin() + guard_state - 1);
            break;
        case 18:
            execution.erase(execution.begin() + guard_execution);
            break;
        case 19:
            execution.push_back(execution[guard_execution]);
            break;
        case 20:
            ++execution[guard_execution].run_id;
            break;
        case 21:
            ++execution[guard_execution].seed;
            break;
        case 22:
            states[guard_state].source = candidate.dispatch;
            break;
        case 23:
        {
            auto extra = edges[guard_edge];
            ++extra.sequence;
            edges.push_back(extra);
            break;
        }
        case 24:
            edges.erase(edges.begin());
            break;
        case 25:
            edges[guard_edge + 1].kind = hybrid::ExecEdge::Kind::Return;
            break;
        case 26:
            states.push_back(states[guard_state + 1]);
            break;
        }
        view = vm::project_observations({candidate}, bad, 0x800, 12, true, true);
        check(view.records.size() == 3 && view.records.front().at("path").find("unresolved") == 0 &&
                  view.records.front().at("transition_reason") == "complete local path required" &&
                  view.transition_attempts == 2 && view.queries == 4,
              "malformed guarded witness never skipped to a later dispatch output");
    }
}
}
int main()
{
    try
    {
        {
            const auto c = vm_test::path_candidate(64, true);
            auto e = fixture(c);
            auto v = project(c, e);
            check(v.records.size() == 3, "discontiguous observations retained");
            check(v.records.front().at("path") == "sampled local address/size path",
                  "ordered discontiguous support observed");
            e.events.data.push_back({0x900, c.support.back().address, 0, 1, RAX_MEM_WRITE,
                                     hybrid::DataScope::IMAGE, 5, 1, 9});
            v = project(c, e);
            check(v.records.front().at("runtime_code_identity").find("recorded write overlaps") !=
                      std::string::npos,
                  "write to lower-address path segment invalidates code identity");
            e.events.data.back().addr = 0x7800;
            v = project(c, e);
            check(v.records.front().at("runtime_code_identity").find("recorded write overlaps") ==
                      std::string::npos,
                  "unvisited address gap is not candidate code");
        }
        for (unsigned mode : {32u, 64u})
        {
            for (bool relative : {false, true})
                for (bool backward : {false, true})
                    guarded_observations(mode, relative, backward);
            const auto c = vm_test::candidate(mode, false, false, true);
            auto e = fixture(c);
            auto v = project(c, e);
            check(v.available && v.records.size() == 3, "three visits");
            std::set<std::string> ids, vips;
            for (const auto &r : v.records)
            {
                ids.insert(r.at("vm_state"));
                vips.insert(r.at("entry_vip"));
                check(r.at("path") == "sampled local address/size path", "native path association");
                check(r.at("virtual_stack") == "unknown" && r.at("vm_context") == "unknown" &&
                          r.at("memory_epoch") == "unknown",
                      "unknown roles retained");
                check(r.at("merge") == "not admitted" &&
                          r.at("semantic_validation") == "not performed",
                      "no promotion");
                check(r.at("access_0_value_low64") == "0x25" &&
                          r.at("data_capture_complete") == "false",
                      "bounded memory observations");
            }
            check(ids.size() == 3 && vips.size() == 3, "same native address distinct states");
            std::reverse(e.events.states.begin(), e.events.states.end());
            std::reverse(e.events.execution.begin(), e.events.execution.end());
            check(project(c, e).records == v.records, "input normalization independent");
            e = fixture(c);
            check(!vm::project_observations({c}, e, 0x800, 0, true).available, "zero publication");
            check(!vm::project_observations({c}, e, 0x800, 12, false).available, "stale capture");
            check(!vm::project_observations({c}, e, 0x801, 12, true).available, "foreign function");
            e.events.states[0].regs.clear();
            check(project(c, e).records[0].at("entry_vip").find("unknown") == 0,
                  "missing register");
            e = fixture(c);
            auto bad = e.events.states[0].regs[size_t(c.vip)];
            ++bad.value;
            e.events.states[0].regs.push_back(bad);
            check(project(c, e).records[0].at("entry_vip").find("conflicting") != std::string::npos,
                  "conflicting register");
            e = fixture(c);
            e.events.states[0].regs[size_t(c.vip)].width = 2;
            check(project(c, e).records[0].at("entry_vip").find("unknown") == 0,
                  "wrong register width");
            e = fixture(c);
            e.events.execution.erase(e.events.execution.begin() + 1);
            check(project(c, e).records[0].at("path").find("unresolved") == 0,
                  "missing instruction");
            e = fixture(c);
            ++e.events.execution[0].size;
            check(project(c, e).records[0].at("path").find("unresolved") == 0,
                  "wrong instruction size");
            e = fixture(c);
            e.events.execution.push_back(e.events.execution[0]);
            check(project(c, e).records[0].at("path").find("unresolved") == 0,
                  "extra execution record");
            e = fixture(c);
            e.events.execution[1].sequence = e.events.execution[0].sequence;
            check(project(c, e).records[0].at("path").find("unresolved") == 0,
                  "duplicate instruction sequence");
            e = fixture(c);
            e.events.states[1].source = 0x900;
            check(project(c, e).records[0].at("path").find("unresolved") == 0,
                  "intervening transfer");
            e = fixture(c);
            e.events.states.push_back(e.events.states[0]);
            v = project(c, e);
            check(v.records.size() == 4 &&
                      v.records[0].at("path").find("duplicate") != std::string::npos,
                  "ambiguous sequence");
            e = fixture(c);
            e.runs.push_back(e.runs[0]);
            check(project(c, e).records[0].at("path").find("unresolved") == 0, "ambiguous run");
            e = fixture(c);
            e.runs[0].provenance.generation = 18;
            check(project(c, e).records[0].at("run_provenance") != "matched", "foreign generation");
            e = fixture(c);
            e.runs[0].provenance.ticket = 999;
            check(project(c, e).records[0].at("run_provenance") != "matched", "foreign ticket");
            e = fixture(c);
            e.runs[0].provenance.function_hash = 999;
            check(project(c, e).records[0].at("run_provenance") != "matched",
                  "foreign function bytes");
            e = fixture(c);
            e.events.data.push_back(
                {0x900, c.start, 0x90, 1, RAX_MEM_WRITE, hybrid::DataScope::IMAGE, 1, 1, 9});
            check(project(c, e).records[0].at("runtime_code_identity").find("recorded write") == 0,
                  "prior code write");
            e = fixture(c);
            e.runs[0].outcome.function_boundary = true;
            e.runs[0].outcome.function_boundary_source = c.dispatch;
            e.runs[0].outcome.function_boundary_target = 0x1800;
            v = project(c, e);
            check(v.records[2].at("exit").find("function-boundary") == 0 &&
                      v.records[0].at("exit") == "sampled transfer target",
                  "boundary only final transfer");
            e = fixture(c);
            for (unsigned i = 0; i < 20; ++i)
                e.events.data.push_back({c.read, 0x3000 + i, i, 1, RAX_MEM_READ,
                                         hybrid::DataScope::IMAGE, 11 + i, 1, 9});
            v = project(c, e);
            check(v.records[0].at("accesses_captured") == "21" &&
                      v.records[0].at("accesses_omitted") == "5",
                  "exact access omissions");
            e = fixture(c);
            const auto sample = e.events.states[0];
            e.events.states.clear();
            for (unsigned i = 0; i < 140; ++i)
            {
                auto s = sample;
                s.sequence = i;
                e.events.states.push_back(s);
            }
            v = project(c, e);
            check(v.records.size() == 128 && v.omitted == 12, "exact state omissions");
            e = fixture(c);
            e.events.execution.resize(262144);
            check(!project(c, e).available, "input work budget");
            e = fixture(c);
            e.events.edges.resize(262144);
            check(!project(c, e).available, "edge witnesses share the input work budget");
            e = fixture(c);
            check(!vm::project_observations({c, c}, e, 0x800, 12, true).available,
                  "duplicate candidates");
            auto unchecked = vm::project_observations({c}, e, 0x800, 12, true, true);
            check(unchecked.transition_attempts == 0 && unchecked.queries == 0 &&
                      unchecked.records[0].at("transition_reason") ==
                          "complete direct data trace required",
                  "incomplete trace does not reach solver");
            e.runs[0].outcome.data_trace_complete = true;
            e.events.data.push_back(
                {0x900, c.start, 0x90, 1, RAX_MEM_WRITE, hybrid::DataScope::IMAGE, 1, 1, 9});
            unchecked = vm::project_observations({c}, e, 0x800, 12, true, true);
            check(unchecked.transition_attempts == 0 && unchecked.queries == 0 &&
                      unchecked.records[0].at("transition_reason") ==
                          "recorded candidate code write",
                  "code writes veto transition checks");
            e = fixture(c);
            auto many = e;
            e.runs.clear();
            e.events = {};
            for (uint32_t run = 1; run <= 7; ++run)
            {
                auto r = many.runs[0];
                r.provenance.run_id = run;
                r.outcome.data_trace_complete = true;
                e.runs.push_back(r);
                for (auto s : many.events.states)
                {
                    s.run_id = run;
                    e.events.states.push_back(s);
                }
                for (auto x : many.events.execution)
                {
                    x.run_id = run;
                    e.events.execution.push_back(x);
                }
                for (auto edge : many.events.edges)
                {
                    edge.run_id = run;
                    e.events.edges.push_back(edge);
                }
                for (auto d : many.events.data)
                {
                    d.run_id = run;
                    e.events.data.push_back(d);
                }
            }
            unchecked = vm::project_observations({c}, e, 0x800, 12, true, true);
            check(unchecked.transition_attempts == 16 && unchecked.records.size() == 21 &&
                      unchecked.records.back().at("transition_reason") ==
                          "transition attempt budget exhausted",
                  "transition attempt quota");
            e = fixture(c);
            e.events.states[0].regs.resize(65);
            check(!project(c, e).available, "register work budget");
            e = fixture(c);
            e.architecture = hybrid::HybridArch::UNSUPPORTED;
            check(!project(c, e).available, "unsupported architecture");
            if (mode == 32)
            {
                e = fixture(c);
                e.events.states[0].regs[size_t(c.vip)].value = UINT64_C(1) << 32;
                check(project(c, e).records[0].at("entry_vip").find("unknown") == 0,
                      "noncanonical 32-bit value");
            }
        }
        std::cout << checks << " VM observation checks passed\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
