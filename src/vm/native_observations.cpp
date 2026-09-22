#include "native_observations.hpp"
#include "transition.hpp"
#include "../common/solver_evidence.hpp"
#include <algorithm>
#include <atomic>
#include <sstream>

namespace chernobog::vm
{
namespace
{
std::string hex(uint64_t n)
{
    std::ostringstream out;
    out << "0x" << std::hex << n;
    return out.str();
}
uint64_t next_check()
{
    static std::atomic<uint64_t> next{1};
    auto value = next.load();
    while (value != UINT64_MAX)
        if (next.compare_exchange_weak(value, value + 1))
            return value;
    return 0;
}
std::string reg(const hybrid::StatePoint &state, int id, unsigned mode)
{
    std::optional<uint64_t> value;
    for (const auto &r : state.regs)
        if (r.reg == id)
        {
            if (r.width != mode / 8 || (mode == 32 && r.value > UINT32_MAX) ||
                (value && *value != r.value))
                return "unknown: conflicting value or width";
            value = r.value;
        }
    return value ? hex(*value) : "unknown: register absent";
}
void roles(ObservationView::Row &row, const Candidate &c, const hybrid::StatePoint &state,
           const char *prefix)
{
    auto gpr = [&](int id)
    {
        return reg(state, c.address_bits == 64 ? RAX_X86_GPR64(id) : RAX_X86_GPR32(id),
                   c.address_bits);
    };
    const std::string p = prefix;
    row[p + "vip"] = gpr(c.vip);
    row[p + "decoded_register"] = gpr(c.value);
    row[p + "key"] = c.key < 0 ? "not used by candidate" : gpr(c.key);
    row[p + "dispatch_base"] =
        c.dispatch_base < 0 ? "absolute table displacement" : gpr(c.dispatch_base);
    row[p + "virtual_stack"] =
        c.virtual_stack < 0 ? "not identified by candidate" : gpr(c.virtual_stack);
    row[p + "payload_register"] =
        c.payload_value < 0 ? "not used by candidate" : gpr(c.payload_value);
    row[p + "stack_check_register"] =
        c.stack_check_value < 0 ? "not used by candidate" : gpr(c.stack_check_value);
    row[p + "native_sp"] = gpr(4);
    row[p + "flags"] =
        reg(state, c.address_bits == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS, c.address_bits);
}
bool overlaps(const hybrid::DataAcc &access, const Instruction &i)
{
    return access.size && (access.size - 1 > UINT64_MAX - access.addr ||
                           (access.addr < i.address + i.size &&
                            (access.addr >= i.address || access.size > i.address - access.addr)));
}
}

NativeObservationView project_native_observations(const NativeRegion &region,
                                                  const std::map<uint64_t, Instruction> &decoded,
                                                  const hybrid::EmuEvents &events,
                                                  const hybrid::EmuOutcome &outcome, unsigned mode,
                                                  uint64_t capture, uint64_t function,
                                                  bool validate, int64_t database)
{
    using namespace hybrid;
    using Row = ObservationView::Row;
    NativeObservationView view;
    auto reject = [&](const char *reason)
    {
        view.reason = reason;
        return view;
    };
    if (!capture || !region.available() || function != region.entry() ||
        (mode != 32 && mode != 64) || mode != region.address_bits() || !outcome.native_region ||
        outcome.region_identity != region.identity() || !outcome.stop_valid)
        return reject("exact native capture and region identity required");
    if (!outcome.native_state_capture_requested || !outcome.native_state_capture_complete)
        return reject("complete native instruction-entry sampling required");
    if (events.execution.empty() || events.execution.size() > 4096 || events.data.size() > 4096 ||
        events.states.size() > 12289 || events.edges.size() > 4096 || decoded.size() > 4096)
        return reject("native observation input budget exceeded");
    const uint32_t run = events.execution.front().run_id;
    const uint64_t seed = events.execution.front().seed;
    const auto same_run = [&](const auto &event)
    { return event.run_id == run && event.seed == seed; };
    uint64_t previous = 0;
    bool first = true;
    for (const auto &point : events.execution)
    {
        const auto *head = region.at(point.pc);
        const auto d = decoded.find(point.pc);
        if (!same_run(point) || (!first && point.sequence <= previous) || !head ||
            head->bytes.size() != point.size || d == decoded.end() ||
            d->second.address != point.pc || d->second.size != point.size)
            return reject("execution order, identity or checked instruction span differs");
        previous = point.sequence;
        first = false;
    }
    previous = 0;
    first = true;
    size_t memory_instruction = 0;
    for (const auto &access : events.data)
    {
        if (!same_run(access) || (!first && access.sequence <= previous))
            return reject("data order or identity differs");
        while (memory_instruction + 1 < events.execution.size() &&
               events.execution[memory_instruction + 1].sequence < access.sequence)
            ++memory_instruction;
        if (events.execution[memory_instruction].sequence >= access.sequence ||
            events.execution[memory_instruction].pc != access.from ||
            (memory_instruction + 1 < events.execution.size() &&
             events.execution[memory_instruction + 1].sequence == access.sequence))
            return reject("data event does not follow its entered instruction");
        previous = access.sequence;
        first = false;
    }
    std::map<uint64_t, const StatePoint *> entries, outputs;
    for (const auto &state : events.states)
    {
        if (!same_run(state) || state.regs.size() > 64)
            return reject("state identity or register budget differs");
        auto *index = state.kind == StatePoint::Kind::NativeInstructionEntry ? &entries
                      : state.kind == StatePoint::Kind::TransferTarget       ? &outputs
                                                                             : nullptr;
        if (index && !index->emplace(state.sequence, &state).second)
            return reject("duplicate native state sequence");
    }
    if (entries.size() != events.execution.size())
        return reject("instruction-entry sample count differs");
    for (const auto &point : events.execution)
    {
        const auto found = entries.find(point.sequence);
        if (found == entries.end() || found->second->pc != point.pc)
            return reject("instruction-entry sample path differs");
    }
    previous = 0;
    first = true;
    std::map<uint64_t, const ExecEdge *> edges;
    size_t edge_instruction = 0;
    for (const auto &edge : events.edges)
    {
        if (!same_run(edge) || (!first && edge.sequence <= previous) ||
            !edges.emplace(edge.sequence, &edge).second)
            return reject("edge order or identity differs");
        while (edge_instruction + 1 < events.execution.size() &&
               events.execution[edge_instruction + 1].sequence < edge.sequence)
            ++edge_instruction;
        if (events.execution[edge_instruction].sequence >= edge.sequence ||
            events.execution[edge_instruction].pc != edge.from ||
            (edge_instruction + 1 < events.execution.size() &&
             (events.execution[edge_instruction + 1].sequence != edge.sequence ||
              events.execution[edge_instruction + 1].pc != edge.to)))
            return reject("edge does not join its entered source and destination");
        previous = edge.sequence;
        first = false;
    }
    view.available = true;
    view.reason =
        "exact captured native paths; local role hypotheses; VM identity and other entry points unproved";
    for (size_t start = 0; start < events.execution.size(); ++start)
    {
        const auto &initial = decoded.at(events.execution[start].pc);
        if (!((initial.op == Op::load && initial.src.kind == Kind::memory) ||
              (initial.op == Op::sub && initial.dst.kind == Kind::reg &&
               initial.src.kind == Kind::immediate &&
               (initial.src.value == 1 || initial.src.value == 2 || initial.src.value == 4 ||
                initial.src.value == 8))))
            continue;
        ++view.starts_examined;
        std::vector<Instruction> path;
        bool ended = false;
        for (size_t at = start; at < events.execution.size() && path.size() < instruction_limit;
             ++at)
        {
            if (view.path_steps == 8192)
            {
                view.path_limited = true;
                break;
            }
            ++view.path_steps;
            const auto &instruction = decoded.at(events.execution[at].pc);
            if (instruction.op == Op::unsupported)
            {
                ++view.unsupported_path_stops;
                ended = true;
                break;
            }
            path.push_back(instruction);
            if (instruction.op != Op::jump && instruction.op != Op::near_return)
                continue;
            ended = true;
            const auto candidate = recognize(path, mode);
            if (!candidate)
            {
                ++view.recognizer_rejections;
                break;
            }
            ++view.candidate_visits;
            if (view.records.size() == 128)
            {
                ++view.omitted;
                break;
            }
            const auto &c = *candidate;
            const auto &entry = *entries.at(events.execution[start].sequence);
            const uint64_t end_sequence =
                at + 1 < events.execution.size() ? events.execution[at + 1].sequence : UINT64_MAX;
            auto output = outputs.upper_bound(events.execution[at].sequence);
            const StatePoint *exit = output != outputs.end() && output->first <= end_sequence &&
                                             output->second->source == c.dispatch
                                         ? output->second
                                         : nullptr;
            Row row{{"vm_state", hex(capture) + ":" + hex(entry.sequence)},
                    {"vm_candidate", hex(c.start) + ":" + hex(c.dispatch)},
                    {"scope", "native-region"},
                    {"capture", hex(capture)},
                    {"region_identity", hex(region.identity())},
                    {"image_hash", hex(region.image_hash())},
                    {"site", hex(c.start)},
                    {"dispatch", hex(c.dispatch)},
                    {"read", hex(c.read)},
                    {"sequence", hex(entry.sequence)},
                    {"run", hex(run)},
                    {"seed", hex(seed)},
                    {"kind", "native instruction-entry candidate observation"},
                    {"truth", "observation"},
                    {"read_bits", std::to_string(c.read_bits)},
                    {"address_bits", std::to_string(mode)},
                    {"direction", c.direction == Direction::forward ? "forward" : "backward"},
                    {"vip_register", std::to_string(c.vip)},
                    {"value_register", std::to_string(c.value)},
                    {"key_register", std::to_string(c.key)},
                    {"dispatch_base_register", std::to_string(c.dispatch_base)},
                    {"payload_read", hex(c.payload_read)},
                    {"payload_store", hex(c.payload_store)},
                    {"payload_bits", std::to_string(c.payload_bits)},
                    {"stored_bits", std::to_string(c.stored_bits)},
                    {"payload_value_register", std::to_string(c.payload_value)},
                    {"virtual_stack_register", std::to_string(c.virtual_stack)},
                    {"stack_check", c.stack_check ? "true" : "false"},
                    {"stack_check_branch", hex(c.stack_check_branch)},
                    {"stack_check_offset", std::to_string(c.stack_check_offset)},
                    {"stack_check_register", std::to_string(c.stack_check_value)},
                    {"payload_register_scope",
                     "native register snapshot; stored payload is the ordered store value"},
                    {"virtual_stack",
                     c.virtual_stack < 0 ? "unknown" : "captured native register hypothesis"},
                    {"vm_context", "unknown"},
                    {"memory_epoch", "unknown"},
                    {"logical_state_complete", "false"},
                    {"merge", "not admitted"},
                    {"runtime_code_identity",
                     "exact planned bytes checked before each recorded instruction"},
                    {"entry_contract",
                     "specified captured entry; other entry points unknown and not summarized"},
                    {"semantic_validation", "not performed"},
                    {"path", "unresolved: dispatch output absent"},
                    {"data_capture_complete", outcome.data_trace_complete ? "true" : "false"},
                    {"run_stop", hybrid_emu_outcome_name(outcome)}};
            std::string spans;
            for (const auto &i : c.support)
                spans += hex(i.address) + ":" + std::to_string(i.size) + ";";
            row["instruction_spans"] = spans;
            roles(row, c, entry, "entry_");
            bool internal_transfers = true;
            for (size_t index = start; index < at && internal_transfers; ++index)
            {
                const auto &instruction = decoded.at(events.execution[index].pc);
                const auto &next = events.execution[index + 1];
                const auto state = outputs.find(next.sequence);
                const auto edge = edges.find(next.sequence);
                if (instruction.op != Op::direct_jump && instruction.op != Op::jump_above)
                {
                    internal_transfers = state == outputs.end() && edge == edges.end();
                    continue;
                }
                internal_transfers =
                    state != outputs.end() && edge != edges.end() &&
                    state->second->source == instruction.address && state->second->pc == next.pc &&
                    next.pc == instruction.dst.value && edge->second->from == instruction.address &&
                    edge->second->to == next.pc && edge->second->kind == ExecEdge::Kind::Jump;
                if (!internal_transfers)
                    break;
                const auto &entered = *entries.at(next.sequence);
                for (int id = 0; id <= (mode == 64 ? 16 : 8); ++id)
                {
                    const bool flags = id == (mode == 64 ? 16 : 8);
                    const int r = flags ? (mode == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS)
                                        : (mode == 64 ? RAX_X86_GPR64(id) : RAX_X86_GPR32(id));
                    const auto value = reg(*state->second, r, mode);
                    if (value.find("unknown:") == 0 || value != reg(entered, r, mode))
                        internal_transfers = false;
                }
            }
            row["internal_transfers"] =
                internal_transfers ? "exact captured witnesses" : "missing or inconsistent witness";
            bool matched = false;
            if (exit)
            {
                const auto edge = edges.find(exit->sequence);
                matched = internal_transfers && edge != edges.end() &&
                          edge->second->from == c.dispatch && edge->second->to == exit->pc &&
                          edge->second->kind ==
                              (c.stack_dispatch ? ExecEdge::Kind::Return : ExecEdge::Kind::Jump);
                row["output_sequence"] = hex(exit->sequence);
                row["target"] = hex(exit->pc);
                roles(row, c, *exit, "output_");
                if (matched)
                    row["path"] = "complete captured native path";
            }
            std::vector<DataAcc> accesses;
            bool code_write = false;
            const uint64_t until = exit ? exit->sequence : events.execution[at].sequence;
            for (const auto &access : events.data)
            {
                if (access.sequence >= until)
                    break;
                if (access.kind == RAX_MEM_WRITE &&
                    std::any_of(c.support.begin(), c.support.end(),
                                [&](const auto &i) { return overlaps(access, i); }))
                    code_write = true;
                if (access.sequence > entry.sequence)
                    accesses.push_back(access);
            }
            row["accesses_captured"] = std::to_string(accesses.size());
            if (validate)
            {
                row["semantic_validation"] = "transition not checked";
                row["transition_contract"] =
                    "one observed fixed-entry normal-completion path; flat little-endian memory; no concurrency/devices/segment bases/exceptions; no cross-input equivalence";
                if (c.stack_dispatch)
                    row["transition_contract"] += "; CET shadow stack disabled";
                if (c.stack_check)
                    row["transition_contract"] +=
                        "; taken JA domain required; relocation arm not summarized";
                if (code_write)
                    row["transition_reason"] = "recorded candidate code write";
                else if (!outcome.data_trace_complete)
                    row["transition_reason"] = "complete direct data trace required";
                else if (!matched)
                    row["transition_reason"] = "complete dispatch observation required";
                else if (accesses.size() > 64)
                    row["transition_reason"] = "transition access budget exceeded";
                else if (view.transition_attempts == 16)
                    row["transition_reason"] = "transition attempt budget exhausted";
                else
                {
                    const auto check = next_check();
                    if (!check)
                        row["transition_reason"] = "check identity exhausted";
                    else
                    {
                        ++view.transition_attempts;
                        solver_evidence::Scope scope({database, function, c.start, -1,
                                                      "vm-native-observed-transition", capture, run,
                                                      seed, entry.sequence, check});
                        const auto result = check_transition(c, entry, *exit, accesses);
                        view.queries += result.queries;
                        row["transition_check"] = hex(check);
                        row["transition_queries"] = std::to_string(result.queries);
                        row["semantic_validation"] = transition_result_name(result.result);
                        row["transition_reason"] = result.reason;
                    }
                }
            }
            view.records.push_back(std::move(row));
            break;
        }
        if (!view.path_limited && !ended)
        {
            if (path.size() == instruction_limit)
                ++view.path_length_stops;
            else
                ++view.capture_end_stops;
        }
        if (view.path_limited)
            break;
    }
    return view;
}
}
