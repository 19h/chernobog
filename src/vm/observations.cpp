#include "observations.hpp"
#include "transition.hpp"
#include "../common/solver_evidence.hpp"
#include "../hybrid/evidence.hpp"
#include <algorithm>
#include <atomic>
#include <sstream>
#include <tuple>

namespace chernobog::vm
{
namespace
{
using namespace hybrid;
using Run = std::pair<uint32_t, uint64_t>;
using Row = ObservationView::Row;
uint64_t check_identity()
{
    static std::atomic<uint64_t> next{1};
    auto value = next.load();
    while (value != UINT64_MAX)
        if (next.compare_exchange_weak(value, value + 1))
            return value;
    return 0; // Never reuse an inspection-check identity after exhaustion.
}
std::string hex(uint64_t n)
{
    std::ostringstream s;
    s << "0x" << std::hex << n;
    return s.str();
}
std::string boolean(bool b) { return b ? "true" : "false"; }
template <class T> Run run(const T &e) { return {e.run_id, e.seed}; }
template <class T> void order(std::vector<const T *> &items)
{
    std::stable_sort(items.begin(), items.end(),
                     [](auto a, auto b) { return a->sequence < b->sequence; });
}
template <class T> auto at(const std::vector<const T *> &items, uint64_t sequence)
{
    return std::lower_bound(items.begin(), items.end(), sequence,
                            [](auto p, uint64_t s) { return p->sequence < s; });
}
std::string reg(const StatePoint &s, int id, unsigned mode)
{
    std::optional<uint64_t> value;
    for (const auto &r : s.regs)
        if (r.reg == id)
        {
            if (r.width != mode / 8 || (mode == 32 && r.value > UINT32_MAX) ||
                (value && *value != r.value))
                return "unknown: conflicting value or width";
            value = r.value;
        }
    return value ? hex(*value) : "unknown: register absent";
}
void roles(Row &row, const StatePoint &s, const Candidate &c, const std::string &prefix)
{
    const auto gpr = [&](int r)
    { return reg(s, c.address_bits == 64 ? RAX_X86_GPR64(r) : RAX_X86_GPR32(r), c.address_bits); };
    row[prefix + "vip"] = gpr(c.vip);
    row[prefix + "decoded_register"] = gpr(c.value);
    row[prefix + "key"] = c.key < 0 ? "not used by candidate" : gpr(c.key);
    row[prefix + "dispatch_base"] =
        c.dispatch_base < 0 ? "absolute table displacement" : gpr(c.dispatch_base);
    row[prefix + "native_sp"] = gpr(4);
    row[prefix + "virtual_stack"] =
        c.virtual_stack < 0 ? "not identified by candidate" : gpr(c.virtual_stack);
    row[prefix + "payload_register"] =
        c.payload_value < 0 ? "not used by candidate" : gpr(c.payload_value);
    row[prefix + "stack_check_register"] =
        c.stack_check_value < 0 ? "not used by candidate" : gpr(c.stack_check_value);
    row[prefix + "flags"] =
        reg(s, c.address_bits == 64 ? RAX_X86_REG_RFLAGS : RAX_X86_REG_EFLAGS, c.address_bits);
}
bool overlap(uint64_t a, uint64_t size, uint64_t lo, uint64_t hi)
{
    // Malformed/wrapping access ranges cannot establish an unchanged scaffold.
    return size && (size - 1 > UINT64_MAX - a || (a < hi && (a >= lo || size > lo - a)));
}
struct Trace
{
    std::vector<const StatePoint *> states;
    std::vector<const ExecPoint *> execution;
    std::vector<const ExecEdge *> edges;
    std::vector<const DataAcc *> data;
    const RunObservation *observation = nullptr;
    bool ambiguous = false;
};
struct LocalPath
{
    const StatePoint *output = nullptr;
    size_t output_index = 0, internal_transfers = 0;
    bool matched = false;
    const char *reason = "unresolved: native instruction path differs";
};
LocalPath local_path(const Trace &trace, const Candidate &candidate, size_t entry_index)
{
    LocalPath result;
    const auto &entry = *trace.states[entry_index];
    if ((entry_index && trace.states[entry_index - 1]->sequence == entry.sequence) ||
        (entry_index + 1 < trace.states.size() &&
         trace.states[entry_index + 1]->sequence == entry.sequence))
    {
        result.reason = "unresolved: duplicate sample sequence";
        return result;
    }
    const auto first = at(trace.execution, entry.sequence);
    if (size_t(trace.execution.end() - first) < candidate.support.size())
        return result;
    for (size_t j = 0; j < candidate.support.size(); ++j)
        if (first[j]->pc != candidate.support[j].address ||
            first[j]->size != candidate.support[j].size || run(*first[j]) != run(entry) ||
            (j ? first[j - 1]->sequence >= first[j]->sequence
               : first[j]->sequence != entry.sequence))
            return result;
    size_t state_index = entry_index + 1;
    std::vector<const StatePoint *> transfers{&entry};
    for (size_t j = 1; j < candidate.support.size(); ++j)
    {
        const auto &previous = candidate.support[j - 1];
        if (candidate.support[j].address == previous.address + previous.size)
            continue; // Ordinary captures sample only non-fallthrough transfers.
        if (state_index == trace.states.size())
        {
            result.reason = "unresolved: internal transfer sample absent";
            return result;
        }
        const auto *state = trace.states[state_index++];
        if ((previous.op != Op::direct_jump && previous.op != Op::jump_above) ||
            state->sequence != first[j]->sequence || state->source != previous.address ||
            state->pc != candidate.support[j].address || run(*state) != run(entry))
        {
            result.reason = "unresolved: internal transfer does not follow candidate support";
            return result;
        }
        transfers.push_back(state);
        ++result.internal_transfers;
    }
    if (state_index == trace.states.size())
    {
        result.reason = "unresolved: output sample absent";
        return result;
    }
    result.output_index = state_index;
    const auto *output = trace.states[state_index];
    if (output->source != candidate.dispatch ||
        output->sequence <= first[candidate.support.size() - 1]->sequence ||
        run(*output) != run(entry) ||
        output->pc == candidate.dispatch + candidate.support.back().size)
    {
        result.reason = "unresolved: next supported transfer is not candidate dispatch";
        return result;
    }
    result.output = output;
    if ((state_index + 1 < trace.states.size() &&
         trace.states[state_index + 1]->sequence == output->sequence) ||
        at(trace.execution, output->sequence) != first + candidate.support.size())
    {
        result.reason = "unresolved: duplicate sample or extra native instruction";
        return result;
    }
    const auto target = at(trace.execution, output->sequence);
    if (target != trace.execution.end() && (*target)->sequence == output->sequence &&
        ((*target)->pc != output->pc ||
         (target + 1 != trace.execution.end() && (*(target + 1))->sequence == output->sequence)))
    {
        result.reason = "unresolved: target sample and entered instruction differ";
        return result;
    }
    transfers.push_back(output);
    auto edge = at(trace.edges, entry.sequence);
    for (size_t index = 0; index < transfers.size(); ++index)
    {
        const auto &state = *transfers[index];
        const auto kind = index + 1 == transfers.size() && candidate.stack_dispatch
                              ? ExecEdge::Kind::Return
                              : ExecEdge::Kind::Jump;
        if (edge == trace.edges.end() || (*edge)->sequence != state.sequence ||
            (*edge)->from != state.source || (*edge)->to != state.pc || run(**edge) != run(entry) ||
            (index && (*edge)->kind != kind))
        {
            result.reason = "unresolved: transfer edge and state witnesses differ";
            return result;
        }
        ++edge;
    }
    if (edge != trace.edges.end() && (*edge)->sequence <= output->sequence)
    {
        result.reason = "unresolved: extra or duplicate transfer edge";
        return result;
    }
    result.matched = true;
    result.reason = "sampled local address/size path";
    return result;
}
}

ObservationView project_observations(const std::vector<Candidate> &input,
                                     const hybrid::TargetEvidence &source, uint64_t function,
                                     uint64_t revision, bool fresh, bool validate_transitions,
                                     int64_t database)
{
    ObservationView view;
    if (!fresh || !revision || source.scope.function_start != function)
    {
        view.reason = "fresh exact publication for selected function required";
        return view;
    }
    const unsigned mode = source.architecture == hybrid::HybridArch::X86_64   ? 64
                          : source.architecture == hybrid::HybridArch::X86_32 ? 32
                                                                              : 0;
    if (!mode)
    {
        view.reason = "unsupported capture architecture";
        return view;
    }
    size_t budget = 262144;
    for (auto n : {source.events.states.size(), source.events.execution.size(),
                   source.events.edges.size(), source.events.data.size(), source.runs.size()})
    {
        if (n > budget)
        {
            view.reason = "trace input budget exceeded; no partial join";
            return view;
        }
        budget -= n;
    }
    if (input.size() > 64)
    {
        view.reason = "candidate input budget exceeded";
        return view;
    }
    for (const auto &s : source.events.states)
        if (s.regs.size() > 64)
        {
            view.reason = "register input budget exceeded";
            return view;
        }
    std::map<uint64_t, Candidate> candidates;
    for (const auto &claimed : input)
    {
        auto c = recognize(claimed.support, mode);
        if (!c || claimed.address_bits != mode || !candidates.emplace(c->start, *c).second)
        {
            view.reason = "invalid, mixed-mode or duplicate candidate input";
            return view;
        }
    }
    std::map<Run, Trace> traces;
    for (const auto &r : source.runs)
    {
        auto &trace = traces[run(r.provenance)];
        if (trace.observation)
            trace.ambiguous = true;
        else
            trace.observation = &r;
    }
    for (const auto &s : source.events.states)
        if (s.kind == StatePoint::Kind::TransferTarget)
            traces[run(s)].states.push_back(&s);
    for (const auto &e : source.events.execution)
        traces[run(e)].execution.push_back(&e);
    for (const auto &edge : source.events.edges)
        traces[run(edge)].edges.push_back(&edge);
    for (const auto &d : source.events.data)
        traces[run(d)].data.push_back(&d);
    view.available = true;
    view.reason = "taken-transfer samples only; fallthrough entries are not sampled";
    size_t ordinal = 0;
    for (auto &[identity, t] : traces)
    {
        order(t.states);
        order(t.execution);
        order(t.edges);
        order(t.data);
        for (size_t i = 0; i < t.states.size(); ++i)
        {
            const auto &entry = *t.states[i];
            const auto found = candidates.find(entry.pc);
            if (found == candidates.end())
                continue;
            if (view.records.size() == 128)
            {
                ++view.omitted;
                continue;
            }
            const auto &c = found->second;
            const auto id = hex(c.start) + ":" + hex(c.dispatch);
            Row row{{"vm_state", hex(revision) + ":" + hex(identity.first) + ":" +
                                     hex(identity.second) + ":" + hex(entry.sequence) + ":" +
                                     std::to_string(ordinal++)},
                    {"vm_candidate", id},
                    {"site", hex(c.start)},
                    {"dispatch", hex(c.dispatch)},
                    {"run", hex(identity.first)},
                    {"seed", hex(identity.second)},
                    {"sequence", hex(entry.sequence)},
                    {"revision", hex(revision)},
                    {"entry_source", hex(entry.source)},
                    {"payload_value_register", std::to_string(c.payload_value)},
                    {"virtual_stack_register", std::to_string(c.virtual_stack)},
                    {"stack_check_register", std::to_string(c.stack_check_value)},
                    {"stack_check", boolean(c.stack_check)},
                    {"payload_read", hex(c.payload_read)},
                    {"payload_store", hex(c.payload_store)},
                    {"payload_bits", std::to_string(c.payload_bits)},
                    {"stored_bits", std::to_string(c.stored_bits)},
                    {"kind", "sampled candidate entry"},
                    {"truth", "observation"},
                    {"classification",
                     "captured registers associated with current IDB role hypotheses"},
                    {"virtual_stack",
                     c.virtual_stack < 0 ? "unknown" : "captured native register hypothesis"},
                    {"vm_context", "unknown"},
                    {"memory_epoch", "unknown"},
                    {"logical_state_complete", "false"},
                    {"merge", "not admitted"},
                    {"runtime_code_identity",
                     "unverified; trace records addresses and sizes, not fetched bytes"},
                    {"semantic_validation", "not performed"},
                    {"path", "unresolved: output sample absent"},
                    {"data_capture_complete", "false"}};
            if (c.payload_bits)
                row["payload_contract"] =
                    "entry/output payload register snapshots; final register may be overwritten; pushed value requires the ordered payload-store access";
            if (c.stack_check)
                row["stack_check_contract"] =
                    "observed taken unsigned JA fast path only; slow relocation path not represented";
            const auto *r = t.observation;
            const bool valid_run = r && !t.ambiguous && r->ran &&
                                   r->provenance.function_start == function &&
                                   r->provenance.generation == source.scope.generation &&
                                   r->provenance.function_hash == source.scope.function_hash &&
                                   r->provenance.image_hash == source.scope.image_hash &&
                                   r->provenance.ticket == source.scope.ticket &&
                                   r->provenance.focus_address == source.scope.focus_address;
            row["run_provenance"] = valid_run ? "matched" : "unresolved or ambiguous";
            if (r)
            {
                row["run_stop"] = hybrid::hybrid_emu_outcome_name(r->outcome);
                row["modeled"] = boolean(r->outcome.external_model_used);
                row["synthetic_entry"] = boolean(r->outcome.synthetic_entry_context);
                row["consumed_context_complete"] = boolean(r->outcome.consumed_context_complete);
                row["memory_hooks_available"] = boolean(r->outcome.memory_observation_available);
                row["data_capture_complete"] = boolean(valid_run && r->outcome.data_trace_complete);
                row["data_trace_truncated"] = boolean(r->outcome.data_trace_truncated);
                row["data_trace_filtered"] = boolean(r->outcome.data_trace_filtered);
            }
            // Register values are observations even if run metadata is incomplete.
            roles(row, entry, c, "entry_");
            const auto path = local_path(t, c, i);
            const auto *output = path.output;
            row["path"] = !valid_run && path.matched
                              ? "unresolved: native path or run provenance differs"
                              : path.reason;
            row["internal_transfers"] = std::to_string(path.internal_transfers);
            if (output)
            {
                row["target"] = hex(output->pc);
                row["output_sequence"] = hex(output->sequence);
                roles(row, *output, c, "output_");
                row["exit"] = valid_run && r->outcome.function_boundary &&
                                      r->outcome.function_boundary_source == c.dispatch &&
                                      r->outcome.function_boundary_target == output->pc &&
                                      path.output_index + 1 == t.states.size()
                                  ? "function-boundary; target instruction not admitted"
                                  : "sampled transfer target";
                const auto begin = at(t.data, entry.sequence), end = at(t.data, output->sequence);
                const size_t count = size_t(end - begin), retained = std::min<size_t>(count, 16);
                row["accesses_captured"] = std::to_string(count);
                row["accesses_omitted"] = std::to_string(count - retained);
                for (size_t j = 0; j < retained; ++j)
                {
                    const auto &a = *begin[j];
                    const auto p = "access_" + std::to_string(j) + "_";
                    row[p + "kind"] = a.kind == RAX_MEM_READ    ? "read"
                                      : a.kind == RAX_MEM_WRITE ? "write"
                                                                : "unknown";
                    row[p + "site"] = hex(a.from);
                    row[p + "address"] = hex(a.addr);
                    row[p + "sequence"] = hex(a.sequence);
                    row[p + "size_bytes"] = std::to_string(a.size);
                    row[p + "value_low64"] = hex(a.value);
                }
            }
            // A prior or local write disproves the stable-code assumption. Absence of
            // a recorded write cannot prove it, because data events may be incomplete.
            const uint64_t until =
                output && output->source == c.dispatch ? output->sequence : entry.sequence;
            bool code_write = false;
            for (auto p = t.data.cbegin(), end = at(t.data, until); p != end; ++p)
                if ((*p)->kind == RAX_MEM_WRITE &&
                    std::any_of(
                        c.support.begin(), c.support.end(), [&](const auto &i)
                        { return overlap((*p)->addr, (*p)->size, i.address, i.address + i.size); }))
                {
                    code_write = true;
                    row["runtime_code_identity"] =
                        "recorded write overlaps candidate; IDB roles unverified at runtime";
                    break;
                }
            if (validate_transitions)
            {
                row["semantic_validation"] = "transition not checked";
                row["transition_contract"] =
                    "one captured normal-completion transition; current snapshot instruction bytes; flat little-endian memory; no concurrency/devices/segment-base/exception effects; target execution not admitted";
                if (c.stack_dispatch)
                    row["transition_contract"] += "; CET shadow stack disabled";
                if (code_write)
                    row["transition_reason"] = "recorded candidate code write";
                else if (!valid_run || !r->outcome.data_trace_complete)
                    row["transition_reason"] = "complete direct data trace required";
                else if (row["path"] != "sampled local address/size path")
                    row["transition_reason"] = "complete local path required";
                else if (view.transition_attempts == 16)
                    row["transition_reason"] = "transition attempt budget exhausted";
                else
                {
                    ++view.transition_attempts;
                    const auto first = at(t.data, entry.sequence),
                               last = at(t.data, output->sequence);
                    if (last - first > 64)
                        row["transition_reason"] = "transition access budget exceeded";
                    else
                    {
                        std::vector<hybrid::DataAcc> accesses;
                        for (auto p = first; p != last; ++p)
                            accesses.push_back(**p);
                        const auto check_id = check_identity();
                        if (!check_id)
                            row["transition_reason"] = "check identity exhausted";
                        else
                        {
                            solver_evidence::Scope scope(
                                {database, function, c.start, -1, "vm-observed-transition",
                                 revision, entry.run_id, entry.seed, entry.sequence, check_id});
                            const auto result = check_transition(c, entry, *output, accesses);
                            view.queries += result.queries;
                            row["transition_check"] = hex(check_id);
                            row["semantic_validation"] = transition_result_name(result.result);
                            row["transition_reason"] = result.reason;
                            row["transition_queries"] = std::to_string(result.queries);
                        }
                    }
                }
            }
            view.records.push_back(std::move(row));
        }
    }
    return view;
}
}
