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
template <class T> auto at(std::vector<const T *> &items, uint64_t sequence)
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
    std::vector<const DataAcc *> data;
    const RunObservation *observation = nullptr;
    bool ambiguous = false;
};
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
                   source.events.data.size(), source.runs.size()})
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
    for (const auto &d : source.events.data)
        traces[run(d)].data.push_back(&d);
    view.available = true;
    view.reason = "taken-transfer samples only; fallthrough entries are not sampled";
    size_t ordinal = 0;
    for (auto &[identity, t] : traces)
    {
        order(t.states);
        order(t.execution);
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
                    {"kind", "sampled candidate entry"},
                    {"truth", "observation"},
                    {"classification",
                     "captured registers associated with current IDB role hypotheses"},
                    {"virtual_stack", "unknown"},
                    {"vm_context", "unknown"},
                    {"memory_epoch", "unknown"},
                    {"logical_state_complete", "false"},
                    {"merge", "not admitted"},
                    {"runtime_code_identity",
                     "unverified; trace records addresses and sizes, not fetched bytes"},
                    {"semantic_validation", "not performed"},
                    {"path", "unresolved: output sample absent"},
                    {"data_capture_complete", "false"}};
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
            const StatePoint *output = i + 1 < t.states.size() ? t.states[i + 1] : nullptr;
            const bool duplicate = (i && t.states[i - 1]->sequence == entry.sequence) ||
                                   (output && output->sequence == entry.sequence);
            if (duplicate)
                row["path"] = "unresolved: duplicate sample sequence";
            else if (output && output->source == c.dispatch)
            {
                row["target"] = hex(output->pc);
                row["output_sequence"] = hex(output->sequence);
                roles(row, *output, c, "output_");
                auto first = at(t.execution, entry.sequence),
                     last = at(t.execution, output->sequence);
                bool match = valid_run && size_t(last - first) == c.support.size();
                for (size_t j = 0; match && j < c.support.size(); ++j)
                    match = first[j]->pc == c.support[j].address &&
                            first[j]->size == c.support[j].size &&
                            (j ? first[j - 1]->sequence < first[j]->sequence
                               : first[j]->sequence == entry.sequence);
                if (i + 2 < t.states.size() && t.states[i + 2]->sequence == output->sequence)
                    match = false;
                row["path"] = match ? "sampled local address/size path"
                                    : "unresolved: native path or run provenance differs";
                row["exit"] = valid_run && r->outcome.function_boundary &&
                                      r->outcome.function_boundary_source == c.dispatch &&
                                      r->outcome.function_boundary_target == output->pc &&
                                      i + 2 == t.states.size()
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
            else if (output)
                row["path"] = "unresolved: next sampled transfer is not candidate dispatch";
            // A prior or local write disproves the stable-code assumption. Absence of
            // a recorded write cannot prove it, because data events may be incomplete.
            const uint64_t until =
                output && output->source == c.dispatch ? output->sequence : entry.sequence;
            bool code_write = false;
            for (auto p = t.data.begin(), end = at(t.data, until); p != end; ++p)
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
