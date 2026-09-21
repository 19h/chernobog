/* Bounded inspection projection. No database access and no proof promotion. */
#pragma once
#include "evidence.hpp"
#include "../common/inspection_json.hpp"
#include <map>
#include <sstream>
#include <tuple>

namespace chernobog::hybrid {

using EvidenceViewRow = std::map<std::string, std::string>;
struct EvidenceView
{
  static constexpr size_t edge_limit = 256, event_limit = 1024;
  static constexpr size_t lifetime_limit = 128, run_limit = 128, claim_limit = 128;
  std::vector<EvidenceViewRow> edges, events, lifetimes, runs, claims;
  std::map<std::string, size_t> omitted;
};

inline std::string view_hex(uint64_t value)
{ std::ostringstream out; out << "0x" << std::hex << value; return out.str(); }

inline std::string view_bytes(const std::vector<uint8_t> &bytes)
{
  static const char digits[] = "0123456789abcdef";
  std::string out;
  for (size_t i = 0; i < std::min<size_t>(64, bytes.size()); ++i)
  { out += digits[bytes[i] >> 4]; out += digits[bytes[i] & 15]; }
  return out;
}

inline EvidenceView project_evidence_view(const TargetEvidence &source)
{
  EvidenceView view;
  using Key = std::tuple<uint64_t, uint32_t, uint64_t, std::string, size_t>;
  std::map<Key, EvidenceViewRow> retained;
  size_t serial = 0;
  const auto event = [&](const char *kind, uint32_t run, uint64_t seed,
                         uint64_t sequence, uint64_t site, EvidenceViewRow row) {
    row["kind"] = kind; row["run"] = view_hex(run); row["seed"] = view_hex(seed);
    row["sequence"] = view_hex(sequence); row["site"] = view_hex(site);
    // Retain early sequence positions across runs, then display grouped by
    // run/seed. Sequences are not a shared clock between independent runs.
    retained.emplace(Key{sequence, run, seed, kind, serial++}, std::move(row));
    if (retained.size() > EvidenceView::event_limit)
    { retained.erase(std::prev(retained.end())); ++view.omitted["events"]; }
  };
  const auto bounded = [&](auto &rows, size_t limit, const char *name, EvidenceViewRow row) {
    if (rows.size() < limit) rows.push_back(std::move(row));
    else ++view.omitted[name];
  };
  // Half of the edge allowance is reserved for each evidence family.
  size_t encoded = 0, observed = 0;
  for (const auto &item : source.static_analysis.instructions)
  {
    if (!item.ida.valid) continue;
    const auto edge = [&](uint64_t target, const char *kind) {
      if (encoded++ >= EvidenceView::edge_limit / 2) { ++view.omitted["encoded_edges"]; return; }
      view.edges.push_back({{"kind", kind}, {"truth", "encoding"},
          {"site", view_hex(item.address)}, {"target", view_hex(target)},
          {"assumption", "IDA decoded instruction; reachability is not established"}});
    };
    if (item.ida.has_target && !item.ida.indirect) edge(item.ida.target, "encoded-target");
    if (item.ida.has_fallthrough) edge(item.ida.fallthrough, "encoded-fallthrough");
  }
  for (const auto &item : source.events.edges)
  {
    EvidenceViewRow row{{"target", view_hex(item.to)}, {"transfer_kind", view_hex(uint8_t(item.kind))},
        {"truth", "witness"}, {"assumption", "observed transfer for this run; not a unique-target proof"}};
    event("transfer", item.run_id, item.seed, item.sequence, item.from, row);
    row.insert({{"kind", "observed-transfer"}, {"site", view_hex(item.from)},
        {"run", view_hex(item.run_id)}, {"seed", view_hex(item.seed)}, {"sequence", view_hex(item.sequence)}});
    if (observed++ < EvidenceView::edge_limit / 2) view.edges.push_back(std::move(row));
    else ++view.omitted["observed_edges"];
  }
  for (const auto &item : source.events.allocations)
  {
    EvidenceViewRow row{{"allocation", view_hex(item.id)}, {"generation", view_hex(item.generation)},
        {"address", view_hex(item.address)}, {"size", view_hex(item.size)},
        {"context", view_hex(item.context)}, {"callee", view_hex(item.callee)}, {"allocation_site", view_hex(item.site)},
        {"occurrence", view_hex(item.occurrence)}, {"allocated", view_hex(item.allocated)},
        {"released", view_hex(item.released)}, {"live", item.live ? "true" : "false"}};
    event("allocate", item.run_id, item.seed, item.allocated, item.site, row);
    // The lifetime ledger records release order, not the freeing callsite.
    if (!item.live) event("release", item.run_id, item.seed, item.released, 0, row);
    row.insert({{"site", view_hex(item.site)}, {"run", view_hex(item.run_id)}, {"seed", view_hex(item.seed)}});
    bounded(view.lifetimes, EvidenceView::lifetime_limit, "lifetimes", std::move(row));
  }
  for (const auto &item : source.events.uses)
    event("use", item.run_id, item.seed, item.sequence, item.site,
        {{"allocation", view_hex(item.allocation_id)}, {"generation", view_hex(item.generation)},
         {"address", view_hex(item.address)}, {"context", view_hex(item.context)},
         {"callee", view_hex(item.callee)}, {"occurrence", view_hex(item.occurrence)},
         {"argument", std::to_string(item.argument)}, {"scope", view_hex(uint8_t(item.scope))},
         {"offset", std::to_string(item.offset)}, {"status", view_hex(uint8_t(item.status))},
         {"producer", item.producer == UseProducer::MODELED_ARGUMENT ? "modeled-argument" : "executed-read"},
         {"model_kind", view_hex(item.model_kind)}, {"observed_size", view_hex(item.observed_size)},
         {"captured_size", view_hex(item.bytes.size())}, {"bytes_hex", view_bytes(item.bytes)},
         {"display_truncated", item.bytes.size() > 64 ? "true" : "false"}});
  for (const auto &item : source.events.data)
    event("memory", item.run_id, item.seed, item.sequence, item.from,
        {{"address", view_hex(item.addr)}, {"size", view_hex(item.size)},
         {"access_kind", std::to_string(item.kind)}, {"scope", view_hex(uint8_t(item.scope))},
         {"hook_low64", view_hex(item.value)}});
  for (const auto &item : source.events.execution)
    event("execute", item.run_id, item.seed, item.sequence, item.pc, {{"size", view_hex(item.size)}});
  for (const auto &item : source.events.states)
  {
    EvidenceViewRow row{{"source", view_hex(item.source)}, {"state_kind", view_hex(uint8_t(item.kind))}};
    for (size_t i = 0; i < std::min<size_t>(32, item.regs.size()); ++i)
      row["reg_" + std::to_string(item.regs[i].reg)] = view_hex(item.regs[i].value)
          + "/" + std::to_string(item.regs[i].width) + "B";
    row["registers_omitted"] = std::to_string(item.regs.size() > 32 ? item.regs.size() - 32 : 0);
    event("state", item.run_id, item.seed, item.sequence, item.pc, std::move(row));
  }
  for (const auto &item : source.runs)
  {
    const auto &outcome = item.outcome;
    bounded(view.runs, EvidenceView::run_limit, "runs",
        {{"run", view_hex(item.provenance.run_id)}, {"seed", view_hex(item.provenance.seed)},
         {"data_trace_complete", outcome.data_trace_complete ? "true" : "false"},
         {"data_trace_truncated", outcome.data_trace_truncated ? "true" : "false"},
         {"data_trace_filtered", outcome.data_trace_filtered ? "true" : "false"},
         {"ran", item.ran ? "true" : "false"}, {"returned", outcome.returned ? "true" : "false"},
         {"kind", hybrid_emu_outcome_name(outcome)},
         {"stop_valid", outcome.stop_valid ? "true" : "false"}, {"stop_reason", std::to_string(outcome.stop_reason)},
         {"stop_reason_name", hybrid_rax_stop_reason_name(outcome.stop_reason)},
         {"stop_status", std::to_string(outcome.stop_status)}, {"site", view_hex(outcome.stop_pc)},
         {"instructions", view_hex(outcome.instruction_count)},
         {"boundary", outcome.function_boundary ? "true" : "false"},
         {"boundary_source", view_hex(outcome.function_boundary_source)},
         {"boundary_target", view_hex(outcome.function_boundary_target)},
         {"unmodeled_external", outcome.unmodeled_external ? "true" : "false"},
         {"environment_failure", outcome.environment_model_failure ? "true" : "false"},
         {"permission_violation", outcome.permission_violation ? "true" : "false"},
         {"cancelled", outcome.cancelled ? "true" : "false"},
         {"escaped_image", outcome.escaped_image ? "true" : "false"},
         {"modeled", outcome.external_model_used ? "true" : "false"},
         {"synthetic_entry", outcome.synthetic_entry_context ? "true" : "false"},
         {"memory_observation_available", outcome.memory_observation_available ? "true" : "false"},
         {"context_complete", outcome.consumed_context_complete ? "true" : "false"},
         {"temporal_complete", outcome.temporal_capture_complete ? "true" : "false"},
         {"temporal_truncated", outcome.temporal_capture_truncated ? "true" : "false"}});
  }
  std::set<uint64_t> sites;
  for (const auto &item : source.branches)
  {
    sites.insert(item.instruction);
    event("branch", item.provenance.run_id, item.provenance.seed, item.sequence, item.instruction,
        {{"target", view_hex(item.observed_successor)}, {"encoded_target", view_hex(item.encoded_target)},
         {"fallthrough", view_hex(item.fallthrough)}, {"disposition", view_hex(uint8_t(item.disposition))},
         {"context_complete", item.consumed_context_complete ? "true" : "false"}});
  }
  for (uint64_t site : sites)
    for (bool taken : {false, true})
    {
      if (view.claims.size() >= EvidenceView::claim_limit) { ++view.omitted["claims"]; continue; }
      const auto claim = source.check_branch_claim(site, taken);
      bounded(view.claims, EvidenceView::claim_limit, "claims",
          {{"site", view_hex(site)}, {"expected_taken", taken ? "true" : "false"},
           {"verdict", hybrid_branch_verdict_name(claim.verdict)},
           {"matching", std::to_string(claim.matching)}, {"opposing", std::to_string(claim.opposing)},
           {"opposing_context_complete", std::to_string(claim.opposing_context_complete)},
           {"other", std::to_string(claim.other)},
           {"falsifies_claim", claim.falsifies_universal_claim() ? "true" : "false"},
           {"assumption", "hypothetical branch claim; agreement is not a universal proof"}});
    }
  for (auto &item : retained) view.events.push_back(std::move(item.second));
  const auto key = [](const EvidenceViewRow &row) {
    return std::make_tuple(std::stoull(row.at("run"), nullptr, 16),
        std::stoull(row.at("seed"), nullptr, 16), std::stoull(row.at("sequence"), nullptr, 16), row.at("kind"));
  };
  std::stable_sort(view.events.begin(), view.events.end(), [&](const auto &a, const auto &b) { return key(a) < key(b); });
  return view;
}

// Values produced by the projection are ASCII (including exact bytes as hex).
inline std::string evidence_view_json(const TargetEvidence &source, const EvidenceView &view,
                                      bool fresh, int64_t database_id, uint64_t revision = 0)
{
  const auto quote = inspection_json_quote;
  std::ostringstream out;
  out << "{\"schema\":1,\"available\":true,\"fresh\":" << (fresh ? "true" : "false")
      << ",\"database\":" << quote(std::to_string(database_id))
      << ",\"revision\":" << quote(view_hex(revision))
      << ",\"function\":" << quote(view_hex(source.scope.function_start))
      << ",\"generation\":" << quote(view_hex(source.scope.generation))
      << ",\"function_hash\":" << quote(view_hex(source.scope.function_hash))
      << ",\"image_hash\":" << quote(view_hex(source.scope.image_hash))
      << ",\"ticket\":" << quote(view_hex(source.scope.ticket))
      << ",\"static_truncated\":" << (source.summary.static_analysis_truncated ? "true" : "false");
  const auto rows = [&](const char *name, const std::vector<EvidenceViewRow> &items) {
    inspection_json_rows(out, name, items);
  };
  rows("edges", view.edges); rows("events", view.events); rows("lifetimes", view.lifetimes);
  rows("runs", view.runs); rows("claims", view.claims);
  out << ",\"omitted\":{";
  bool first = true;
  for (const auto &item : view.omitted)
  { if (!first) out << ','; first = false; out << quote(item.first) << ':' << item.second; }
  out << "}}";
  return out.str();
}
} // namespace chernobog::hybrid
