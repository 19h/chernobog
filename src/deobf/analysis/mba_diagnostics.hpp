#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace chernobog::mba_diagnostics
{

// Outcomes of actual catalog attempts, not diagnoses of a missing identity,
// reaching definition or alias. No additional matcher or solver is invoked.
enum class Outcome
{
    NoAst,
    NoIndexedPattern,
    StructuralMismatch,
    CandidateConstraint,
    ConstantConstraint,
    ReplacementUnavailable,
    InstanceDisproved,
    InstanceUnsupported,
    InstanceUnknown,
    CatalogApplied,
    Count,
};

constexpr size_t outcome_count = static_cast<size_t>(Outcome::Count);
constexpr size_t sample_limit = 64;
constexpr size_t detail_byte_limit = 256;
constexpr size_t rule_byte_limit = 128;
const char *outcome_name(Outcome outcome);

struct Site
{
    uint64_t entry = 0, source = 0;
    int maturity = 0, block = 0, opcode = 0, width_bytes = 0;
};

struct Sample
{
    Site site;
    Outcome outcome = Outcome::NoAst;
    uint64_t indexed_patterns = 0, structural_matches = 0;
    uint64_t candidate_rejections = 0, constant_rejections = 0;
    std::string detail, rule;
    uint64_t count = 0;
};

struct Snapshot
{
    std::array<uint64_t, outcome_count> counts{};
    uint64_t events = 0, unrecorded = 0;
    std::vector<Sample> samples;
};

// One bounded process-local inventory. Repeated retained keys increment their
// samples even after the quota fills. Every event contributes to its outcome;
// events without a retained key contribute to unrecorded. Snapshots own data.
void record(Outcome outcome, Site site, uint64_t indexed_patterns, uint64_t structural_matches,
            uint64_t candidate_rejections, uint64_t constant_rejections,
            std::string_view detail = {}, std::string_view rule = {});
Snapshot snapshot();
void reset();

} // namespace chernobog::mba_diagnostics
