#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>
#include <utility>

namespace chernobog::mba_smt
{
namespace limits
{
inline constexpr size_t blocks = 64;
inline constexpr size_t statements = 256;
inline constexpr size_t storage_regions = 64;
inline constexpr size_t expression_visits = 512;
inline constexpr unsigned expression_depth = 64;
inline constexpr size_t synthesis_inputs = 8;
inline constexpr size_t replacement_operations = 8;
inline constexpr size_t division_cost = 8;
inline constexpr unsigned invariant_degree = 2;
inline constexpr size_t invariant_variables = 4;
inline constexpr unsigned normal_budget_ms = 1000;
inline constexpr unsigned deep_budget_ms = 30000;
} // namespace limits

enum class Op
{
    Constant,
    Variable,
    Add,
    Sub,
    Mul,
    UnsignedDivide,
    And,
    Or,
    Xor,
    Not,
    Neg,
    ZeroExtend,
    SignExtend,
    Low,
    High,
    Shl,
    Shr,
    Sar,
    Equal,
    NotEqual,
    UnsignedLess,
    SignedLess,
    Load,
};
struct Expression;
using Term = std::shared_ptr<const Expression>;

struct Expression
{
    Op op;
    unsigned bits;
    uint64_t value;
    Term left;
    Term right;
};

Term constant(uint64_t value, unsigned bits);
Term variable(size_t index, unsigned bits);
Term expression(Op op, Term left, Term right = {}, unsigned bits = 0);
Term load(Term address, unsigned bits);
size_t cost(const Term &term);
std::string key(const Term &term);
std::vector<size_t> variables(const Term &term);

struct Statement
{
    enum class Kind
    {
        Assign,
        Store,
        Havoc
    } kind = Kind::Assign;
    size_t destination = 0;
    unsigned offset = 0;
    Term value;
    Term address;
    // Empty destinations means all registers; memory is always invalidated.
    std::vector<size_t> spoiled;
    static Statement assign(size_t destination, Term value);
    static Statement store(Term address, Term value);
    static Statement havoc(std::vector<size_t> spoiled = {});
};

struct Edge
{
    size_t target;
    Term condition;
    bool inverted = false;
};

struct Block
{
    std::vector<Statement> statements;
    std::vector<Edge> edges;
};

struct Program
{
    unsigned address_bits = 64;
    bool big_endian = false;
    std::vector<unsigned> widths;
    std::vector<size_t> readonly;
    std::vector<Term> available;
    std::vector<std::pair<size_t, size_t>> targets;
    std::vector<Block> blocks;
    size_t entry = 0;
};

bool validate(const Program &program);

enum class Backend
{
    Legacy,
    Cobra
};
enum class Profile
{
    Normal,
    Deep
};
enum class RejectReason
{
    None,
    PostProofExpiry,
    BudgetExhaustedPreFlight,
    PostProofDeadlineOrCancel,
    EmittedDestinationOrFrameMismatch,
    StaleSnapshot,
    CallbackFailure,
};

struct SnapshotToken
{
    uint64_t generation = 0;
    uint64_t mutation_epoch = 0;
    bool operator==(const SnapshotToken &other) const noexcept
    {
        return generation == other.generation && mutation_epoch == other.mutation_epoch;
    }
    bool operator!=(const SnapshotToken &other) const noexcept { return !(*this == other); }
};

Backend selected_backend() noexcept;
const char *backend_diagnostic() noexcept;

struct Options
{
    Backend backend = selected_backend();
    Profile profile = Profile::Normal;
    SnapshotToken snapshot;
    std::chrono::steady_clock::time_point absolute_deadline =
        std::chrono::steady_clock::time_point::max();
    unsigned budget_ms = limits::normal_budget_ms;
    unsigned query_ms = 250;
    unsigned resource_limit = 10000000;
    size_t max_invariants = 256;
    size_t max_candidates = 4096;
    std::function<bool()> cancelled;
    static Options deep();
};
enum class Verdict
{
    Verified,
    Disproved,
    Unsupported,
    Unknown,
    Exhausted
};

struct CobraStatistics
{
    size_t calls = 0, candidates = 0, unchanged = 0, unsupported = 0, exhausted = 0, failures = 0;
    size_t proved = 0, emitted_proved = 0, applied = 0, frame_rejections = 0;
    size_t raw_leaves = 0, input_nodes = 0, output_nodes = 0, raw_support = 0,
           canonical_support = 0;
    size_t scratch_peak_bytes = 0;
    uint64_t generation_ns = 0, candidate_proof_ns = 0, emission_ns = 0, emitted_proof_ns = 0;
    uint64_t overshoot_ns = 0;
    uint64_t proved_widths = 0;
    unsigned last_status = 0, last_reason = 0;
    bool spot_check = false;
};
struct Statistics
{
    CobraStatistics cobra;
    size_t candidates = 0;
    size_t verified = 0;
    size_t applied = 0;
    size_t disproved = 0;
    size_t unsupported = 0;
    size_t unknown = 0;
    size_t invariant_candidates = 0;
    size_t invariants = 0;
    size_t invariants_rejected = 0;
    size_t exhausted = 0;
    uint64_t elapsed_ns = 0;
    uint64_t deadline_overshoot_ns = 0;
    RejectReason cancel_stage = RejectReason::None;
    size_t rejected_mutations = 0;
};

class ProofReceipt
{
    friend class Analysis;
    uint64_t analysis_ = 0;
    SnapshotToken snapshot_;
    size_t block_ = 0, statement_ = 0;
    Term source_, candidate_, emitted_;
    bool cobra_ = false;

  public:
    bool from_cobra() const noexcept { return cobra_; }
    bool has_emitted_proof() const noexcept { return bool(emitted_); }
};

struct Proposal
{
    size_t block;
    size_t statement;
    Term replacement;
    SnapshotToken snapshot;
    std::shared_ptr<const ProofReceipt> proof;
};

// One immutable CFG snapshot. Every proposal, including re-emitted code, must
// be checked here before the owning live microcode generation is mutated.
class Analysis
{
    struct Impl;
    std::unique_ptr<Impl> impl_;
    Verdict verify_at(size_t block, size_t statement, const Term &replacement, const char *purpose);

  public:
    Analysis(Program program, Options options = {});
    ~Analysis();
    Analysis(const Analysis &) = delete;
    Analysis &operator=(const Analysis &) = delete;
    std::vector<Proposal> run();
    // A model proposes one value; a universal mismatch check must prove it.
    // This avoids expression enumeration when a caller only needs a constant.
    Term constant_value(size_t block, size_t statement);
    Verdict verify(size_t block, size_t statement, const Term &replacement);
    std::shared_ptr<const ProofReceipt> prove_candidate(size_t block, size_t statement,
                                                        const Term &candidate,
                                                        bool cobra_origin = false);
    std::shared_ptr<const ProofReceipt> prove_emission(const ProofReceipt &candidate,
                                                       const Term &emitted);
    bool eligible_for_commit(const ProofReceipt &receipt, bool legacy_deadline_exempt,
                             const std::function<bool()> &unchanged);
    // The tagged legacy fallback may waive deadline expiry only after both
    // proofs completed in time. Cancellation is never exempt.
    bool eligible_for_commit(bool legacy_deadline_exempt = false,
                             const std::function<bool()> &unchanged = {});
    SnapshotToken snapshot() const noexcept;
    void reject_mutation(RejectReason reason);
    void record_emission(uint64_t elapsed_ns);
    const Statistics &statistics() const;
};
void accumulate_statistics(Statistics &total, const Statistics &attempt);
} // namespace chernobog::mba_smt
