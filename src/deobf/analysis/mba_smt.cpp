#include "mba_smt.hpp"
#include "mba_smt_internal.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <limits>
#include <set>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <z3++.h>

namespace chernobog::mba_smt
{
namespace
{
bool valid_bit_width(unsigned bits) { return bits >= 8 && bits <= 64 && bits % 8 == 0; }

bool is_unary_operation(Op op)
{
    return op == Op::Not || op == Op::Neg || op == Op::Low || op == Op::High ||
           op == Op::ZeroExtend || op == Op::SignExtend;
}

bool is_comparison(Op op)
{
    return op == Op::Equal || op == Op::NotEqual || op == Op::UnsignedLess || op == Op::SignedLess;
}

bool validate_term(const Term &term, const Program &program, size_t &visits, unsigned depth = 0)
{
    if (!term || !valid_bit_width(term->bits) || ++visits > limits::expression_visits ||
        depth > limits::expression_depth)
    {
        return false;
    }

    if (term->op == Op::Constant)
    {
        return !term->left && !term->right;
    }
    if (term->op == Op::Variable)
    {
        return term->value < program.widths.size() &&
               program.widths[static_cast<size_t>(term->value)] == term->bits && !term->left &&
               !term->right;
    }

    if (!validate_term(term->left, program, visits, depth + 1))
    {
        return false;
    }

    const unsigned input_width = term->left->bits;
    if (term->op == Op::UnsignedDivide &&
        (!term->right || term->right->op != Op::Constant || term->right->value == 0))
    {
        return false;
    }
    if (term->op == Op::Load)
    {
        return input_width == program.address_bits && !term->right;
    }
    if (is_unary_operation(term->op))
    {
        if (term->right)
        {
            return false;
        }
        if (term->op == Op::Low || term->op == Op::High)
        {
            return input_width >= term->bits;
        }
        if (term->op == Op::ZeroExtend || term->op == Op::SignExtend)
        {
            return input_width <= term->bits;
        }
        return input_width == term->bits;
    }

    if (!validate_term(term->right, program, visits, depth + 1))
    {
        return false;
    }
    if (term->op == Op::UnsignedDivide && term->right->bits < 64 &&
        (term->right->value >> term->right->bits) != 0)
    {
        return false;
    }
    if (term->op == Op::Shl || term->op == Op::Shr || term->op == Op::Sar)
    {
        return input_width == term->bits && term->right->bits == 8;
    }

    const bool matching_inputs = input_width == term->right->bits;
    const bool valid_result = is_comparison(term->op) ? term->bits == 8 : input_width == term->bits;
    return matching_inputs && valid_result;
}

unsigned expression_degree(const Term &term)
{
    constexpr unsigned unsupported_degree = limits::invariant_degree + 1;

    if (!term)
    {
        return unsupported_degree;
    }
    if (term->op == Op::Constant)
    {
        return 0;
    }
    if (term->op == Op::Variable || term->op == Op::Load)
    {
        return 1;
    }
    if (term->op == Op::Low || term->op == Op::High)
    {
        return expression_degree(term->left) == 1 ? 1 : unsupported_degree;
    }
    if (term->op == Op::Neg)
    {
        return expression_degree(term->left);
    }
    if (term->op == Op::Add || term->op == Op::Sub)
    {
        return std::max(expression_degree(term->left), expression_degree(term->right));
    }
    if (term->op == Op::Mul)
    {
        const unsigned degree = expression_degree(term->left) + expression_degree(term->right);
        return std::min(degree, unsupported_degree);
    }
    return unsupported_degree;
}

void collect_term_literals(const Term &term, std::set<uint64_t> &values, unsigned bits)
{
    if (!term)
    {
        return;
    }
    if (term->op == Op::Constant && term->bits == bits)
    {
        values.insert(term->value);
    }
    collect_term_literals(term->left, values, bits);
    collect_term_literals(term->right, values, bits);
}
} // namespace

Term constant(uint64_t value, unsigned bits)
{
    return std::make_shared<Expression>(Expression{Op::Constant, bits, value, {}, {}});
}

Term variable(size_t index, unsigned bits)
{
    return std::make_shared<Expression>(Expression{Op::Variable, bits, uint64_t(index), {}, {}});
}

Term expression(Op op, Term left, Term right, unsigned bits)
{
    if (!bits)
    {
        bits = is_comparison(op) ? 8 : (left ? left->bits : 0);
    }
    return std::make_shared<Expression>(Expression{op, bits, 0, std::move(left), std::move(right)});
}

Term load(Term address, unsigned bits)
{
    return expression(Op::Load, std::move(address), {}, bits);
}

size_t cost(const Term &term)
{
    if (!term || term->op == Op::Constant || term->op == Op::Variable)
    {
        return 0;
    }
    const size_t operation_cost = term->op == Op::UnsignedDivide ? limits::division_cost : 1;
    return operation_cost + cost(term->left) + cost(term->right);
}

std::string key(const Term &term)
{
    if (!term)
    {
        return "_";
    }
    return std::to_string(unsigned(term->op)) + ":" + std::to_string(term->bits) + ":" +
           std::to_string(term->value) + "(" + key(term->left) + "," + key(term->right) + ")";
}

std::vector<size_t> variables(const Term &term)
{
    std::set<size_t> result;
    std::function<void(const Term &)> walk = [&](const Term &node)
    {
        if (!node)
        {
            return;
        }
        if (node->op == Op::Variable)
        {
            result.insert(size_t(node->value));
        }
        walk(node->left);
        walk(node->right);
    };
    walk(term);
    return {result.begin(), result.end()};
}

Statement Statement::assign(size_t destination, Term value)
{
    Statement statement;
    statement.destination = destination;
    statement.value = std::move(value);
    return statement;
}

Statement Statement::store(Term address, Term value)
{
    Statement statement;
    statement.kind = Kind::Store;
    statement.address = std::move(address);
    statement.value = std::move(value);
    return statement;
}

Statement Statement::havoc(std::vector<size_t> spoiled)
{
    Statement statement;
    statement.kind = Kind::Havoc;
    statement.spoiled = std::move(spoiled);
    return statement;
}

Options Options::deep()
{
    Options options;
    options.profile = Profile::Deep;
    options.budget_ms = limits::deep_budget_ms;
    options.query_ms = 2000;
    options.resource_limit = 10000000;
    return options;
}

bool validate(const Program &program)
{
    if ((program.address_bits != 32 && program.address_bits != 64) || program.blocks.empty() ||
        program.entry >= program.blocks.size() || program.blocks.size() > limits::blocks ||
        program.widths.size() > limits::storage_regions)
    {
        return false;
    }
    for (auto bits : program.widths)
    {
        if (!valid_bit_width(bits))
        {
            return false;
        }
    }
    size_t instructions = 0;
    for (const auto &block : program.blocks)
    {
        instructions += block.statements.size();
        if (instructions > limits::statements)
        {
            return false;
        }
        for (const auto &statement : block.statements)
        {
            size_t visits = 0;
            if (statement.kind == Statement::Kind::Havoc)
            {
                for (auto id : statement.spoiled)
                {
                    if (id >= program.widths.size())
                    {
                        return false;
                    }
                }
                continue;
            }
            if (!validate_term(statement.value, program, visits))
            {
                return false;
            }
            if (statement.kind == Statement::Kind::Assign)
            {
                if (statement.destination >= program.widths.size() || statement.offset % 8 != 0 ||
                    statement.offset + statement.value->bits >
                        program.widths[statement.destination] ||
                    std::find(program.readonly.begin(), program.readonly.end(),
                              statement.destination) != program.readonly.end())
                {
                    return false;
                }
            }
            else if (!validate_term(statement.address, program, visits) ||
                     statement.address->bits != program.address_bits)
            {
                return false;
            }
        }
        for (const auto &e : block.edges)
        {
            size_t visits = 0;
            if (e.target >= program.blocks.size() ||
                (e.condition && !validate_term(e.condition, program, visits)))
            {
                return false;
            }
        }
    }
    for (auto id : program.readonly)
    {
        if (id >= program.widths.size())
        {
            return false;
        }
    }
    for (const auto &term : program.available)
    {
        size_t visits = 0;
        if (!validate_term(term, program, visits))
        {
            return false;
        }
    }
    return true;
}

bool same_program(const Program &left, const Program &right)
{
    const auto same_term = [](const Term &a, const Term &b)
    {
        size_t visits = 0;
        const auto compare = [&](const auto &self, const Term &x, const Term &y,
                                 unsigned depth) -> bool
        {
            if (!x || !y)
                return !x && !y;
            if (++visits > limits::expression_visits || depth > limits::expression_depth)
                return false;
            return x->op == y->op && x->bits == y->bits && x->value == y->value &&
                   self(self, x->left, y->left, depth + 1) &&
                   self(self, x->right, y->right, depth + 1);
        };
        return compare(compare, a, b, 0);
    };
    if (left.address_bits != right.address_bits || left.big_endian != right.big_endian ||
        left.widths != right.widths || left.readonly != right.readonly ||
        left.targets != right.targets || left.entry != right.entry ||
        left.available.size() != right.available.size() ||
        left.blocks.size() != right.blocks.size())
        return false;
    for (size_t i = 0; i < left.available.size(); ++i)
        if (!same_term(left.available[i], right.available[i]))
            return false;
    for (size_t i = 0; i < left.blocks.size(); ++i)
    {
        const auto &a = left.blocks[i], &b = right.blocks[i];
        if (a.statements.size() != b.statements.size() || a.edges.size() != b.edges.size())
            return false;
        for (size_t j = 0; j < a.statements.size(); ++j)
        {
            const auto &x = a.statements[j], &y = b.statements[j];
            if (x.kind != y.kind || x.destination != y.destination || x.offset != y.offset ||
                x.spoiled != y.spoiled || !same_term(x.value, y.value) ||
                !same_term(x.address, y.address))
                return false;
        }
        for (size_t j = 0; j < a.edges.size(); ++j)
        {
            const auto &x = a.edges[j], &y = b.edges[j];
            if (x.target != y.target || x.inverted != y.inverted ||
                !same_term(x.condition, y.condition))
                return false;
        }
    }
    return true;
}

namespace detail
{
bool validate_expression(const Term &term, const Program &program)
{
    size_t visits = 0;
    return validate_term(term, program, visits);
}

unsigned polynomial_degree(const Term &term) { return expression_degree(term); }

void collect_literals(const Term &term, unsigned bit_width, std::set<uint64_t> &values)
{
    collect_term_literals(term, values, bit_width);
}
} // namespace detail

struct Analysis::Impl
{
    Impl(Program input_program, Options options)
        : program(std::move(input_program)), session(std::move(options), statistics),
          symbolic(program, session)
    {
    }

    bool prepare()
    {
        if (preparation_attempted)
        {
            return invariants.has_value();
        }

        preparation_attempted = true;
        if (!session.has_budget())
        {
            session.record_expiry(RejectReason::BudgetExhaustedPreFlight);
            return false;
        }
        if (!validate(program))
        {
            record_diagnostic(statistics, session.options, DiagnosticStage::Extraction,
                              DiagnosticOutcome::ExtractionRefused);
            return false;
        }

        symbolic.build();
        detail::InvariantInference inference(symbolic);
        invariants = inference.run();
        return true;
    }

    bool is_rewrite_site(size_t block, size_t statement) const
    {
        if (program.blocks[block].statements[statement].kind != Statement::Kind::Assign)
        {
            return false;
        }

        if (program.targets.empty())
        {
            return true;
        }

        const auto site = std::make_pair(block, statement);
        return std::find(program.targets.begin(), program.targets.end(), site) !=
               program.targets.end();
    }

    std::vector<std::pair<size_t, size_t>> prioritized_sites() const
    {
        std::vector<std::pair<size_t, size_t>> sites;
        for (size_t block = 0; block < program.blocks.size(); ++block)
        {
            for (size_t statement = 0; statement < program.blocks[block].statements.size();
                 ++statement)
            {
                if (is_rewrite_site(block, statement))
                {
                    sites.emplace_back(block, statement);
                }
            }
        }

        std::stable_sort(sites.begin(), sites.end(),
                         [&](const auto &left, const auto &right)
                         {
                             const Term &left_value =
                                 program.blocks[left.first].statements[left.second].value;
                             const Term &right_value =
                                 program.blocks[right.first].statements[right.second].value;
                             return cost(left_value) > cost(right_value);
                         });
        return sites;
    }

    inline static std::atomic<uint64_t> next_identity{1};
    const uint64_t identity = next_identity.fetch_add(1, std::memory_order_relaxed);
    Program program;
    Statistics statistics;
    detail::SolverSession session;
    detail::SymbolicProgram symbolic;
    std::optional<detail::BlockInvariants> invariants;
    bool preparation_attempted = false;
};

Analysis::Analysis(Program program, Options options)
    : impl_(std::make_unique<Impl>(std::move(program), std::move(options)))
{
}

Analysis::~Analysis() = default;

std::vector<Proposal> Analysis::run(const std::function<bool(const Proposal &)> &can_emit)
{
    try
    {
        if (!impl_->prepare())
        {
            ++impl_->statistics.unsupported;
            return {};
        }

        for (const auto &[block, statement] : impl_->prioritized_sites())
        {
            impl_->session.diagnostic_block = block;
            impl_->session.diagnostic_statement = statement;
            impl_->session.diagnostic_region =
                diagnostic_region_key(impl_->program.blocks[block].statements[statement].value);
            if (!impl_->session.has_budget())
            {
                impl_->session.record_expiry(RejectReason::BudgetExhaustedPreFlight);
                return {};
            }

            // Invariant-backed constants are a retained contextual proof path,
            // independent of algebraic candidate generation. In particular,
            // CoBRA intentionally does not admit loads or synthesize loop facts.
            // Run this before CoBRA; a failed CoBRA search never reruns legacy.
            if ((impl_->session.options.backend == Backend::Cobra ||
                 impl_->session.options.contextual_constants_only) &&
                !impl_->invariants->at(block).empty())
            {
                if (Term candidate = constant_value(block, statement))
                {
                    if (cost(candidate) <
                        cost(impl_->program.blocks[block].statements[statement].value))
                    {
                        if (auto proof = prove_candidate(block, statement, candidate))
                        {
                            Proposal proposal{block, statement, std::move(candidate),
                                              impl_->session.options.snapshot, std::move(proof)};
                            if (!can_emit || can_emit(proposal))
                                return {std::move(proposal)};
                            continue;
                        }
                    }
                }
            }

            if (impl_->session.options.contextual_constants_only)
                continue;

            detail::CandidateSynthesis synthesis(impl_->symbolic, *impl_->invariants, block,
                                                 statement);
            Term replacement = synthesis.run();
            if (!replacement)
            {
                continue;
            }

            const auto proof =
                prove_candidate(block, statement, replacement, synthesis.from_cobra());
            if (proof)
            {
                Proposal proposal{block, statement, std::move(replacement),
                                  impl_->session.options.snapshot, proof};
                if (!can_emit || can_emit(proposal))
                    return {std::move(proposal)};
            }
        }
    }
    catch (const std::exception &)
    {
        ++impl_->statistics.unsupported;
    }

    impl_->session.has_budget();
    return {};
}

namespace
{
DiagnosticOutcome diagnostic_verdict(Verdict verdict)
{
    switch (verdict)
    {
    case Verdict::Verified:
        return DiagnosticOutcome::Verified;
    case Verdict::Disproved:
        return DiagnosticOutcome::Disproved;
    case Verdict::Unknown:
        return DiagnosticOutcome::Unknown;
    case Verdict::Exhausted:
        return DiagnosticOutcome::Exhausted;
    default:
        return DiagnosticOutcome::ExtractionRefused;
    }
}
}
Term Analysis::constant_value(size_t block, size_t statement)
{
    impl_->session.diagnostic_block = block;
    impl_->session.diagnostic_statement = statement;
    impl_->session.diagnostic_region =
        block < impl_->program.blocks.size() &&
                statement < impl_->program.blocks[block].statements.size()
            ? diagnostic_region_key(impl_->program.blocks[block].statements[statement].value)
            : 0;
    try
    {
        if (!impl_->prepare() || block >= impl_->program.blocks.size() ||
            statement >= impl_->program.blocks[block].statements.size() ||
            !impl_->is_rewrite_site(block, statement))
        {
            return {};
        }

        auto &symbolic = impl_->symbolic;
        auto &session = impl_->session;
        const auto &assignment = impl_->program.blocks[block].statements[statement];
        const auto &state = symbolic.before_statement(block, statement);
        // Caller expansion proofs precede algebraic candidate search. Prepare
        // unconditional word lemmas before constant and fallback queries too;
        // later synthesis reuses their same-session universal proof receipts.
        detail::prepare_algebraic_proofs(symbolic, state, assignment.value);
        const z3::expr value = symbolic.evaluate(assignment.value, state);
        z3::solver solver(session.context);
        solver.add(symbolic.conjunction(impl_->invariants->at(block), symbolic.block_entry(block)));
        if (session.check(solver, "MBA constant proposal feasibility") != z3::sat)
        {
            return {};
        }

        uint64_t literal = 0;
        if (!solver.get_model().eval(value, true).is_numeral_u64(literal))
        {
            return {};
        }
        const Term candidate = constant(literal, assignment.value->bits);
        ++impl_->statistics.candidates;
        const auto verdict =
            detail::verify_replacement(symbolic, *impl_->invariants, block, statement, candidate);
        record_diagnostic(impl_->statistics, impl_->session.options, DiagnosticStage::ContextProof,
                          diagnostic_verdict(verdict), block, statement,
                          impl_->session.diagnostic_region);
        if (verdict == Verdict::Verified)
        {
            return candidate;
        }
    }
    catch (const std::exception &)
    {
        ++impl_->statistics.unsupported;
    }
    return {};
}

Verdict Analysis::verify(size_t block, size_t statement, const Term &replacement)
{
    const auto verdict =
        verify_at(block, statement, replacement, "MBA contextual candidate mismatch");
    record_diagnostic(impl_->statistics, impl_->session.options, DiagnosticStage::ContextProof,
                      diagnostic_verdict(verdict), block, statement,
                      impl_->session.diagnostic_region);
    return verdict;
}

Verdict Analysis::verify_at(size_t block, size_t statement, const Term &replacement,
                            const char *purpose)
{
    impl_->session.diagnostic_block = block;
    impl_->session.diagnostic_statement = statement;
    impl_->session.diagnostic_region =
        block < impl_->program.blocks.size() &&
                statement < impl_->program.blocks[block].statements.size()
            ? diagnostic_region_key(impl_->program.blocks[block].statements[statement].value)
            : 0;
    try
    {
        if (!impl_->session.has_budget())
        {
            ++impl_->statistics.exhausted;
            return Verdict::Exhausted;
        }

        if (!impl_->prepare())
        {
            return Verdict::Unsupported;
        }

        const auto verdict = detail::verify_replacement(impl_->symbolic, *impl_->invariants, block,
                                                        statement, replacement, purpose);
        if (verdict == Verdict::Verified && !impl_->session.has_budget())
        {
            impl_->session.record_expiry(RejectReason::PostProofExpiry);
            return Verdict::Exhausted;
        }
        return verdict;
    }
    catch (const std::exception &)
    {
        ++impl_->statistics.unsupported;
        return Verdict::Unsupported;
    }
}

std::shared_ptr<const ProofReceipt>
Analysis::prove_candidate(size_t block, size_t statement, const Term &candidate, bool cobra_origin)
{
    const auto started = impl_->session.now();
    const auto verdict =
        verify_at(block, statement, candidate, "MBA contextual candidate mismatch");
    record_diagnostic(
        impl_->statistics, impl_->session.options, DiagnosticStage::CandidateProof,
        diagnostic_verdict(verdict), block, statement,
        block < impl_->program.blocks.size() &&
                statement < impl_->program.blocks[block].statements.size()
            ? diagnostic_region_key(impl_->program.blocks[block].statements[statement].value)
            : 0);
    impl_->statistics.last_candidate_verdict = unsigned(verdict) + 1;
    if (cobra_origin)
        impl_->statistics.cobra.candidate_proof_ns += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(impl_->session.now() - started)
                .count());
    if (verdict != Verdict::Verified)
        return {};
    auto receipt = std::shared_ptr<ProofReceipt>(new ProofReceipt);
    receipt->analysis_ = impl_->identity;
    receipt->snapshot_ = snapshot();
    receipt->block_ = block;
    receipt->statement_ = statement;
    receipt->source_ = impl_->program.blocks[block].statements[statement].value;
    receipt->candidate_ = candidate;
    receipt->cobra_ = cobra_origin;
    impl_->statistics.last_receipt_cobra = cobra_origin;
    if (!impl_->session.has_budget())
    {
        impl_->session.record_expiry(RejectReason::PostProofExpiry);
        impl_->statistics.last_candidate_verdict = unsigned(Verdict::Exhausted) + 1;
        record_diagnostic(impl_->statistics, impl_->session.options,
                          DiagnosticStage::CandidateProof, DiagnosticOutcome::Exhausted, block,
                          statement, 0, 0, RejectReason::PostProofExpiry);
        return {};
    }
    return receipt;
}

std::shared_ptr<const ProofReceipt> Analysis::prove_emission(const ProofReceipt &candidate,
                                                             const Term &emitted)
{
    if (candidate.analysis_ != impl_->identity || candidate.snapshot_ != snapshot() ||
        candidate.block_ >= impl_->program.blocks.size() ||
        candidate.statement_ >= impl_->program.blocks[candidate.block_].statements.size() ||
        candidate.source_ !=
            impl_->program.blocks[candidate.block_].statements[candidate.statement_].value)
    {
        reject_mutation(RejectReason::StaleSnapshot);
        return {};
    }
    const auto started = impl_->session.now();
    const auto verdict = verify_at(candidate.block_, candidate.statement_, emitted,
                                   "MBA emitted replacement mismatch");
    impl_->statistics.last_emitted_verdict = unsigned(verdict) + 1;
    record_diagnostic(impl_->statistics, impl_->session.options, DiagnosticStage::EmittedProof,
                      diagnostic_verdict(verdict), candidate.block_, candidate.statement_,
                      diagnostic_region_key(candidate.source_));
    if (candidate.cobra_)
        impl_->statistics.cobra.emitted_proof_ns += static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(impl_->session.now() - started)
                .count());
    if (verdict != Verdict::Verified)
        return {};
    auto receipt = std::shared_ptr<ProofReceipt>(new ProofReceipt(candidate));
    receipt->emitted_ = emitted;
    if (!impl_->session.has_budget())
    {
        impl_->session.record_expiry(RejectReason::PostProofExpiry);
        impl_->statistics.last_emitted_verdict = unsigned(Verdict::Exhausted) + 1;
        record_diagnostic(impl_->statistics, impl_->session.options, DiagnosticStage::EmittedProof,
                          DiagnosticOutcome::Exhausted, candidate.block_, candidate.statement_, 0,
                          0, RejectReason::PostProofExpiry);
        return {};
    }
    if (candidate.cobra_)
    {
        ++impl_->statistics.cobra.emitted_proved;
    }
    return receipt;
}

bool Analysis::eligible_for_commit(const ProofReceipt &receipt, bool legacy_deadline_exempt,
                                   const std::function<bool()> &unchanged)
{
    impl_->session.diagnostic_block = receipt.block_;
    impl_->session.diagnostic_statement = receipt.statement_;
    impl_->session.diagnostic_region = diagnostic_region_key(receipt.source_);
    if (!receipt.emitted_ || receipt.analysis_ != impl_->identity ||
        receipt.snapshot_ != snapshot())
    {
        reject_mutation(RejectReason::StaleSnapshot);
        return false;
    }
    const bool exempt = legacy_deadline_exempt &&
                        impl_->session.options.backend == Backend::Legacy && !receipt.cobra_;
    impl_->statistics.last_receipt_cobra = receipt.cobra_;
    impl_->statistics.last_deadline_exempt = exempt;
    return eligible_for_commit(exempt, unchanged);
}

bool Analysis::eligible_for_commit(bool legacy_deadline_exempt,
                                   const std::function<bool()> &unchanged)
{
    return impl_->session.eligible_for_commit(legacy_deadline_exempt, unchanged);
}

SnapshotToken Analysis::snapshot() const noexcept { return impl_->session.options.snapshot; }

void Analysis::reject_mutation(RejectReason reason)
{
    ++impl_->statistics.rejected_mutations;
    if (reason == RejectReason::EmittedDestinationOrFrameMismatch)
        ++impl_->statistics.cobra.frame_rejections;
    impl_->statistics.cancel_stage = reason;
    record_diagnostic(impl_->statistics, impl_->session.options, DiagnosticStage::Commit,
                      DiagnosticOutcome::EmissionRejected, impl_->session.diagnostic_block,
                      impl_->session.diagnostic_statement, impl_->session.diagnostic_region, 0,
                      reason);
}

void Analysis::record_emission(uint64_t elapsed_ns)
{
    impl_->statistics.cobra.emission_ns += elapsed_ns;
}

const Statistics &Analysis::statistics() const { return impl_->statistics; }
void RegionDiagnostics::record(const DiagnosticEvent &event) noexcept
{
    const size_t index = size_t(event.outcome);
    if (index >= counts.size())
        return;
    ++counts[index];
    if (used < events.size())
        events[used++] = event;
    else
        ++unrecorded;
}
void RegionDiagnostics::accumulate(const RegionDiagnostics &other) noexcept
{
    if (this == &other)
    {
        const RegionDiagnostics copy(other);
        accumulate(copy);
        return;
    }
    for (size_t i = 0; i < counts.size(); ++i)
        counts[i] += other.counts[i];
    unrecorded += other.unrecorded;
    for (size_t i = 0; i < other.used; ++i)
        if (used < events.size())
            events[used++] = other.events[i];
        else
            ++unrecorded;
}
const char *diagnostic_phase_name(DiagnosticPhase phase) noexcept
{
    static constexpr const char *names[] = {"core",   "microcode", "calls",
                                            "memory", "control",   "catalog"};
    return size_t(phase) < std::size(names) ? names[size_t(phase)] : "unknown";
}
const char *diagnostic_stage_name(DiagnosticStage stage) noexcept
{
    static constexpr const char *names[] = {"extraction",      "generation",    "context_proof",
                                            "candidate_proof", "emitted_proof", "commit",
                                            "solver_query"};
    return size_t(stage) < std::size(names) ? names[size_t(stage)] : "unknown";
}
const char *diagnostic_outcome_name(DiagnosticOutcome outcome) noexcept
{
    static constexpr const char *names[] = {
        "extraction_refused", "no_improvement", "generated", "generation_failed", "verified",
        "disproved",          "unknown",        "exhausted", "emission_rejected", "applied"};
    return size_t(outcome) < std::size(names) ? names[size_t(outcome)] : "unknown";
}
uint64_t diagnostic_region_key(const Term &value) noexcept
{
    uint64_t hash = UINT64_C(14695981039346656037);
    size_t visits = 0;
    const auto add = [&](uint64_t word)
    {
        for (unsigned byte = 0; byte < 8; ++byte)
        {
            hash ^= (word >> (8 * byte)) & 255;
            hash *= UINT64_C(1099511628211);
        }
    };
    const auto visit = [&](const auto &self, const Term &node, unsigned depth) -> bool
    {
        if (!node)
        {
            add(0);
            return true;
        }
        if (++visits > limits::expression_visits || depth > limits::expression_depth)
            return false;
        add(1);
        add(uint64_t(node->op));
        add(node->bits);
        add(node->value);
        return self(self, node->left, depth + 1) && self(self, node->right, depth + 1);
    };
    return visit(visit, value, 0) ? hash : 0;
}
void record_diagnostic(Statistics &statistics, const Options &options, DiagnosticStage stage,
                       DiagnosticOutcome outcome, size_t block, size_t statement,
                       uint64_t region_key, unsigned generation_reason,
                       RejectReason reject_reason) noexcept
{
    DiagnosticContext context = options.diagnostic;
    try
    {
        if (options.diagnostic_context)
            context = options.diagnostic_context(block, statement);
    }
    catch (...)
    {
    }
    statistics.regions.record({context, options.snapshot, stage, outcome, block, statement,
                               region_key, generation_reason, reject_reason});
}
void Analysis::record_applied(const ProofReceipt &receipt)
{
    record_diagnostic(impl_->statistics, impl_->session.options, DiagnosticStage::Commit,
                      DiagnosticOutcome::Applied, receipt.block_, receipt.statement_,
                      diagnostic_region_key(receipt.source_));
}
void accumulate_statistics(Statistics &total, const Statistics &attempt)
{
    total.regions.accumulate(attempt.regions);
    total.candidates += attempt.candidates;
    total.verified += attempt.verified;
    total.applied += attempt.applied;
    total.disproved += attempt.disproved;
    total.unsupported += attempt.unsupported;
    total.unknown += attempt.unknown;
    total.invariant_candidates += attempt.invariant_candidates;
    total.invariants += attempt.invariants;
    total.invariants_rejected += attempt.invariants_rejected;
    total.exhausted += attempt.exhausted;
    total.rejected_mutations += attempt.rejected_mutations;
    if (attempt.last_solver_observed)
    {
        total.last_solver_observed = attempt.last_solver_observed;
        total.last_solver_usable = attempt.last_solver_usable;
    }
    total.deadline_overshoot_ns =
        std::max(total.deadline_overshoot_ns, attempt.deadline_overshoot_ns);
    if (attempt.cancel_stage != RejectReason::None)
        total.cancel_stage = attempt.cancel_stage;
    total.cobra.calls += attempt.cobra.calls;
    total.cobra.candidates += attempt.cobra.candidates;
    total.cobra.unchanged += attempt.cobra.unchanged;
    total.cobra.unsupported += attempt.cobra.unsupported;
    total.cobra.exhausted += attempt.cobra.exhausted;
    total.cobra.failures += attempt.cobra.failures;
    total.cobra.proved += attempt.cobra.proved;
    total.cobra.emitted_proved += attempt.cobra.emitted_proved;
    total.cobra.applied += attempt.cobra.applied;
    total.cobra.frame_rejections += attempt.cobra.frame_rejections;
    total.cobra.generation_ns += attempt.cobra.generation_ns;
    total.cobra.extraction_ns += attempt.cobra.extraction_ns;
    total.cobra.invocation_ns += attempt.cobra.invocation_ns;
    total.cobra.reconstruction_ns += attempt.cobra.reconstruction_ns;
    total.cobra.cleanup_ns += attempt.cobra.cleanup_ns;
    total.cobra.admitted += attempt.cobra.admitted;
    total.cobra.rejected += attempt.cobra.rejected;
    if (attempt.last_candidate_verdict)
    {
        total.last_candidate_verdict = attempt.last_candidate_verdict;
        total.last_receipt_cobra = attempt.last_receipt_cobra;
        total.last_deadline_exempt = attempt.last_deadline_exempt;
    }
    if (attempt.last_emitted_verdict)
        total.last_emitted_verdict = attempt.last_emitted_verdict;
    total.cobra.candidate_proof_ns += attempt.cobra.candidate_proof_ns;
    total.cobra.emission_ns += attempt.cobra.emission_ns;
    total.cobra.emitted_proof_ns += attempt.cobra.emitted_proof_ns;
    total.cobra.overshoot_ns = std::max(total.cobra.overshoot_ns, attempt.cobra.overshoot_ns);
    total.cobra.scratch_peak_bytes =
        std::max(total.cobra.scratch_peak_bytes, attempt.cobra.scratch_peak_bytes);
    total.cobra.proved_widths |= attempt.cobra.proved_widths;
    if (attempt.cobra.calls)
    {
        total.cobra.raw_leaves = attempt.cobra.raw_leaves;
        total.cobra.input_cost = attempt.cobra.input_cost;
        total.cobra.output_cost = attempt.cobra.output_cost;
        total.cobra.timings_complete = attempt.cobra.timings_complete;
        total.cobra.raw_indices = attempt.cobra.raw_indices;
        total.cobra.input_nodes = attempt.cobra.input_nodes;
        total.cobra.output_nodes = attempt.cobra.output_nodes;
        total.cobra.raw_support = attempt.cobra.raw_support;
        total.cobra.canonical_support = attempt.cobra.canonical_support;
        total.cobra.last_generation_phase = attempt.cobra.last_generation_phase;
        total.cobra.last_status = attempt.cobra.last_status;
        total.cobra.last_reason = attempt.cobra.last_reason;
        total.cobra.spot_check = attempt.cobra.spot_check;
    }
}
} // namespace chernobog::mba_smt
