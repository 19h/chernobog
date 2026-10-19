#pragma once

#include "mba_smt.hpp"
#include "mba_smt_known_bits.hpp"

#include <chrono>
#include <optional>
#include <set>
#include <unordered_set>
#include <z3++.h>

namespace chernobog::mba_smt::detail
{
using BlockInvariants = std::vector<std::vector<Term>>;

bool validate_expression(const Term &term, const Program &program);
unsigned polynomial_degree(const Term &term);
void collect_literals(const Term &term, unsigned bit_width, std::set<uint64_t> &literals);

// The context and budget have the same lifetime as one immutable analysis.
// Every solver query, including search queries, consumes this shared budget.
class SolverSession
{
  public:
    SolverSession(Options options, Statistics &statistics);

    bool has_budget();
    z3::check_result check(z3::solver &solver, const char *purpose);
    z3::expr fresh_value(unsigned bit_width);
    z3::expr fresh_memory(unsigned address_width);

    z3::context context;
    const Options options;
    Statistics &statistics;

  private:
    using Clock = std::chrono::steady_clock;

    Clock::time_point started_;
    size_t next_symbol_ = 0;
};

struct SymbolicState
{
    explicit SymbolicState(z3::expr memory);

    std::vector<z3::expr> registers;
    z3::expr memory;
};

// Block entry states are independent symbols. Edge proofs relate them to the
// predecessor's final state; statement snapshots retain instruction ordering.
class SymbolicProgram
{
  public:
    SymbolicProgram(const Program &program, SolverSession &session);

    void build();
    z3::expr evaluate(const Term &term, const SymbolicState &state) const;
    z3::expr conjunction(const std::vector<Term> &terms, const SymbolicState &state) const;
    z3::expr edge_condition(size_t source, const Edge &edge) const;
    // Admit only an unconditional equality already proved UNSAT, possibly
    // composed from earlier entries. The list belongs to this snapshot alone.
    void retain_verified_rewrite(const z3::expr &before, const z3::expr &after);
    z3::expr apply_verified_rewrites(z3::expr value) const;

    const SymbolicState &block_entry(size_t block) const;
    const SymbolicState &block_exit(size_t block) const;
    const SymbolicState &before_statement(size_t block, size_t statement) const;

    const Program &program;
    SolverSession &session;

  private:
    SymbolicState fresh_state();
    z3::expr read_memory(const z3::expr &address, unsigned bit_width,
                         const SymbolicState &state) const;
    void execute(const Statement &statement, SymbolicState &state);
    void invalidate(const Statement &statement, SymbolicState &state);
    void assign_register(const Statement &statement, const z3::expr &value,
                         SymbolicState &state) const;
    void write_memory(const Statement &statement, const z3::expr &value,
                      SymbolicState &state) const;

    std::vector<SymbolicState> entries_;
    std::vector<SymbolicState> exits_;
    std::vector<std::vector<SymbolicState>> statement_states_;
    std::vector<std::pair<z3::expr, z3::expr>> verified_rewrites_;
};

// Candidate annotations become usable only after initiation and every edge
// have been checked against the final, mutually consistent annotation set.
class InvariantInference
{
  public:
    explicit InvariantInference(SymbolicProgram &symbolic_program);
    BlockInvariants run();

  private:
    void add_template(Term candidate);
    void collect_definition_templates();
    void collect_scalar_templates();
    bool prune(size_t target, const SymbolicState &incoming, const z3::expr &domain);
    bool check_transitions();

    SymbolicProgram &symbolic_;
    SolverSession &session_;
    std::vector<Term> templates_;
    std::unordered_set<std::string> template_keys_;
    BlockInvariants invariants_;
};

// Search samples may reject candidates cheaply. Only a solver query over the
// complete site domain can accept one; a sample collision is never a proof.
Term simplify_algebraic(SymbolicProgram &program, const SymbolicState &state, const Term &original);

// Return a structural hypothesis. The algebraic pass must prove it before use.
Term normalize_masks(const Term &term);

// Construct a hypothesis from Boolean-word samples. Callers must prove equality
// over the full word domain before using it, including at nested expression sites.
Term reconstruct_linear_mba(SymbolicProgram &program, const SymbolicState &state,
                            const Term &original, const std::vector<Term> &inputs);

class CandidateSynthesis
{
  public:
    CandidateSynthesis(SymbolicProgram &symbolic_program, const BlockInvariants &invariants,
                       size_t block, size_t statement);
    Term run();

  private:
    enum class CandidateStatus
    {
        Rejected,
        Verified,
        Counterexample,
        Exhausted,
    };

    void collect_inputs();
    bool initialize_samples();
    bool acceptable_cost(const Term &candidate) const;
    Term search_linear_mba();
    Term fit_affine(const std::vector<Term> &basis);
    Term instantiate_affine(const std::vector<Term> &basis,
                            const std::vector<z3::expr> &coefficients,
                            const z3::model &model) const;
    Term search_affine();
    Term search_grammar();
    CandidateStatus consider(const Term &candidate, size_t operation_count);
    Term enumerate_unary(size_t operation_count);
    Term enumerate_binary(size_t operation_count);
    bool should_stop_enumeration();

    SymbolicProgram &symbolic_;
    SolverSession &session_;
    const Term original_;
    const SymbolicState &state_;
    const z3::expr domain_;
    const z3::expr original_value_;
    const std::string original_key_;
    const unsigned bit_width_;
    const size_t operation_limit_;

    std::vector<Term> inputs_;
    std::vector<z3::model> samples_;
    std::vector<std::vector<Term>> layers_;
    std::unordered_set<std::string> signatures_;
    size_t generated_ = 0;
    bool restart_requested_ = false;
};

Verdict verify_replacement(SymbolicProgram &symbolic_program, const BlockInvariants &invariants,
                           size_t block, size_t statement, const Term &replacement);
} // namespace chernobog::mba_smt::detail
