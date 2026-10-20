#include "mba_smt_internal.hpp"
#include "../../common/smt_bitvector.hpp"
#include "../../common/solver_evidence.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace chernobog::mba_smt::detail
{
namespace
{
bool contains_register(const std::vector<size_t> &registers, size_t index)
{
    return std::find(registers.begin(), registers.end(), index) != registers.end();
}

z3::expr boolean_value(const z3::expr &condition)
{
    auto &context = condition.ctx();
    return z3::ite(condition, context.bv_val(1, 8), context.bv_val(0, 8));
}
} // namespace

SolverSession::SolverSession(Options configured_options, Statistics &output_statistics)
    : options(std::move(configured_options)), statistics(output_statistics), started_(now()),
      deadline_(started_ + std::chrono::milliseconds(options.budget_ms))
{
}

SolverSession::Clock::time_point SolverSession::now() const
{
    return session_test_hooks && session_test_hooks->now ? session_test_hooks->now() : Clock::now();
}

SolverSession::Clock::time_point SolverSession::deadline() const noexcept { return deadline_; }

std::chrono::nanoseconds SolverSession::remaining_budget(Clock::time_point time) const noexcept
{
    return time >= deadline_
               ? std::chrono::nanoseconds::zero()
               : std::chrono::duration_cast<std::chrono::nanoseconds>(deadline_ - time);
}

bool SolverSession::is_deadline_expired(Clock::time_point time) const noexcept
{
    return time >= deadline_;
}

bool SolverSession::is_cancelled()
{
    if (callback_failed_)
        return true;
    try
    {
        return options.cancelled && options.cancelled();
    }
    catch (...)
    {
        callback_failed_ = true;
        statistics.cancel_stage = RejectReason::CallbackFailure;
        return true;
    }
}

void SolverSession::record_expiry(RejectReason stage)
{
    const auto time = now();
    statistics.elapsed_ns = static_cast<uint64_t>(std::max<int64_t>(
        0, std::chrono::duration_cast<std::chrono::nanoseconds>(time - started_).count()));
    if (!callback_failed_)
        statistics.cancel_stage = stage;
    if (time > deadline_)
        statistics.deadline_overshoot_ns = std::max(
            statistics.deadline_overshoot_ns,
            static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(time - deadline_).count()));
    ++statistics.exhausted;
}

bool SolverSession::has_budget()
{
    // A callback can take time or reenter the host. Sample time after it.
    const bool cancelled = is_cancelled();
    const auto time = now();
    statistics.elapsed_ns = static_cast<uint64_t>(std::max<int64_t>(
        0, std::chrono::duration_cast<std::chrono::nanoseconds>(time - started_).count()));
    return !cancelled && !is_deadline_expired(time);
}

bool SolverSession::eligible_for_commit(bool legacy_deadline_exempt,
                                        const std::function<bool()> &unchanged)
{
    const bool cancelled = is_cancelled();
    if (!cancelled && unchanged && !unchanged())
    {
        ++statistics.rejected_mutations;
        statistics.cancel_stage = RejectReason::StaleSnapshot;
        return false;
    }
    const auto time = now();
    if (cancelled || (!legacy_deadline_exempt && is_deadline_expired(time)))
    {
        record_expiry(RejectReason::PostProofDeadlineOrCancel);
        ++statistics.rejected_mutations;
        return false;
    }
    return true;
}

z3::check_result SolverSession::check(z3::solver &solver, const char *purpose)
{
    if (!has_budget())
    {
        record_expiry(RejectReason::PostProofExpiry);
        return z3::unknown;
    }
    const auto remaining_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(remaining_budget(now())).count();
    if (remaining_ms < 1 || options.query_ms == 0)
    {
        record_expiry(RejectReason::PostProofExpiry);
        return z3::unknown;
    }
    const auto timeout_ms =
        static_cast<unsigned>(std::min<int64_t>(options.query_ms, remaining_ms));
    z3::params parameters(context);
    parameters.set("timeout", timeout_ms);
    if (options.resource_limit != 0)
        parameters.set("rlimit", options.resource_limit);
    solver.set(parameters);
    const std::string description = "timeout_ms=" + std::to_string(timeout_ms) +
                                    ";rlimit=" + std::to_string(options.resource_limit);
    const auto result = solver_evidence::check(solver, purpose, description.c_str());
    if (session_test_hooks && session_test_hooks->after_query)
        session_test_hooks->after_query(purpose);
    // Capture preserves the observed solver result. Acceptance is a separate gate.
    if (!has_budget())
    {
        record_expiry(RejectReason::PostProofExpiry);
        return z3::unknown;
    }
    return result;
}

z3::expr SolverSession::fresh_value(unsigned bit_width)
{
    const std::string name = "mba:value:" + std::to_string(next_symbol_++);
    return context.bv_const(name.c_str(), bit_width);
}

z3::expr SolverSession::fresh_memory(unsigned address_width)
{
    const std::string name = "mba:memory:" + std::to_string(next_symbol_++);
    const auto memory_sort = context.array_sort(context.bv_sort(address_width), context.bv_sort(8));
    return context.constant(name.c_str(), memory_sort);
}

SymbolicState::SymbolicState(z3::expr initial_memory) : memory(std::move(initial_memory)) {}

SymbolicProgram::SymbolicProgram(const Program &input_program, SolverSession &solver_session)
    : program(input_program), session(solver_session)
{
}

SymbolicState SymbolicProgram::fresh_state()
{
    SymbolicState state(session.fresh_memory(program.address_bits));
    state.registers.reserve(program.widths.size());
    for (unsigned bit_width : program.widths)
    {
        state.registers.push_back(session.fresh_value(bit_width));
    }
    return state;
}

void SymbolicProgram::build()
{
    entries_.reserve(program.blocks.size());
    exits_.reserve(program.blocks.size());
    statement_states_.resize(program.blocks.size());

    for (size_t block = 0; block < program.blocks.size(); ++block)
    {
        entries_.push_back(fresh_state());
    }

    for (size_t block = 0; block < program.blocks.size(); ++block)
    {
        SymbolicState state = entries_[block];
        auto &snapshots = statement_states_[block];
        snapshots.reserve(program.blocks[block].statements.size());

        for (const Statement &statement : program.blocks[block].statements)
        {
            snapshots.push_back(state);
            execute(statement, state);
        }
        exits_.push_back(std::move(state));
    }
}

z3::expr SymbolicProgram::read_memory(const z3::expr &address, unsigned bit_width,
                                      const SymbolicState &state) const
{
    auto &context = session.context;
    z3::expr result = z3::select(state.memory, address);

    for (unsigned byte_offset = 1; byte_offset < bit_width / 8; ++byte_offset)
    {
        const auto offset = context.bv_val(byte_offset, program.address_bits);
        const auto byte = z3::select(state.memory, address + offset);
        if (program.big_endian)
        {
            result = z3::concat(result, byte);
        }
        else
        {
            result = z3::concat(byte, result);
        }
    }
    return result;
}

z3::expr SymbolicProgram::evaluate(const Term &term, const SymbolicState &state) const
{
    if (!term)
    {
        throw std::invalid_argument("missing expression");
    }

    switch (term->op)
    {
    case Op::Constant:
        return session.context.bv_val(term->value, term->bits);
    case Op::Variable:
        return state.registers.at(static_cast<size_t>(term->value));
    default:
        break;
    }

    const z3::expr left = evaluate(term->left, state);
    const unsigned input_width = left.get_sort().bv_size();

    switch (term->op)
    {
    case Op::Load:
        return read_memory(left, term->bits, state);
    case Op::Not:
        return ~left;
    case Op::Neg:
        return -left;
    case Op::Low:
        return left.extract(term->bits - 1, 0);
    case Op::High:
        return left.extract(input_width - 1, input_width - term->bits);
    case Op::ZeroExtend:
        return z3::zext(left, term->bits - input_width);
    case Op::SignExtend:
        return z3::sext(left, term->bits - input_width);
    default:
        break;
    }

    const z3::expr right = evaluate(term->right, state);
    switch (term->op)
    {
    case Op::Add:
        return smt::arithmetic(smt::Arithmetic::Add, left, right);
    case Op::Sub:
        return smt::arithmetic(smt::Arithmetic::Sub, left, right);
    case Op::Mul:
        return smt::arithmetic(smt::Arithmetic::Mul, left, right);
    case Op::UnsignedDivide:
        return z3::udiv(left, right);
    case Op::And:
        return smt::arithmetic(smt::Arithmetic::And, left, right);
    case Op::Or:
        return smt::arithmetic(smt::Arithmetic::Or, left, right);
    case Op::Xor:
        return smt::arithmetic(smt::Arithmetic::Xor, left, right);
    case Op::Equal:
        return boolean_value(left == right);
    case Op::NotEqual:
        return boolean_value(left != right);
    case Op::UnsignedLess:
        return boolean_value(z3::ult(left, right));
    case Op::SignedLess:
        return boolean_value(left < right);
    case Op::Shl:
        return z3::shl(left, z3::zext(right, input_width - 8));
    case Op::Shr:
        return z3::lshr(left, z3::zext(right, input_width - 8));
    case Op::Sar:
        return z3::ashr(left, z3::zext(right, input_width - 8));
    default:
        throw std::invalid_argument("unsupported expression operator");
    }
}

void SymbolicProgram::invalidate(const Statement &statement, SymbolicState &state)
{
    for (size_t index = 0; index < state.registers.size(); ++index)
    {
        if (contains_register(program.readonly, index))
        {
            continue;
        }

        const bool clobbered =
            statement.spoiled.empty() || contains_register(statement.spoiled, index);
        if (clobbered)
        {
            state.registers[index] = session.fresh_value(program.widths[index]);
        }
    }
    state.memory = session.fresh_memory(program.address_bits);
}

void SymbolicProgram::assign_register(const Statement &statement, const z3::expr &value,
                                      SymbolicState &state) const
{
    const z3::expr &previous = state.registers[statement.destination];
    const unsigned register_width = previous.get_sort().bv_size();
    const unsigned end_bit = statement.offset + statement.value->bits;
    z3::expr updated = value;

    if (statement.offset != 0)
    {
        updated = z3::concat(updated, previous.extract(statement.offset - 1, 0));
    }
    if (end_bit < register_width)
    {
        updated = z3::concat(previous.extract(register_width - 1, end_bit), updated);
    }
    state.registers[statement.destination] = updated;
}

void SymbolicProgram::write_memory(const Statement &statement, const z3::expr &value,
                                   SymbolicState &state) const
{
    const z3::expr address = evaluate(statement.address, state);
    const unsigned byte_count = statement.value->bits / 8;

    for (unsigned byte_offset = 0; byte_offset < byte_count; ++byte_offset)
    {
        const unsigned value_byte = program.big_endian ? byte_count - 1 - byte_offset : byte_offset;
        const auto byte = value.extract(value_byte * 8 + 7, value_byte * 8);
        const auto offset = session.context.bv_val(byte_offset, program.address_bits);
        state.memory = z3::store(state.memory, address + offset, byte);
    }
}

void SymbolicProgram::execute(const Statement &statement, SymbolicState &state)
{
    if (statement.kind == Statement::Kind::Havoc)
    {
        invalidate(statement, state);
        return;
    }

    const z3::expr value = evaluate(statement.value, state);
    if (statement.kind == Statement::Kind::Assign)
    {
        assign_register(statement, value, state);
    }
    else
    {
        write_memory(statement, value, state);
    }
}

z3::expr SymbolicProgram::conjunction(const std::vector<Term> &terms,
                                      const SymbolicState &state) const
{
    z3::expr result = session.context.bool_val(true);
    for (const Term &term : terms)
    {
        result = result && (evaluate(term, state) != 0);
    }
    return result;
}

z3::expr SymbolicProgram::edge_condition(size_t source, const Edge &edge) const
{
    if (!edge.condition)
    {
        return session.context.bool_val(true);
    }

    const z3::expr condition = evaluate(edge.condition, block_exit(source)) != 0;
    return edge.inverted ? !condition : condition;
}

const SymbolicState &SymbolicProgram::block_entry(size_t block) const { return entries_.at(block); }

const SymbolicState &SymbolicProgram::block_exit(size_t block) const { return exits_.at(block); }

const SymbolicState &SymbolicProgram::before_statement(size_t block, size_t statement) const
{
    return statement_states_.at(block).at(statement);
}

void SymbolicProgram::retain_verified_rewrite(const z3::expr &before, const z3::expr &after)
{
    verified_rewrites_.emplace_back(before, after);
}

z3::expr SymbolicProgram::apply_verified_rewrites(z3::expr value) const
{
    for (const auto &[before, after] : verified_rewrites_)
    {
        z3::expr_vector source(session.context), replacement(session.context);
        source.push_back(before);
        replacement.push_back(after);
        value = value.substitute(source, replacement);
    }
    return value;
}

Verdict verify_replacement(SymbolicProgram &symbolic_program, const BlockInvariants &invariants,
                           size_t block, size_t statement_index, const Term &replacement)
{
    auto &session = symbolic_program.session;
    const auto &program = symbolic_program.program;

    if (!session.has_budget())
    {
        ++session.statistics.exhausted;
        return Verdict::Exhausted;
    }

    if (block >= program.blocks.size() ||
        statement_index >= program.blocks[block].statements.size())
    {
        return Verdict::Unsupported;
    }

    const auto &statement = program.blocks[block].statements[statement_index];
    if (statement.kind != Statement::Kind::Assign || !validate_expression(replacement, program) ||
        replacement->bits != statement.value->bits)
    {
        return Verdict::Unsupported;
    }

    z3::solver solver(session.context);
    solver.add(
        symbolic_program.conjunction(invariants.at(block), symbolic_program.block_entry(block)));
    const auto feasibility = session.check(solver, "MBA site feasibility");
    if (feasibility != z3::sat)
    {
        return !session.has_budget()        ? Verdict::Exhausted
               : feasibility == z3::unknown ? Verdict::Unknown
                                            : Verdict::Unsupported;
    }

    const auto &state = symbolic_program.before_statement(block, statement_index);
    solver.add(
        symbolic_program.apply_verified_rewrites(
            symbolic_program.evaluate(statement.value, state)) !=
        symbolic_program.apply_verified_rewrites(symbolic_program.evaluate(replacement, state)));

    const auto result = session.check(solver, "MBA contextual emitted replacement mismatch");
    if (result == z3::unsat)
    {
        if (!session.has_budget())
        {
            session.record_expiry(RejectReason::PostProofExpiry);
            return Verdict::Exhausted;
        }
        ++session.statistics.verified;
        return Verdict::Verified;
    }
    if (result == z3::sat)
    {
        ++session.statistics.disproved;
        return Verdict::Disproved;
    }

    ++session.statistics.unknown;
    return session.has_budget() ? Verdict::Unknown : Verdict::Exhausted;
}
} // namespace chernobog::mba_smt::detail
