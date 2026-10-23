#include "mba_smt.h"
#include "mba_smt_microcode.hpp"
#include "../../common/bitvector.h"
#include "../analysis/ast.h"
#include <chrono>
#include <stdexcept>
#include <tuple>

namespace chernobog::mba_smt
{
namespace
{

bool has_volatile_inputs(ea_t entry)
{
    tinfo_t function_type;
    func_type_data_t details;
    if (!get_tinfo(&function_type, entry) || !function_type.get_func_details(&details))
    {
        return false;
    }
    for (const auto &argument : details)
    {
        tinfo_t type = argument.type;
        for (unsigned depth = 0; depth < limits::expression_depth; ++depth)
        {
            if (type.is_volatile())
            {
                return true;
            }
            if (type.is_ptr())
            {
                type = type.get_pointed_object();
            }
            else if (type.is_array())
            {
                type = type.get_array_element();
            }
            else
            {
                break;
            }
        }
    }
    return false;
}

class BudgetCharge
{
  public:
    explicit BudgetCharge(FunctionBudget &budget)
        : budget_(budget), started_(std::chrono::steady_clock::now())
    {
    }

    ~BudgetCharge() { budget_.spent_ns += elapsed_ns(); }

    std::chrono::steady_clock::time_point deadline() const
    {
        const uint64_t limit = uint64_t(budget_.limit_ms) * 1000000;
        return started_ +
               std::chrono::nanoseconds(limit > budget_.spent_ns ? limit - budget_.spent_ns : 0);
    }

    uint64_t elapsed_ns() const
    {
        const auto elapsed = std::chrono::steady_clock::now() - started_;
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
    }

  private:
    FunctionBudget &budget_;
    std::chrono::steady_clock::time_point started_;
};

bool apply_verified_proposal(MicrocodeAdapter &adapter, Analysis &analysis,
                             const Proposal &proposal, FunctionBudget &budget,
                             const Program &snapshot_program)
{
    const auto site = std::make_pair(proposal.block, proposal.statement);
    const auto found = adapter.originals.find(site);
    if (found == adapter.originals.end())
    {
        return false;
    }

    minsn_t *original = found->second;
    const auto saved = adapter.sources.find(site);
    if (saved == adapter.sources.end())
        return false;
    const minsn_t &source = *saved->second;
    minsn_t replacement(source);
    const auto emission_started = std::chrono::steady_clock::now();
    const mop_t value = adapter.emit_operand(proposal.replacement, original->ea);

    if (value.t == mop_d && value.d != nullptr)
    {
        replacement.opcode = value.d->opcode;
        replacement.l = value.d->l;
        replacement.r = value.d->r;
    }
    else
    {
        replacement.opcode = m_mov;
        replacement.l = value;
        replacement.r.erase();
    }

    if (MicrocodeAdapter::expression_cost(&replacement) >=
        MicrocodeAdapter::expression_cost(original))
    {
        return false;
    }

    // Emission is an independent boundary: verify the actual SDK operands,
    // not the synthesizer's expression or its textual representation.
    const auto receipt =
        proposal.proof ? MicrocodeEmissionProof::prove(
                             analysis, *proposal.proof, replacement,
                             [&](const minsn_t &temporary)
                             {
                                 const auto emitted = adapter.translate_instruction(&temporary);
                                 analysis.record_emission(static_cast<uint64_t>(
                                     std::chrono::duration_cast<std::chrono::nanoseconds>(
                                         std::chrono::steady_clock::now() - emission_started)
                                         .count()));
                                 return emitted;
                             })
                       : nullptr;
    if (!receipt)
        return false;

    const auto domain_unchanged = [&]
    {
        MicrocodeAdapter current(adapter.mba, adapter.local_block, adapter.local_instruction);
        current.sequential_locations = adapter.sequential_locations;
        current.build();
        const auto current_site = current.originals.find(site);
        if (current_site == current.originals.end() || current_site->second != original ||
            current.registers.size() != adapter.registers.size() ||
            current.frames != adapter.frames || current.locals != adapter.locals ||
            current.local_values != adapter.local_values ||
            current.address_values != adapter.address_values ||
            !same_program(snapshot_program, current.program))
            return false;
        for (size_t i = 0; i < current.registers.size(); ++i)
        {
            const auto &a = current.registers[i], &b = adapter.registers[i];
            if (a.start != b.start || a.bytes != b.bytes || a.value_number != b.value_number)
                return false;
        }
        return true;
    };
    if (!commit_microcode_replacement(*original, source, replacement, analysis, *receipt,
                                      proposal.snapshot, budget.snapshot, domain_unchanged))
        return false;
    mblock_t *owner = adapter.local_block;
    if (!owner)
    {
        owner = adapter.mba->get_mblock(static_cast<int>(proposal.block));
    }
    owner->mark_lists_dirty();
    return true;
}

int simplify_once(mbl_array_t *mba, FunctionBudget &budget, mblock_t *local_block = nullptr,
                  minsn_t *local_instruction = nullptr)
{
    BudgetCharge charge(budget);

    try
    {
        MicrocodeAdapter adapter(mba, local_block, local_instruction);
        adapter.sequential_locations = !local_instruction && mba->maturity == MMAT_CALLS;
        adapter.build();
        if (adapter.originals.empty())
        {
            return 0;
        }

        const uint64_t used_ms = (budget.spent_ns + charge.elapsed_ns()) / 1000000;
        if (used_ms >= budget.limit_ms)
        {
            ++budget.totals.exhausted;
            return 0;
        }

        Options options = budget.profile == Profile::Deep ? Options::deep() : Options{};
        options.absolute_deadline = charge.deadline();
        options.snapshot = budget.snapshot;
        options.backend = budget.backend;
        options.contextual_constants_only = adapter.sequential_locations;
        options.budget_ms = budget.limit_ms - static_cast<unsigned>(used_ms);
        options.cancelled = [] { return user_cancelled(); };
        options.diagnostic = {DiagnosticPhase::Microcode, 0, int(mba->maturity), false};
        options.diagnostic_context = [&](size_t block, size_t statement)
        {
            DiagnosticContext context{DiagnosticPhase::Microcode, 0, int(mba->maturity), false};
            const auto found = adapter.originals.find({block, statement});
            if (found != adapter.originals.end())
            {
                context.source_ea = uint64_t(found->second->ea);
                context.source_known = found->second->ea != BADADDR;
            }
            return context;
        };

        const Program snapshot_program = adapter.program;
        Analysis analysis(snapshot_program, options);
        const auto proposals = analysis.run(
            [&](const Proposal &proposal)
            {
                const auto found = adapter.originals.find({proposal.block, proposal.statement});
                if (found == adapter.originals.end())
                    return false;
                const auto started = std::chrono::steady_clock::now();
                bool lowerable = false;
                try
                {
                    const auto value =
                        adapter.emit_operand(proposal.replacement, found->second->ea);
                    lowerable =
                        (value.t == mop_d ? MicrocodeAdapter::expression_cost(value.d) : 0) <
                        MicrocodeAdapter::expression_cost(found->second);
                }
                catch (const std::invalid_argument &error)
                {
                    ++budget.totals.unsupported;
                    deobf::log_verbose("[MBA SMT] Retained unlowerable proposal: %s\n",
                                       error.what());
                }
                analysis.record_emission(
                    static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                              std::chrono::steady_clock::now() - started)
                                              .count()));
                return lowerable;
            });
        bool applied = false;
        for (const Proposal &proposal : proposals)
        {
            try
            {
                if (apply_verified_proposal(adapter, analysis, proposal, budget, snapshot_program))
                {
                    applied = true;
                    ++budget.totals.applied;
                    if (proposal.proof && proposal.proof->from_cobra())
                        ++budget.totals.cobra.applied;
                    break;
                }
            }
            catch (const std::invalid_argument &error)
            {
                // A proved value can mention a snapshot-only operand that
                // this site cannot emit. Reject that temporary and continue
                // with other proved sites in the same immutable analysis.
                ++budget.totals.unsupported;
                deobf::log_verbose("[MBA SMT] Retained unlowerable proposal: %s\n", error.what());
            }
        }
        accumulate_statistics(budget.totals, analysis.statistics());

        if (applied)
        {
            mba->verify(false);
            return 1;
        }
    }
    catch (const std::exception &error)
    {
        ++budget.totals.unsupported;
        deobf::log_verbose("[MBA SMT] Retained original microcode: %s\n", error.what());
    }

    return 0;
}

struct LocalCandidate
{
    mblock_t *block;
    minsn_t *instruction;
    size_t cost;
};

bool collect_local_candidates(mblock_t *block, minsn_t *instruction, unsigned depth,
                              std::set<minsn_t *> &visited, std::vector<LocalCandidate> &candidates)
{
    if (!instruction || depth > limits::expression_depth || visited.size() >= limits::statements ||
        !visited.insert(instruction).second)
    {
        return false;
    }

    for (mop_t *operand : {&instruction->l, &instruction->r})
    {
        if (operand->t == mop_d &&
            !collect_local_candidates(block, operand->d, depth + 1, visited, candidates))
        {
            return false;
        }
    }
    if (is_mcode_call(instruction->opcode) && instruction->d.t == mop_f && instruction->d.f)
    {
        for (auto &argument : instruction->d.f->args)
            if (argument.t == mop_d &&
                !collect_local_candidates(block, argument.d, depth + 1, visited, candidates))
                return false;
    }

    switch (instruction->opcode)
    {
    case m_add:
    case m_sub:
    case m_mul:
    case m_udiv:
    case m_and:
    case m_or:
    case m_xor:
    case m_bnot:
    case m_neg:
    case m_shl:
    case m_shr:
    case m_sar:
    case m_setz:
    case m_setnz:
    case m_setb:
    case m_setl:
    {
        const size_t cost = MicrocodeAdapter::expression_cost(instruction);
        if (cost >= 2)
        {
            candidates.push_back({block, instruction, cost});
        }
        break;
    }
    default:
        break;
    }
    return true;
}

int simplify_local_trees(mbl_array_t *mba, FunctionBudget &budget)
{
    std::vector<LocalCandidate> candidates;
    std::set<minsn_t *> visited;
    for (int index = 0; index < mba->qty && visited.size() < limits::statements; ++index)
    {
        mblock_t *block = mba->get_mblock(index);
        for (minsn_t *instruction = block->head; instruction; instruction = instruction->next)
        {
            if (!collect_local_candidates(block, instruction, 0, visited, candidates))
            {
                break;
            }
        }
    }

    std::stable_sort(candidates.begin(), candidates.end(),
                     [](const LocalCandidate &left, const LocalCandidate &right)
                     { return left.cost > right.cost; });

    for (const LocalCandidate &candidate : candidates)
    {
        if (budget.spent_ns / 1000000 >= budget.limit_ms || user_cancelled())
        {
            break;
        }
        if (simplify_once(mba, budget, candidate.block, candidate.instruction) != 0)
        {
            return 1;
        }
    }
    return 0;
}
} // namespace

int simplify(mbl_array_t *mba, FunctionBudget &budget)
{
    qstring enabled;
    if (mba == nullptr || (qgetenv("CHERNOBOG_MBA_SMT", &enabled) && enabled == "0"))
    {
        return 0;
    }
    if (has_volatile_inputs(mba->entry_ea))
    {
        // The CFG memory model represents ordinary sequential memory. A
        // declared volatile pointee cannot participate in those equalities;
        // independent pure scalars remain eligible in the final ctree pass.
        ++budget.totals.unsupported;
        return 0;
    }

    int total_changes = 0;
    while (budget.spent_ns / 1000000 < budget.limit_ms && !user_cancelled())
    {
        int changes = 0;
        if (mba->maturity == MMAT_LOCOPT && mba->qty > 3)
        {
            changes = simplify_once(mba, budget);
        }
        if (changes == 0 && budget.spent_ns / 1000000 < budget.limit_ms)
        {
            changes = simplify_local_trees(mba, budget);
        }
        if (changes == 0 && budget.spent_ns / 1000000 < budget.limit_ms)
        {
            changes = simplify_once(mba, budget);
        }
        if (changes == 0)
        {
            break;
        }
        total_changes += changes;
        // Each accepted rewrite requires a fresh analysis snapshot.
    }
    return total_changes;
}
} // namespace chernobog::mba_smt
