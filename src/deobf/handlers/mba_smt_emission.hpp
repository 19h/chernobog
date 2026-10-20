#pragma once
#include "mba_smt.h"
#include <new>
namespace chernobog::mba_smt
{
// Own the exact SDK object that was independently lifted for Boundary 2.
// A core value receipt alone cannot authorize a later edited temporary.
template <class SdkExpression> class SdkEmissionProof
{
    SdkExpression emitted_;
    std::shared_ptr<const ProofReceipt> receipt_;
    explicit SdkEmissionProof(const SdkExpression &emitted) : emitted_(emitted) {}

  public:
    static std::shared_ptr<const SdkEmissionProof>
    prove(Analysis &analysis, const ProofReceipt &candidate, const SdkExpression &emitted,
          const std::function<Term(const SdkExpression &)> &lift)
    {
        try
        {
            auto result = std::shared_ptr<SdkEmissionProof>(new SdkEmissionProof(emitted));
            const auto term = lift(result->emitted_);
            result->receipt_ = analysis.prove_emission(candidate, term);
            return result->receipt_ ? result : nullptr;
        }
        catch (const std::bad_alloc &)
        {
            analysis.reject_mutation(RejectReason::EmissionAllocationFailure);
            return {};
        }
        catch (const std::invalid_argument &)
        {
            analysis.reject_mutation(RejectReason::EmittedDestinationOrFrameMismatch);
            return {};
        }
        catch (...)
        {
            analysis.reject_mutation(RejectReason::EmissionFailure);
            return {};
        }
    }
    const SdkExpression &emitted_snapshot() const noexcept { return emitted_; }
    const ProofReceipt &core() const noexcept { return *receipt_; }
    bool from_cobra() const noexcept { return receipt_->from_cobra(); }
};
using MicrocodeEmissionProof = SdkEmissionProof<minsn_t>;
using CtreeEmissionProof = SdkEmissionProof<cexpr_t>;
size_t microcode_expression_cost(const minsn_t *instruction);
mop_t emit_microcode_operand(const Term &term, ea_t ea,
                             const std::vector<std::pair<Term, mop_t>> &available);
bool verify_emitted_instruction_frame(const minsn_t &source, const minsn_t &emitted);
bool same_microcode_instruction(const minsn_t &left, const minsn_t &right);
bool commit_microcode_replacement(minsn_t &original, const minsn_t &snapshot, minsn_t &replacement,
                                  Analysis &analysis, const MicrocodeEmissionProof &proof,
                                  SnapshotToken expected, SnapshotToken &current,
                                  const std::function<bool()> &domain_unchanged = {});
bool commit_ctree_replacement(cexpr_t &original, const cexpr_t &snapshot, cexpr_t &replacement,
                              Analysis &analysis, const CtreeEmissionProof &proof,
                              SnapshotToken expected, SnapshotToken &current,
                              const cexpr_t *parent_target, const cexpr_t *saved_target,
                              bool legacy_fallback,
                              const std::function<bool()> &domain_unchanged = {});
}
