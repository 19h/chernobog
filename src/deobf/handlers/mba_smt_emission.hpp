#pragma once
#include "mba_smt.h"
namespace chernobog::mba_smt
{
size_t microcode_expression_cost(const minsn_t *instruction);
mop_t emit_microcode_operand(const Term &term, ea_t ea,
                             const std::vector<std::pair<Term, mop_t>> &available);
bool verify_emitted_instruction_frame(const minsn_t &source, const minsn_t &emitted);
bool same_microcode_instruction(const minsn_t &left, const minsn_t &right);
bool commit_microcode_replacement(minsn_t &original, const minsn_t &snapshot, minsn_t &replacement,
                                  Analysis &analysis, const ProofReceipt &receipt,
                                  SnapshotToken expected, SnapshotToken &current,
                                  const std::function<bool()> &domain_unchanged = {});
bool commit_ctree_replacement(cexpr_t &original, const cexpr_t &snapshot, cexpr_t &replacement,
                              Analysis &analysis, const ProofReceipt &receipt,
                              SnapshotToken expected, SnapshotToken &current,
                              const cexpr_t *parent_target, const cexpr_t *saved_target,
                              bool legacy_fallback,
                              const std::function<bool()> &domain_unchanged = {});
}
