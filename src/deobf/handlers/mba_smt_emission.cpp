#include "mba_smt_emission.hpp"
#include "mba_smt_ctree.h"
#include "../analysis/ast.h"
#include <stdexcept>
namespace chernobog::mba_smt
{
size_t microcode_expression_cost(const minsn_t *ins)
{
    if (!ins)
    {
        return 0;
    }
    const size_t weight =
        ins->opcode == m_udiv ? limits::division_cost : size_t(ins->opcode != m_mov);
    return weight + (ins->l.t == mop_d ? microcode_expression_cost(ins->l.d) : 0) +
           (ins->r.t == mop_d ? microcode_expression_cost(ins->r.d) : 0);
}
mop_t emit_microcode_operand(const Term &term, ea_t ea,
                             const std::vector<std::pair<Term, mop_t>> &available)
{
    mop_t result;
    for (const auto &leaf : available)
    {
        if (key(leaf.first) == key(term))
        {
            return leaf.second;
        }
    }
    if (term->op == Op::Constant)
    {
        result.make_number(term->value, int(term->bits / 8));
        return result;
    }
    minsn_t node(ea);
    node.d.size = int(term->bits / 8);
    switch (term->op)
    {
    case Op::Add:
        node.opcode = m_add;
        break;
    case Op::Sub:
        node.opcode = m_sub;
        break;
    case Op::Mul:
        node.opcode = m_mul;
        break;
    case Op::UnsignedDivide:
        node.opcode = m_udiv;
        break;
    case Op::And:
        node.opcode = m_and;
        break;
    case Op::Or:
        node.opcode = m_or;
        break;
    case Op::Xor:
        node.opcode = m_xor;
        break;
    case Op::Not:
        node.opcode = m_bnot;
        break;
    case Op::Neg:
        node.opcode = m_neg;
        break;
    case Op::Low:
        node.opcode = m_low;
        break;
    case Op::High:
        node.opcode = m_high;
        break;
    case Op::ZeroExtend:
        node.opcode = m_xdu;
        break;
    case Op::SignExtend:
        node.opcode = m_xds;
        break;
    case Op::Shl:
        node.opcode = m_shl;
        break;
    case Op::Shr:
        node.opcode = m_shr;
        break;
    case Op::Sar:
        node.opcode = m_sar;
        break;
    case Op::Equal:
        node.opcode = m_setz;
        break;
    case Op::NotEqual:
        node.opcode = m_setnz;
        break;
    case Op::UnsignedLess:
        node.opcode = m_setb;
        break;
    case Op::SignedLess:
        node.opcode = m_setl;
        break;
    default:
        throw std::invalid_argument("unavailable operand");
    }
    node.l = emit_microcode_operand(term->left, ea, available);
    if (term->right)
    {
        node.r = emit_microcode_operand(term->right, ea, available);
    }
    result.create_from_insn(&node);
    result.size = int(term->bits / 8);
    return result;
}
namespace
{
bool pure_instruction(const minsn_t &instruction)
{
    if (instruction.is_fpinsn() || instruction.is_mbarrier() || instruction.is_persistent() ||
        instruction.is_assert() || !instruction.is_combinable() || !instruction.is_propagatable())
        return false;
    switch (instruction.opcode)
    {
    case m_mov:
    case m_add:
    case m_sub:
    case m_mul:
    case m_udiv:
    case m_and:
    case m_or:
    case m_xor:
    case m_bnot:
    case m_neg:
    case m_low:
    case m_high:
    case m_xdu:
    case m_xds:
    case m_shl:
    case m_shr:
    case m_sar:
    case m_setz:
    case m_setnz:
    case m_setb:
    case m_setl:
        return true;
    default:
        return false;
    }
}
bool pure_operand(const mop_t &operand, size_t &visits, unsigned depth = 0)
{
    if (++visits > 512 || depth > 64)
        return false;
    switch (operand.t)
    {
    case mop_z:
    case mop_n:
    case mop_r:
    case mop_S:
    case mop_l:
        return true;
    case mop_d:
        return operand.d && pure_instruction(*operand.d) &&
               pure_operand(operand.d->l, visits, depth + 1) &&
               pure_operand(operand.d->r, visits, depth + 1);
    default:
        return false;
    }
}
bool same_eas(const mop_t &left, const mop_t &right, size_t &visits, unsigned depth = 0)
{
    if (++visits > 512 || depth > 64)
        return false;
    if (left.t != mop_d)
        return true;
    return left.d && right.d && left.d->ea == right.d->ea &&
           same_eas(left.d->l, right.d->l, visits, depth + 1) &&
           same_eas(left.d->r, right.d->r, visits, depth + 1) &&
           same_eas(left.d->d, right.d->d, visits, depth + 1);
}
}
bool same_microcode_instruction(const minsn_t &left, const minsn_t &right)
{
    size_t visits = 0;
    return left.opcode == right.opcode && left.ea == right.ea && left.iprops == right.iprops &&
           ast::mops_equal_strict(left.d, right.d) && ast::mops_equal_strict(left.l, right.l) &&
           ast::mops_equal_strict(left.r, right.r) && same_eas(left.d, right.d, visits) &&
           same_eas(left.l, right.l, visits) && same_eas(left.r, right.r, visits);
}
bool verify_emitted_instruction_frame(const minsn_t &source, const minsn_t &emitted)
{
    size_t visits = 0;
    return source.ea == emitted.ea && source.iprops == emitted.iprops &&
           ast::mops_equal_strict(source.d, emitted.d) && pure_instruction(emitted) &&
           pure_operand(emitted.l, visits) && pure_operand(emitted.r, visits);
}
bool commit_microcode_replacement(minsn_t &original, const minsn_t &snapshot, minsn_t &replacement,
                                  Analysis &analysis, const MicrocodeEmissionProof &proof,
                                  SnapshotToken expected, SnapshotToken &current,
                                  const std::function<bool()> &domain_unchanged)
{
    const auto &receipt = proof.core();
    const auto &emitted_snapshot = proof.emitted_snapshot();
    if (!verify_emitted_instruction_frame(snapshot, replacement) ||
        !same_microcode_instruction(replacement, emitted_snapshot))
    {
        analysis.reject_mutation(RejectReason::EmittedDestinationOrFrameMismatch);
        return false;
    }
    if (microcode_expression_cost(&replacement) >= microcode_expression_cost(&snapshot))
        return false;
    const auto unchanged = [&]
    {
        return current == expected && analysis.snapshot() == expected &&
               (!domain_unchanged || domain_unchanged()) &&
               same_microcode_instruction(original, snapshot) &&
               same_microcode_instruction(replacement, emitted_snapshot);
    };
    if (!analysis.eligible_for_commit(receipt, false, unchanged))
        return false;
    original.swap(replacement);
    ++current.mutation_epoch;
    return true;
}
bool commit_ctree_replacement(cexpr_t &original, const cexpr_t &snapshot, cexpr_t &replacement,
                              Analysis &analysis, const CtreeEmissionProof &proof,
                              SnapshotToken expected, SnapshotToken &current,
                              const cexpr_t *parent_target, const cexpr_t *saved_target,
                              bool legacy_fallback, const std::function<bool()> &domain_unchanged)
{
    const auto &receipt = proof.core();
    const auto &emitted_snapshot = proof.emitted_snapshot();
    if (replacement.type != snapshot.type || replacement.ea != snapshot.ea ||
        replacement.exflags != snapshot.exflags || replacement.label_num != snapshot.label_num ||
        replacement.compare(emitted_snapshot) != 0 || replacement.type != emitted_snapshot.type ||
        replacement.ea != emitted_snapshot.ea || replacement.exflags != emitted_snapshot.exflags ||
        replacement.label_num != emitted_snapshot.label_num ||
        replacement.type.get_size() * 8 != receipt.source_bits() ||
        original.type.get_size() * 8 != receipt.source_bits() ||
        (parent_target && (!saved_target || parent_target->type != saved_target->type ||
                           parent_target->compare(*saved_target) != 0)))
    {
        analysis.reject_mutation(RejectReason::EmittedDestinationOrFrameMismatch);
        return false;
    }
    const bool constant_result = replacement.op == cot_num && snapshot.op != cot_num;
    if (!constant_result && !scalar_expression_improves(replacement, snapshot))
        return false;
    if (receipt.from_cobra() &&
        scalar_expression_cost(replacement) >= scalar_expression_cost(snapshot))
        return false;
    const auto unchanged = [&]
    {
        return current == expected && analysis.snapshot() == expected &&
               (!domain_unchanged || domain_unchanged()) && original.type == snapshot.type &&
               original.ea == snapshot.ea && original.exflags == snapshot.exflags &&
               original.label_num == snapshot.label_num && original.compare(snapshot) == 0 &&
               replacement.type == emitted_snapshot.type && replacement.ea == emitted_snapshot.ea &&
               replacement.exflags == emitted_snapshot.exflags &&
               replacement.label_num == emitted_snapshot.label_num &&
               replacement.compare(emitted_snapshot) == 0 &&
               (!parent_target || (saved_target && parent_target->type == saved_target->type &&
                                   parent_target->compare(*saved_target) == 0));
    };
    if (!analysis.eligible_for_commit(receipt, legacy_fallback, unchanged))
        return false;
    original.swap(replacement);
    ++current.mutation_epoch;
    return true;
}
}
