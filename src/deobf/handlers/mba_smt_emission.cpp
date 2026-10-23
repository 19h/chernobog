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
bool same_expression_metadata(const cexpr_t &left, const cexpr_t &right)
{
    if (left.op != right.op || left.type != right.type || left.ea != right.ea ||
        left.exflags != right.exflags || left.label_num != right.label_num)
        return false;
    if (left.op == cot_var && (left.v.mba != right.v.mba || left.v.idx != right.v.idx))
        return false;
    if (left.op == cot_call)
    {
        if (!left.a || !right.a)
            return left.a == right.a;
        if (left.a->size() != right.a->size())
            return false;
        for (size_t i = 0; i < left.a->size(); ++i)
            if ((*left.a)[i].formal_type != (*right.a)[i].formal_type ||
                (*left.a)[i].is_vararg != (*right.a)[i].is_vararg)
                return false;
    }
    return true;
}
struct CtreeFrames : ctree_visitor_t
{
    std::vector<const cexpr_t *> expressions;
    std::vector<const cinsn_t *> instructions;
    size_t limit;
    size_t depth_limit;
    explicit CtreeFrames(size_t count)
        : ctree_visitor_t(CV_PARENTS), limit(count),
          depth_limit(count == limits::expression_visits ? limits::expression_depth : 512)
    {
    }
    int idaapi visit_expr(cexpr_t *node) override
    {
        if (expressions.size() + instructions.size() >= limit || parents.size() > depth_limit)
            return 1;
        expressions.push_back(node);
        return 0;
    }
    int idaapi visit_insn(cinsn_t *node) override
    {
        if (expressions.size() + instructions.size() >= limit || parents.size() > depth_limit)
            return 1;
        instructions.push_back(node);
        return 0;
    }
};
template <class Tree> bool same_ctree(const Tree &left, const Tree &right, size_t limit)
{
    CtreeFrames a(limit), b(limit);
    if (a.apply_to(const_cast<Tree *>(&left), nullptr) != 0 ||
        b.apply_to(const_cast<Tree *>(&right), nullptr) != 0 ||
        a.expressions.size() != b.expressions.size() ||
        a.instructions.size() != b.instructions.size())
        return false;
    if (left.compare(right) != 0)
        return false;
    for (size_t i = 0; i < a.expressions.size(); ++i)
        if (!same_expression_metadata(*a.expressions[i], *b.expressions[i]))
            return false;
    for (size_t i = 0; i < a.instructions.size(); ++i)
    {
        const auto &x = *a.instructions[i], &y = *b.instructions[i];
        if (x.op != y.op || x.ea != y.ea || x.label_num != y.label_num)
            return false;
    }
    return true;
}
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
    case mop_a:
        return operand.oprops == 0 && operand.a && operand.a->oprops == 0 &&
               ((operand.a->t == mop_S && operand.a->s && operand.a->s->mba) ||
                (operand.a->t == mop_l && operand.a->l && operand.a->l->mba) ||
                operand.a->t == mop_v);
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
bool same_ctree_expression(const cexpr_t &left, const cexpr_t &right)
{
    return same_ctree(left, right, limits::expression_visits);
}
bool same_ctree_locals(const lvars_t &left, const lvars_t &right)
{
    const auto properties = [](const lvar_t &local)
    {
        return std::array<bool, 29>{{local.used(),
                                     local.typed(),
                                     local.mreg_done(),
                                     local.has_nice_name(),
                                     local.is_unknown_width(),
                                     local.has_user_info(),
                                     local.has_user_name(),
                                     local.has_user_type(),
                                     local.is_result_var(),
                                     local.is_arg_var(),
                                     local.is_fake_var(),
                                     local.is_overlapped_var(),
                                     local.is_floating_var(),
                                     local.is_spoiled_var(),
                                     local.is_partialy_typed(),
                                     local.is_noptr_var(),
                                     local.is_mapdst_var(),
                                     local.is_thisarg(),
                                     local.is_split_var(),
                                     local.has_regname(),
                                     local.in_asm(),
                                     local.is_dummy_arg(),
                                     local.is_notarg(),
                                     local.is_automapped(),
                                     local.is_used_byref(),
                                     local.is_decl_unused(),
                                     local.is_shared(),
                                     local.was_scattered_arg(),
                                     local.is_noprop()}};
    };
    if (left.size() != right.size())
        return false;
    for (size_t i = 0; i < left.size(); ++i)
    {
        const auto &a = left[i], &b = right[i];
        if (a.tif != b.tif || a.width != b.width || a.location != b.location ||
            a.defea != b.defea || a.defblk != b.defblk || a.divisor != b.divisor ||
            a.name != b.name || a.cmt != b.cmt || properties(a) != properties(b))
            return false;
    }
    return true;
}

bool same_ctree_body(const cinsn_t &left, const cinsn_t &right)
{
    return same_ctree(left, right, 131072);
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
        return (!domain_unchanged || domain_unchanged()) && current == expected &&
               analysis.snapshot() == expected && same_microcode_instruction(original, snapshot) &&
               same_microcode_instruction(replacement, emitted_snapshot);
    };
    if (!analysis.eligible_for_commit(receipt, false, unchanged))
        return false;
    if (current != expected)
    {
        analysis.reject_mutation(RejectReason::StaleSnapshot);
        return false;
    }
    original.swap(replacement);
    ++current.mutation_epoch;
    analysis.record_applied(receipt);
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
        !same_ctree_expression(replacement, emitted_snapshot) ||
        replacement.type != emitted_snapshot.type || replacement.ea != emitted_snapshot.ea ||
        replacement.exflags != emitted_snapshot.exflags ||
        replacement.label_num != emitted_snapshot.label_num ||
        replacement.type.get_size() * 8 != receipt.source_bits() ||
        original.type.get_size() * 8 != receipt.source_bits() ||
        (parent_target && (!saved_target || parent_target->type != saved_target->type ||
                           !same_ctree_expression(*parent_target, *saved_target))))
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
        return (!domain_unchanged || domain_unchanged()) && current == expected &&
               analysis.snapshot() == expected && original.type == snapshot.type &&
               original.ea == snapshot.ea && original.exflags == snapshot.exflags &&
               original.label_num == snapshot.label_num &&
               same_ctree_expression(original, snapshot) &&
               replacement.type == emitted_snapshot.type && replacement.ea == emitted_snapshot.ea &&
               replacement.exflags == emitted_snapshot.exflags &&
               replacement.label_num == emitted_snapshot.label_num &&
               same_ctree_expression(replacement, emitted_snapshot) &&
               (!parent_target || (saved_target && parent_target->type == saved_target->type &&
                                   same_ctree_expression(*parent_target, *saved_target)));
    };
    if (!analysis.eligible_for_commit(receipt, legacy_fallback, unchanged))
        return false;
    if (current != expected)
    {
        analysis.reject_mutation(RejectReason::StaleSnapshot);
        return false;
    }
    original.swap(replacement);
    ++current.mutation_epoch;
    analysis.record_applied(receipt);
    return true;
}
}
