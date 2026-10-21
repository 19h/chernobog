#include "mba_smt_ctree.h"
#include <algorithm>

namespace chernobog::mba_smt
{
unsigned scalar_integer_bits(const tinfo_t &type)
{
    if (!type.is_integral() || type.is_volatile() || type.is_enum())
    {
        return 0;
    }
    const size_t bytes = type.get_size();
    return bytes == 1 || bytes == 2 || bytes == 4 || bytes == 8 ? unsigned(bytes * 8) : 0;
}

Term resize_scalar_integer(Term value, unsigned bits, bool sign_extend)
{
    if (!value || value->bits == 0 || bits == 0)
    {
        return {};
    }
    if (value->op == Op::Constant)
    {
        const uint64_t source_mask =
            value->bits == 64 ? UINT64_MAX : (uint64_t{1} << value->bits) - 1;
        const uint64_t target_mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
        uint64_t literal = value->value & source_mask;
        if (bits > value->bits && sign_extend && (literal & (uint64_t{1} << (value->bits - 1))))
        {
            literal |= ~source_mask;
        }
        return constant(literal & target_mask, bits);
    }
    if (bits == value->bits)
    {
        return value;
    }
    if (bits < value->bits)
    {
        return expression(Op::Low, value, {}, bits);
    }
    return expression(sign_extend ? Op::SignExtend : Op::ZeroExtend, value, {}, bits);
}

Term convert_scalar_integer(Term value, const tinfo_t &source, const tinfo_t &destination)
{
    const unsigned bits = scalar_integer_bits(destination);
    if (!value || bits == 0)
    {
        return {};
    }
    if (destination.is_bool())
    {
        return expression(Op::NotEqual, value, constant(0, value->bits), bits);
    }
    return resize_scalar_integer(value, bits, source.is_signed());
}

namespace
{
class PureScalarTerms
{
  public:
    PureScalarTerms(const std::function<Term(const cexpr_t &)> &resolve,
                    const std::function<bool()> &available, size_t &visits)
        : resolve_(resolve), available_(available), visits_(visits)
    {
    }
    Term translate(const cexpr_t *node, unsigned depth = 0);

  private:
    const std::function<Term(const cexpr_t &)> &resolve_;
    const std::function<bool()> &available_;
    size_t &visits_;
};
Term PureScalarTerms::translate(const cexpr_t *node, unsigned depth)
{
    if (!node || !(!available_ || available_()) || depth > limits::expression_depth ||
        ++visits_ > limits::expression_visits || !scalar_integer_bits(node->type))
    {
        return {};
    }
    const unsigned bits = scalar_integer_bits(node->type);
    if (node->op == cot_num)
    {
        const uint64_t mask = bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1;
        return constant(node->numval() & mask, bits);
    }
    if (node->op == cot_var || node->op == cot_call)
    {
        const Term value = resolve_(*node);
        return value && value->bits == bits ? value : Term{};
    }
    if (node->op == cot_cast)
    {
        return node->x ? convert_scalar_integer(translate(node->x, depth + 1), node->x->type,
                                                node->type)
                       : Term{};
    }
    if (node->op == cot_land || node->op == cot_lor)
    {
        Term left = translate(node->x, depth + 1);
        Term right = translate(node->y, depth + 1);
        if (!left || !right)
        {
            return {};
        }
        left = expression(Op::NotEqual, left, constant(0, left->bits), 8);
        right = expression(Op::NotEqual, right, constant(0, right->bits), 8);
        return resize_scalar_integer(
            expression(node->op == cot_land ? Op::And : Op::Or, left, right), bits, false);
    }

    if (!is_binary(node->op) && node->op != cot_lnot && node->op != cot_bnot && node->op != cot_neg)
    {
        return {};
    }

    Term left = translate(node->x, depth + 1);
    if (!left)
    {
        return {};
    }
    if (node->op == cot_lnot)
    {
        return expression(Op::Equal, left, constant(0, left->bits), bits);
    }
    if (node->op == cot_bnot || node->op == cot_neg)
    {
        left = convert_scalar_integer(left, node->x->type, node->type);
        return left ? expression(node->op == cot_bnot ? Op::Not : Op::Neg, left) : Term{};
    }

    Op operation;
    bool comparison = false;
    bool reverse = false;
    bool invert = false;
    switch (node->op)
    {
    case cot_add:
        operation = Op::Add;
        break;
    case cot_sub:
        operation = Op::Sub;
        break;
    case cot_mul:
        operation = Op::Mul;
        break;
    case cot_udiv:
        operation = Op::UnsignedDivide;
        break;
    case cot_band:
        operation = Op::And;
        break;
    case cot_bor:
        operation = Op::Or;
        break;
    case cot_xor:
        operation = Op::Xor;
        break;
    case cot_shl:
        operation = Op::Shl;
        break;
    case cot_ushr:
        operation = Op::Shr;
        break;
    case cot_sshr:
        operation = Op::Sar;
        break;
    case cot_eq:
        operation = Op::Equal;
        comparison = true;
        break;
    case cot_ne:
        operation = Op::NotEqual;
        comparison = true;
        break;
    case cot_slt:
        operation = Op::SignedLess;
        comparison = true;
        break;
    case cot_ult:
        operation = Op::UnsignedLess;
        comparison = true;
        break;
    case cot_sgt:
        operation = Op::SignedLess;
        comparison = true;
        reverse = true;
        break;
    case cot_ugt:
        operation = Op::UnsignedLess;
        comparison = true;
        reverse = true;
        break;
    case cot_sge:
        operation = Op::SignedLess;
        comparison = true;
        invert = true;
        break;
    case cot_uge:
        operation = Op::UnsignedLess;
        comparison = true;
        invert = true;
        break;
    case cot_sle:
        operation = Op::SignedLess;
        comparison = true;
        reverse = true;
        invert = true;
        break;
    case cot_ule:
        operation = Op::UnsignedLess;
        comparison = true;
        reverse = true;
        invert = true;
        break;
    default:
        return {};
    }
    Term right = translate(node->y, depth + 1);
    if (!right)
    {
        return {};
    }

    // C integer promotions happen before the operation; a narrow result is
    // truncated afterwards. In particular, truncating before division or a
    // right shift would change the result.
    const bool shift = operation == Op::Shl || operation == Op::Shr || operation == Op::Sar;
    const unsigned operand_bits =
        std::max({32u, left->bits, shift ? 0u : right->bits, comparison ? 0u : bits});
    left = resize_scalar_integer(left, operand_bits, node->x->type.is_signed());

    if (shift)
    {
        if (right->op != Op::Constant || right->value >= operand_bits)
        {
            return {};
        }
        right = constant(right->value, 8);
    }
    else
    {
        right = resize_scalar_integer(right, operand_bits, node->y->type.is_signed());
    }
    if (operation == Op::UnsignedDivide && (right->op != Op::Constant || right->value == 0))
    {
        return {};
    }
    Term result = expression(operation, reverse ? right : left, reverse ? left : right,
                             comparison ? bits : operand_bits);
    if (!comparison && operand_bits != bits)
    {
        result = expression(Op::Low, result, {}, bits);
    }
    return invert ? expression(Op::Equal, result, constant(0, bits), bits) : result;
}

}
Term lift_scalar_expression(const cexpr_t &node, const ScalarContext::Bindings &bindings,
                            const mba_t *owner, const std::function<bool()> &available)
{
    size_t visits = 0;
    const auto resolve = [&](const cexpr_t &leaf) -> Term
    {
        if (leaf.op != cot_var || leaf.v.mba != owner)
            return {};
        const auto bound = bindings.find(leaf.v.idx);
        return bound != bindings.end() ? bound->second : Term{};
    };
    return PureScalarTerms(resolve, available, visits).translate(&node);
}
Term lift_scalar_expression_with_leaves(const cexpr_t *node,
                                        const std::function<Term(const cexpr_t &)> &resolve,
                                        const std::function<bool()> &available, size_t &visits,
                                        unsigned depth)
{
    return PureScalarTerms(resolve, available, visits).translate(node, depth);
}
}
