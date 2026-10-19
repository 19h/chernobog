#include "mba_smt_internal.hpp"

#include <algorithm>
#include <optional>

namespace chernobog::mba_smt::detail
{
namespace
{
uint64_t width_mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }

std::optional<unsigned> power_of_two_shift(uint64_t value)
{
    if (value == 0 || (value & (value - 1)) != 0)
    {
        return {};
    }
    unsigned amount = 0;
    while ((value >>= 1) != 0)
    {
        ++amount;
    }
    return amount;
}

KnownBits shifted_bits(KnownBits input, Op operation, unsigned amount, unsigned bits)
{
    const uint64_t mask = width_mask(bits);
    if (amount >= bits && operation != Op::Sar)
    {
        return {mask, 0};
    }
    amount = std::min(amount, bits - 1);
    if (amount == 0)
    {
        return input;
    }
    if (operation == Op::Shl)
    {
        return {((input.zero << amount) | width_mask(amount)) & mask, (input.one << amount) & mask};
    }

    const uint64_t high = mask ^ width_mask(bits - amount);
    const uint64_t sign = uint64_t{1} << (bits - 1);
    const bool zero_fill = operation == Op::Shr || (input.zero & sign) != 0;
    const bool one_fill = operation == Op::Sar && (input.one & sign) != 0;
    return {(input.zero >> amount) | (zero_fill ? high : 0),
            (input.one >> amount) | (one_fill ? high : 0)};
}

// Distribute an observation mask only when it removes work. This avoids
// expanding a compact expression into separately masked operands.
class MaskNormalizer
{
  public:
    Term apply(const Term &term)
    {
        if (term->op == Op::And)
        {
            const Term literal = term->left->op == Op::Constant ? term->left : term->right;
            const Term input = term->left->op == Op::Constant ? term->right : term->left;
            if (literal->op == Op::Constant)
            {
                return observe(input, literal->value);
            }
        }
        if (term->op == Op::Xor || term->op == Op::Or || term->op == Op::And)
        {
            return combine(term->op, term->left, term->right);
        }
        return term;
    }

  private:
    Term combine(Op operation, const Term &left, const Term &right) const
    {
        const bool left_zero = left->op == Op::Constant && left->value == 0;
        const bool right_zero = right->op == Op::Constant && right->value == 0;
        if (left_zero || right_zero)
        {
            if (operation == Op::And)
            {
                return constant(0, left->bits);
            }
            return left_zero ? right : left;
        }

        const uint64_t mask = width_mask(left->bits);
        const KnownBits left_bits = known_bits(left);
        const KnownBits right_bits = known_bits(right);
        const bool disjoint = ((~left_bits.zero & ~right_bits.zero) & mask) == 0;
        if (disjoint && operation == Op::And)
        {
            return constant(0, left->bits);
        }
        if (disjoint && operation == Op::Xor)
        {
            operation = Op::Or;
        }
        return expression(operation, left, right);
    }

    Term observe(const Term &input, uint64_t mask)
    {
        mask &= width_mask(input->bits);
        const Term original = expression(Op::And, input, constant(mask, input->bits));
        if (++visited_ > limits::expression_visits)
        {
            return original;
        }
        if (mask == 0)
        {
            return constant(0, input->bits);
        }
        if (input->op == Op::Constant)
        {
            return constant(input->value & mask, input->bits);
        }
        const uint64_t removed = width_mask(input->bits) ^ mask;
        if ((removed & ~known_bits(input).zero) == 0)
        {
            return input;
        }
        if (input->op == Op::And)
        {
            const Term literal = input->left->op == Op::Constant ? input->left : input->right;
            const Term value = input->left->op == Op::Constant ? input->right : input->left;
            if (literal->op == Op::Constant)
            {
                return observe(value, mask & literal->value);
            }
        }
        if (input->op == Op::Or || input->op == Op::Xor)
        {
            const Term left = observe(input->left, mask);
            const Term right = observe(input->right, mask);
            const Term distributed = combine(input->op, left, right);
            if (cost(distributed) < cost(original))
            {
                return distributed;
            }
        }
        return original;
    }

    size_t visited_ = 0;
};
} // namespace

KnownBits known_bits(const Term &term)
{
    const uint64_t mask = width_mask(term->bits);
    if (term->op == Op::Constant)
    {
        return {~term->value & mask, term->value & mask};
    }
    if (term->op == Op::Variable || term->op == Op::Load)
    {
        return {};
    }

    const KnownBits left = known_bits(term->left);
    const KnownBits right = term->right ? known_bits(term->right) : KnownBits{};
    switch (term->op)
    {
    case Op::Not:
        return {left.one, left.zero};
    case Op::And:
        return {(left.zero | right.zero) & mask, left.one & right.one};
    case Op::Or:
        return {left.zero & right.zero, (left.one | right.one) & mask};
    case Op::Xor:
        return {(left.zero & right.zero) | (left.one & right.one),
                (left.zero & right.one) | (left.one & right.zero)};
    case Op::Low:
        return {left.zero & mask, left.one & mask};
    case Op::High:
    {
        const unsigned amount = term->left->bits - term->bits;
        return {(left.zero >> amount) & mask, (left.one >> amount) & mask};
    }
    case Op::ZeroExtend:
        return {left.zero | (mask ^ width_mask(term->left->bits)), left.one};
    case Op::SignExtend:
    {
        const uint64_t sign = uint64_t{1} << (term->left->bits - 1);
        const uint64_t high = mask ^ width_mask(term->left->bits);
        return {left.zero | ((left.zero & sign) != 0 ? high : 0),
                left.one | ((left.one & sign) != 0 ? high : 0)};
    }
    case Op::Shl:
    case Op::Shr:
    case Op::Sar:
        return term->right->op == Op::Constant
                   ? shifted_bits(left, term->op, unsigned(term->right->value & 0xFF), term->bits)
                   : KnownBits{};
    case Op::Mul:
    {
        const Term literal = term->left->op == Op::Constant ? term->left : term->right;
        if (literal->op != Op::Constant)
        {
            return {};
        }
        const uint64_t value = literal->value & mask;
        if (value == 0)
        {
            return {mask, 0};
        }
        const auto amount = power_of_two_shift(value);
        const KnownBits input = term->left->op == Op::Constant ? right : left;
        return amount ? shifted_bits(input, Op::Shl, *amount, term->bits) : KnownBits{};
    }
    case Op::Equal:
    case Op::NotEqual:
    case Op::UnsignedLess:
    case Op::SignedLess:
        return {mask ^ 1, 0};
    default:
        return {};
    }
}

Term normalize_masks(const Term &term)
{
    MaskNormalizer normalizer;
    return normalizer.apply(term);
}
} // namespace chernobog::mba_smt::detail
