#include "mba_smt_ctree.h"
#include "../analysis/mba_smt_known_bits.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <memory>
#include <optional>

namespace chernobog::mba_smt
{
namespace
{
using ExpressionPtr = std::unique_ptr<cexpr_t>;

uint64_t width_mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (uint64_t{1} << bits) - 1; }

std::optional<unsigned> power_of_two_shift(uint64_t value)
{
    if (value <= 1 || (value & (value - 1)) != 0)
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

bool compact_clear_mask(uint64_t value, unsigned bits)
{
    const uint64_t removed = width_mask(bits) & ~value;
    return bits >= 32 && removed != 0 && removed <= UINT16_MAX;
}

std::optional<uint64_t> literal_bits(const Term &value)
{
    if (value->op == Op::Constant)
    {
        return value->value & width_mask(value->bits);
    }
    if (value->op == Op::Not && value->left->op == Op::Constant)
    {
        return ~value->left->value & width_mask(value->bits);
    }
    return {};
}

tinfo_t integer_type(unsigned bits, bool is_signed = false)
{
    if (bits != 8 && bits != 16 && bits != 32 && bits != 64)
    {
        return {};
    }
    return get_int_type_by_width_and_sign(bits / 8, is_signed ? type_signed : type_unsigned);
}

ExpressionPtr cast(ExpressionPtr value, const tinfo_t &type)
{
    if (!value || type.empty())
    {
        return {};
    }
    if (value->type == type)
    {
        return value;
    }
    if (value->op == cot_num && type.is_integral() && !type.is_bool() &&
        value->type.get_size() == type.get_size() &&
        (!type.is_signed() || (value->numval() & width_mask(unsigned(type.get_size() * 8))) <=
                                  (width_mask(unsigned(type.get_size() * 8)) >> 1)))
    {
        value->type = type;
        return value;
    }
    if (value->op == cot_cast && value->x && type.is_integral() && !type.is_bool() &&
        value->type.is_integral() && !value->type.is_bool() && value->x->type.is_integral())
    {
        const tinfo_t &source_type = value->x->type;
        const size_t source_bytes = source_type.get_size();
        const size_t middle_bytes = value->type.get_size();
        const size_t destination_bytes = type.get_size();
        const bool final_truncation = destination_bytes <= middle_bytes;
        const bool same_extension =
            middle_bytes == source_bytes && value->type.is_signed() == source_type.is_signed();
        const bool preserved_extension =
            middle_bytes > source_bytes && (!source_type.is_signed() || value->type.is_signed());
        if (final_truncation || same_extension || preserved_extension)
        {
            // Truncation observes only the low bits. Widening can skip an
            // intermediate cast only when its extension agrees with the source.
            ExpressionPtr source(value->x);
            value->x = nullptr;
            return cast(std::move(source), type);
        }
    }
    auto result = std::make_unique<cexpr_t>(cot_cast, value.release());
    result->type = type;
    return result;
}

ExpressionPtr binary(ctype_t operation, ExpressionPtr left, ExpressionPtr right,
                     const tinfo_t &type)
{
    if (!left || !right || type.empty())
    {
        return {};
    }
    auto result = std::make_unique<cexpr_t>(operation, left.release(), right.release());
    result->type = type;
    return result;
}

class ScalarEmitter
{
  public:
    ScalarEmitter(cfunc_t &function, const ScalarContext &context, const ScalarLeaves *leaves)
        : function_(function), leaves_(leaves)
    {
        for (const auto &[local, value] : context.bindings())
        {
            locals_.emplace(key(value), local);
        }
    }

    ExpressionPtr emit(const Term &value, unsigned depth = 0, bool field_insertion = false)
    {
        if (!value || ++visits_ > limits::expression_visits || depth > limits::expression_depth)
        {
            return {};
        }
        const tinfo_t type = integer_type(value->bits);
        if (type.empty())
        {
            return {};
        }
        if (value->op == Op::Constant)
        {
            const bool signed_literal =
                value->bits >= 32 && value->value <= (width_mask(value->bits) >> 1);
            return number(value->value, value->bits, signed_literal);
        }

        if (leaves_)
            for (const auto &leaf : *leaves_)
                if (key(leaf.first) == key(value))
                    return std::make_unique<cexpr_t>(leaf.second);

        const auto local = locals_.find(key(value));
        if (local != locals_.end())
        {
            auto result = std::make_unique<cexpr_t>();
            result->op = cot_var;
            result->v.mba = function_.mba;
            result->v.idx = local->second;
            result->type = (*function_.get_lvars())[local->second].tif;
            return result;
        }
        if (value->op == Op::Variable || value->op == Op::Load)
        {
            // An old symbol may no longer have a readable local representative.
            return {};
        }

        if (value->op == Op::Or)
        {
            if (ExpressionPtr fields = field_update(value, depth))
            {
                return fields;
            }
        }
        if (field_insertion && value->op == Op::Mul)
        {
            const Term literal = value->left->op == Op::Constant ? value->left : value->right;
            const Term input = value->left->op == Op::Constant ? value->right : value->left;
            if (literal->op == Op::Constant)
            {
                if (const auto amount = power_of_two_shift(literal->value))
                {
                    return emit(expression(Op::Shl, input, constant(*amount, 8)), depth + 1);
                }
            }
        }

        ExpressionPtr left = emit(value->left, depth + 1);
        if (!left)
        {
            return {};
        }
        if (value->op == Op::Low || value->op == Op::ZeroExtend || value->op == Op::SignExtend)
        {
            left =
                cast(std::move(left), integer_type(value->left->bits, value->op == Op::SignExtend));
            return cast(std::move(left), type);
        }
        if (value->op == Op::High)
        {
            auto amount = std::make_unique<cexpr_t>();
            amount->put_number(&function_, value->left->bits - value->bits, 4, no_sign);
            amount->type = integer_type(32);
            left = cast(std::move(left), integer_type(value->left->bits));
            left = binary(cot_ushr, std::move(left), std::move(amount),
                          integer_type(value->left->bits));
            return cast(std::move(left), type);
        }
        if (value->op == Op::Not || value->op == Op::Neg)
        {
            const tinfo_t promoted = integer_type(std::max(32u, value->bits));
            left = cast(std::move(left), promoted);
            auto result = std::make_unique<cexpr_t>(value->op == Op::Not ? cot_bnot : cot_neg,
                                                    left.release());
            result->type = promoted;
            return cast(std::move(result), type);
        }

        ExpressionPtr right = emit(value->right, depth + 1);
        ctype_t operation;
        bool comparison = false;
        bool is_signed = false;
        switch (value->op)
        {
        case Op::Add:
            operation = cot_add;
            break;
        case Op::Sub:
            operation = cot_sub;
            break;
        case Op::Mul:
            operation = cot_mul;
            break;
        case Op::UnsignedDivide:
            operation = cot_udiv;
            break;
        case Op::And:
            operation = cot_band;
            break;
        case Op::Or:
            operation = cot_bor;
            break;
        case Op::Xor:
            operation = cot_xor;
            break;
        case Op::Shl:
            operation = cot_shl;
            break;
        case Op::Shr:
            operation = cot_ushr;
            break;
        case Op::Sar:
            operation = cot_sshr;
            is_signed = true;
            break;
        case Op::Equal:
            operation = cot_eq;
            comparison = true;
            break;
        case Op::NotEqual:
            operation = cot_ne;
            comparison = true;
            break;
        case Op::UnsignedLess:
            operation = cot_ult;
            comparison = true;
            break;
        case Op::SignedLess:
            operation = cot_slt;
            comparison = true;
            is_signed = true;
            break;
        default:
            return {};
        }

        // Signedness is explicit at the operation that observes it. All other
        // arithmetic uses unsigned types to retain modular machine semantics.
        const unsigned operation_bits = std::max(32u, value->left->bits);
        const bool bitwise = value->op == Op::And || value->op == Op::Or || value->op == Op::Xor;
        if (bitwise)
        {
            if (value->op == Op::And)
            {
                left = clear_mask(value->left, std::move(left));
                right = clear_mask(value->right, std::move(right));
            }
            auto result = bitwise_binary(operation, std::move(left), std::move(right));
            return value->bits < 32 ? cast(std::move(result), type) : std::move(result);
        }
        if (value->op == Op::Shl && value->right->op == Op::Constant)
        {
            const unsigned amount = unsigned(value->right->value);
            const auto known = detail::known_bits(value->left);
            const uint64_t maximum = width_mask(value->left->bits) & ~known.zero;
            const bool nonnegative = (known.zero & (uint64_t{1} << (value->left->bits - 1))) != 0;
            const bool signed_shift_safe = nonnegative && amount < operation_bits &&
                                           maximum <= ((width_mask(operation_bits) >> 1) >> amount);
            if (left->type.is_signed() && signed_shift_safe)
            {
                left = cast(std::move(left), integer_type(operation_bits, true));
                right = number(amount, 32, true);
                auto result = binary(cot_shl, std::move(left), std::move(right),
                                     integer_type(operation_bits, true));
                return value->bits < 32 ? cast(std::move(result), type) : std::move(result);
            }
        }
        left = cast(std::move(left), integer_type(operation_bits, is_signed));
        if (comparison)
        {
            right =
                cast(std::move(right), integer_type(std::max(32u, value->right->bits), is_signed));
        }
        else if (value->op != Op::Shl && value->op != Op::Shr && value->op != Op::Sar)
        {
            right = cast(std::move(right), integer_type(operation_bits));
        }
        auto result =
            binary(operation, std::move(left), std::move(right),
                   comparison ? tinfo_t(BTF_BOOL) : integer_type(operation_bits, is_signed));
        return cast(std::move(result), type);
    }

  private:
    struct Field
    {
        unsigned position;
        Term value;
    };

    ExpressionPtr number(uint64_t value, unsigned bits, bool is_signed = false)
    {
        auto result = std::make_unique<cexpr_t>();
        result->put_number(&function_, value, bits / 8, is_signed ? type_signed : type_unsigned);
        result->type = integer_type(bits, is_signed);
        return result;
    }

    ExpressionPtr clear_mask(const Term &value, ExpressionPtr original)
    {
        const auto literal = literal_bits(value);
        if (!literal || !compact_clear_mask(*literal, value->bits))
        {
            return original;
        }
        ExpressionPtr removed = number(width_mask(value->bits) & ~*literal, value->bits);
        removed->n->nf.flags = hex_flag();
        removed->n->nf.props = NF_FIXED;
        auto result = std::make_unique<cexpr_t>(cot_bnot, removed.release());
        result->type = integer_type(value->bits);
        return result;
    }

    ExpressionPtr bitwise_binary(ctype_t operation, ExpressionPtr left, ExpressionPtr right)
    {
        if (!left || !right)
        {
            return {};
        }
        // Integer promotions preserve these bit patterns without a same-width
        // sign cast. Arithmetic and signed comparisons still cast explicitly.
        if (left->type.get_size() < 4)
        {
            left = cast(std::move(left), integer_type(32, true));
        }
        if (right->type.get_size() < 4)
        {
            right = cast(std::move(right), integer_type(32, true));
        }
        const size_t left_bytes = left->type.get_size();
        const size_t right_bytes = right->type.get_size();
        const unsigned bits = unsigned(std::max(left_bytes, right_bytes) * 8);
        bool is_signed = left->type.is_signed() && right->type.is_signed();
        if (left_bytes != right_bytes)
        {
            is_signed = left_bytes > right_bytes ? left->type.is_signed() : right->type.is_signed();
        }
        return binary(operation, std::move(left), std::move(right), integer_type(bits, is_signed));
    }

    ExpressionPtr field_update(const Term &value, unsigned depth)
    {
        // Only reorder complete field updates: retained bits first, then
        // insertions in increasing bit position. Other OR expressions retain
        // their existing grouping.
        std::vector<Field> fields;
        std::vector<Term> pending{value};
        bool has_clear_mask = false;
        while (!pending.empty() && fields.size() < limits::expression_visits)
        {
            const Term field = pending.back();
            pending.pop_back();
            if (field->op == Op::Or)
            {
                pending.push_back(field->right);
                pending.push_back(field->left);
                continue;
            }
            if (field->op == Op::And)
            {
                const auto left = literal_bits(field->left);
                const auto right = literal_bits(field->right);
                const auto literal = left ? left : right;
                if (literal && compact_clear_mask(*literal, field->bits))
                {
                    fields.push_back({0, field});
                    has_clear_mask = true;
                    continue;
                }
            }
            if (field->op == Op::Shl && field->right->op == Op::Constant)
            {
                fields.push_back({unsigned(field->right->value) + 1, field});
                continue;
            }
            if (field->op == Op::Mul)
            {
                const Term literal = field->left->op == Op::Constant ? field->left : field->right;
                if (literal->op == Op::Constant)
                {
                    if (const auto amount = power_of_two_shift(literal->value))
                    {
                        fields.push_back({*amount + 1, field});
                        continue;
                    }
                }
            }
            return {};
        }
        if (!has_clear_mask || !pending.empty())
        {
            return {};
        }
        std::stable_sort(fields.begin(), fields.end(), [](const Field &left, const Field &right)
                         { return left.position < right.position; });
        ExpressionPtr result;
        for (const Field &field : fields)
        {
            ExpressionPtr next = emit(field.value, depth + 1, true);
            if (!next)
            {
                return {};
            }
            result = result ? bitwise_binary(cot_bor, std::move(result), std::move(next))
                            : std::move(next);
        }
        return result;
    }

    cfunc_t &function_;
    const ScalarLeaves *leaves_;
    std::map<std::string, int> locals_;
    size_t visits_ = 0;
};
} // namespace

bool emit_scalar_expression(cfunc_t &function, const ScalarContext &context, const Term &value,
                            const tinfo_t &type, cexpr_t &output, const ScalarLeaves *leaves)
{
    ScalarEmitter emitter(function, context, leaves);
    ExpressionPtr result = cast(emitter.emit(value), type);
    if (!result)
    {
        return false;
    }
    output.swap(*result);
    return true;
}

size_t scalar_expression_cost(const cexpr_t &expression)
{
    struct Cost final : ctree_visitor_t
    {
        Cost() : ctree_visitor_t(CV_FAST) {}

        int idaapi visit_expr(cexpr_t *node) override
        {
            if (++visited > limits::expression_visits)
            {
                value = std::numeric_limits<size_t>::max();
                return 1;
            }
            switch (node->op)
            {
            case cot_num:
            case cot_var:
            case cot_obj:
            case cot_cast:
                break;
            case cot_call:
                value += 4;
                break;
            case cot_udiv:
            case cot_sdiv:
                value += limits::division_cost;
                break;
            case cot_bnot:
                value += !node->x || node->x->op != cot_num;
                break;
            default:
                ++value;
                break;
            }
            return 0;
        }

        size_t value = 0;
        size_t visited = 0;
    } cost;

    cost.apply_to(const_cast<cexpr_t *>(&expression), nullptr);
    return cost.value;
}

bool scalar_expression_improves(const cexpr_t &candidate, const cexpr_t &original)
{
    const size_t candidate_cost = scalar_expression_cost(candidate);
    const size_t original_cost = scalar_expression_cost(original);
    if (candidate_cost != original_cost)
    {
        return candidate_cost < original_cost;
    }

    struct PresentationCost final : ctree_visitor_t
    {
        PresentationCost() : ctree_visitor_t(CV_FAST) {}

        int idaapi visit_expr(cexpr_t *node) override
        {
            if (++visited > limits::expression_visits)
            {
                value = std::numeric_limits<size_t>::max();
                return 1;
            }
            value += node->op == cot_cast;
            // A leading insertion prevents the retained field from appearing
            // first. Count it only as a tie breaker, never as an operation.
            if (node->op == cot_bor && node->x &&
                (node->x->op == cot_shl || node->x->op == cot_mul))
            {
                ++value;
            }
            if ((node->op == cot_mul || node->op == cot_band) && node->x && node->y)
            {
                const cexpr_t *literal = node->x->op == cot_num ? node->x : node->y;
                if (literal->op == cot_num)
                {
                    const unsigned bits = unsigned(literal->type.get_size() * 8);
                    value += node->op == cot_mul
                                 ? 2 * bool(power_of_two_shift(literal->numval()))
                                 : compact_clear_mask(literal->numval() & width_mask(bits), bits);
                }
            }
            return 0;
        }

        size_t value = 0;
        size_t visited = 0;
    } candidate_format, original_format;

    candidate_format.apply_to(const_cast<cexpr_t *>(&candidate), nullptr);
    original_format.apply_to(const_cast<cexpr_t *>(&original), nullptr);
    return candidate_format.value < original_format.value;
}
} // namespace chernobog::mba_smt
