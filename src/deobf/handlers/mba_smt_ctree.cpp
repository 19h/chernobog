#include "mba_smt_ctree.h"

#include <algorithm>
#include <limits>
#include <map>
#include <memory>

namespace chernobog::mba_smt
{
namespace
{
using ExpressionPtr = std::unique_ptr<cexpr_t>;

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
    if (value->op == cot_num && type.is_integral() && value->type.get_size() == type.get_size())
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
    ScalarEmitter(cfunc_t &function, const ScalarContext &context) : function_(function)
    {
        for (const auto &[local, value] : context.bindings())
        {
            locals_.emplace(key(value), local);
        }
    }

    ExpressionPtr emit(const Term &value, unsigned depth = 0)
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
            auto result = std::make_unique<cexpr_t>();
            result->put_number(&function_, value->value, value->bits / 8, no_sign);
            result->type = type;
            return result;
        }

        const auto local = locals_.find(key(value));
        if (local != locals_.end())
        {
            auto result = std::make_unique<cexpr_t>();
            result->op = cot_var;
            result->v.mba = function_.mba;
            result->v.idx = local->second;
            result->type = (*function_.get_lvars())[local->second].tif;
            return cast(std::move(result), type);
        }
        if (value->op == Op::Variable || value->op == Op::Load)
        {
            // An old symbol may no longer have a readable local representative.
            return {};
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
    cfunc_t &function_;
    std::map<std::string, int> locals_;
    size_t visits_ = 0;
};
} // namespace

bool emit_scalar_expression(cfunc_t &function, const ScalarContext &context, const Term &value,
                            const tinfo_t &type, cexpr_t &output)
{
    ScalarEmitter emitter(function, context);
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
} // namespace chernobog::mba_smt
