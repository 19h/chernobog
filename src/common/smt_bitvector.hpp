#pragma once
#include <z3++.h>
#include <stdexcept>

namespace chernobog::smt
{
enum class Arithmetic
{
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor
};

// Callers check microcode properties and explicit widths before invoking this
// shared fixed-width operation. No implicit widening or signed conversion.
inline z3::expr arithmetic(Arithmetic op, const z3::expr &left, const z3::expr &right)
{
    if (!left.is_bv() || !right.is_bv() || left.get_sort().bv_size() != right.get_sort().bv_size())
    {
        throw std::invalid_argument("unequal arithmetic widths");
    }
    switch (op)
    {
    case Arithmetic::Add:
        return left + right;
    case Arithmetic::Sub:
        return left - right;
    case Arithmetic::Mul:
        return left * right;
    case Arithmetic::And:
        return left & right;
    case Arithmetic::Or:
        return left | right;
    case Arithmetic::Xor:
        return left ^ right;
    }
    throw std::invalid_argument("unknown arithmetic operation");
}
} // namespace chernobog::smt
