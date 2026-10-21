#pragma once

#include "mba_smt.h"
#include "../analysis/mba_smt_context.hpp"

namespace chernobog::mba_smt
{
unsigned scalar_integer_bits(const tinfo_t &type);
Term resize_scalar_integer(Term value, unsigned bits, bool sign_extend);
Term convert_scalar_integer(Term value, const tinfo_t &source, const tinfo_t &destination);
// Only explicitly bound locals of this MBA can be read; calls and memory
// expressions are refused. Used to lift the actual detached SDK emission.
Term lift_scalar_expression(const cexpr_t &expression, const ScalarContext::Bindings &bindings,
                            const mba_t *owner, const std::function<bool()> &available = {});
// Common typed arithmetic engine. Effectful leaves require an explicit resolver;
// ordinary pure/memory adapters use the owner-checked binding overload above.
Term lift_scalar_expression_with_leaves(const cexpr_t *expression,
                                        const std::function<Term(const cexpr_t &)> &resolve,
                                        const std::function<bool()> &available, size_t &visits,
                                        unsigned depth = 0);
using ScalarLeaves = std::vector<std::pair<Term, cexpr_t>>;
// The caller must translate and prove this detached expression before installing
// it. Only current local values can stand for historical symbols during emission.
bool emit_scalar_expression(cfunc_t &function, const ScalarContext &context, const Term &value,
                            const tinfo_t &type, cexpr_t &output,
                            const ScalarLeaves *leaves = nullptr);

size_t scalar_expression_cost(const cexpr_t &expression);
// Break equal-operation-cost ties in favor of local reuse and flag-field syntax.
bool scalar_expression_improves(const cexpr_t &candidate, const cexpr_t &original);
} // namespace chernobog::mba_smt
