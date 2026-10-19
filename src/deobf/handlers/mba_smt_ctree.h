#pragma once

#include "mba_smt.h"
#include "../analysis/mba_smt_context.hpp"

namespace chernobog::mba_smt
{
// The caller must translate and prove this detached expression before installing
// it. Only current local values can stand for historical symbols during emission.
bool emit_scalar_expression(cfunc_t &function, const ScalarContext &context, const Term &value,
                            const tinfo_t &type, cexpr_t &output);

size_t scalar_expression_cost(const cexpr_t &expression);
} // namespace chernobog::mba_smt
