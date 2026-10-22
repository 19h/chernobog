#pragma once

#include <pro.h>
#include <hexrays.hpp>

namespace chernobog::ida_analysis
{
// Value operations omitted by the standard generator are retained as explicit
// intrinsics. Conventional return-address hints retain native frame handling.
bool matches_arm64e_primitive(const codegen_t &codegen);
merror_t emit_arm64e_primitive(codegen_t &codegen);
} // namespace chernobog::ida_analysis
