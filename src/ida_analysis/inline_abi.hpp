#pragma once

class codegen_t;

namespace chernobog::ida_analysis
{
// Retain proven native callee saves when an outlined AMD64 function is inlined.
int preserve_inlined_abi(codegen_t *codegen, int source, int first, int last);
}
