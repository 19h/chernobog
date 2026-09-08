#pragma once

// The standalone executor test has no initialized Hex-Rays runtime. Apply
// the same dispatcher declaration to every translation unit before the SDK
// defines its inline operand operations.
extern "C" void *chernobog_executor_hexdsp(int code, ...);
#undef HEXDSP
#define HEXDSP chernobog_executor_hexdsp
