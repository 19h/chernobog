// Keep the existing unsigned oracle and its recorded source unchanged.
#if defined(_MSC_VER)
#define __attribute__(attributes) __declspec(dllexport) __declspec(noinline)
#endif
#include "vmp_native/mba_nested.c"
