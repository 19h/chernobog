// Preserve the existing fixture sources and their recorded hashes.
#include <stdint.h>

#if defined(_MSC_VER)
#define __attribute__(attributes) __declspec(dllexport) __declspec(noinline)
__declspec(dllexport) extern volatile uint32_t mba_mask_effects;
__declspec(dllexport) extern uint32_t mba_mask_alias_target;
__declspec(dllexport) extern volatile uint32_t mba_call_effects;
#endif

#define main mba_cobra_nested_main
#define check_values mba_cobra_nested_check_values
#define verify_functions mba_cobra_nested_verify_functions
#include "vmp_native/mba_nested.c"
#undef main
#undef check_values
#undef verify_functions

#define main mba_cobra_masks_main
#define check_values mba_cobra_masks_check_values
#define verify_functions mba_cobra_masks_verify_functions
#include "vmp_native/mba_masks.c"
#undef main
#undef check_values
#undef verify_functions

#define main mba_cobra_semantic_main
#include "vmp_native/mba_smt.c"
#undef main

int main(void)
{
    return mba_cobra_nested_main() || mba_cobra_masks_main() || mba_cobra_semantic_main();
}
