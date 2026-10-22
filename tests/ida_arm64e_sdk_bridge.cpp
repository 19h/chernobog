#include "deobf/analysis/arch_utils.h"

#ifdef _WIN32
#define ARM64E_EXPORT __declspec(dllexport)
#else
#define ARM64E_EXPORT __attribute__((visibility("default")))
#endif

extern "C" ARM64E_EXPORT int chernobog_arm64e_identity(uint64_t address)
{
    return arch::analyze_identity_function(ea_t(address)) ? 1 : 0;
}
extern "C" ARM64E_EXPORT int chernobog_arm64e_argument_register()
{
    return arch::get_first_arg_reg();
}
extern "C" ARM64E_EXPORT int chernobog_arm64e_return_register() { return arch::get_return_reg(); }
