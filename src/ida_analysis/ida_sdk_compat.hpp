#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <regfinder.hpp>

namespace chernobog::ida_analysis {

// IDA 9.4 added inf_get_effective_addrsize(). Keep the same 2/4/8-byte
// semantics when compiling against the stable 9.3 SDK used by CI.
inline int effective_address_size_compat()
{
  return int(inf_get_app_bitness() / 8);
}

// IDA 9.4's reg_value_info_t carries the address-size context and exposes
// get_addr(). The 9.3 tracker only exposes its unique numeric value, so apply
// the equivalent address-width truncation explicitly.
inline bool reg_value_address_compat(
    const reg_value_info_t &value,
    ea_t *address)
{
  if ( address == nullptr )
    return false;
#if IDA_SDK_VERSION >= 940
  return value.get_addr(address);
#else
  uval_t raw = 0;
  if ( !value.get_num(&raw) )
    return false;
  if ( inf_is_16bit() )
    raw &= uval_t(0xFFFFU);
  else if ( !inf_is_64bit() )
    raw &= uval_t(0xFFFFFFFFU);
  *address = ea_t(raw);
  return true;
#endif
}

// Named register tracking was added in IDA 9.4. On 9.3, use the decoded
// processor-register id when available, or resolve the native register name.
inline bool find_register_value_info_compat(
    reg_value_info_t *value,
    ea_t address,
    const char *register_name,
    int processor_register,
    int maximum_depth)
{
#if IDA_SDK_VERSION >= 940
  if ( register_name != nullptr && register_name[0] != '\0' )
  {
    return find_regname_value_info(
        value, address, register_name, maximum_depth);
  }
#else
  if ( processor_register < 0
    && register_name != nullptr && register_name[0] != '\0' )
  {
    processor_register = str2reg(register_name);
  }
#endif
  return processor_register >= 0
      && find_reg_value_info(
          value, address, processor_register, maximum_depth);
}

} // namespace chernobog::ida_analysis
