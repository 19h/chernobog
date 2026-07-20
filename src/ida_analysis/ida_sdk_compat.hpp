#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <regfinder.hpp>

namespace chernobog::ida_analysis {

// Keep address-size handling explicit and uniform across the IDA 9.4 public
// SDK variants. CMake rejects older SDK ABIs before this header is compiled.
inline int effective_address_size_compat()
{
  return int(inf_get_app_bitness() / 8);
}

// IDA 9.4's reg_value_info_t carries address-size context and exposes
// get_addr(). The pre-9.4 branch documents the equivalent truncation for
// source compatibility, but is unreachable in supported Chernobog builds.
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

// Named register tracking is available in IDA 9.4. The fallback is retained as
// documentation/source compatibility; supported builds always take the 9.4
// branch because the SDK ABI is hard-pinned at configure time.
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
