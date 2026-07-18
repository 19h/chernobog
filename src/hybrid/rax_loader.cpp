/*
 * rax_loader.cpp — process-once adapter for the statically linked rax C ABI.
 *
 * No IDA headers are used here.  Keeping the address table behind rax_load()
 * preserves the existing consumer boundary while making every production
 * entry point resolve at link time.  A build with an incomplete C ABI fails at
 * the native link step instead of producing a partially usable plugin.
 */
#include "rax_loader.hpp"

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace chernobog::hybrid {

namespace {

std::string g_reason;

bool disabled_by_environment()
{
  const char *value = std::getenv("CHERNOBOG_RAX_DISABLE");
  return value != nullptr && std::strcmp(value, "1") == 0;
}

bool bind_linked_api(RaxApi *out)
{
#define X(field, sym) out->field = &sym;
  CHERNOBOG_RAX_API_FUNCS(X)
  CHERNOBOG_RAX_API_OPTIONAL_FUNCS(X)
#undef X

  out->decode = &rax_decode;
  out->analyze = &rax_analyze;

  // This should be invariant because the header and archive are built from the
  // same rax-capi source tree.  Retain the gate so an incorrectly mixed build
  // fails closed and reports the exact version mismatch.
  static const uint32_t kRequiredMinor = 3;
  uint32_t maj = 0;
  uint32_t min = 0;
  uint32_t patch = 0;
  out->version(&maj, &min, &patch);
  if ( maj != RAX_API_MAJOR || min < kRequiredMinor )
  {
    g_reason = "linked rax ABI incompatible (hybrid needs "
             + std::to_string(static_cast<unsigned>(RAX_API_MAJOR)) + "."
             + std::to_string(static_cast<unsigned>(kRequiredMinor))
             + "+, found " + std::to_string(maj) + "."
             + std::to_string(min) + ")";
    *out = RaxApi{};
    return false;
  }

  return true;
}

const RaxApi *load_once()
{
  static RaxApi api;
  static bool ok = false;
  static std::once_flag flag;
  std::call_once(flag, [] {
    if ( disabled_by_environment() )
    {
      g_reason = "statically linked rax disabled by CHERNOBOG_RAX_DISABLE=1";
      return;
    }
    ok = bind_linked_api(&api);
  });
  return ok ? &api : nullptr;
}

} // namespace

const RaxApi *rax_load() { return load_once(); }

const char *rax_unavailable_reason() { return g_reason.c_str(); }

} // namespace chernobog::hybrid
