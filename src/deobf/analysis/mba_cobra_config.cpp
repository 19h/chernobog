#include "mba_cobra.hpp"
#include <cstdlib>
#include <cstring>
#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <psapi.h>
#else
#include <sys/resource.h>
#endif
namespace chernobog::mba_smt
{
Backend selected_backend() noexcept
{
    const char *value = std::getenv("CHERNOBOG_MBA_BACKEND");
    return value && std::strcmp(value, "cobra") == 0 && cobra_backend::available()
               ? Backend::Cobra
               : Backend::Legacy;
}
const char *backend_diagnostic() noexcept
{
    const char *value = std::getenv("CHERNOBOG_MBA_BACKEND");
    if (!value || std::strcmp(value, "legacy") == 0)
        return "none";
    if (std::strcmp(value, "cobra") == 0)
        return cobra_backend::available() ? "none" : "cobra_unavailable";
    return "invalid_backend";
}
} // namespace chernobog::mba_smt

namespace chernobog::mba_smt::cobra_backend
{
uint64_t process_peak_rss_bytes() noexcept
{
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS counters{};
    if (!K32GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters)))
        return 0;
    return static_cast<uint64_t>(counters.PeakWorkingSetSize);
#else
    rusage usage{};
    if (getrusage(RUSAGE_SELF, &usage) != 0 || usage.ru_maxrss < 0)
        return 0;
#if defined(__APPLE__)
    return static_cast<uint64_t>(usage.ru_maxrss);
#else
    return static_cast<uint64_t>(usage.ru_maxrss) * UINT64_C(1024);
#endif
#endif
}
}
