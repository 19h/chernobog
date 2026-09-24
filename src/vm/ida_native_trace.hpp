#pragma once
#include <cstdint>
#include <string>
namespace chernobog::vm
{
// Explicit main-thread capture; no IDB mutation, ordinary evidence publication,
// automatic application, persistent cache, or VM-state identity inference.
std::string trace_native_region(uint64_t function, uint64_t seed);
std::string trace_native_candidate_region(uint64_t root, uint64_t seed);
std::string trace_native_candidate_region_input(uint64_t root, uint64_t seed,
                                                const std::string &request);
std::string trace_native_region_input(uint64_t function, uint64_t seed, const std::string &request);
std::string trace_native_region_walk(uint64_t function, uint64_t seed, const std::string &request);
std::string trace_native_region_check(uint64_t function, uint64_t seed, const std::string &request);
std::string trace_native_region_temporal(uint64_t function, uint64_t seed,
                                         const std::string &request, const std::string &bindings);
std::string inspect_native_temporal_strings(uint64_t function, const std::string &request,
                                            const std::string &bindings);
std::string inspect_native_temporal_prefix_strings(uint64_t function, const std::string &request,
                                                   const std::string &bindings);
std::string native_temporal_string_state(uint64_t ticket, const std::string &identity);
void clear_native_temporal_strings();
}
