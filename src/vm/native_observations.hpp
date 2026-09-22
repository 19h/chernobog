#pragma once
#include "observations.hpp"
#include "native_region.hpp"
#include "../hybrid/emu_driver.hpp"

namespace chernobog::vm
{
struct NativeObservationView : ObservationView
{
    size_t path_steps = 0, starts_examined = 0, candidate_visits = 0;
    size_t unsupported_path_stops = 0, recognizer_rejections = 0, path_length_stops = 0,
           capture_end_stops = 0;
    bool path_limited = false;
};
// A separate ephemeral capture contract, never a TargetEvidence publication.
// The caller supplies semantic decoding checked against the planned bytes/mode.
// Instruction-entry samples cover fallthrough and repeated candidate visits.
NativeObservationView
project_native_observations(const NativeRegion &, const std::map<uint64_t, Instruction> &,
                            const hybrid::EmuEvents &, const hybrid::EmuOutcome &, unsigned mode,
                            uint64_t capture, uint64_t function, bool validate_transitions = false,
                            int64_t database = -1);
}
