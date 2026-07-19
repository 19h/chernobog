/* Current-database bridge between Z3 claims and generation-bound rax evidence. */
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "evidence.hpp"

namespace chernobog::hybrid {

struct HybridBranchCheck
{
  bool evidence_available = false;
  bool snapshot_current = false;
  uint64_t generation = 0;
  BranchClaimCheck claim;

  bool veto() const
  {
    return evidence_available && snapshot_current
        && claim.falsifies_universal_claim();
  }
};

// Session lifecycle. Database IDs are IDA's signed dbctx identifiers cast to
// int64_t; shared ownership allows a concurrent reader to finish safely.
bool hybrid_publish_evidence(
    int64_t database_id, std::shared_ptr<const TargetEvidence> evidence);
void hybrid_clear_evidence(int64_t database_id);

// Exact current-function plus consumed-context freshness check. Main thread
// only; false also covers missing evidence and a database-context mismatch.
bool hybrid_current_evidence_is_fresh(uint64_t function_start);

// Start a display-only projection immediately before Chernobog mutates the
// explored function, seal intermediate trusted mutations, then finish it at
// CMAT_FINAL. The source evidence remains stale for proof consumers; only
// cross-run runtime literals may survive through this explicitly bounded
// transformation window. All operations are main-thread only. A failed seal
// invalidates the window; changed function bytes also require exact patch-site
// authorization. Finish prevents any later resealing.
bool hybrid_begin_deobfuscation_projection(uint64_t function_start);
void hybrid_abandon_deobfuscation_projection(uint64_t function_start);
bool hybrid_authorize_deobfuscation_patch(
    uint64_t function_start, uint64_t address, size_t size);
bool hybrid_seal_deobfuscation_projection(uint64_t function_start);
bool hybrid_finish_deobfuscation_projection(uint64_t function_start);

// Consensus runtime plaintext for proof-adjacent consumers. This requires the
// complete function-plus-consumed-context identity to remain current.
std::vector<RuntimeStringCandidate> hybrid_current_runtime_strings(
    uint64_t function_start);

// Display-only projection for the ctree produced from the explored function.
// It accepts either the original exact function identity or the post-pass
// identity sealed by the begin/seal window above. It intentionally does not
// promote stale source evidence to branch/Z3 proof. The values remain concrete
// cross-run witnesses and may only be used as transient literals.
std::vector<RuntimeStringCandidate>
hybrid_current_runtime_strings_for_decompilation(uint64_t function_start);

// Main-thread convenience used by microcode handlers. It derives the current
// database ID and byte-compares every snapshotted function chunk before using
// an observation, so stale evidence fails closed after patches/reanalysis.
HybridBranchCheck hybrid_check_current_branch_claim(
    uint64_t function_start, uint64_t branch_instruction,
    bool expected_taken);

struct Z3ConcreteRegisterInput
{
  int micro_register = -1;
  uint8_t width = 0;
  uint64_t value = 0;
  std::string native_register;
};

struct Z3ConcretePredicateInput
{
  uint32_t run_id = 0;
  uint64_t seed = 0;
  std::vector<Z3ConcreteRegisterInput> registers;
};

// Concrete architectural states captured immediately before a conditional
// instruction and mapped into Hex-Rays micro-register identifiers. Consumers
// must still model preceding microcode/aliases; these are inputs, not proofs.
std::vector<Z3ConcretePredicateInput> hybrid_collect_current_z3_inputs(
    uint64_t function_start, uint64_t branch_instruction);

struct HybridObservedTargetCandidate
{
  uint64_t target = 0;
  ExecEdge::Kind kind = ExecEdge::Kind::Unknown;
  size_t observations = 0;
  std::vector<uint32_t> runs;
};

// Observation-only candidates for unresolved microcode calls/jumps. The
// bridge intentionally does not expose a "unique proof" operation: repeated
// concrete runs cannot establish that no other target exists.
std::vector<HybridObservedTargetCandidate>
hybrid_current_indirect_target_candidates(
    uint64_t function_start, uint64_t instruction);

// Generic hand-off for Z3 consumers that can express a model in source-level
// explicit-argument order. For Objective-C methods the session preserves the
// hidden ABI `self`/`_cmd` pair and begins these values at the third argument
// register. The current-function session drains only requests matching its
// exact database/function; no background/global model sweep is possible.
struct Z3ModelReplayRequest
{
  uint64_t function_start = 0;
  uint64_t claim_address = 0;
  std::vector<uint64_t> arguments;
  std::string label;
};

bool hybrid_queue_z3_model_replay(
    int64_t database_id, Z3ModelReplayRequest request);
std::vector<Z3ModelReplayRequest> hybrid_take_z3_model_replays(
    int64_t database_id, uint64_t function_start);

} // namespace chernobog::hybrid
