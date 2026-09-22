# Bounded continuation of observed native transfers

`chernobog_vm_trace_walk(ea, seed, input_json)` extends separately scoped native
observations past an observed indirect call, indirect jump, or near return.
The JSON input contract is unchanged from `VMP_NATIVE_INPUTS.md`. Existing
`chernobog_vm_trace` and `chernobog_vm_trace_input` retain their stopped-prefix
behavior. Ordinary function execution and publication retain their boundaries.

This checkpoint extends 224 protected input captures and records 1,463 native
destination admissions. It does not establish logical VM ownership, unique
targets for other inputs, or complete protected-function behavior. All 384
virtualization/combined cases remain incomplete; the concrete reasons are
reported below. Full review implementation remains in progress.

## Admission and execution contract

`extend_native_region` in `src/vm/native_region.cpp` constructs a copied plan.
It checks the prior image content/generation identity, an already admitted
indirect/return source, and a new destination. Planning uses the existing
mode-aware decoder, loaded executable bytes, explicit permissions, supported
control flow, and nonoverlapping instruction spans. Existing instruction
interpretations must remain identical. The root entry is preserved; the
previous plan is unchanged. Source eligibility is a structural check, not a
proof that an arbitrary caller actually observed the supplied destination.

The production driver supplies that observation from the stopped emulator:
the current PC, boundary source/destination, most recent edge, and event sequence
must agree. Code, memory, and invalid-access hooks must be available and the
retained prefix must not have exceeded its relevant trace quotas. Native
instructions execute their effects before the destination is observed.

After extension, the same engine resumes at the unexecuted destination.
Registers, flags, memory, stack, and backend state remain in that engine.
No baseline restoration, register reseeding, callee summary, or replay is used
between admissions. The stopped target's edge and register sample already
exist. Resumption reuses that event sequence for the target instruction and
does not duplicate the transfer or its target-state sample. Exact runtime
instruction-byte checks still run before the destination executes.

The final plan, `initial_region_identity`, and `native_admissions` are exported.
Each admission records source, target, event sequence, before/after plan labels,
added-head count, acceptance, and reason. Labels remain noncryptographic
identifiers, not proofs or persistent cache keys. `native_walk_stop` exposes
admission and shared-budget stops alongside the existing execution stop.
Admission means byte eligibility; it does not guarantee that the target
instruction executed before a budget expired. Execution rows answer that
separate question.

The API uses one 4,096-instruction and 250 ms execution/planning budget, at most
64 admission attempts, at most 4,096 admitted heads, and at most 8,192 distinct
frontier records. The portable driver clamps larger execution requests to
65,536 instructions and 1,000 ms. Planning time between emulator slices counts
against the shared wall-time budget. Decoder calls and snapshot/hash work are
not preemptible; the API does not promise a strict 250 ms end-to-end deadline.
The bounded ordinary input and final-byte quotas remain in force.

Far calls/jumps/returns and interrupt returns are now explicitly rejected by
the IDA native decoder: segment/privilege changes are outside the flat user-mode
snapshot. Rejected instruction semantics, including 16-bit BSWAP, are not
enabled by observing their addresses. Changed code, unsupported spans, overlap,
and external/unmapped execution retain explicit stops.

For at most K extensions, an I-byte image, and H bounded native heads, added
planning costs O(K * (I + H log H)) time, excluding decoder internals and the
underlying execution. Working plan storage is O(H + F), with F bounded frontier
records; retained admissions cost O(K). Existing image snapshots and event
storage remain additional costs. Image hashing is repeated during extension;
incremental reuse has not been established as fresh or equivalent.

## Measurements and independent checks

The accepted matrix uses the same ten binaries and 16 input triples per selected
function per architecture as the explicit-input checkpoint. Each walk has a
separate stopped-prefix comparison capture, making 640 walk captures and 640
comparison captures. These are separate engine executions, not shared clock
environments. Production assertions and behavior counts below refer to the walk
matrix; comparison records provide additional diagnostics.

| Measurement | x64 Mach-O | i386 ELF |
|---|---:|---:|
| Walk captures | 320 | 320 |
| Original/mutation return, result, memory, stack and defined-flags matches | 128 | 128 |
| Virtualization/combined captures extended beyond stopped comparison | 128 | 96 |
| Native destination admissions | 839 | 624 |
| Admitted targets entered at their recorded transfer event | 824 | 624 |
| Distinct binary-label/source/target triples admitted | 57 | 39 |
| Register-jump transfer oracles passed | 341 | 256 |
| Near-return transfer oracles passed | 498 | 368 |
| Entered instruction records independently decoded | 74,461 | 43,296 |
| Stopped-comparison instruction records | 18,980 | 11,616 |
| Recorded memory accesses in walks | 13,616 | 6,320 |
| Rejected 16-bit BSWAP boundary captures | 176 | 192 |
| Shared host-budget boundary stops | 15 | 0 |
| Backend timeout stops | 1 | 0 |
| Largest admission count in one walk | 18 | 14 |
| Largest admitted head count in one walk | 1,068 | 840 |
| Largest entered instruction count in one walk | 1,782 | 878 |
| Production matrix assertions | 5,526 | 5,106 |
| Sum of runner elapsed time / s | 115.563550957 | 104.740001331 |
| Maximum measured runner resident memory / bytes | 475,824,128 | 225,263,616 |

The 15 host-budget stops occur after planning admitted a target but before its
instruction executed. They retain native-boundary status plus
`native_walk_stop=time_budget`. The backend timeout is separately reported as
`stop=timeout`. None is counted as completed behavior or silently retried with
a larger budget. All 640 walks have complete retained data prefixes under the
existing data-event contract; that does not imply complete execution.

The architecture matrices ran concurrently and overlapped auxiliary controls
and CTest. Times are sums of measured runner-process elapsed nanoseconds divided
by 10^9, not combined wall time or a speedup. Resident-memory measurements include
the runner/IDA scope. Extension count and clock-dependent environment state can
also affect timing. These measurements do not isolate extension-planner cost.

Capstone 5.0.7 verifies all 117,757 entered instruction spans, file-backed bytes,
and linear successors: zero mismatches. `verify_vm_native_walk.py` independently
decodes each admission source and joins its precise edge, target register
sample, source instruction visit, and intervening memory events. For a
register jump, the sampled source register must equal the destination. For a
near return, the source's pointer-width stack read must equal the destination,
and the sampled target SP must equal read_address + pointer_width + adjustment.
All 1,463 admission records satisfy those checks. These checks independently
interpret recorded effects; they are not a second execution engine or a proof
of all preceding handler semantics. Register-indirect calls are covered by
portable execution controls; none occurs among these corpus admissions.

Four corrupted-target controls (one register jump and one near return per
architecture) are rejected even when the target is changed consistently in the
edge and target-state records. The actual source-register/stack-read value still
contradicts the altered destination. The earlier instruction-decoder negative
checkpoint remains documented in `VMP_NATIVE_REGION_CAPTURE.md`.

The 256 completed original/mutation walks match the existing paired integer
oracle, including both guard words, ADD-defined flags masked by `0x8d5`, and
callee-entry/caller-relative stack normalization. No new protected-function
completion is claimed. The additional 87,161 entered instruction records
(117,757 - 30,596) provide larger native prefixes for subsequent VM-state and
semantic-summary work.

Twenty native inventories preserve image bytes/loaded masks, instruction items,
xrefs, function flags/chunks, and ordinary evidence publication. Separate
disposable-database controls pass 12 checks per architecture: ordinary near
returns with and without adjustment, far/interrupt entry rejection, rejection
of a far-return destination after an observed transfer, and restoration of
test bytes/topology. The disabled-backend probe passes four checks across all
three native capture APIs and publication preservation. Total production
assertions: 5,526 + 5,106 + 24 + 4 = 10,660. The four corrupted-target controls
are additional independent verifier checks, excluded from that total.

All 19 CTest suites pass in 13.34 s. The native-region fixture adds 38 portable
assertion instances across both modes: live indirect-call/return/jump effects,
event uniqueness, immutable prior plans, stale/overlap/decoder rejection,
instruction and extension limits, planning-time exhaustion, and runtime byte
guards on both existing and newly admitted instructions. The time control
delays a decoder callback beyond its configured budget and checks that the
new destination is not entered.

## Repeatability counterexample

The initial x64 matrix was rejected by its assertion that every scalar register
sample in two separate captures must be identical. In `virtualization-0`,
`corpus_transform` executes `RDTSC` before its first native boundary. Sixteen
input cases have different sampled registers while their instruction, edge,
and memory-event prefixes match. The final matched matrix reproduces this
result. All four compared prefix fields match in the i386 matrix.

The local backend primary sources explain why argument seeds do not control
this state: `vendor/rax/src/isa/x86_64/execute/system/timing.rs` reads `vcpu.tsc()`,
and the implementation in `vendor/rax/src/isa/x86_64/cpu.rs` scales elapsed
host time. The runtime clock is not an explicit argument or object in the input
contract. No backend source was changed.

The probe now retains each separate-run prefix comparison as a measurement,
including every mismatch; it does not turn those mismatches into equivalence.
Snapshot identity, supplied inputs, initial entry state, event order, admission
provenance, and completed behavior remain assertions. The API explicitly reports
its backend-defined timestamp/randomness/processor/device environment contract.
The continuation itself retains one machine state and therefore does not depend
on a claim that two independently initialized engines replay identically.

## Assumptions, falsification, and scope

| ID | Assumption / dependent result | Falsification probe and limit |
|---|---|---|
| W1 | Stopped edge, PC, and event sequence identify the observed transfer instance | Runtime agreement checks, unique edge/target-state checks, and corrupted-target verifier controls; no universal target inference |
| W2 | Admission preserves one coherent mode and instruction interpretation | Exact snapshot/runtime bytes, overlap rejection, stale-generation controls, independent decoding, and near/far production controls |
| W3 | Resumption retains state without replay or duplicate transfer events | Executed CALL/RET/PUSH/jump-chain controls, exact SP/data effects, and unique ordered production records |
| W4 | Resource limits apply across all resumptions | Shared instruction/time accounting, exhausted extension limit, delayed decoder, reported corpus budget stops; decoder calls are nonpreemptible |
| W5 | Explicit inputs do not determine all execution environment state | Reproduced RDTSC counterexample and backend source inspection; separate-run state equivalence remains false in the reported 16 cases |
| W6 | Native observation remains separate from logical VM proof and ordinary ownership | Existing ordinary publication veto and 20 unchanged inventories; VM ownership and complete handler semantics remain unknown |

High impact: larger observed native prefixes can supply concrete state to
existing VM-role/transition analysis, but that integration still requires
explicit VM context and memory identity. High impact: instruction seeds cannot
stand in for clock/device input provenance; replay claims need a declared
environment model. Medium impact: repeated immutable-image hashing contributes
to extension cost; a cache would require independent freshness validation.
Medium impact: byte admission and actual instruction entry differ at budget
boundaries and must remain separately visible. These are bounded findings, not
claims that full devirtualization or cross-input semantic equivalence is solved.

Accepted artifacts: `build/vmp-native-walk-final-x64`,
`build/vmp-native-walk-final-x86`, `build/vmp-native-walk-controls-x64`,
`build/vmp-native-walk-controls-x86`, and `build/vmp-native-walk-disabled`.
The earlier `build/vmp-native-walk-matrix-x64` report is the rejected
repeatability checkpoint; the earlier i386 and first-sample runs are preliminary,
not the accepted totals. Reproduction uses `tests/run_vmp_native_inputs.py
--walk`, followed by the instruction and transfer verifiers. Source, SDK/backend
reference, corpus, build, and accepted/rejected artifact hashes are in
`VMP_NATIVE_WALK_EVIDENCE.json`.

QG1: technical behavior only. QG2: W1–W6 with probes above. QG3: observed-native
continuation implemented and tested; the full review goal remains incomplete.
QG4: exact pointer-width arithmetic, event counts, and measurement units stated.
QG5: repeatability counterexample, time stops, environment inputs, rejected
semantics, and admission/entry distinction remain explicit. QG6: primary local
source and artifact identities recorded; source-to-protector build attestation
remains unknown. QG7: bounded adjacent opportunities and unproved scope stated.
