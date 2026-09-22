# Observed local VM transitions from native captures

`chernobog_vm_trace_check(ea, seed, input_json)` adds scalar instruction-entry
samples and local semantic checking to the bounded native walk. It uses the
explicit input contract in `VMP_NATIVE_INPUTS.md` and continuation contract in
`VMP_NATIVE_WALK.md`. Results describe individual captured paths. They do not
establish full handler behavior, logical VM identity, or equivalence for other
inputs. The complete review objective remains in progress.

## Admission, recognition and proof contract

The opt-in capture records GPRs, instruction pointer and arithmetic flags before
each entered instruction, after checking its exact planned bytes. These are
scalar samples, not complete processor states. The IDA semantic decoder checks
mode, address, size and bytes against the final native plan. Unsupported decoded
instructions remain explicit recognition boundaries.

`src/vm/native_observations.cpp` joins execution, scalar samples, memory events,
dispatch edges and post-dispatch samples by capture/run/seed/sequence. Missing,
duplicate, conflicting or out-of-order records reject projection. Each candidate
starts at an actual executed bytecode-read hypothesis or a backward-read
decrement. Recognition follows the recorded path, retaining intervening modeled
instructions and direct jumps. An internal direct jump does not prematurely
select the candidate's output state. Repeated visits remain separate records.

The existing typed recognizer identifies VIP, decoded value, optional rolling
key, direction, and dispatch base. These are local role hypotheses. Virtual
stack, VM context and memory epoch remain `unknown`; logical-state completeness
is false and merging is not admitted. The input contract is the specified
captured entry. Other entry points are neither excluded nor summarized.

The existing transition checker re-recognizes the path and constructs its local
normal-completion model. It first requires satisfiable recorded inputs, then
requires an unsatisfiable mismatch query covering every GPR, defined arithmetic
flags, destination, and ordered data accesses. This order excludes a vacuous
UNSAT result from contradictory inputs. SAT mismatches, UNKNOWN, unsupported
semantics, missing outputs, incomplete data and exhausted quotas retain distinct
results. Prior or local writes overlapping candidate code prevent checking.

Each actual SMT query uses phase `vm-native-observed-transition` and the exact
database/function/candidate/capture/run/seed/visit/check identity. Check and
capture identifiers stop at exhaustion rather than wrap. The projection never
creates ordinary `TargetEvidence`; production controls check unchanged function
evidence and database inventories. JSON query identifiers do not establish a
persistent GUI cache or current applicability after a database edit.

## Bounds and cost

| Resource | Bound per capture |
|---|---:|
| Entered instructions / admitted heads | 4,096 each |
| Scalar state records | 12,289 |
| Recorded data events / edges | 4,096 each |
| Recognition path length | 128 instructions |
| Total examined path instructions | 8,192 |
| Retained candidate visits | 128 |
| Transition attempts | 16 |
| Ordered accesses per checked transition | 64, each at most 8 bytes |
| SMT queries | At most 32 |
| Per-query solver limits | 100 ms and 200,000 resource units |

The sample bound is `3 * 4096 + 1 = 12289`: instruction, transfer and predicate
samples plus an entry sample. Native scalar sampling additionally clamps the
portable driver's larger instruction allowance to 4,096. Solver limits are
per query; they do not make 250 ms execution/planning or 3.2 s nominal solver
time a hard end-to-end deadline. Decoding, image copying, hashing, construction
and serialization add time outside individual solver calls.

Let N be entered instructions, S scalar states, H decoded heads, D data events,
E edges, P examined path instructions, K the maximum path length, and C retained
candidates. Excluding decoding, recognition and SMT internals, projection costs
`O(N log H + S log S + E log E + P log H + C D K)` time. The last term bounds
the conservative code-write overlap scan. Each candidate's recognizer cost is
additional and bounded by K = 128. Working indexes and retained paths cost
`O(S + E + K + C K)` space, excluding input records and solver allocations.
Scalar capture costs O(N R) time and space before caps, with R the fixed sampled
register count. No general polynomial bound is claimed for SMT solving.

Counters distinguish unsupported instructions, grammar rejection, path length,
capture end, and global path exhaustion. `omitted` counts recognized visits
discarded after the row quota; it cannot count candidates beyond an unexamined
path budget. Recognition yield is not a recall estimate without an independent
enumeration of all genuine VM transitions.

## Carry defect exposed by independent replay

The separate Python/Capstone oracle in
`tests/verify_vm_native_observations.py` compares every captured instruction's
GPR effects, defined arithmetic flags, successor and ordered memory accesses.
It maintains byte consistency across the local path and fails on an unsupported
instruction. It imports no Chernobog recognition or semantic implementation.
It remains interpretation of captured inputs and effects, not a second native
execution of the protected function.

This stricter check exposed a carry discrepancy at one-byte i386 `DEC EDX`.
The pinned backend's `decode/dispatch/legacy.rs` replaces pending arithmetic
flags with INC/DEC flags without resolving the previous CF. Its FE/FF handlers
already resolve CF. Read-only flag sampling observes the resolved value but
does not materialize it in the backend. In the protected counterexample, later
XOR/ADD instructions overwrite the discrepancy, so the local final-state SMT
check remains satisfiable and then proves no final mismatch. That result does
not prove correctness of every intermediate instruction.

`src/hybrid/emu_driver.cpp` now round-trips architectural EFLAGS through the
public register API immediately before legacy 40h–4Fh encodings in 32-bit mode.
It recognizes prefixes from actual instruction bytes and leaves arithmetic,
operand effects and exception handling to the backend. A failed byte read or
state round-trip stops execution as an environment-model failure. The pinned
vendor checkout and its provenance policy remain unchanged; this is a driver
compatibility correction. JSON records the correction explicitly.

The regression deliberately makes stored CF disagree with a pending SUB/XOR
result. All 56 combinations of INC/DEC, 16/32-bit operands, both carry values and
seven arithmetic boundary values failed before the correction and pass after
it. Another 56 checks compare execution with scalar sampling disabled. This
test does not establish every prefix, fault or protected/real-mode combination.
The driver executes 32-bit application snapshots; standalone RAX consumers
retain the upstream defect until separately corrected.

Architectural provenance: the locally supplied Intel SDM, volume 2 instruction
entries **INC—Increment by 1** and **DEC—Decrement by 1**, “Flags Affected,”
specify preservation of CF and result-dependent OF/SF/ZF/AF/PF. The checked local
manual and relevant backend/C API sources are hashed in the evidence manifest.

## Accepted measurements

Accepted roots: `build/vmp-native-observation-accepted-x64` and
`build/vmp-native-observation-accepted-x86`. Each uses ten binaries, two functions
and 16 input triples: `10 * 2 * 16 = 320` captures per architecture, each with a
separately executed stopped-prefix comparison. Earlier `first-*` and `final-*`
roots predate the carry correction and are excluded from accepted correctness
measurements.

| Measurement | x64 Mach-O | i386 ELF |
|---|---:|---:|
| Captures | 320 | 320 |
| Completed original/mutation oracle matches | 128 | 128 |
| Incomplete virtualization/combined captures | 192 | 192 |
| Recognized and SMT-corroborated local visits | 160 | 256 |
| Distinct binary/start/dispatch triples | 6 | 15 |
| Actual SMT queries | 320 | 512 |
| Independently replayed instruction visits | 3,952 | 5,856 |
| All entered records independently decoded | 111,780 | 43,296 |
| Independently checked native admissions | 1,184 | 624 |
| Candidate starts examined | 8,080 | 2,560 |
| Path instructions examined | 69,524 | 20,320 |
| Unsupported-instruction recognition stops | 7,488 | 2,048 |
| Grammar rejections | 352 | 256 |
| Capture-end recognition stops | 80 | 0 |
| Global path/row/check quota omissions | 0 | 0 |
| Production matrix assertions | 7,496 | 6,578 |
| Sum of runner elapsed time / s | 73.716804875 | 58.653096915 |
| Maximum runner resident memory / bytes | 488,161,280 | 270,663,680 |

All 384 incomplete executions stop at rejected 16-bit BSWAP semantics. The 256
completed original/mutation captures agree with the independent paired result,
defined flags, stack delta and guarded-memory oracle. All 416 candidate visits
pass the nonvacuous SMT check and independent scalar replay: 832 queries and
9,808 instruction visits. Repeated visits are not distinct handlers.

| Protected variant | x64 corroborated visits | i386 corroborated visits |
|---|---:|---:|
| virtualization-0 | 48 | 0 |
| virtualization-1 | 80 | 0 |
| virtualization-12648430 | 16 | 16 |
| combined-0 | 0 | 176 |
| combined-1 | 0 | 16 |
| combined-12648430 | 16 | 48 |

Original and mutation-only captures produce no candidates. These yields are not
false-positive/false-negative rates against an independently labeled corpus.
Eight corrupted-transition controls alter a GPR, carry, target or read value;
independent replay rejects all eight. Four altered admission-target controls
also reject. Capstone 5.0.7 finds no file-byte, instruction-size or linear-successor
mismatch across 155,076 entered records. Separate prefix comparisons retain 16
x64 register-state differences associated with the documented timestamp
environment; instruction, edge and data prefixes agree. All i386 prefixes agree.

Final production controls pass 18 checks per architecture, including encoded
contiguous and discontiguous table dispatch, near/far boundaries, unknown VM
state and unchanged publication. The disabled-backend probe passes five checks.
All 20 CTest suites pass in 11.18 s. Portable controls cover invalid samples,
altered GPRs, code writes, incomplete memory, solver provenance and quotas.
The row-quota fixture retains 128 of 130 recognized visits with two omissions;
the dense scan fixture stops at 8,192 examined instructions.

Elapsed seconds are integer nanoseconds divided by 10^9; decimal digits describe
recorded units, not clock accuracy. Matrices overlap each other and auxiliary
tests. Memory measurements cover runner/IDA scope. These observations do not
establish isolated sampling cost, a timing distribution or a speedup.

`VMP_NATIVE_OBSERVATIONS_EVIDENCE.json` binds sources, runtime binaries, primary
references, accepted reports and the pre-fix regression. Report hashes bind
individual captures and paired binaries. Reproduce with
`tests/run_vmp_native_inputs.py --check`, then the three independent scripts
`verify_vm_native_region_decode.py`, `verify_vm_native_walk.py` and
`verify_vm_native_observations.py` on each report. Select the corresponding
paired corpus and a fresh output directory; keep local IDA/plugin paths private.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Probe and status |
|---|---|---|
| N1 | Exact captured bytes and scalar state describe the executed local path; all corroboration depends on this. | File-backed Capstone decode, missing/duplicate/reordered sample controls and independent instruction effects. Retained for the accepted measured captures. |
| N2 | The admitted model is flat little-endian normal completion, with no concurrency, devices, segment bases or exceptions; stack dispatch additionally assumes CET shadow stack disabled. | Unsupported forms and incomplete access traces reject checking. Retained contract, not a universal x86 claim. |
| N3 | The paired fixtures represent some transformations of interest. | Development and reserved seeds in both architectures; record explicit misses. Protector source/build identity and broad real-world coverage remain unknown. |
| N4 | Backend instructions implement each intermediate architectural effect. | Independent replay falsified this for legacy INC/DEC carry; the driver correction and red/green regression narrow the accepted claim. Other instruction classes remain independently unproved. |
| N5 | Explicit inputs imply reproducible whole-engine state. | Falsified by the earlier RDTSC counterexample; separate-run register differences remain diagnostics. No clock-determinism claim is made. |
| N6 | Local VIP/key hypotheses identify a complete logical VM state. | Not assumed: unknown virtual stack/context/memory epoch prevent logical merging and full-handler claims. |

## Bounded findings and remaining scope

- **High:** Intermediate-state replay detects errors hidden by overwritten
  effects at a candidate's exit. The carry counterexample establishes this
  concretely; final-state equality must not be relabeled instruction-level
  equivalence.
- **High:** Unsupported instructions and unknown logical VM state still prevent
  complete protected-function recovery. Recognition counters expose these
  limits; local corroboration does not eliminate them.
- **Medium:** Scalar sampling, repeated image hashing and bounded SMT checks add
  latency and storage. The recorded corpus measurements do not isolate these
  costs or establish a speedup.
- **Medium:** Query provenance is available through existing solver evidence;
  persistent native-capture GUI lifecycle and whole-handler reuse remain open.

Quality gates apply to this bounded checkpoint. They do not close the complete
review ledger or establish universal semantic correctness.
