# Captured local transition validation

The new `chernobog_vm_transitions(ea)` inspection checks complete captured local
transitions against the existing normal-completion VM-candidate summaries. It
advances ledger 6b. It does not recover VM context, admit cross-function execution
or complete the full review ledger. Evidence is recorded in
[VMP_VM_TRANSITIONS_EVIDENCE.json](VMP_VM_TRANSITIONS_EVIDENCE.json).

## Capture and admission

The driver now reports `data_trace_complete`, `data_trace_truncated` and
`data_trace_filtered` separately from `consumed_context_complete`. Completeness
requires successful code/memory hooks, enabled data capture, an interpretable
stop, no dropped or filtered data events, no execution-record truncation and no
permission, cancellation, escaped-image or environment-model failure. Modeled
external calls and synthetic entry contexts remain excluded. Wide values still
retain only their low 64 bits; the checker rejects local accesses wider than
8 bytes.

A function-boundary stop can have a complete directly executed prefix while
`consumed_context_complete` remains false. The output snapshot is taken before
the target executes. This distinction permits checking the completed dispatch
without admitting any target instruction.

The existing exact-publication/current-function/candidate freshness checks and
complete ordered native address/size path remain prerequisites. Recorded writes
overlapping candidate code before or during the interval prevent checking.
The instruction stream is the current immutable snapshot under the local model;
actual fetched bytes are not independently captured. The normal-completion
contract excludes concurrency, device effects, segment bases and exceptions.

## Check construction

`check_transition` re-recognizes the candidate and requires complete unambiguous
entry/output GPRs and arithmetic-flag snapshots, matching run/seed identities,
ordered access sequences, and matching access sources, kinds and widths. All
8 or 16 architectural GPRs are checked, including preserved registers and native
SP. Architecturally undefined output flags are excluded according to the summary.
Each access also retains its source instruction; source addresses are provenance,
not part of role-normalized summary equivalence.

The input memory constraints are built from **observed addresses**, not from
assumed equality with modeled access addresses:

```text
pin every input GPR and arithmetic flag to the entry snapshot
observed_writes := empty byte map
for each ordered captured access:
    if write: update observed_writes byte by byte
    if read of a byte previously written:
        require agreement with that observed write, else INCONSISTENT
    otherwise:
        constrain initial_memory[observed_address] to the observed byte
check input constraints
    UNSAT -> INCONSISTENT; UNKNOWN -> unresolved
    SAT -> continue
mismatch := any output GPR, defined flag, dispatch target,
            ordered access address or ordered access value differs
check input constraints AND mismatch
    UNSAT -> corroborated for this captured transition under the local model
    SAT -> modeled transition counterexample under the observed initial reads
    UNKNOWN -> unresolved
```

The first query prevents vacuous corroboration from contradictory initial reads.
Observations inconsistent with an earlier observed write are rejected before a
query. A wrong modeled read address remains part of the mismatch rather than
being silently assumed equal. The symbolic byte array retains overlapping
read/write effects, including the high 32 bits of an 8-byte stack slot after a
4-byte key update. Final memory is not compared to a complete runtime snapshot;
agreement covers the ordered writes and reads under the stated memory model.

UNSAT here corroborates one captured transition. It is neither a proof of all
VM inputs nor an ISA/engine correctness proof. SAT is a model counterexample
under the recorded input constraints, which may leave unobserved memory bytes
unconstrained. It is not automatically a diagnosed bug in either producer.

## Inspection and provenance

`chernobog_vm_states(ea)` remains a pure projection without solver calls.
`chernobog_vm_transitions(ea)` performs explicit checks. The companion invokes
it on load/reload, then loads the actual SMT query records. Polling checks
freshness without rerunning validation.

Each attempted check receives a non-reused identity within the loaded plugin.
Actual query records include that identity plus capture revision, run, seed,
sequence and source. The VM-state detail links to its own query IDs; repeated
checks of an identical visit cannot borrow earlier query records. Existing SMT
record quotas can omit query detail while the validation result and query count
remain explicit. Array-bearing formulas can be omitted by the existing bounded
SMT serializer; this does not change which queries were executed or their result.

State observations remain distinct and incomplete. Historical results remain
visible after a patch or publication change. Navigation requires both exact
capture identity and current candidate recognition. SMT source navigation retains
its narrower historical-query contract and does not assert current applicability.

## Bounds and complexity

At most 16 transition attempts occur per explicit inspection. Each has at most
2 solver checks, with a 100 ms timeout and a 200,000 resource-unit limit per
check. The nominal sum of solver timeouts is at most 3.2 s; this is not an
end-to-end wall-time guarantee because expression construction and solver setup
also take time. Each transition admits at most 64 accesses, each at most 8 bytes,
and at most 64 captured register entries in each state. Observation/candidate
input and output caps remain those documented in `VMP_VM_OBSERVATIONS.md`.

For A captured accesses and W at most 8 bytes per access, constructing the
observed-write map costs O(A·W·log(A·W)) time and O(A·W) space. Register checks
use a fixed architectural register count and bounded capture size. Candidate
symbolic construction is bounded by its admitted 128-instruction grammar.
Solver complexity is separate and constrained by the explicit query budgets.
Display omissions never truncate the internal access comparison.

## Independent validation

Portable controls use independently calculated byte decode and arithmetic flags
for both address widths, directions and keyed/unkeyed table dispatch. Every
output GPR and defined flag is individually corrupted to require rejection.
Target/address/source/width/order/identity corruptions, undefined-AF handling,
conflicting initial reads, aliased stack read/write consistency, inconsistent
and consistently incorrect writes, missing/conflicting register values and
actual solver resource exhaustion are covered. Projection tests cover complete
trace admission, code-write vetoes and the 16-attempt cap.

Driver tests execute repeated memory read-modify-write instructions so that the
data-event quota is exhausted before the instruction budget. The incomplete
trace cannot pass admission. A non-strict read of mapped page padding tests
filtering outside recorded image/stack/heap scopes. Existing driver tests retain
fault, modeled-call, boundary and synthetic-entry controls.

The independent x64 production fixture has three cases: repeated keyed table
dispatch, a dispatch into another function, and relative dispatch with
`push key64; xor [SP]32,value32; pop key64`. In the relative case,
`ROR32((-32 - 7) mod 2^32, 3) XOR 0x5566775a = 0x6a9988a1`.
Decoding produces `0xffffffe0`, sign-extends to a displacement of -32 bytes,
and updates the full key to `0x11223344aa9988ba`. Five ordered data accesses
retain the initial read, stack write, 32-bit read/write and full-width pop.
Native SP is restored while the stack write remains observable. These are exact
modular-integer calculations, with no rounding error.

Four seeds per case produce 12 + 4 + 4 = 20 checked local transitions per primary
probe pass and 40 primary consistency/mismatch queries. Additional checks verify
freshness, explicit revalidation and Qt behavior. The previous 416-case native
oracle dataset is replayed against the updated summary implementation; native
execution is not repeated for this checkpoint. No new protector-generated
corpus or protected hello-world coverage result is claimed.

Final acceptance evidence: 632 portable transition checks, 85 observation
checks, 17/17 CTest targets, and 18,158 summary assertions when including the
416 recorded native cases. The production matrix passes 364 checks: 29 terminal
and 36 GUI transition checks, 38 observation GUI checks, 83 x64 and 72 x86
candidate/summary checks, and 106 SMT/native/temporal GUI regression checks.
The CTest run reported 9.48 s; this single elapsed time is not a latency benchmark.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Probe |
|---|---|---|
| T1 | Data hooks and sequence attribution describe directly executed data effects. Admission depends on this producer contract. | Actual RMW quota exhaustion, filtered page-padding read, ordered table/stack captures; missing and reordered event controls. |
| T2 | Current snapshot instructions and flat normal-completion semantics describe the checked local scaffold. Corroboration is conditional on this. | Candidate re-recognition, exact freshness, recorded code-write veto; independent native oracle replay. Fetched-byte identity, concurrency and exceptional behavior remain outside the claim. |
| T3 | Recorded input reads can be represented by one initial byte array plus ordered writes. | Contradictory initial reads require UNSAT input consistency; read-after-write conflicts are rejected; consistently wrong writes yield a modeled counterexample. |
| T4 | Evidence/query identities associate the result with its actual visit and attempt. | Production query-reference checks; repeated explicit validation, patch/restoration and Qt polling controls. |
| T5 | The supported local forms occur in a relevant protected corpus. Coverage extrapolation depends on this and remains unknown. | Settings/build/seed-attributed protector-generated fixtures are still required. |

## Bounded expansion and quality gates

**High impact:** a complete local prefix and a complete function execution are
different claims. Boundary samples validate the former without weakening the
existing execution boundary.

**High impact:** satisfiability of captured inputs is a separate acceptance gate.
An UNSAT mismatch is insufficient if its inputs are inconsistent.

**Medium impact:** unknown initial memory can produce a model counterexample
without establishing an engine defect. Retain the formula scope and observed
input constraints when interpreting failures.

**Medium impact:** direct data-trace completeness can support later consumers,
but it does not establish complete wide values, memory epochs or VM ownership.

The quality audit is scoped to this captured local-transition feature. Tests and
source hashes establish the implemented admission gates and modeled comparison;
they do not establish full review completion, full handler recovery, exceptions,
VM context/virtual-stack recovery, protected coverage or performance gains.
