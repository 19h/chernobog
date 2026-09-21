# Captured VM-role observations

Follow-up: [VMP_VM_TRANSITIONS.md](VMP_VM_TRANSITIONS.md) adds direct data-trace
completeness and explicit captured-transition checks. The description and
manifest below record the earlier observation-only checkpoint; in particular,
its unknown-data-completeness limitation has since received that bounded fix.

This checkpoint attaches fresh RAX register snapshots to current local VM
candidate role hypotheses. It advances ledger 6a and the inspection portion of
6b. It does not complete logical-state recovery or validate a VM transition.
The reproducibility manifest is
[VMP_VM_OBSERVATIONS_EVIDENCE.json](VMP_VM_OBSERVATIONS_EVIDENCE.json).

The new `chernobog_vm_states(ea)` API and **VM states** tab retain repeated visits
to the same native candidate. Each observation has a publication, run, seed,
sequence and unique retained-row identity. Entry/output VIP, decoder key,
decoded-value register, dispatch base, native SP and flags are sampled values
associated with the current IDB role hypothesis. Missing registers and
conflicting values or widths produce explicit unknown values. Native SP is
labeled native SP; virtual stack, VM context and memory epoch remain unknown.
No partial states are merged.

Only taken-transfer targets are sampled by the existing driver. A fallthrough
entry, an entry at the initial PC, or a transfer whose snapshot was not retained
can have no row. Absence of a row is not evidence of an unreachable candidate.
The API performs no emulation, solver check, database mutation or edge insertion.

## Observation contract

The API requires the current session's exact published evidence for the selected
function, a nonzero revision and successful existing freshness checks. It
recomputes local candidates before associating roles. Stale evidence yields no
new role association; a previously loaded GUI snapshot remains inspectable as
historical. GUI navigation requires both the same current capture publication
and exact recomputed candidate records. Data patches, candidate patches,
publication replacement and session clearing invalidate these conditions.
Explicit reload obtains a new association. Polling performs no solver check.

For a candidate-entry sample, the next captured taken-transfer sample may be its
dispatch output. The native execution records between those samples must match
the candidate's complete ordered support addresses and sizes, with no missing,
extra or repeated instruction record. Run identity checks include function,
generation, function/image hashes, ticket and focus. Duplicate sample sequences
and ambiguous run records cannot produce a matching local path. The result is
labeled **sampled local address/size path**. It establishes the recorded path
association, not fetched-byte identity or instruction semantics.

Up to 16 captured memory accesses in that interval retain sequence, source,
address, size in bytes, kind and low 64-bit value. Larger counts report exact
display omissions. The driver currently has no complete-data-trace flag:
`consumed_context_complete` describes a different dependency contract and does
not establish completeness of `DataAcc`. Consequently this projection reports
data-trace completeness as unknown. It cannot support a full memory-effect
comparison against the symbolic summary yet.

A recorded prior/local write overlapping candidate bytes explicitly marks the
runtime role association as unverified. Absence of such a write does not establish
unchanged runtime bytes. The driver records instruction addresses/sizes rather
than fetched instruction bytes. A selected-function boundary retains the output
sample and the existing boundary stop; the target instruction is not admitted.

## Algorithm and bounds

```text
require exact fresh publication, selected function and x86-32/x86-64 capture
reject inputs exceeding the work limits
re-recognize each candidate from its instruction support
index states, execution and data by (run, seed); sort each by sequence
for each candidate-entry transfer sample, in run/seed/sequence order:
    retain unique visit identity and partial register-role observations
    associate the next sampled transfer with this dispatch when possible
    compare the complete recorded local address/size sequence
    retain bounded captured access detail and explicit boundary metadata
    report overlapping code writes without inferring unchanged bytes
```

Limits: 64 candidates, 128 retained state rows, 16 displayed accesses per row,
64 register entries per input state and 262,144 total input records across run,
state, execution and data vectors. Excess input work or register counts reject
the join. Candidate scanning retains its existing 1,024-instruction/64-candidate
limits and reports omissions independently. State omission counts are exact for
recognized retained candidates in an admitted trace. They do not count visits to
unscanned/unretained candidates or missing samples.

For N input records, C candidates, S maximum support length, R maximum registers
per state and L retained rows, time is O(N log N + C·S + L·(N + R)); space is
O(N + C·S + L·R), with fixed bounded access detail. The L·N term conservatively
accounts for checking earlier recorded writes. The limits are work bounds, not
measured latency or peak-memory guarantees.

## Independent fixture and validation

The independent x64 assembly fixture in
[vm_observations.S](../tests/vmp_native/vm_observations.S) revisits one dispatcher
three times. Its byte decode is:

`decoded = (ROL8(encoded XOR key, 3) + 7) mod 256; key := key XOR decoded`.

| Visit | Encoded byte | Entry key | Decoded index | Output key |
|---|---|---|---|---|
| 1 | `25` | `5a` | `02` | `58` |
| 2 | `67` | `58` | `00` | `58` |
| 3 | `07` | `58` | `01` | `59` |
| Separate boundary case | `c5` | `5a` | `03` | `59` |

Values in the table are hexadecimal exact integers; operations are 8-bit modular
arithmetic. VIP advances by 1 byte per visit. The four seeded production runs
retain 12 distinct entry observations for the repeated-visit case. The separate
boundary case retains four output observations and stops before the external
function's marker write. Fixture function ranges are explicitly established by
the probe; they are not inferred interpreter ownership.

Portable controls exercise x86-32 and x86-64 register association, missing and
conflicting registers, widths, noncanonical 32-bit values, trace gaps, mismatched
sizes, intervening transfers, duplicate state/run records, publication and run
identity, prior code writes, boundaries and exact quotas. Production probes test
real IDA decoding/RAX capture and the actual Qt form, including run selection,
patch/restoration, replacement, reload and polling. Final counts, hashes and
regression results are recorded in the manifest. This fixture is independently
authored, not emitted by the supplied VMP tree. Coverage on the supplied protected
hello-world executable remains unknown.

Final validation: 79 portable observation checks; 16/16 CTest targets; 28 terminal
and 38 GUI observation checks; 83 existing VM-region/summary GUI checks; and
106 SMT/native/temporal GUI regression checks. The production total is 255 checks.
The CTest elapsed time was 8.56 s for this run, not a performance benchmark.
The SMT regression requires `CHERNOBOG_MBA_AFFINE=1`; the native regression
requires `CHERNOBOG_NATIVE_FIXTURE=stack`. Preliminary invocations missing those
settings are excluded from final acceptance evidence.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| O1 | Current IDB recognition provides the role hypothesis used to label register observations. It does not establish runtime VM identity. | Patch a candidate or its consumed data; require failed freshness/navigation. Report recorded code writes and keep runtime code identity unverified. |
| O2 | The driver sequence contract orders instruction entry, data accesses and the following transfer snapshot. Local path association depends on this. | Independent repeated-dispatch capture, ordered byte/table reads, missing/extra/malformed portable records and boundary probe. |
| O3 | Publication/run provenance identifies the capture associated with a visit. All cross-record associations depend on this. | Foreign function/generation/ticket/hash, duplicate run and superseded-publication controls reject current association. |
| O4 | The admitted scaffold is relevant to a future protected corpus. Coverage extrapolation depends on this and is unknown. | Obtain settings/build/seed-attributed protector-generated pairs and test emitted traces; this checkpoint supplies no such coverage measurement. |

## Bounded expansion and quality audit

**High impact:** distinguish dependency completeness from data-trace completeness
before adding a captured-transition SMT check. A data quota must not yield a
vacuously successful comparison. A future check needs complete modeled accesses,
consistent input constraints, explicit fetched-code identity assumptions and a
separate satisfiability check before an output-mismatch query.

**Medium impact:** taken-transfer sampling omits some candidate entries.
Additional sampling requires its own overhead budget and coverage diagnostics.

**Medium impact:** equal native address/register tuples do not supply VM context
or memory identity. Keeping partial visits distinct preserves evidence needed
for later state recovery and prevents unsupported merges.

Quality gates apply to this bounded observation feature. The implementation and
tests make no VM-identity, complete-memory, semantic-transition, cross-function
ownership or protected-coverage claim. Provenance is local primary source and
recorded production evidence. Counts are exact; no performance improvement is
asserted. The full review ledger remains in progress.
