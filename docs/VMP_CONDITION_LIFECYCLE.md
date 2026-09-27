# Condition generation across database lifecycle transitions

Review rows 2b and 5 now have a separate-process audit of the existing owned
compound-condition fixtures. This changes the test harness and evidence,
without changing the native analyzer or emission implementation. The audit
uses IDA 9.4 SDK generation, current native proof queries and the frozen
independent microcode interpreter [L1–L3]. Full review completion remains in
progress.

## Scope and transitions [L1, L2]

Each architecture has 85 named roots: 40 compound-condition positives,
40 conflicting alternatives, one nine-state overflow and four invalid LOCK
controls. The positives span BE true, A false, both outcomes of L/GE/LE/G,
and Jcc, SETcc, register CMOV and memory CMOV consumers. The detailed ISA and
effect contract remains in `VMP_RELATIONAL_CONDITIONS.md`.

The runner starts seven isolated IDA processes per architecture. The writer
establishes actual function ownership, adds a user annotation at all 40
positive consumers, captures facts and generated IR, and saves a checkpoint.
Later processes inspect persisted owners; they do not recreate functions.
Reopening requires the production ownership-recovery diagnostic before the
audit queries facts. This checks receipt recovery followed by current proof
recomputation, rather than treating saved proof state as authoritative.

| Process | Input/action | Snapshots | Assertions per architecture | IR checks per architecture |
|---|---|---|---:|---:|
| write | Raw fixture, ownership and explicit save | loaded | 540 | 140 |
| read | Reopen writer checkpoint | loaded | 540 | 140 |
| rebase | Writer checkpoint; +1,048,576 bytes with MSF_FIXONCE; save | loaded, rebased | 1,120 | 280 |
| read_rebased | Reopen rebased checkpoint | loaded | 540 | 140 |
| rebase_nodes | Writer checkpoint; same delta with MSF_FIXONCE and MSF_NETNODES; save | loaded, rebased | 1,120 | 280 |
| read_rebased_nodes | Reopen netnode-rebased checkpoint | loaded | 540 | 140 |
| undo | Writer checkpoint; patch, undo, redo, restore | loaded, patched, undone, redone, restored | 2,625 | 644 |

All 85 roots must relocate by the specified delta. Each rebase rejects the
previous UI captures for all 40 positives and rechecks current truth, support,
publication and generation. User annotations must survive exactly once.
MSF_NETNODES exercises physical netnode movement in addition to the default
netdelta path; the installed SDK header defines these distinct modes [L1].

The undo group patches one flag-input immediate from 3 to 2 in BE-true and
A-false fixtures across all four families: eight independent sites. This
introduces conflicting condition outcomes. Each patch immediately revokes
its exact native fact, rejects the old UI capture and removes only the owned
annotation, retaining the user note. Reanalysis keeps the disagreement
unresolved and custom SETcc/CMOV generation declines. Undo restores the
literal inputs and complete generation; redo restores the disagreement;
explicit restoration reestablishes the complete result. Consumer instruction
bytes remain unchanged. Non-rebase processes also compare all fixture bytes
before and after. Rebase may apply i386 absolute-address fixups; byte identity
across relocation is outside that assertion.

Every snapshot checks query inventory for mutation, native condition truth,
supporting instruction coverage, unchanged joined decisive flag bits,
condition basis, user annotations and per-consumer generation-counter deltas.
Invalid LOCK, overflow and conflicting controls retain abstention. Generation
uses DECOMP_NO_CACHE and each generated MBA passes SDK verification.

## Independent effects and counts [L2, L3]

There are 13 snapshots per architecture: 11 complete and two patched.
Each complete snapshot has 40 exact condition consumers and 30 custom value
lowerings; each patched snapshot retains 32 exact consumers and 24 value
lowerings. The eight patched consumers are checked for abstention, including
zero custom generation at the six SETcc/CMOV sites. They are excluded from
the interpreter's custom-emission effect count.

For each admitted value lowering, the frozen interpreter executes both
literal flag profiles and compares the full return register, other GPRs,
five modeled status registers, DS, memory and source-read address/width/count.
Each admitted memory CMOV is also tested with each of four source bytes
absent, requiring a read fault before any architectural destination change.

```text
complete snapshot: 30 × 2 + 10 × 2 × 4 = 140 effect/fault checks
patched snapshot:  24 × 2 +  8 × 2 × 4 = 112 effect/fault checks
two architectures: 22 × 140 + 4 × 112 = 3,528 effect/fault checks
production checks: 2 × (540 + 540 + 1,120 + 540 + 1,120 + 540 + 2,625)
                 = 14,050 assertions
admitted lowerings: 22 × 30 + 4 × 24 = 756
```

The 756 lowerings comprise 252 SETcc, 252 register CMOV and 252 memory CMOV
observations. These are repeated lifecycle observations of the same fixture
families, rather than additional independent program cases.

The shared primary probe, after its initialization/owner-inspection refactor,
also passes 1,013 assertions and 140 IR checks per architecture. Its native
fixture execution passes 41,476 checks per architecture. The lifecycle runner
verifies and reuses that report and the exact binary hashes; it does not
claim a new native execution at every stage. Execution environments retain
the translated macOS x86-64 and source-pinned QEMU i386 bounds in the earlier
condition evidence [L3].

All 14 lifecycle processes pass with source/tool/input hash stability.
Their measured runner elapsed time sums to 108.390300 s; maximum reported
child peak resident memory is 187,695,104 bytes. These are observations from
this run, not performance bounds or exclusive IDA-process memory accounting.
The initial CTest sweep passes 20/21 suites: VM transitions reports a canceled
solver query under its existing 100 ms limit. An isolated, unchanged retry
passes that suite. Both logs are retained; deterministic solver timing and
interactive latency remain unknown [L4].

## Checkpoint naming counterexample [L1]

An initial runner saved the rebased checkpoint under the active database's
basename. Rebased facts and IR passed in that process, but the subsequent
reader found no ownership-recovery diagnostic. A separate IDA inspection
with Chernobog absent measured 40 ownership receipts in the writer checkpoint
and zero in that initial rebased checkpoint. At the two inspected consumers,
the latter retains the user notes and has removed the owned comments; the
inspected branch has no outgoing owned edge.

`NativeEngine::Impl::~Impl` invalidates live proofs when the engine unloads
outside database closure. This cleanup and a later save of the active database
explain the observed checkpoint overwrite; the exact shutdown ordering is an
inference from source and the retained observations. The corrected harness
saves relocation checkpoints as `condition_rebased.i64`, distinct from the
opened `condition_lifecycle.i64`. Both rebase/reopen paths now pass. This is
a harness checkpoint fix; no production rebase defect is asserted. The
diagnostic samples two consumers on x86-64 and is not a full plugin-absence
or reload audit.

## Bounds and reproduction [L1–L4]

The analyzer retains K≤8 alternatives, F=6 status bits and configured native
scan depths of 64. Existing graph/fixed-point limits and universal-condition
O(K·2^F) time/O(1) additional space remain unchanged. For S snapshots and M
roots, the harness performs O(S·M) queries plus production analysis and
generation costs. Capture storage is O(S·M·P), where P is the serialized
record/IR size per root; no measured constant bound on P is claimed. The
runner executes one child at a time with a 120 s stage deadline and checks
source, plugin, IDA, input and checkpoint identities.

```sh
python3 -B tests/run_relational_conditions.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/condition-primary-reproduction \
  --linux32-image chernobog-vmp-linux32:qemu9.2
python3 -B tests/run_condition_lifecycle.py \
  --fixture-report build/condition-primary-reproduction/relation_analysis.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/condition-lifecycle-reproduction
```

Output directories must be new. Artifact identities, SDK header hashes,
source pins, the initial counterexample, the absence diagnostic and regression
logs are recorded in `VMP_CONDITION_LIFECYCLE_EVIDENCE.json`. Primary provenance
is the installed SDK's loader/segment/undo/netnode headers, the pinned native
engine and harness source, and the retained measurements.

## Assumption register and falsification probes

| ID | Assumption and dependent scope | Stress/falsification probe | Result/bound |
|---|---|---|---|
| L1 | Saved checkpoints preserve the intended ownership state; lifecycle observations | Distinct-path save, fresh-process receipt-recovery check, both rebase modes, all-root relocation, absent-plugin inspection of initial failure | Final 14 stages pass; active-path overwrite counterexample retained; other shutdown sequences unknown |
| L2 | Generation and UI records describe current inputs; truth/effect observations | No-cache MBA generation, counter deltas, stale captures, eight predicate patches, undo/redo, annotation and byte checks | Current exact results or explicit decline; no owner recreation after writer |
| L3 | Literal-profile/native and frozen-IR oracles are independent of plugin proof fields; effect claims | Reuse pinned Boolean C/native oracle; full-register/memory/read checks and four source-byte fault probes for each memory lowering | 3,528 effects; translated runtimes and 85 fixed roots only; physical x86 equivalence unknown |
| L4 | Recorded finite measurements establish their scoped results; regression/resource claims | Hash stability, child exit/deadline/output gates, preserve solver cancellation and isolated retry | 20 initial CTest passes plus retry pass; deterministic solver timing and broader protected/lifecycle coverage unknown |

## Bounded scope expansion

- High impact: saving a checkpoint under the active database basename can
  overwrite ownership evidence during shutdown; independent-path checkpoints
  and recovery diagnostics detect this fixture failure.
- Medium impact: undo/redo and physical netnode relocation exercise different
  invalidation paths while retaining user notes and effect/fault semantics.
- Medium impact: the observed solver cancellation makes an unqualified
  deterministic whole-suite timing claim unsupported; both attempts are pinned.
- Low impact: the shared probe initialization and read-only owner lookup permit
  persisted-owner audits without reconstructing the state under test.

## Self-red-team quality gates

QG1 passes: no normative content is required. QG2 passes with L1–L4 and their
falsification probes. QG3 passes for this lifecycle checkpoint's stated scope;
the entire review is not complete. QG4 passes with explicit integer counts,
bytes and seconds, including the reused-native-execution distinction. QG5
passes with the failed checkpoint, solver cancellation and fixup byte exception
recorded. QG6 passes through pinned primary source and observation hashes.
QG7 passes through the bounded expansions above. Broader protected fixtures,
database switching, provider unload/reload, plugin absence across all consumers
and arbitrary lifecycle ordering remain outside this checkpoint.
