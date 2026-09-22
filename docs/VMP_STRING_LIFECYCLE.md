# Native-string capture identity across IDA restarts

A saved native-string snapshot could previously become navigable after another
IDA process reused its numeric capture ticket. The first process captured
`secret!` and `second!`; after reopening its saved database and changing the
decryption key, the second captured `recret!` and `recond!`. Both issued ticket 4.
The old API and client accepted the historical snapshot against the new capture.
The two-process counterexample is recorded separately from the fixed regression.

Freshness now requires a per-capture opaque lease identity in addition to the
numeric ticket. This addresses the observed restart collision and advances
review rows 3b and 5. Exact image/profile/model comparison remains the input
freshness criterion.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| L1 | Numeric tickets and database context IDs are local process identifiers. | Save a database, reopen it in a second process, change input bytes and capture again. The counterexample reproduces equal numeric tickets with different observed values. |
| L2 | Successful SDK `gen_rand_buf` calls provide independent lease identities. Cross-process identity isolation depends on non-repetition. | Generate 32 bytes per new capture, reject failure and all-zero output, and compare the complete returned identity. The tested processes have distinct identities. Generator entropy and failure injection remain unverified. |
| L3 | Clients retain the lease with its original snapshot. Navigation decisions depend on this association. | Require matching nonempty lease, ticket and database fields in the client, and the current lease in the backend. Reject legacy, malformed, foreign and wrong-ticket requests. This is not snapshot authentication. |
| L4 | Exact snapshot equality represents unchanged captured inputs. | Test both rebase modes, stale navigation, reverse rebase, invalid recapture, existing byte/profile/model/permission edits, supersession and timer shutdown. |

## Current API and behavior

`chernobog_vm_temporal_strings` returns an additional `lease` field containing
64 hexadecimal characters. Retain it together with `ticket` and `database`.
The state API now requires both identity components:

```python
state = api("chernobog_vm_temporal_string_state", snapshot["ticket"], snapshot["lease"])
```

Numeric-only calls are rejected. A missing lease in a historical client snapshot
cannot enable navigation. Valid state responses include the lease and database
identity; the client checks both along with the ticket and freshness result.
Wrong identities are rejected before re-snapshotting. A valid identity still
requires exact current input equality. Failed recaptures clear the prior lease,
while invalid state queries leave the current lease intact.

The SDK random-buffer function is declared in `ida-sdk/src/include/pro.h`.
Only its declared success/failure contract is assumed here; no cryptographic
entropy claim is inferred from the declaration. Under the additional assumption
of independent uniform 256-bit outputs, the pairwise collision probability would
be 2^-256. That distribution has not been established by these tests.

## Validation

The original implementation reproduces the restart collision in an isolated
two-process run with 18 diagnostic checks. The fixed lifecycle regression runs
capture, reopened-console and reopened-GUI processes with 13, 26 and 28 checks:
67 checks total. It verifies changed values under reused numeric tickets,
historical API/client rejection, empty/zero/truncated/non-hex leases, wrong
tickets, legacy numeric-only requests, foreign database labels, both rebase
modes and exact restoration, invalid recapture, disabled historical navigation,
and timer shutdown. The actual historical Qt view was inspected.

The scalar/modeled snapshot regression adds 82 production checks and its three
native oracle exits remain 0, 1 and 1. The protected read-stream corpus adds
183 checks across ten binaries, retaining 4/18 protected value occurrences.
These total 332 current production checks; the historical counterexample is
counted separately. Accepted artifacts and exact test outcomes are recorded in
[VMP_STRING_LIFECYCLE_EVIDENCE.json](VMP_STRING_LIFECYCLE_EVIDENCE.json).

An initial concurrent CTest run passed 19/20 suites in 116.20 s and failed
`chernobog.vm_transitions` at its output-register assertion. That test uses a
100 ms solver budget. Concurrent IDA runs also took substantially longer than
the preceding checkpoint. Resource contention is a hypothesis; the failed
assertion did not record the solver result, so its cause is unknown. The original
failure log is retained separately from subsequent isolated verification.

The subsequent isolated CTest run also passed 19/20 suites, in 75.09 s. The
transition suite passed, but `chernobog.vm_native_observations` failed its
repeated-visit/solver-budget assertion. A diagnostic copy of that test, with
logging of unresolved solver results and otherwise unchanged assertions and
budgets, then passed all 94 checks without an unresolved-result diagnostic.
Neither original failure recorded enough information to establish its cause.
These runs do not establish a clean full-suite result; timing sensitivity remains
a hypothesis. No solver budget or acceptance criterion was relaxed.

```sh
python3 -B tests/run_native_string_lifecycle.py \
  --input build/vmp-use-snapshots-release/original \
  --ida "$IDA_CONSOLE" --gui "$IDA_GUI" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-string-lifecycle-new
```

The runner first saves a database, then supplies that exact checkpoint to each
new process using the explicit database-input admission option. Inputs, plugin,
IDA binaries, scripts and output artifacts are hash bound. The diagnostic
`--expect-restart-collision` mode belongs to the pre-fix implementation and
companion recorded by its source hashes.

Lease storage and identity comparison are O(1) with a fixed 32-byte identity.
Valid requests retain O(M + F) snapshot comparison, for mapped bytes/masks M and
function/segment/model metadata F. No latency improvement is claimed.

## Bounded implications and quality gates

- **High:** historical evidence needs an identity domain beyond restart-local
  counters. Other inspection families have separate contracts and remain to be
  audited for analogous persistence assumptions.
- **Medium:** the tested matrix covers process restart, saved-database reopen,
  two rebase modes and historical Qt navigation. Plugin unload/reload within one
  process, simultaneous open databases and the full lifecycle matrix remain.
- **Medium:** SDK randomness quality and both solver-test failures' precise
  causes remain unknown. Full-suite verification is unresolved at this checkpoint.

QG1: technical identity/freshness scope. QG2: L1–L4 with probes. QG3: reproduced
counterexample, backend/client correction and scoped lifecycle coverage supplied;
the complete review remains open. QG4: identity size, counts, probability
assumption and complexity scope explicit. QG5: numeric reuse cannot satisfy the
new identity check by itself. QG6: local SDK declaration and hash-bound source,
runtime and artifacts. QG7: adjacent identity and lifecycle limits stated.
