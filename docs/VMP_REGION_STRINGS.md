# Protected native read-stream consensus and inspection

`chernobog_vm_temporal_strings(ea, input_json, bindings_json)` now reconstructs
contiguous scalar-read strings from four complete native-region captures under
one explicit ABI-model contract. The paired original and mutation seeds 0 and
12648430 each yield both erased strings. The seven incomplete binaries yield
none. Every value retains four capture witnesses and eight original byte reads
per witness, including NUL.

This advances review rows 3a/3b and 5 through a separate native-region inspection
surface. It does not create function evidence or protected pseudocode annotations.
Ownerless read sites remain ownerless. Model assumptions, incomplete runs and
the broader implementation ledger remain explicit.

**Assumption register**

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| R1 | The named ABI models and native capture contract describe the observations. Callee equivalence remains **unknown**. | Require the same sorted address/kind/name bindings, image identity and context across every scheduled run. Preserve the contract from `VMP_REGION_TEMPORAL.md`. Reject changed bindings and ordinary proof flags. |
| R2 | Ordered scalar reads describe a contiguous use within one object lifetime. String derivation depends on this. | Match every UseSnapshot to its exact following DataAcc, byte value, width, scope and address. Check allocation origin, offset, generation and release order. Other memory accesses, calls and lifetime boundaries interrupt a stream. |
| R3 | Every scheduled capture contributes a matching value at the same semantic use and read shape. Consensus depends on this finite corpus. | Reject missing/incomplete/duplicate runs and foreign events. Contradicting bytes omit that use; an unrelated agreeing lifetime survives. Different heap addresses are allowed. Four agreeing seeds do not prove a universal value. |
| R4 | Exact current snapshot/profile/model equality permits source navigation for the retained capture. | Compare actual bytes, loaded masks, segment metadata, function profile and chunks, file type and current model names. Patch data, rename the entry/model and change permissions; require stale state, then exact restoration. Replacing a capture invalidates its predecessor. |
| R5 | The independent paired fixture supplies the expected consumed values. Coverage claims depend on that workload. | Reuse its hash-bound native byte oracle and unchanged comparator from `VMP_PROTECTED_STRINGS.md`. Source-to-protector build attestation, wider architectures and current commercial-release coverage remain **unknown**. |

**Projection and freshness [R1–R4]**

The reconstruction algorithm is shared with ordinary native read-stream
recovery, while admission stays separate. `NativeTemporalStringRun` records
capture identity, selected-entry context, image/generation labels, model bindings,
outcome and original events. `NativeTemporalStringProjection` never converts it
to `TargetEvidence` or sets ordinary completeness/proof flags. Both ordinary
use-string paths explicitly reject native-region outcomes.

Admission requires a successful sentinel return and complete temporal/memory
observation in every run. Boundary, changed-code, environment, permission,
truncation and cancellation failures reject the corpus. Each ledger must contain
only its own run/seed identities. Duplicate event sequences and quota violations
also reject the projection. The portable projection accepts at most 16 runs;
the production API schedules exactly seeds 0, 1, 17 and 12648430 with the same
explicit scalar arguments and bindings. Caller objects retain the temporal
API's current rejection policy.

Streams use 1–8-byte executed reads, preserve byte order and stop at an observed
NUL. UTF-8 validity and minimum Unicode-scalar length use the existing string
validator. Maximum payload is 4,096 bytes. Matching uses preserve their complete
ordered `(site, width)` shape; two matching addresses alone do not establish
object identity or temporal correspondence. Producer `executed-read-stream`
identifies the derived observation; it is not inserted into raw memory events.

The response contains separate observation, witness, fragment, run-stop and
binding tables. At most 64 observations, four witnesses per observation and
16 original fragments per witness are displayed. Omitted observations and
fragments are counted explicitly; omitted fragments are not reconstructed by
the client. In this corpus, nothing is omitted.

One process-local freshness lease retains at most one bounded snapshot. A new
capture supersedes it; database close clears it. The snapshot is bounded to
64 MiB of mapped bytes plus loaded-bit masks and metadata. The state API
`chernobog_vm_temporal_string_state(ticket)` re-snapshots and compares inputs
exactly; noncryptographic image hashes are labels, not the comparison criterion.
It also checks the database context and file type. It does not execute the
program. Full close/reopen/rebase lifecycle coverage remains incomplete.

**Linked display and use**

The companion `python/chernobog_temporal_strings.py` supplies
`show(ea, bindings, input_request=None)`. Loading the companion does not execute
a capture; calling `show` is the explicit capture action. The bindings are the
same current-name/address records accepted by the temporal API. For the fixture,
an IDAPython client can resolve `_malloc`, `_memset` and `_free` and call:

```python
bindings = [{"address": hex(ida_name.get_name_ea(ida_idaapi.BADADDR, name)),
             "name": name} for name in ("_malloc", "_memset", "_free")]
form = chernobog_temporal_strings.show(entry, bindings)
```

The panel links a string to its capture/seed and allocation generation, then to
the original read/data sequences, source EAs, addresses and bytes. The selected
value and witness summary precede the full provenance detail. Polling occurs
every 2 s and preserves detail scroll position. Changed/superseded captures
remain labeled historical and disable navigation; navigation itself rechecks
freshness before jumping. Closing the form stops its timer. The actual Qt panel
was inspected with both protected strings and all eight selected byte reads
visible. No database names or host paths are embedded in the screenshot.

**Results [R5]**

| Family | Expected value occurrences | Recovered | Witnesses | Status |
|---|---:|---:|---:|---|
| Original | 2 | 2 | 8 | Complete modeled captures |
| Mutation, three protector seeds | 6 | 4 | 16 | Seed 1 remains incomplete at BSWAP16 |
| Virtualization, three seeds | 6 | 0 | 0 | All captures incomplete at BSWAP16 |
| Combined, three seeds | 6 | 0 | 0 | All captures incomplete at BSWAP16 |

Protected value coverage is 4/18 expected occurrences in this fixed corpus.
All four reported protected values match the native oracle. Precision is
undefined for individual binaries publishing no values. This is not general
devirtualization or a population recovery estimate. The ten primary inspections
contain 40 scheduled captures; each probe additionally repeats capture to test
lease supersession. The GUI and ordinary regression run separately.

All 183 console checks, 32 actual Qt checks and 24 ordinary native-string
regression checks pass: 239 production checks. All 20 CTest suites pass
(10.98 s). The portable suite covers 21 distinct invalid-corpus mutations,
hard bounds, binding-order independence, forged ordinary publication, unequal
use values, lifetime correspondence and the preexisting stream/UTF-8 controls.

Across 80 full-snapshot freshness checks, measured elapsed time ranges from
0.000293 to 0.421 s. Twenty additional name-invalid/superseded checks take short
rejection paths. Isolated runner process times span 2.94–4.59 s, with reported
peak resident sizes of 192,987,136–294,043,648 bytes. These measurements include
the stated test workload and process accounting; the worst-case latency for
64 MiB images is **unknown**. No throughput or speedup claim is made.

**Reproduction and complexity**

```sh
python3 -B tests/run_vmp_region_temporal.py --strings \
  --corpus-report build/vmp-protected-strings-release/strings.json \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-region-strings-new
ctest --test-dir build --output-on-failure
```

Accepted artifacts use `build/vmp-region-strings-release`,
`build/vmp-region-strings-release-gui` and
`build/vmp-region-strings-release-ordinary`. Their hashes, source hashes and
runtime identities are in
[VMP_REGION_STRINGS_EVIDENCE.json](VMP_REGION_STRINGS_EVIDENCE.json).

For E retained events and B retained stream bytes, ordered indexing and sorting
cost O(E log E), with additional bounded read-shape/key comparisons; retained
memory is O(E + B). Snapshot freshness costs O(M + F), where M is copied mapped
bytes/masks and F is function/segment/model metadata. These bounds exclude the
emulator and planner and do not imply constant-latency GUI polling.

**Bounded implications and quality gates**

- **High:** protected read sites can lie outside ordinary function ownership;
  separate capture/projection types preserve that distinction while exposing
  useful plaintext witnesses.
- **Medium:** exact whole-snapshot freshness has observable cost. Narrower
  dependency leases need their own completeness argument before replacing it.
- **Medium:** single-read literals, modeled-argument strings, interleaved read
  algorithms, protected ctree annotation and wider architectures remain outside
  this native-region stream projection.

QG1: technical implementation only. QG2: R1–R5 with probes. QG3: scoped capture,
consensus, display, freshness and regression evidence supplied; the full review
remains incomplete. QG4: exact counts, bytes, Unicode units, timings and complexity
scope stated. QG5: incomplete runs never shrink to a successful subset or acquire
ordinary proof flags. QG6: primary fixture, source and artifacts are hash bound.
QG7: adjacent opportunities and remaining limits are explicit.
