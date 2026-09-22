# String observations before an unexecuted frontier

Mutation seed 1 captures both string lifetimes and their read bytes, erases and
releases both allocations, then stops before a rejected BSWAP16 instruction.
Requiring eventual sentinel return hid these already recorded observations.

`chernobog_vm_temporal_prefix_strings(ea, input_json, bindings_json)` now exposes
an explicit prefix scope. It compares four seeded captures under the same named
ABI models and retains original use/data events, allocation generations and
per-capture exclusive sequence bounds. The existing completed-run API and default
Qt action keep their return requirement. Use the companion's
`show(ea, bindings, input_request=None, prefix=True)` to select the new scope.

In the paired protected string corpus, this API recovers 6/18 protected value
occurrences, versus 4/18 through the completed-run API. These counts describe
different admission contracts, not an increase in completed execution. Mutation
seed 1 remains incomplete in every capture. The six virtualization/combined
variants still have zero string observations; their bounded prefixes stop before
the required uses. This advances review rows 3a, 3b, 5 and V without completing
their broader requirements.

## Admission and assumptions

The driver asserts prefix completeness only with intact instruction, memory,
dependency and temporal ledgers, valid hooks/status, and either sentinel return
or a native-region host stop before an instruction is entered. It rejects
truncation, filtering, cancellation, changed code, permission violations, escaped
execution, function boundaries, unmodeled dependencies, model failures and
synthetic entry contexts. Timeout and instruction-budget stops are not admitted.

For a region stop, the boundary code hook has consumed a sequence number without
recording or executing the target instruction. The exclusive bound is that hook's
sequence. For a sentinel return, it is the next sequence number. The projection
requires a nonempty ordered instruction ledger with matching run/seed identity;
every use, data access and allocation/release event must precede the bound. A
transfer edge at the bound is permitted only for the exact reported frontier.
It remains boundary evidence, not target execution. The maximum nonfrontier
record sequence plus one must equal the bound.

Every scheduled capture must qualify; a rejected capture prevents projection of
the entire corpus. Returned and stopped captures may coexist under the prefix
contract. Original cross-run semantic-use/fragment-shape agreement, exact byte
joins and lifetime checks remain required. Ordinary function evidence, VM
identity and completed-execution flags are never promoted by this API.

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| P1 | The backend invokes the region code hook before executing the stopped target and delivers earlier memory events before that hook. Prefix completeness depends on this ordering. | Driver fixture stops before its final RET and preserves exact earlier use witnesses; production ledgers place every entered instruction and memory event below the exclusive bound. Independent decoding verifies the unexecuted frontiers. |
| P2 | Explicit named ABI models and bounded seeded inputs define the observed behavior. They do not prove callee equivalence or universal inputs. | Existing binding/rename, source-byte, permission, profile and supersession controls pass; old completed-run admission is checked beside every prefix capture. |
| P3 | Every scheduled ledger is intact and correctly identified. | Twenty-eight portable corruptions cover missing/shifted bounds, stop/status mismatches, foreign/duplicate execution identities, events at/beyond the cutoff and all five ledger caps. Each rejects the whole corpus. Truncated driver capture and ordinary/budget-stop controls remain ineligible. |
| P4 | Original bytes and lifetime witnesses, rather than post-erasure memory, support each value. | Mutation seed 1 retains two released generations at a reused heap address, four witnesses per value and eight original byte fragments per witness. Existing scalar/modeled and shared-allocation interleaving regressions pass independent positive/negative native oracles. |

The prefix flag is a contract of the internal driver, not authentication of
arbitrary caller-forged C++ event structures. Broader backend/architecture
validation and universal semantic correctness remain unknown.

## Bounds and algorithm

```text
for every scheduled capture:
    require an intact driver prefix ending at return or a pre-instruction stop
    validate execution identity, ordering, frontier and exclusive cutoff
    require all use/data/lifetime records before the cutoff
    retain only the exact frontier edge at the cutoff, if present
    require the final nonfrontier event to end immediately before the cutoff
derive observations with existing exact-byte, lifetime and stream rules
compare semantic-use/fragment shapes across every scheduled capture
```

The portable corpus cap remains 16 captures; the production API schedules four
seeds: 0, 1, 17 and 12648430. Per capture, prefix validation admits at most 4,096
instruction records, 4,096 edges, 4,096 uses, 65,536 data records and 4,096
allocations. Existing string/output caps are unchanged. Added validation costs
O(I + E + U + D + A) time and O(1) auxiliary space per capture. Existing stream
derivation, model checks and cross-run comparison costs are additional. Sequence
numbers are event ordinals, not elapsed time or instruction counts.

## Validation

All 20 CTest suites pass in 11.31 s. Portable regressions cover complete, stopped,
mixed and corrupt prefix corpora, the exact frontier-edge exception, unchanged
completed-run rejection and the existing string/lifetime/interleaving controls.

| Production validation | Checks | Result |
|---|---:|---|
| Ten binaries, prefix and completed-run comparison | 244 | 6/18 prefix occurrences; completed-run 4/18 |
| Ten binaries, raw temporal ledgers and binding controls | 474 | All 40 prefixes bounded; 12 returns, 28 explicit stops |
| Mutation seed 1, actual Qt inspector | 38 | Two values; visible `OBSERVED PREFIX ONLY` and `Incomplete executions: 4/4` |
| Existing scalar/modeled console fixture | 38 | Original four producer-specific observations |
| Existing shared-allocation interleaved console fixture | 35 | Two values retain distinct offsets and original alternating reads |

These total 829 production checks. Both native regression fixtures retain their
three independent process-oracle exits 0, 1 and 1. The host is arm64 and fixtures
are x86-64; this does not establish hardware-only x86-64 differential coverage.

Capstone 5.0.7 independently checks 7,156 entered instruction records against
file-backed bytes with zero size, byte or linear-successor mismatches; all 28
stopped frontiers decode as BSWAP16. No BSWAP16 result is assigned or used. In
mutation seed 1, each capture ends at exclusive event ordinal 413, after the last
entered instruction at ordinal 412 and both recorded allocation releases.

The actual Qt screenshot was inspected: scope and incomplete execution are
visible above the values, captures and original byte events. Exact freshness,
restoration, navigation gating, supersession and timer shutdown pass. Current
input freshness does not imply completed execution.

Reproduce the new protected measurement with:

```sh
python3 -B tests/run_vmp_region_temporal.py \
  --corpus-report build/vmp-protected-strings-release/strings.json \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/prefix-strings-new --prefix-strings
```

Source and artifact hashes are recorded in
[VMP_PREFIX_STRINGS_EVIDENCE.json](VMP_PREFIX_STRINGS_EVIDENCE.json). Existing
corpus provenance and independent native byte oracles remain documented in
[VMP_REGION_TEMPORAL.md](VMP_REGION_TEMPORAL.md) and
[VMP_PROTECTED_STRINGS.md](VMP_PROTECTED_STRINGS.md).

## Bounded findings and quality gates

- **High:** completed uses can remain observable when later execution stops,
  provided the earlier ledger has an explicit intact boundary.
- **Medium:** timeout/fault prefixes require a separately established retirement
  contract; they remain rejected here.
- **Medium:** this API adds no protected ctree annotations, logical VM-state
  recovery, continuation through BSWAP16, broader architecture coverage or
  universal string proof. These remain separate requirements.

QG1: technical observation scope. QG2: P1–P4 and falsification probes. QG3: scoped
API, driver, projection, client and regression coverage supplied; full review
remains open. QG4: event bounds, byte witnesses, counts and complexity explicit.
QG5: incomplete execution, mixed captures, frontier edges and truncation covered.
QG6: hash-bound primary source and independent production/decoder artifacts.
QG7: remaining backend, architecture and publication limits stated.
