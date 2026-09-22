# Strings from interleaved native reads

The previous aggregator retained one pending stream and required consecutive
memory-read events. Alternating reads from two buffers therefore discarded both
prefixes. The counterexample fixture completed all four production captures but
produced zero string observations. Its independent native oracle returned the
expected result, and separate corrupt-oracle controls rejected both values.

The aggregator now retains independent pending streams. Both separate heap
allocations and two buffers within one allocation recover `secret!` and `second!`
from alternating byte reads, before erasure and release. The same derivation is
used by ordinary function evidence and the separate native-region inspector.
This advances review requirements 3a, 3b and 5; it does not complete the review.

## Derivation and assumptions

A pending stream is indexed by memory scope, heap allocation ID/generation when
applicable, and the next expected address. Each new exact read can extend only
the matching stream. Its address must immediately follow that stream's bytes;
heap identity and stack-relative offset checks still apply. The original use
snapshot must match the following data event's source, address, width and bytes.

Other reads may occur between members, including recorded reads without an
eligible string-use snapshot. Writes or unknown data-event kinds, call/unknown
transfers, modeled uses, allocation and release events clear all pending streams.
An invalid use snapshot also clears them. These global barriers remain
conservative even when the affected address belongs to another object.

If two distinct prefixes reach the same endpoint, both are discarded; no prefix
is selected arbitrarily. A member containing NUL closes its stream. Aggregates
still require at least two original reads and a valid bounded UTF-8 prefix.
Single scalar reads and modeled arguments retain their separate producers.

Across runs, correspondence retains the first use's semantic key and the ordered
read-site/width shape. It does not require an identical schedule of unrelated
reads. Physical addresses, allocation generations and event sequences remain
per-run witnesses. The derived stream is a collection of observed reads, not a
single architectural load or a universal literal assigned to an address.

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| I1 | The admitted complete ledger and flat-memory model expose relevant writes and lifetime changes. Stream grouping depends on this contract. | Preserve completeness/truncation rejection; insert writes, unknown memory kinds and call/unknown transfers between active prefixes. Both affected streams lose consensus. Existing invalid-lifetime and allocation-reuse regressions also pass. |
| I2 | Spatial adjacency plus scope/lifetime identity defines a candidate read stream. | Exercise separate/shared allocations, image/frame data, 1/2/4-byte members, overlapping endpoint collisions and original address/generation witnesses. |
| I3 | Semantic-use/shape correspondence permits comparison across runs. | Reverse the interleaving order in the second portable run; alter one value and require only that stream to lose consensus. |
| I4 | The compiled fixture actually performs the intended alternating reads. | Verify two eight-member alternating sequence lists in every production capture, exact original bytes, allocation sharing/separation and native positive/negative byte oracles. |

## Bounds and algorithm

```text
for each use in total event order:
    clear pending streams if a global barrier intervened
    reject/reset invalid uses; retain eligible scalar/modeled observations
    take the pending stream whose scoped endpoint equals this read's address
    validate adjacency and original lifetime/frame identity, or start a new stream
    append the original read within the existing byte bound
    on NUL: validate and retain a completed multi-read stream
    otherwise: index its next endpoint, discarding colliding prefixes
compare completed streams across every scheduled run using semantic-use/shape keys
```

The existing per-run limit is 4,096 use records. Thus at most 4,096 pending
prefixes can exist, and their aggregate directly read payload is at most
`4096 * 8 = 32768` bytes, with additional copied fragment metadata and bytes.
The per-stream cap remains 4,096 bytes and the retained-output allowance remains
1,048,576 bytes per run. No quota was increased.

For U uses per run, endpoint lookup/insertion adds O(U log U) time and O(U)
pending records. Fragment and payload storage remain linear in captured reads;
each read belongs to at most one pending stream. Barrier clearing is amortized
over inserted prefixes. Existing event indexing, decoding and cross-run shape
comparison costs remain additional. These bounds exclude emulator and solver
execution. No latency improvement is claimed.

## Validation

The portable counterexample fails before the implementation change. The fixed
suite passes 384 new interleaved-read checks across four layouts and three read
widths, alongside the existing stream/lifetime/encoding/quota regressions.
All 20 CTest suites pass in 12.04 s.

| Production run | Checks | Result |
|---|---:|---|
| Separate allocations, native-region console/Qt | 35 + 40 | Both values, eight witnesses and 64 original fragments |
| Shared allocation, native-region console/Qt | 35 + 40 | Both values retain the same allocation identity and distinct offsets |
| Existing scalar/modeled console/Qt | 38 + 44 | Four observations retain their separate producers |
| Separate/shared interleaved ordinary ctree | 24 + 24 | Exact transient annotations, byte/profile freshness and restoration |
| Existing ordinary ctree regression | 24 | Existing display and freshness controls pass |
| Ten-binary protected corpus | 183 | Recovery remains 4/18 protected value occurrences |

These total 487 production checks. Each of the two new fixture layouts and the
scalar/modeled regression executes three native oracles with exits 0, 1 and 1.
The new fixtures contain no plaintext literals. The independent process oracle
compares all eight consumed bytes against encoded constants after erasure/free;
the plugin projection does not supply its expected values. The x86-64 fixtures
execute on an arm64 runner through the host's execution support; hardware-only
x86-64 differential validation is not claimed.

Both actual native-region Qt captures were inspected. They show both values,
four capture witnesses per value, nonconsecutive original use/data events and
the exact fragment bytes. Navigation freshness, edits/restoration, supersession
and timer shutdown are tested. Ctree checks verify observed annotations without
changing function bytes, the AST or persistent comments.

The protected matrix still has seven incomplete binaries that publish no values.
New interleaved recovery is established on independently written native fixtures,
not on newly generated protected interleaved code. The existing protected corpus
is regression evidence, not evidence of a protected coverage increase.

Reproduce each new layout with:

```sh
python3 -B tests/run_native_use_snapshots.py \
  --ida "$IDA_CONSOLE" --gui "$IDA_GUI" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/interleaved-separate-new --interleaved separate
python3 -B tests/run_native_use_snapshots.py \
  --ida "$IDA_CONSOLE" --gui "$IDA_GUI" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/interleaved-shared-new --interleaved shared
```

The ordinary ctree probe accepts `CHERNOBOG_INTERLEAVED_READS=separate` or
`shared` through `tests/run_ida_smoke.py --set`. Sources, runtime binaries and
accepted/counterexample artifacts are hash bound in
[VMP_INTERLEAVED_READS_EVIDENCE.json](VMP_INTERLEAVED_READS_EVIDENCE.json).

## Bounded findings and quality gates

- **High:** unrelated read events need not destroy temporal byte evidence when
  writes and lifetime barriers remain explicit. The result preserves original
  fragments rather than inventing one synthetic machine read.
- **Medium:** global write/call/lifetime barriers can still suppress recoverable
  strings. Removing them requires a separately justified effects/alias contract.
- **Medium:** reverse, strided or permuted reads, write-interleaved algorithms,
  protected interleaved fixtures and broader architecture validation remain.

QG1: technical observation scope. QG2: I1–I4 and probes. QG3: derivation, both
production consumers, original witnesses and regression coverage supplied; the
complete review remains open. QG4: byte limits, exact counts and algorithmic
bounds explicit. QG5: effects/lifetime barriers and endpoint collisions covered.
QG6: hash-bound code and independent native/production artifacts. QG7: remaining
algorithm, architecture and protected-corpus boundaries stated.
