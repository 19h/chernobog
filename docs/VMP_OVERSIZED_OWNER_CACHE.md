# Oversized owned-function inventory cache

Repeated x86 owned-function inventory rejection was measured in the i386
protected condition corpus. The sampled `virtualization-12648430` IDB has
183,458 code heads and 1,160 decoded adjacent PUSH/RET pairs. One function
at `0x80521b9` owns 7,443 code heads and contains 100 of those pairs. Each
candidate can reach the same 4,096-head inventory limit in `flow_before`.
The pair count is an IDB inventory, not a runtime execution count.

`flow_before` now remembers only a negative result: a function has more than
4,096 code heads. The cache is scoped to the current IDB and at most 64
owners. Every lookup compares the complete current function range set,
including tails, with the stored set. IDB code/data item and byte changes
invalidate overlapping owners; function topology, segment, close, undo and
engine-reset events clear the cache. The notification runs before proof
callbacks. A cache hit returns the same unknown result as an oversized
inventory and publishes no positive dataflow fact, edge or condition proof.

## Boundary and protected observations

The dedicated x86-64 fixture has a nine-head branch diamond in which both
arms establish `ECX = 1`. Its `SETE` decision is false. After IDA appends a
4,088-head filler function as a tail, the owner has 4,097 heads and the
decision is unknown. Replacing two one-byte NOPs in the tail with one
two-byte NOP reduces the owner to exactly 4,096 heads. The decision becomes
false with 4,095 support heads without rebuilding the IDB. Restoring the
two NOPs returns to unknown. Removing the tail returns to the original
nine-head result; reattaching it returns to unknown. All 12 checks in the
fresh IDA probe passed. The first cache version stored only the entry chunk
and failed the exact-limit edit; the passing version stores all chunks.

One paired, default-enabled protected i386 run measured
74,053,455,917 ns (74.053455917 s) with the preceding installed plugin and
35,797,892,333 ns (35.797892333 s) with the cache. The difference is
38,255,563,584 ns (38.255563584 s), or 51.6594% of the preceding elapsed
time. Both used the same binary and IDA executable. Native selected-entry
inventories, function status, native proof hashes and condition rows, plus
generated microcode and decompiled text hashes, matched owner by owner.
This is one paired process observation; it does not estimate a timing
distribution or a universal speedup. The full condition matrix comparison
is recorded in the evidence manifest. Independent MBA rule-verifier timeout
counts varied between matrix processes; the exact captured condition reports
still matched after excluding elapsed-time fields.

## Bounds and falsification

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| O1 | IDA's decoded function heads define the 4,096-head inventory. The cache result depends on the current IDB classification. | Change item boundaries across 4,096 in the same IDB; require the result to switch at the threshold. |
| O2 | The SDK's function range set includes every attached tail. Range-equality and overlap invalidation depend on that behavior. | Edit code in a tail without changing its range, then remove and reattach the tail; require identical decisions at each head count. |
| O3 | The observed process elapsed values describe the exact paired artifact and environment only. The percentage depends on those two measurements. | Repeat paired runs with order reversal and report a distribution; compare complete raw condition reports. |
| O4 | IDB notifications cover mutations that can change an oversized owner's inventory. The immediate invalidation result depends on this callback path. | Exercise code/data creation, destruction, patch, tail ownership, undo and reopen in fresh IDBs; compare against a forced cache clear. Untested event variants remain unknown. |

**High impact:** repeated oversized-owner scans are removed from the
protected i386 workload while its inspected decisions remain unchanged.
**Medium risk:** a mutation that evades both range comparison and observed
IDB notifications can leave a stale negative result and delay recovery until
cache clear. It cannot by itself promote an unknown result to a positive
proof. **Low impact:** cache capacity is 64 owners; overflow clears the map
and preserves the original inventory path.

For an owner with `H` code heads and `C` function chunks, first rejection
enumerates at most 4,097 heads, `O(min(H, 4097))` item operations. A hit
fetches and compares `C` ranges plus a map lookup, `O(C + log 64)` under
the SDK range iteration contract. At most 64 range sets are stored,
`O(64C)` when each owner has at most `C` chunks. Range invalidation examines
at most 64 owners. The subsequent graph analysis for owners within the
limit is unchanged.

## Reproduction and quality gates

Build the fixture and run a fresh IDA process:

```sh
clang -arch x86_64 -O0 -o build/oversized-owner-cache-fixture \
  tests/vmp_native/oversized_owner_cache.c
python3 tests/run_ida_smoke.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/oversized-owner-cache-recheck \
  build/oversized-owner-cache-fixture \
  tests/ida_oversized_owner_cache_probe.py
```

The fixture source is `tests/vmp_native/oversized_owner_cache.c`; the
diagnostic inventory script is `tests/ida_pushret_latency_probe.py`. The
evidence manifest pins source, binary, plugin, IDA and report SHA-256 values.

QG1: no normative claim is required. QG2: O1–O4 list dependent results and
probes. QG3: negative-cache behavior, invalidation and matched protected
outputs are covered; the full VMP review remains in progress. QG4: head
limits, time units and the percentage calculation are explicit. QG5: a
cached rejection never becomes a proof. QG6: source and captured IDA report
hashes are pinned. QG7: mutation and timing limits are labeled above.
