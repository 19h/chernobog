# Read streams across disjoint heap writes

This records the allocation-disjoint admission rule and its measured plugin
revision. The later same-allocation byte-span refinement is recorded in
`VMP_SAME_OBJECT_WRITE_STREAMS.md`; the hashes in this report remain historical.

Review requirements 3a and 3b require use-time string evidence to retain
allocation identity and memory order. The earlier interleaved-read aggregator
cleared every active stream at any write. A write to one heap allocation thus
erased the read-only stream from a separate allocation. The new production
aggregator keeps that separate stream while retaining a barrier for the written
allocation. It does not infer a string from unobserved bytes or reconstruct a
final heap image.

## Admission and algorithm

An exact executed read still requires its matching memory event, a valid live
allocation witness, complete temporal and data capture, spatially adjacent
fragments, and cross-run agreement on semantic use and read shape. The ledger
indexes a heap write separately only if it has known scope, an exact positive
width of at most 8 bytes, and a nonoverflowing address interval. Other writes,
unknown memory kinds, modeled uses, calls, allocation/release events, and
invalid snapshots retain the global barrier.

For a pending heap stream, a write between consecutive read fragments is
admitted only when its byte interval is disjoint from the **entire** witnessed
allocation interval. A write anywhere inside that allocation discards the
stream, including when it misses bytes already read. Image and stack streams
still treat every write as a barrier. Both endpoints use checked unsigned-byte
arithmetic; an overflowing interval abstains. At most 256 intervening heap
writes are inspected per attempted extension; the 257th discards it. Stale
prefixes that reach an endpoint after a write are removed before a new prefix
is inserted, so they cannot displace that new prefix. No memory or call effect
is silently assumed absent.

```text
for each exact read use in event order:
    clear pending streams at a global barrier
    find the scoped pending prefix ending at this read address
    admit it only if all intervening heap writes (at most 256) are disjoint
        from the prefix's complete allocation interval
    append the original read bytes and retain their use/data witnesses
    on NUL, compare the completed stream across all scheduled runs
```

With U ≤ 4,096 use records, W ≤ 65,536 data records, and A ≤ 4,096 allocation
records per run, indexed write insertion costs O(W log W). Each attempted
extension costs O(log W + log A + 256), excluding preexisting endpoint lookup,
fragment copying and cross-run comparison. Additional indexed-write storage is
O(W). The 256-write cap bounds an individual continuity check; it does not
claim that all execution or IDA work is bounded by that number.

## Controlled observations

The independent native x86-64 fixture performs eight alternating byte reads
from each of two plaintext-bearing heap buffers. A volatile write to byte offset
24 of the first allocation occurs after each pair of reads. Neither plaintext
appears as a literal in the compiled binaries. The positive separate and
shared-allocation executables exit 0. Corrupting either of the fixture's two
expected values yields exit 1; these are independent process-oracle controls.
The fixed output contract does not depend on Chernobog's recovered strings.

| Fresh IDA profile | Allocation layout | Completed runs | Retained heap writes | Recovered strings | Ctree use annotations |
|---|---|---:|---:|---|---:|
| Previous installed plugin | Separate | 4/4 | 48 | None | 0 |
| Updated plugin | Separate | 4/4 | 48 | `second!` | 1 |
| Updated plugin | Shared | 4/4 | 44 | None | 0 |

The previous and updated profiles use identical separate-allocation binary,
IDA executable and probe bytes. The updated profile retains eight original
read fragments per run, four agreeing witnesses, and exactly one transient
ctree annotation for `second!`. The first allocation's stream is withheld
because that allocation is written. In the shared layout both buffers belong
to one allocation; withholding both is the conservative result. The evidence
view displays at most 1,024 events, so its retained-write counts are display
counts, not total executed-write counts.

Portable controls cover four layouts (separate heap, shared heap, image and
stack), read widths 1, 2 and 4 bytes, independent interleavings, colliding
prefixes, an unrelated heap write, a same-allocation write, malformed/overflowed
writes, and the exact 256/257-write boundary. The interleaved-read suite now
passes 404 assertions. Existing separate and shared native/IDA regressions pass
35 console assertions each, and 21/21 CTest suites pass. The raw identities,
report hashes and outcomes are in `VMP_HEAP_WRITE_STREAMS_EVIDENCE.json`.

Reproduce the new native fixture and isolated IDA profiles with unused output
directories, a local IDA 9.4 SP1 console path and an installed plugin path:

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-unroll-loops \
  -D_FORTIFY_SOURCE=0 -Wl,-no_fixup_chains -Wl,-no_data_const \
  -DWRITE_FIRST_ALLOCATION=1 tests/vmp_native/native_interleaved_strings.c \
  -o build/vmp-native-interleaved-writes-new
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-unroll-loops \
  -D_FORTIFY_SOURCE=0 -Wl,-no_fixup_chains -Wl,-no_data_const \
  -DWRITE_FIRST_ALLOCATION=1 -DSHARED_ALLOCATION=1 \
  tests/vmp_native/native_interleaved_strings.c \
  -o build/vmp-native-interleaved-writes-shared-new
python3 -B tests/run_ida_smoke.py build/vmp-native-interleaved-writes-new \
  tests/ida_heap_write_strings_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/heap-write-strings-new \
  --set CHERNOBOG_HEAP_WRITE_EXPECT=1
python3 -B tests/run_ida_smoke.py build/vmp-native-interleaved-writes-shared-new \
  tests/ida_heap_write_strings_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/heap-write-strings-shared-new \
  --set CHERNOBOG_HEAP_WRITE_EXPECT=0 --set CHERNOBOG_HEAP_WRITE_SHARED=1
ctest --test-dir build --output-on-failure -j 20
```

## Assumption register, bounds and quality gates

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| H1 | The complete flat-memory ledger records writes and allocation lifetimes accurately. The disjointness decision depends on this. | Require complete temporal and data captures in each run; inspect actual heap-write events. Unknown kinds, overflowed intervals, calls and lifecycle events remain barriers. A missing write in a falsely complete ledger would defeat the result. |
| H2 | Nonoverlapping byte intervals identify disjoint allocations in the tested model. Retaining `second!` depends on this. | Compare two allocations with one shared allocation; write inside one allocation and reject its stream. Reject address overflow and all writes outside the admitted heap case. |
| H3 | The eight reads per string are the intended uses and the four runs are comparable. The recovered value depends on this correspondence. | Preserve original read fragments and require all four matching run witnesses; independently execute positive and two corrupted-value process oracles. |
| H4 | The old/new IDA profiles differ in plugin implementation while input, IDA and probe bytes match. Attribution of the measured gain depends on this. | Compare SHA-256 and `run.json` artifact-integrity fields; retain the old plugin and both raw reports. |
| H5 | The arm64 macOS host's x86-64 execution support implements the measured path. Process-oracle conclusions depend on this. | Repeat the four native executables on physical x86-64 macOS or an independent translator; those results are **unknown**. |

**High impact:** a global write barrier can suppress an unrelated use-time
string even when exact allocation intervals prove the writes disjoint.
**Medium impact:** unknown scopes and wide writes still abstain, preserving
soundness at the cost of coverage. **Low impact:** the evidence-view assumption
text now matches the admitted interleavings. This fixture is independently
written native code; VMP-emitted write-interleaved coverage, other architectures,
and isolated aggregation latency remain **unknown**.

QG1: no normative premise. QG2: H1–H5 include falsification probes. QG3: the
scoped heap-write change is tested through native execution, portable consensus,
IDA publication and ctree display; the complete review ledger remains open.
QG4: byte widths, limits, exact counts and complexity are stated. QG5: same
allocation, malformed, unknown-effect and quota cases retain abstention. QG6:
source, native binary, plugin, IDA, probe and raw-report hashes are recorded.
QG7: adjacent scope and measurement limits are bounded above.
