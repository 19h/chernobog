# Read streams across writes outside their completed byte span

Review requirements 3a and 3b call for temporally accurate plaintext and
allocation identity. The prior aggregator discarded a pending stream when any
write touched its allocation. An eight-byte string at allocation offsets 0–7
was therefore lost when the same allocation was written at offset 24. The
current projector retains that stream after checking every intervening write
against its completed observed byte interval. It publishes an observed read
stream, not a claim that the allocation held one immutable string for its
entire lifetime.

## Admission and bounds

Every read fragment must still have an exact matching memory event, a live
allocation witness, adjacent addresses, complete temporal and data capture,
and four-run agreement in the production fixture. A heap write is eligible
for inspection only when its scope is known, its width is 1–8 bytes and its
address interval does not overflow. A write crossing the active allocation boundary,
an unknown or wide write, a call, or an allocation/release event remains a
barrier. Image and stack streams retain their prior write barrier.

During stream extension, an intervening write may lie wholly inside the same
allocation. Before publication, every indexed heap write after the first read
and no later than the last read is checked against the complete observed span,
including the NUL byte. Any byte overlap vetoes that stream even when the
write preceded the read of that particular byte or followed its earlier read.
Writes ending at the span start or starting at its end are disjoint. At most
256 indexed writes are inspected per extension and per completed stream; the
257th causes abstention. The completed check does not use the write's scalar
value to infer unchanged memory.

```text
for each exact read fragment:
    locate the matching pending endpoint and allocation generation
    reject a global effect or malformed/cross-allocation heap write
    append the original observed bytes and read witness
when a NUL-terminated stream is complete:
    scan at most 256 heap writes from first to last read
    reject any write interval intersecting the entire observed byte span
    require matching semantic use, read shape, and value in every scheduled run
```

The added completed check costs `O(log W + min(W, 257))` time and `O(1)`
working space per completed stream for `W` indexed writes. The 257th visit
rejects, so accepted checks inspect at most 256 writes. The existing ledger
caps `W` at 65,536 data records and use attempts at 4,096 per run. This cost
excludes existing event indexing, fragment copying, consensus and IDA work.

## Controlled observations

An independent x86-64 Mach-O fixture alternates eight byte reads from each
of two decoded strings. The positive variant writes byte 24 of the first
allocation after each read pair. The negative variant writes byte 0 of the
first string after that byte was read; the process oracle still checks the
original eight observed bytes. Each variant has separate and shared-allocation
builds. All four unmodified binaries exit 0. Corrupting either expected value
in the shared positive build separately produces exit status 1. Neither
plaintext appears as a literal in the positive shared binary.

| Write and allocation layout | Previous plugin: candidates / annotations | Modified plugin: candidates / annotations |
|---|---:|---:|
| Offset 24, separate allocations | 1 / 1 (`second!`) | 2 / 2 (`secret!`, `second!`) |
| Offset 24, shared allocation | 0 / 0 | 2 / 2 (`secret!`, `second!`) |
| Offset 0, separate allocations | 1 / 1 (`second!`) | 1 / 1 (`second!`) |
| Offset 0, shared allocation | 0 / 0 | 1 / 1 (`second!`) |

The eight fresh IDA 9.4 SP1 profiles use identical binary and probe bytes
within each old/new pair. Every profile has four returned, temporally complete
runs and passes nine checks, including unchanged function bytes and no saved
use comments. A consumed-key edit removes displayed uses until its exact byte
is restored. The modified plugin also passes the earlier no-write native-read
probe's 23 checks. Portable controls cover four layouts, 1-, 2-, and 4-byte
reads, writes to already-read and future string bytes, a different string in
the same allocation, partial allocation overlap, malformed writes and the
256/257-write boundary: 428 checks pass. All 21 CTest suites pass. Exact
identities and raw-report hashes are in
`VMP_SAME_OBJECT_WRITE_STREAMS_EVIDENCE.json`.

Reproduce a shared positive binary and its production probe with:

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-unroll-loops \
  -D_FORTIFY_SOURCE=0 -Wl,-no_fixup_chains -Wl,-no_data_const \
  -DWRITE_FIRST_ALLOCATION=1 -DSHARED_ALLOCATION=1 \
  tests/vmp_native/native_interleaved_strings.c \
  -o build/vmp-same-object-disjoint-shared
python3 tests/run_ida_smoke.py build/vmp-same-object-disjoint-shared \
  tests/ida_same_object_write_stream_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_VALUES=secret!,second! \
  --set CHERNOBOG_SHARED_ALLOCATION=1 \
  --output-dir build/vmp-same-object-reproduction
```

## Assumption register and scope

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| S1 | Complete temporal/data capture records all relevant writes. Safe continuation depends on this. | Every scheduled run must report complete capture; unknown, wide, overflowed and cross-allocation writes reject. A falsely complete ledger with a missing write would invalidate the result. |
| S2 | Allocation interval and generation identify the object containing each read and write. The shared-allocation gain depends on this. | Same-object disjoint writes pass; overlapping first-string writes veto only that string; a partial allocation overlap rejects both. Release/reallocation remain global barriers. |
| S3 | The concatenated exact reads represent the observed string bytes in event order. Both plaintexts depend on this. | The native process oracle and two corrupted controls are independent of plugin output. An overlap with a previously or subsequently read byte rejects. No value is inferred from a write event. |
| S4 | The two candidate uses have the same semantic identity and value across four runs. Publication depends on this. | The probe requires four eligible observations and eight original fragments per candidate. Existing divergent and duplicate-corpus controls remain passing in the evidence suite. |
| S5 | The current IDB and consumed key match the evidence. Ctree display depends on this. | Key patch/restoration, unchanged bytes, absent saved comments, and eight isolated runner integrity reports check this lease. |

**High impact:** a write to an unrelated field of the same allocation no
longer suppresses a fully observed string. **Medium impact:** overlapping or
unattributed writes still abstain; noncontiguous reconstruction, other
architectures and VMP-emitted coverage remain unknown. **Low impact:** this
change adds at most one bounded write scan per completed candidate stream.

QG1: no normative premise. QG2: S1–S5 list falsification probes. QG3: the
bounded same-object extension has portable, native process, production IDA,
baseline and regression evidence; the full review remains open. QG4: byte
intervals, caps and exact counts are stated. QG5: overlap, malformed and
quota cases retain abstention. QG6: source, binary, plugin, IDA and raw-run
hashes are recorded. QG7: adjacent opportunities and limits are bounded above.
