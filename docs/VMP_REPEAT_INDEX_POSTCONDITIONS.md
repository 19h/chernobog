# Bounded REP index postconditions

This changeset advances review rows 1, 2 and V. After successful bounded
REP MOVS/STOS memory admission, the native replay retains index bits common
to every represented normal completion. The complete review remains in progress.

## Transfer and admission

Let `W` be the natural address width, `p` an established index, `c` a compatible
dimensionless count, and `B` the element width in bytes. Each admitted direction
produces:

```text
d = c * B bytes
p_end = (p + d) mod 2^W   when DF = 0
p_end = (p - d) mod 2^W   when DF = 1
known = common zero bits OR common one bits across all endings
value = common one bits
```

`repeat_index` enumerates the complete bounded count domain and the admitted
DF domain. It uses unsigned modular arithmetic and the existing per-bit join.
Unknown DF includes both directions. Unknown count bits contribute every
compatible count; counts above 8 reject the entire domain. Unknown initial
indexes establish no bits. Invalid address widths, element widths or indexes
outside the selected address width establish no bits. This helper does not
prove access validity or recognize an instruction encoding.

The production adapter calls the helper only after the existing complete memory
domain succeeds. MOVS updates SI and DI; STOS updates DI and preserves SI.
The descriptor captures both starting indexes before mutation, and count is
cleared after index calculation. Singleton zero count takes the existing path
and preserves prior partial index and abstract stack state. Nonzero repeats
continue to forget the abstract stack. DF and the six status flags retain their
existing transfers. Memory replay, encoding checks and resource limits are
unchanged.

Nonzero production precision remains restricted to long mode with natural
address size, no segment override, matched implicit operands and admitted REP
prefixes. This changeset introduces no i386 DS/ES base contract. The portable
helper exercises widths 32 and 64; those arithmetic checks do not establish
i386 production memory admission.

For `N <= 9` compatible counts and `D <= 2` directions, the added transfer
takes `O(N D)` time and `O(1)` auxiliary space. The existing memory replay
retains its separate bounds. `B` is 1, 2, 4 or 8 bytes and `c <= 8`, so each
signed displacement has magnitude at most 64 bytes. The join is exact in the
per-bit abstraction for the enumerated Cartesian domain. Correlations between
count, DF and indexes are not retained.

Architectural provenance is Intel SDM revision 090, Vol. 2B: MOVS
4-114–4-117, REP 4-563–4-564, and STOS 4-676–4-678. The operations specify
direction-dependent index updates and normal repetition completion. The
hash-verified local archive is pinned in the evidence JSON. See the
[Intel combined manual](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf).

## Production measurements

The predecessor is the retained installed `266d59e999aa` artifact. Both
versions use the same 20-routine executable and final probe in fresh IDA
processes. Owned flag and register scan depths are explicitly 64; production
defaults are unchanged. Ownerless inspection uses the existing 128-node bound.

| Consumer, 20 routines | Predecessor | Candidate |
|---|---:|---:|
| Exact owned PUSH/RET targets | 0 | 14 |
| Exact ownerless PUSH/RET targets | 0 | 14 |
| Existing exact conditions on each path | 2 | 2 |
| Unresolved conditions on each path | 4 | 4 |

Ten targets use exact counts and established forward/reverse DF, including all
four element widths and both MOVS indexes. Four targets use a subsequent
`AND -16` to recover the aligned block base from index bits retained across
unknown DF, partial count, or both. Their indexes remain in one aligned
16-byte block under every represented completion. The target delta is
established before REP; the computed target is an executable leaf returning
73. Every exact owned target has the measured user code edge, and ownerless
facts remain unpublished.

Unknown DF without a mask, partial count without a mask, count 9, and unknown
MOVS source index remain unresolved. The two existing positive controls show
STOS preserving SI and zero count preserving DI. All 20 ownerless inspections
preserve the complete byte/mask, head/owner, reference, function, comment and
name inventory. Fixtures have owners supplied by normal analysis; the probe
removes them for ownerless inspection. Production does not force ownership.

Patching count 2 to 9 immediately revokes prior publications and removes the
target edge after reanalysis. Restoration produces a new exact publication.
An external entry at REP revokes the target; removal restores it. Changing
the partial-index mask from `-16` to `-8` leaves an unresolved bit and revokes
the target; restoring the bytes restores the proof. All fixture edits occur
in disposable IDBs, and the probe checks byte restoration.

## Independent execution and controls

The fixture oracle executes 5,120 routine/input cases. It varies both incoming
DF values, eight arguments and 16 repetitions, compares the return value, and
compares all 64 source and 64 destination bytes against an independent C
array model. The emitted fixture code establishes memory bytes before REP;
initial writable image contents are not assumed. The standalone repeat oracle
executes 38,400 actual REP cases and checks complete buffers, count, SI/DI,
DF and six status flags.

The portable suite performs 3,237,880 repeat assertions. Its x86-64 execution
build performs 3,468,280 repeat assertions. New checks compare every retained
index bit and the exact common-bit join against an independently enumerated
concrete machine. Exact wrapping results are compared against byte-by-byte
increment/decrement across both address widths, four element widths, counts
0–8 and values near zero and the address-width boundary. Unknown indexes,
unbounded counts, count 9 and invalid widths/indexes reject precision. Existing
overlap, unknown payload, destination validation and eviction tests remain.

All 22 CTest suites pass. Existing x86-64 dataflow checks pass with 37,630 native
and 479 inspection checks; i386 passes with 36,350 native and 412 inspection
checks. x86-64 execution uses macOS translation on this arm64 host; the i386
control uses the pinned QEMU 9.2 backend. Independent bare-metal confirmation
is unknown. The supplied `samples/foo_x86_vmp` control retains 75 nodes,
77 edges and three unresolved facts, with an unchanged inspection inventory.
This checkpoint establishes no protected-corpus recovery gain.

## Reproduction

Retain the predecessor plugin before building the candidate. Build and run:

```sh
cmake --build --preset native-release --parallel 20
xcrun clang -arch x86_64 -O2 -mno-red-zone tests/vmp_native/repeat_indices.S tests/vmp_native/repeat_indices_main.c -o build/repeat-index-native
build/repeat-index-native
xcrun clang++ -arch x86_64 -std=c++17 -O2 -mno-red-zone -DCHERNOBOG_NATIVE_REPEAT_ORACLE -Isrc tests/x86_abstract_tests.cpp -o build/repeat-index-native-oracle
build/repeat-index-native-oracle
build/chernobog_x86_abstract_tests
ctest --test-dir build --output-on-failure --parallel 8
```

Run `tests/run_ida_smoke.py` with input `build/repeat-index-native`, probe
`tests/ida_repeat_indices_probe.py`, explicit `--ida` and `--plugin` arguments,
a fresh `--output-dir`, and both `--set CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64` and
`--set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64`. Add
`--set CHERNOBOG_REPEAT_INDEX_BASELINE=1` for predecessor expectations only.
The report is `repeat_indices.json`. Cross-architecture controls use
`tests/run_native_dataflow.py`; the protected control uses
`tests/ida_protected_region_inspect.py` at root `0x1002946b5`, expectation
`complete`. Evidence JSON pins the actual sources, binaries and process reports.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | Normal completion under unchanged code; all ending-index facts depend on this scope. | Independent execution/array comparisons and patch/revoke/restore. Interrupted or faulted prefixes, concurrent changes and MMIO remain outside the model. |
| A2 | The admitted count and DF domains cover all represented completions; retained bits and targets depend on this. | Unknown/known DF, counts 0–8, partial counts, count 9, insufficient mask and exact common-bit comparisons. |
| A3 | Index precision follows successful existing memory admission; production facts depend on this. | Existing invalid-destination, unknown-source/payload, overlap, width crossing and bounded-map controls; i386 nonzero precision is not introduced. |
| A4 | Source bytes, incoming entries and dependencies remain current; owned edges depend on this. | Immediate publication revocation, count patch, external REP entry, mask patch, restoration/new publication identity and 20 read-only ownerless inventories. |
| A5 | Arithmetic follows unsigned natural-width modular updates; helper results depend on this. | Independent byte-step wrap oracle for both widths, invalid widths and out-of-width indexes. |
| A6 | Scan configuration and translated execution are part of these measurements; yield depends on this. | Same executable and probe, explicit depth 64, pinned artifacts and process receipts. Default-budget yield and bare-metal execution are unknown. |

## Bounded opportunities and limits

- High impact: precise ending indexes can supply subsequent indirect targets;
  this changeset demonstrates 14 finite fixture targets. Yield on supplied
  protected programs is not established.
- Medium impact: retaining correlations could recover results lost by the
  Cartesian per-bit join. Correlation precision and its resource cost are
  unmeasured here.
- Low impact: an arithmetic-only transfer could extend index precision when
  memory admission abstains. Such an independent admission contract is outside
  this changeset.

## Quality gates

QG1 passes: architectural transfers and observations require no normative
claim. QG2 passes: A1–A6 name dependencies and falsification probes. QG3 passes
for this postcondition changeset; the complete review remains in progress.
QG4 passes: byte units, dimensionless counts, modular arithmetic, bounds and
reproduction are explicit. QG5 passes within A1–A6: uncertainty, bounds,
wrap, unchanged controls and publication lifecycle are measured. QG6 passes:
primary archive, source hashes, executable artifacts and process reports are
pinned; full reproducible build attestation remains unknown. QG7 passes:
opportunities and limits are bounded above.
