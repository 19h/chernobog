# Direction flag precision for bounded repeated string memory

This checkpoint advances review row 1 and the native measurements in row V.
It tracks DF separately from the existing six status flags and refines the
bounded REP MOVS/STOS memory replay. The complete review remains in progress.

## Implementation

The native state represents DF as unknown, clear, or set. Entry starts unknown;
no ABI convention establishes DF. An exact unprefixed `FC` (CLD) establishes
clear, and `FD` (STD) establishes set. Other decoded encodings of those
instructions forget DF. State equality includes DF, and a join retains DF
only when both inputs agree. Unsupported instructions use the existing full
state invalidation. Ordinary modeled instructions preserve DF.

Supported full-width PUSHF/POPF operations carry architectural RFLAGS/EFLAGS
bit 10 through the abstract stack. POPF first forgets DF, then restores it only
when the popped word establishes that bit. Unsupported stack widths, an empty
stack, and an unknown popped bit cannot establish DF. The six status flags
retain their existing transfer functions.

`StringRepeat.reverse` selects descending addresses when true and ascending
addresses when false. An absent value admits both directions. The helper
replays every compatible count and admitted direction; only equal bytes survive
the result join. A failed destination validation still rejects the entire
domain without modifying the input. Known forward DF can therefore admit an
otherwise rejected reverse destination without discarding an admitted input.
Sequential MOVS reads precede each element write, including overlap.

Existing bounds remain: count at most 8 iterations, element width 1, 2, 4 or
8 bytes, at most 128 locally established bytes, natural address size, and
admitted REP encodings. Nonzero production memory precision remains restricted
to long mode. i386 receives no DS/ES base contract and retains its nonzero
abstention; zero-count handling remains available. Initial writable image
contents do not establish bytes. Index values are conservatively forgotten
after nonzero execution, and normal completion establishes zero count.

With `N <= 9` compatible counts, `D <= 2` admitted directions, `C <= 8`
iterations, `B <= 8` bytes per element and `M <= 128` retained bytes, time is
`O(N D (M + (C B + M) log M))`, with `O(M)` auxiliary space. Known DF reduces
`D` to 1. Counts are dimensionless; addresses and spans are measured in bytes.
Address arithmetic wraps at the selected width. An element crossing the
address-width boundary is rejected.

Architectural provenance is the hash-verified Intel SDM revision 090 archive:
DF is bit 10 (Vol. 1, section 3.4.3.2); CLD (Vol. 2A 3-141), STD
(Vol. 2B 4-672), POPF (Vol. 2B 4-407 onward), PUSHF (Vol. 2B 4-528 onward),
and the MOVS/REP/STOS sections pinned in `VMP_BOUNDED_STRING_MEMORY.md`.
See the [Intel combined manual](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf).

## Measured results

The predecessor is the copied installed `f7aaf59f9705` artifact. The candidate
is built from the source hashes in `VMP_DIRECTION_FLAG_MEMORY_EVIDENCE.json`.
Both measurements use the identical native binary and final probe. The baseline
switch changes probe expectations only. Owned measurements explicitly use
`CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64`; the production default remains 8. These
17-or-more-instruction fixture functions do not establish a default-depth
yield improvement. Ownerless inspection uses the existing 128-node bound.

| Measurement | Predecessor | Candidate |
|---|---:|---:|
| Exact owned conditions, 12 routines | 0 | 8 |
| Exact ownerless conditions, same routines | 0 | 8 |
| Unknown conditions retained per path | 12 | 4 |
| Production probe checks | 56 | 57 |

The eight recovered conditions cover forward/reverse MOVSB, forward/reverse
saved DF, literal POPF setting DF, equal-direction joins, and forward/reverse
STOSB. Unknown incoming DF, an unknown POPF value after CLD, conflicting DF
joins, and operand-prefixed CLD remain unresolved. Whole-IDB byte/mask,
head/owner, reference, function, comment and name inventories are identical
before and after each of the 12 ownerless inspections.

Patching the establishing CLD to STD revokes the preceding publication and
recomputes the opposite result. Restoration creates a new exact publication.
Count 9 and an external entry at REP revoke precision; restoring each input
recomputes the original fact. The disposable test IDB supplies fixture owners
and removes them for ownerless inspection; production does not force ownership.

The independent x86-64 fixture oracle executes 3,072 routine/input cases and
compares the result and all source/destination bytes against a separate C model.
Inputs cover both incoming DF values, both arguments, and 64 repetitions.
The portable repeated-memory suite performs 3,145,520 assertions. Its separately
compiled x86-64 execution oracle performs 38,400 actual REP executions and
3,375,920 repeated-memory assertions. The oracle checks full buffers, count,
index updates, DF and six status flags; the concrete byte-array model does not
use the production map, count enumerator or join operation. Direction domains
include unknown, known forward and known reverse, both address widths, all
element widths, overlap offsets, partial counts and unknown payloads. These
x86-64 processes run through macOS translation on the arm64 host; an independent
bare-metal x86-64 execution result is unknown.

All 22 CTest suites pass. Existing production dataflow regressions pass with
37,630 native/479 inspection checks on x86-64 and 36,350 native/412 inspection
checks on i386. The supplied `samples/foo_x86_vmp` control retains its measured
75 nodes, 77 edges and three unresolved facts with an unchanged inspection
inventory. No protected-corpus recovery gain is established by this checkpoint.

## Reproduction

Build the plugin with `cmake --build --preset native-release --parallel 20`.
Retain the predecessor artifact before that build. Compile and execute:

```sh
xcrun clang -arch x86_64 -O2 -mno-red-zone tests/vmp_native/direction.S tests/vmp_native/direction_main.c -o build/direction-native
build/direction-native
xcrun clang++ -arch x86_64 -std=c++17 -O2 -mno-red-zone -DCHERNOBOG_NATIVE_REPEAT_ORACLE -Isrc tests/x86_abstract_tests.cpp -o build/direction-repeat-native
build/direction-repeat-native
ctest --test-dir build --output-on-failure --parallel 8
```

Use `tests/run_ida_smoke.py` with input `build/direction-native`, probe
`tests/ida_direction_probe.py`, explicit `--ida` and `--plugin` arguments, a
fresh `--output-dir`, and `--set CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64`. Add
`--set CHERNOBOG_DIRECTION_BASELINE=1` only for the predecessor expectations.
The report is `direction.json`. Existing cross-architecture controls use
`tests/run_native_dataflow.py` and the pinned `chernobog-vmp-linux32:qemu9.2`
backend. Protected inspection uses `tests/ida_protected_region_inspect.py`
at root `0x1002946b5` with expectation `complete`.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | Normal completion under unchanged code; all memory facts depend on this scope. | Full-buffer concrete/native comparisons and opcode/count restoration. Faults, MMIO, interrupts and concurrent writes are outside the model and remain unknown. |
| A2 | DF definitions and the popped bit follow the admitted ISA encodings; all eight recovered conditions depend on this. | Bare FC/FD, saved forward/reverse, literal POPF, unknown popped value, prefixed CLD and conflicting/equal joins. |
| A3 | Bytes originate from writes in the selected replay; memory facts depend on this. | Fixture stores precede each read; unknown payloads, unknown source, invalid destination, width crossing and bounded-map eviction controls. Existing initial-image abstention regressions also pass. |
| A4 | Known DF restricts the admitted domain; helper precision depends on this. | All three DF domains against independent arrays and actual REP; a one-sided writable range admits forward and rejects reverse without mutation. |
| A5 | Captured ownership, incoming entries and source bytes remain current; owned publications depend on this. | Patch/revoke/restore DF, count 9, external entry, new publication identity, and 12 read-only ownerless inventory comparisons. |
| A6 | Configured scan depth and translation are part of these measurements; measured yield depends on this. | Same binary/probe at depth 64, source/artifact hashes and process receipts. Default-depth yield and bare-metal x86-64 confirmation are unknown. |

## Bounded opportunities and limits

- High impact: establishing a validated i386 segment-base contract could extend
  nonzero repeat precision. This checkpoint supplies no such contract.
- Medium impact: shorter witnesses or larger configured owned scan budgets can
  expose the new precision. A larger default budget requires separate coverage
  and resource measurements.
- Low impact: known DF halves direction replay alternatives for the finite
  helper. End-to-end performance improvement is not measured here.

## Quality gates

QG1 passes: architectural transfers and observations require no normative
claim. QG2 passes: A1–A6 identify dependencies and falsification probes. QG3
passes for this DF changeset; the complete review remains in progress. QG4
passes: byte units, dimensionless counts, bounds, counters and reproduction
commands are explicit. QG5 passes within A1–A6: negative controls, joins,
prefixes, count limits and invalidation/restoration are measured. QG6 passes:
the primary archive, sources, artifacts and process receipts are hash-pinned;
full reproducible build attestation remains unknown. QG7 passes: opportunities
and unresolved extensions are bounded above.
