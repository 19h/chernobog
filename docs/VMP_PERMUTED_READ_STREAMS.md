# Permuted exact-read stream reconstruction

The temporal projector now reconstructs a heap string when exact executed
reads at one instruction site cover one contiguous byte interval in an
out-of-address-order permutation. It retains each original fragment in
execution order, sorts only the captured bytes by address for UTF-8 validation,
and uses the lowest-address fragment as the semantic anchor. A completed
candidate requires one terminal NUL, no embedded NUL, no duplicate address or
hole, one allocation generation, a complete temporal/data capture, and no
write overlapping the candidate span. Disjoint writes inside that allocation
remain admissible under the existing 256-write scan bound. Global barriers
still end the group. The existing adjacent forward projector remains the
publisher for ascending streams.

The evidence table's `address` is the reconstructed span start;
`first_sequence` and `last_sequence` reflect actual execution order. Each
bounded `fragments` entry now reports `site:sequence:address:size`, making the
address permutation auditable. The IDC `first_sequence` likewise refers to the
first executed fragment, even when the semantic anchor executed later.

## Independent observations

The native fixture reads `secret!\0` in offset order
`3,1,6,0,7,2,5,4`. Its process oracle assembles the scalar from the actual
reads, then compares against a separately encoded expected value. The positive
and disjoint-write variants exit 0; changing only the expected oracle to zero
exits 1. `strings` finds no literal `secret!` in the positive binary. The
portable evidence suite accepts the permutation with two run-specific heap
addresses and rejects duplicate address, missing byte, embedded NUL, and a
write into a future byte. It retains the candidate for a disjoint same-object
write. All 21 CTest suites pass.

Three isolated IDA 9.4 SP1 profiles ran the same probe with exact plugin hashes.
The prior plugin publishes zero candidates for the positive binary. The
modified plugin publishes one `secret!` candidate in four of four completed
returned runs, with eight exact read fragments per run and one transient ctree
annotation at the indexed byte-read expression. The disjoint-write variant
has the same result. Each profile passes nine checks, including byte-preserving
inspection, no stored user comments, and removal/restoration of the displayed
value when the key byte is patched/restored. Source, binary, plugin, tool and
raw-report hashes are recorded in `VMP_PERMUTED_READ_STREAMS_EVIDENCE.json`.

The same C fixture compiled for native arm64 also passes its independent
process oracle (positive exit 0, corrupted expected value exit 1). An isolated
IDA profile using the prior plugin publishes zero candidates; the installed
plugin publishes one `secret!` candidate with eight fragments in each of four
completed runs and one indexed-read ctree annotation. Both profiles pass the
same nine checks. These arm64 profiles use the exact binary and prior-plugin
hashes recorded for their matched comparison.

Reproduce the positive binary and modified-plugin profile:

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-unroll-loops \
  -D_FORTIFY_SOURCE=0 -Wl,-no_fixup_chains -Wl,-no_data_const \
  tests/vmp_native/native_permuted_strings.c -o build/vmp-permuted-reads
python3 -B tests/run_ida_smoke.py build/vmp-permuted-reads \
  tests/ida_permuted_read_stream_probe.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_COUNT=1 --output-dir build/vmp-permuted-reproduction
```

## Assumption register

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| P1 | The exact read snapshots and data events cover every byte of the consumed string. The reconstructed value depends on this. | The native scalar oracle and corrupted expected-value control are independent of publication. Missing/duplicate addresses and embedded NUL reject. A falsely complete ledger with an omitted read could invalidate this result. |
| P2 | Allocation ID and generation represent one live object over the read interval. Candidate identity depends on this. | The existing lifetime and release/reuse regressions reject cross-generation streams. Global lifetime boundaries close permuted groups. |
| P3 | Relevant writes are recorded with exact intervals. Safe continuation depends on this. | An overlapping future-byte write rejects; a disjoint same-object write passes. Unknown, wide, crossing and >256 intervening writes retain the existing abstention path. |
| P4 | The same site, anchor occurrence, fragment shape and UTF-8 value recur across runs. Publication depends on this. | Four-run IDA observation and two-run portable consensus check this exact shape. Changing the read permutation between runs can change anchor occurrence and cause abstention. |
| P5 | Current IDB bytes and the consumed key match the evidence. Ctree display depends on this. | Key patch/restoration, function-byte equality and absence of stored comments are checked in every IDA profile. |

The spatial continuity check compares `last - first + 1` byte addresses with
the byte-map size; every inserted address is unique. The capture limit is
4,096 bytes per group and 4,096 use snapshots per run. In a run with `U` reads,
`B` captured bytes and `W` intervening writes, map construction costs
`O(B log B + U log U)`, with up to `O(256U)` bounded write examination;
additional memory is `O(U + B)`. These are byte and event counts, so no unit
conversion is needed.

**High impact:** indexed and permuted heap byte reads now yield a directly
auditable string at their actual ctree read expression on x86-64 and arm64.
**Medium impact:** read order that changes anchor occurrence across runs,
noncontiguous spatial sets, stack/image permutations, other architectures and
unknown memory effects still abstain;
the fragment display format gains an address field. **Low impact:** the
additional per-run grouping is bounded by existing snapshot/use limits.

QG1: no normative premise. QG2: P1–P5 have falsification probes. QG3: this
permuted-read requirement has portable, native process, prior-plugin,
modified-plugin, UI and regression evidence; the wider review remains open.
QG4: byte spans, event limits, complexity and exact counts are specified.
QG5: duplicate, hole, internal NUL, write and lifetime boundaries are
accounted for. QG6: local source, binaries, tool and raw reports are hashed;
no external claim is required. QG7: adjacent supported and unsupported shapes
are bounded above.
