# Bounded repeated string memory

This checkpoint addresses the local memory part of review row 1 and the current
edge measurements in row V. Natural-address REP MOVS/STOS can preserve memory
facts when every compatible count is at most eight. It also preserves zero-count
STOS facts on i386. The complete review remains in progress.

## Implementation and scope

`and_constant` preserves register known bits after an immediate AND, including
partial aliases and the zero extension of a 32-bit destination in long mode.
For a count word with known mask `K`, value `V` and address-width mask `A`,
the largest compatible count is `(V & K & A) | (A & ~K)`. A largest count above
eight rejects the finite model; no compatible input is discarded. Enumeration
then includes every `c` satisfying `(c & K & A) == (V & K & A)`.

`repeat_string_memory` replays each compatible count for both DF values on a
copy of the locally established byte map. Each MOVS iteration reads before
writing, including overlaps with preceding iterations. Each STOS iteration
uses the accumulator slice. Unknown payloads erase the destination element.
The output contains only identical known bytes across every replay. A zero
count contributes the unchanged input map. Unknown destination or a failed
destination-range check rejects the complete domain without modifying input.

The production adapter runs before generic implicit-write invalidation.
It requires matched implicit operands, natural address size, no segment
override, REP without REPNE or LOCK, and supported element width. Nonzero
memory precision requires long mode, where the ordinary DS/ES bases are zero.
i386 nonzero repeats retain the existing abstention because this API receives
no segment-base contract. Zero repeats access no memory, advance no index and
preserve the abstract stack. Nonzero repeats conservatively discard the abstract
stack and affected index values. Normal completion sets the count to zero.
The six tracked status flags and unrelated registers remain unchanged.

Only preceding local writes establish bytes; initial writable-image bytes
remain unknown. The map retains at most 128 bytes. Memory faults, MMIO,
asynchronous writes, interrupted partial execution and whole-program reachability
are outside this normal-completion contract. Unsupported encodings receive no
new precision; this checkpoint does not establish exception equivalence.

With `N <= 9` count values, `D = 2` directions, `C <= 8` iterations,
`B <= 8` bytes per element and `M <= 128` retained bytes, time is
`O(N D (M + (C B + M) log M))`, with `O(M)` auxiliary space. Addresses and
memory spans are measured in bytes; count is a dimensionless iteration count.
Between iterations address arithmetic wraps at the selected address width;
an individual element crossing that width boundary is rejected.

Architectural basis: Intel SDM revision 090, MOVS (Vol. 2B 4-105), REP
(Vol. 2B 4-563–4-564), STOS (Vol. 2B 4-676–4-678), and AND. The local
source archive and its hash are recorded in the evidence JSON. The
[Intel combined manual](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)
specifies count-controlled repetition, the DF-selected increments/decrements,
unchanged status flags and implicit source/destination registers.

## Paired observations

The copied installed predecessor is revision `76f01f4c282f`, plugin SHA-256
`b4604bdaa9f4e2d1d056301907aa0133e92b72b2946cf4a62baf88d53c2a5730`.
The measured candidate has SHA-256
`45999878d9c431d3cf5bd0ba838d97a8c9c1078c68e2aa3cc99abe556f2ba6b0`.
Both use the final, source-pinned probes; the predecessor switch changes probe
expectations only. All four paired native binaries are byte-identical.
Build receipts distinguish predecessor source `7c5bd2e72fff` from candidate
source `474708741fd4`; both report SDK 940. Live source hashes in predecessor
reports identify measurement inputs, not its earlier plugin build sources.

| Architecture and path | Prior/current scalar edges | Prior/current exact covers | Current false edges |
|---|---:|---:|---:|
| x86-64 owned | 42/50 → 44/50 | 45/47 → 47/47 | 0 |
| x86-64 ownerless | 42/50 → 44/50 | 45/47 → 47/47 | 0 |
| i386 owned | 33/50 → 33/50 | 36/47 → 36/47 | 0 |
| i386 ownerless | 33/50 → 33/50 | 36/47 → 36/47 | 0 |

Both new scalar edges are the existing disjoint REP MOVS/STOS targets whose
count is `ECX & 1`. Three dynamic sites retain exact two-member covers and
remain scalar abstentions. All 15 concrete-only sites abstain on each row.
Every profile passes 60 capture mutations and seven attribution mutations.

The version-3 contract preserves the version-2 native assembly, driver
semantics, labels, 44 fixed sites, three dynamic sites and 15 excluded sites.
It separately pins the updated probes/runners and the unchanged version-2
scoring helpers. Historical contracts, evidence and source hashes are unchanged.

## Verification and counterexamples

- Portable checks enumerate all `3^8 = 6,561` low-byte count domains under
  32-bit and 64-bit counts, and independently check masked-register bits.
  The final portable repeat group passes 1,480,534 assertions.
- A separate x86-64 build executes 19,200 real REP cases and passes 1,595,734
  repeat assertions. It compares entire 512-byte buffers, count, SI/DI changes,
  DF and six status flags against an independent byte-array machine. Cases
  cover four element widths, both directions, zero through eight iterations,
  partial count domains, overlap in both directions, self-copy, unknown payloads
  and disjoint retained bytes. Its deterministic seed formula exercises 49
  incoming status profiles. `-mno-red-zone` prevents inline PUSHF/POPF from
  overlapping compiler red-zone locals. Execution uses macOS translation on
  the arm64 host; physical x86 equivalence is unknown.
- Portable negative controls reject count nine, unknown high count bits,
  unknown destination, an invalid destination in one DF direction, unsupported
  count width and an element crossing the address boundary. Unreadable source
  loses the written byte. Capacity eviction remains bounded to 128 bytes.
- Production probes patch the count mask to 0, 7, 8, 9, 15 and back to 1 for
  both roots, architectures and paths. Bounds eight retain eligible facts;
  masks admitting nine or more revoke them; restoration recreates proofs.
  Zero STOS gains a proof on both architectures. Each ownerless inspection
  checks unchanged IDB inventory; owned checks inspect actual user edges.
  Per profile, owned probes pass 479/412 assertions and ownerless probes pass
  1,840/1,790, totaling 4,521 production assertions.
- Existing complete native drivers pass 147,960 primary checks per profile
  across four original binaries, plus 9,212 auxiliary ownerless checks. Four
  corrupted driver processes reject their deliberate wrong expectations.
- The relational/SDK regression passes 82,952 native checks, 2,026 production
  assertions and 280 independent generated-IR effect checks. All 21 CTest
  suites pass without retry. The protected VMP initializer passes 8/8 checks
  in each profile and retains 75 nodes, 77 edges and three unresolved facts.

The first candidate failed the two intended production gains because register
AND discarded masked-out known bits. That candidate's reports remain under
`build/vmp-bounded-repeat-current-owned` and `build/vmp-bounded-repeat-current-ownerless`;
they are not acceptance evidence. The final accepted run includes the AND fix
and reexecutes all final probes on the same native inputs for both profiles.

## Reproduction

```sh
cmake --build build --parallel 20
build/chernobog_x86_abstract_tests
xcrun clang++ -arch x86_64 -std=c++17 -O2 -mno-red-zone \
  -DCHERNOBOG_NATIVE_REPEAT_ORACLE -Isrc tests/x86_abstract_tests.cpp \
  -o build/repeat-native-reproduction
build/repeat-native-reproduction
python3 -B tests/run_native_dataflow.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/repeat-owned-reproduction \
  --linux32-image chernobog-vmp-linux32:qemu9.2
python3 -B tests/run_ownerless_dataflow.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/repeat-ownerless-reproduction \
  --linux32-image chernobog-vmp-linux32:qemu9.2 --edge-oracle-driver
python3 -B tests/score_native_edge_benchmark_v3.py \
  --owned-report build/repeat-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/repeat-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$(xcrun --find llvm-nm)" --output-dir build/repeat-score-reproduction
```

Use fresh output directories. For the pinned predecessor, add
`--bounded-repeat-baseline` to both measurement commands. This changes
expectations only. Reports contain child-process elapsed seconds and peak
resident bytes, including startup; they do not measure isolated IDA resource
use or establish a timing improvement.

## Assumption register and bounded expansion

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| S1 | Facts describe flat, unchanged-code normal completion with ordinary memory. All recovered targets depend on this. | Replay both DF values and every count; reject incomplete domains and invalid destination spans; patch/restore source bytes; retain fault and asynchronous execution as outside scope. |
| S2 | Nonzero string-memory addresses use ordinary long-mode DS/ES bases. New nonzero memory precision depends on this. | Require long mode, natural addressing and no segment override; i386 nonzero cases abstain while zero repeats preserve facts. |
| S3 | Local writes, known-bit masks and independent native contracts correctly specify the selected fixtures. Measured coverage depends on this. | Enumerate 6,561 partial domains, independently decode exact PUSH/RET bytes, require byte-identical paired binaries, compare full native buffers and reject 67 scoring mutations per profile. |
| S4 | Recorded artifacts and tools identify the tested implementation. Paired attribution depends on this. | Pin SHA-256 values, distinguish plugin receipts from live measurement sources, verify source and artifact hashes after execution and rerun the installed plugin. Physical x86 results remain unknown. |

- Medium impact: masked register bits can bound memory effects elsewhere;
  unbounded counts and unknown destination aliases still require abstention.
- Medium impact: overlapping repeated copies need sequential reads, rather than
  a single bulk copy; the concrete and native overlap checks cover this distinction.
- Low impact: partial count domains can include zero and prevent establishment
  of a new byte even when every nonzero replay stores the same value.

## Quality gates

QG1: no normative content is required. QG2: S1–S4 list dependencies and probes.
QG3: this bounded string-memory changeset and its paired controls are covered;
the complete review remains in progress. QG4: byte spans, bit widths, count
domains and complexity are reproducible. QG5: count overflow, missing aliases,
zero access, overlap and the initial failed production gains have explicit
controls. QG6: primary ISA source and source/artifact hashes are recorded.
QG7: bounded opportunities and precision limits are identified above.
