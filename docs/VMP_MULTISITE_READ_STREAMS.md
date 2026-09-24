# Exact heap strings read at multiple instruction sites

The native read-stream projector now groups executed heap reads by allocation
generation and context, as well as by individual instruction site. It retains
the allocation-wide group only when at least two source sites actually read
the same contiguous byte span. The existing single-site and forward-stream
paths remain available. Every accepted group has distinct observed byte
addresses, a terminal NUL, no interior NUL, a valid allocation lifetime, and
no write intersecting its completed span. The cross-run shape is ordered by
byte address; source fragments retain execution order, exact sites and
occurrences. Consensus requires equal recovered UTF-8 values and compatible
source shapes across all eligible runs.

Hex-Rays can merge one branch's indexed read away while retaining the other
branch's expression. For each candidate, the ctree annotator considers the
anchor and only fragment sites present in **every** eligible run. It attaches
the value to one surviving `cot_ptr` or `cot_idx` expression at an exact site.
A candidate is annotated at most once per decompilation. No image bytes or
stored user comments are changed.

## Independent observations

The native fixture fills one 32-byte heap object with an encoded eight-byte
`secret!\0` and reads offsets in two schedules selected by an ABI argument:
`3,1,6,0,7,2,5,4` and `7,6,5,4,3,2,1,0`. Its independent encoded scalar
oracle yields process exit 0 on x86-64 and arm64. Changing only the expected
scalar yields exit 1 on each architecture. The x86-64 positive image has no
`secret!` entry in `strings`. The final x86-64 binary has two executed byte-load
instructions at `0x100000610` and `0x100000637`.

The archived prior plugin and modified plugin were run against the same
architecture-specific binary and probe in isolated IDA 9.4 SP1 databases.
The prior plugin reports zero candidates. The modified plugin reports one
`secret!` candidate across all four x86-64 or six arm64 complete runs. Each
run contributes eight fragments from exactly two sites; the first-read offsets
include 3 and 7 on both architectures. Hex-Rays omits the lowest-address
anchor read expression, retains a different exact fragment-site expression,
and displays exactly one transient annotation. The probe also checks no final
image strings, no saved comments, unchanged function bytes, immediate display
revocation after a key edit, and restoration after reverting that edit. All
four matched profiles pass 10/10 checks. The earlier fixed-order and
variable-order x86-64/arm64 probes each pass 9/9 checks with the modified
plugin. The portable evidence test passes its positive case and rejects an
unrelated same-allocation read and a changed source site. All 21 CTest suites
pass.

Exact source, fixture, tool, plugin and raw-report SHA-256 values are recorded
in `VMP_MULTISITE_READ_STREAMS_EVIDENCE.json`. The paired binary hashes refer
to the tested executable bytes; rebuilding Mach-O can change its `LC_UUID`
even when the fixture source and executable instructions are unchanged.

Reproduce the x86-64 fixture and a fresh modified-plugin profile:

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-unroll-loops \
  -D_FORTIFY_SOURCE=0 -Wl,-no_fixup_chains -Wl,-no_data_const \
  tests/vmp_native/native_multisite_strings.c -o build/vmp-multisite-reproduction
python3 -B tests/run_ida_smoke.py build/vmp-multisite-reproduction \
  tests/ida_multisite_string_probe.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_COUNT=1 \
  --output-dir build/vmp-multisite-reproduction-ida
```

## Assumption register and bounds

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| M1 | The complete temporal ledger contains the executed reads, allocation events and relevant writes. Reconstruction depends on this. | The probe checks complete captures for every run; the independent process oracle and wrong-oracle binaries check the fixture. An omitted read or write despite a complete flag would falsify the result. |
| M2 | A contiguous, unique byte span within one allocation generation is one candidate stream. Publication depends on this shape. | The portable case inserts an unrelated read 24 bytes from the start and rejects the resulting hole. Duplicate, interior-NUL and overlapping-write controls remain in the preceding projector regressions. Multiple independent streams in one allocation can conservatively abstain. |
| M3 | The anchor site's first occurrence and address-ordered source shape identify the same use across runs. Consensus depends on this. | Alternating read schedules keep the anchor occurrences 2 and 4; changing one source site in the second run rejects consensus. Additional same-site reads before the stream can cause abstention. |
| M4 | An exact fragment site common to every eligible run represents the candidate when its anchor ctree expression is merged away. Display depends on this. | The probe enumerates surviving `cot_ptr`/`cot_idx` EAs, proves the anchor absent and exactly one fragment site present, checks one annotation, then edits/restores the key. A decompiler that removes all exact read expressions yields no annotation. |
| M5 | The archived prior plugin and modified plugin are the only changed profile input in each matched comparison. The before/after observation depends on their recorded identities. | Both profiles record identical fixture, IDA and probe hashes per architecture; their plugin hashes and raw reports are retained. Other binary or decompiler versions are unmeasured. |

For `U` retained read snapshots and `B` observed bytes in one run, insertion
into the two ordered group indexes costs `O(U log U + B log B)` time and
`O(U + B)` additional space, excluding the existing bounded write scan.
Spatial shape sorting costs `O(U log U)` time and `O(U)` temporary space.
`U <= 4,096` snapshots per run and each group holds at most `4,096` bytes;
the existing run-wide byte limit also applies. These counts are events and
bytes, not SI physical quantities. Ctree common-site intersection costs
`O(F log F)` per run for `F` fragments, bounded by the recorded stream.

**High impact:** two-site indexed heap reads can now reach evidence-backed
consensus and transient ctree display on both measured architectures.
**Medium impact:** holes, duplicate reads, changed source shapes, overlapping
writes and absent exact ctree expressions continue to prevent publication or
display. Protected-sample recovery rates remain **unknown**. **Low impact:**
each accepted read enters one additional bounded grouping index.

QG1: no normative premise. QG2: M1–M5 contain falsification probes. QG3:
portable, independent process, paired-plugin, ctree and regression evidence
cover this multisite change; the full review remains open. QG4: byte/event
limits, counts and asymptotic bounds are explicit. QG5: malformed spans and
missing ctree witnesses abstain. QG6: local primary source, exact binaries,
plugins, IDA and raw reports are hashed. QG7: unsupported stream shapes,
decompiler output and additional work are bounded above.
