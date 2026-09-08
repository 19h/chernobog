# Static instruction budget and cancellation

Before this change, exhaustion of `CHERNOBOG_RAX_MAX_STATIC_INSNS` stopped only
the inner physical-instruction loop. IDA decoding and cross-reference projection
continued to the end of the current function chunk, despite producing no further
records. A 65,537-head live fixture with a cap of 64 therefore reported
`IDA_heads=65537 physical=64`.

The adapter now exits head and chunk traversal once truncation is established.
It permits one successful IDA decode after exhaustion to distinguish omitted
instructions from an exact-cap function followed only by data or undecodable
heads. That lookahead does not project cross-references or call rax/SMIR.
Exhaustion inside an IDA macro stops immediately, since unprocessed physical
components already establish truncation.

Cancellation polling now counts head visits and macro components rather than
successful IDA decodes. Data tails, undecodable heads, and large macro heads can
therefore reach the next poll. Coverage output includes `static_truncated=1`
when the retained static denominator is incomplete. `physical=64/64 (100%)`
with this flag describes those 64 records.

## Assumption register and falsification probes

- S1: A successful IDA decode supplies a positive instruction size. The counted
  interface fixture tests traversal; the full SDK build and live probe check
  the actual adapter integration. The shim does not prove ABI compatibility.
- S2: Exact-cap completion retains its previous meaning. Tests include trailing
  data, failed decodes, empty chunks, zero budget, non-address-ordered chunks,
  and both partially consumed and exact-cap AArch64 macro heads.
- S3: The cap limits retained canonical records. At most cap + 1 successful IDA
  decodes and cap projected heads occur; failed decode attempts and trailing
  data visits remain possible. This is not a hard bound on all IDA operations.
- S4: A cancellation poll occurs every 256 combined head/component work steps,
  including the initial step. This bounds polling frequency, not time spent
  inside a single decoder, cross-reference, or SMIR call. Tests cancel at the
  initial poll, inside data/failed-decode tails, and inside a large macro.
- S5: The live straight-line fixture isolates work after budget exhaustion.
  Performance on production functions, different caps, platforms, and IDA
  versions remains unknown. Use the same probe, input, and configuration
  identities when comparing artifacts; the runner records them in `run.json`.

## Reproduction

The standalone suite compiles production `static_analysis.cpp`, decoder policy,
program-model core, and SMIR negotiation against a counted IDA interface:

```sh
python3 tests/run_static_analysis_tests.py
python3 tests/run_static_analysis_tests.py --sanitize
git show e31f3ed:src/hybrid/static_analysis.cpp > /tmp/chernobog-old-static-analysis.cpp
python3 tests/run_static_analysis_tests.py --static-analysis-source /tmp/chernobog-old-static-analysis.cpp
```

The final command must fail: the previous source violates the tail-work and
cancellation assertions. In the 10,000-head standalone fixture, cap 2 produces
exactly three IDA decode calls, two cross-reference projections, two rax decodes,
and two SMIR calls. The suite also checks sorted output and field preservation.
The baseline source uses the earlier byte-copy input window; well-formed loaded
fixture bytes keep that difference irrelevant to traversal assertions.

The live fixture supports native AArch64 and x86-64 Clang/GCC builds:

```sh
cc -O0 tests/static_analysis/budget_fixture.c -o /tmp/chernobog-static-budget-fixture
python3 tests/run_ida_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax --output-dir /tmp/chernobog-static-budget-run --set CHERNOBOG_RAX_MAX_STATIC_INSNS=64 --set CHERNOBOG_RAX_MAX_INSNS=64 --set CHERNOBOG_RAX_EXPLORE_RUNS=1 --set CHERNOBOG_RAX_MAX_CALLSITE_INPUTS=0 --set CHERNOBOG_RAX_IMPORT_SUMMARIES=0 --set CHERNOBOG_RAX_SMIR=0 --set CHERNOBOG_RAX_DREFS=0 --set CHERNOBOG_RAX_RUNTIME_STRINGS=0 /tmp/chernobog-static-budget-fixture tests/ida_static_budget_probe.py
```

`static_budget.json` records four synchronous exploration durations in
nanoseconds. They include snapshot construction, static analysis, entry planning,
the bounded emulation job, evidence construction, and reporting. They exclude
IDA launch, autoanalysis, function-item counting, and artifact preparation.
The first call may include initialization costs; retain it separately from the
three subsequent calls. This timing measures an actual plugin action, not just
the static traversal loop.

## Live measurements and validation

On 2026-09-08, native arm64 macOS, Apple Clang 21.0.0 Release plugin and IDA SDK
9.40, three alternating baseline/modified process pairs produced the following
times. Each process performed four explorations. No local builds or other test
jobs ran during these final pairs; host scheduling/frequency and system caches
were not controlled. Ranges are observed minima/maxima, not confidence intervals.

| Measured interval | Baseline median (range), s | Modified median (range), s | Median ratio |
|---|---:|---:|---:|
| First exploration, 3 observations | 0.0478 (0.0466–0.0497) | 0.0191 (0.0187–0.0195) | 2.50× |
| Subsequent exploration, 9 observations | 0.0463 (0.0450–0.0477) | 0.0178 (0.0173–0.0186) | 2.61× |
| Entire IDA process, 3 observations | 3.30 (3.28–3.87) | 3.19 (3.14–3.25) | 1.04× |

For subsequent calls, 46,260,792 ns × 10⁻⁹ s/ns = 0.046260792 s, and
17,751,458 ns × 10⁻⁹ s/ns = 0.017751458 s. Their quotient is 2.6060…,
rounded to 2.61×. The nine within-process observations are not nine independent
process samples. The process interval includes IDA startup and autoanalysis;
its small observed difference is not evidence of a general startup speedup.

All four explorations in every baseline process reported `IDA_heads=65537`
and `physical=64`; every modified exploration reported `IDA_heads=65`,
`physical=64`, and `static_truncated=1`. Execution outcome, retained coverage,
and memory/context counters matched across each paired process after removing
only the new truncation field. The input, executed probe, IDA, and configuration
digests were identical across all six reports, with passing artifact integrity
checks and zero runner/process exit codes.

Artifacts are retained at `/tmp/chernobog-static-budget-{before,after}-final-0N`
for N = 1, 2, 3, with an aggregate at
`/tmp/chernobog-static-budget-results.json`. SHA-256 identities:

- Baseline plugin: `6bc6117f8c97cd95522f584bbae4e43cca024ae13f80f86f61a966daa4d05e28`.
- Modified plugin: `2880bea68c13e2887b687dccd729c0668d6d15ef76da682a6a042e5607cfa1ad`.
- Fixture: `7ca77ff608423db69f7ac52f8d32396713736eb9eb5ea6f08333de51725831e0`.
- Probe: `8fb9a71c465c23954eadb350ca16aecdad586f1eb586ebe0b16c9b2a4016eba9`.
- Configuration: `6df90e3aa663d9c2026d1ff8ae1916909c76142ad630f0dffb829615da79efb0`.

The baseline artifact was saved immediately before this traversal/coverage
change and includes the earlier hashing, evidence, and Unicode improvements.
It is not the unmodified `e31f3ed` plugin. The modified build source fingerprint
is `5313df6db15b`; benchmark binaries were held fixed across the pairs.

The full native build and all eight CTest entries passed (4.52 s total).
Counted-interface tests also passed ASan/UBSan; the old source failed nine
assertions. The rebuilt plugin passed the existing live UTF-8 probe (repeated
uncached literal recovery, context invalidation, unchanged bytes and protected
metadata) and Aldaz automatic-decompilation probe (11 expected literals and
stable materialized bytes on repeated decompilation). Their logs are retained
in `/tmp/chernobog-static-budget-utf8` and `/tmp/chernobog-static-budget-aldaz`.
These correctness probes ran after final timing, concurrently with each other;
their process durations are not comparison measurements.

The local linker still warns that libida targets macOS 15.0 while the project
targets 13.3. Successful execution here does not establish macOS 13.3 or native
Windows/Linux compatibility. The interface shim tests traversal semantics;
the native live tests provide the separate IDA integration evidence.

## Complexity and bounded implications

For H visited heads and C retained canonical instructions, traversal work remains
O(H + C), plus projected cross-reference collection/sorting and final O(C log C)
record sorting. Dense decodable tails after the first omitted instruction are
no longer visited. Auxiliary output storage remains O(C), plus cross-reference
and SMIR effect storage. Cancellation uses O(1) state.

- High impact correction: the configured cap stops unnecessary main-thread
  decoder and cross-reference work on long decodable tails.
- Medium impact correction: cancellation polling covers sparse/undecodable tails
  and macro components; coverage exposes its truncated denominator.
- Medium impact limitation: snapshots still copy the mapped image, and proving
  exact-cap completion may still scan remaining nondecodable heads.

Primary provenance is the production adapter, counted interface tests, and
retained live artifacts. Quality review requires successful current-source tests,
a failing baseline, explicit timing boundaries, consistent units, and disclosure
of S1–S5 before interpreting measurements as evidence of improvement.
