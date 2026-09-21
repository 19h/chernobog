# Actual SMT queries in the evidence workspace

The requirement-5 workspace now records actual production Z3 checks and shows
their formulas, results, assignments and provenance in **SMT queries**. It
operates independently of rax captures and native proof records. Complete
recorded formulas can be replayed by the standalone test verifier. A SAT
assignment to a mismatch query is a counterexample to that symbolic candidate;
it is not automatically a source-level or ABI-level input.

This checkpoint extends `VMP_NATIVE_EVIDENCE_VIEW.md`. Earlier manifests retain
their historical source hashes. The current checkpoint is attributed by
`VMP_SOLVER_EVIDENCE_VIEW_EVIDENCE.json`; it does not complete requirement 5 or
the full review ledger.

## Capture and interpretation

`src/common/solver_evidence.hpp` wraps the existing single `solver.check()`.
It records SAT, UNSAT or UNKNOWN, solver version, check-only elapsed nanoseconds,
query role, explicitly supplied parameters, and bounded formula/model detail.
UNKNOWN retains its reason and has no model. UNSAT has no model. Parameters
not supplied by a caller are explicitly uncaptured. A serialization or collector
exception cannot change the solver result, introduce assertions or initiate a
second check. An exception from `solver.check()` itself still propagates to
the existing caller and is not recorded as a completed query.

Scopes identify database context, function, instruction when known, microcode
maturity and callback phase. Instrumented phases are optinsn, optblock,
preoptimized and global optimization. Nested typed-instance and predicate
producers refine the instruction address. Queries without an active scope are
not attributed; callbacks outside these phases are not claimed as covered.
Simplifier-only equality proofs do not fabricate an SMT check. The current
direct C++ `.check()` call sites all pass through the wrapper.

Roles include typed MBA replacement mismatch, catalog identity mismatch,
bitvector equivalence, unique-value existence/exclusion, path or predicate
feasibility, Jcc feasibility, and coefficient/expression samples. Samples do
not authorize an affine replacement; its mismatch must remain UNSAT. Predicate
classification also now requires both polarities to be SAT before reporting
input dependence; a remaining UNKNOWN result preserves uncertainty.

`chernobog_solver_evidence(ea)` returns the retained transcript.
`chernobog_solver_state(ea)` returns matching scope and only query identities
and current source-navigation guards, avoiding periodic formula/model copies.
Inspection does not execute the analyzed program, rerun the solver or mutate
the IDB. The GUI shows literal SMT-LIB newlines, typed assignments and full
diagnostics, and preserves detail scroll position during polling.

Each query and function generation has a monotonic identity within one loaded
plugin instance. A new MBA generation replaces that function's transcript.
Database-host removal discards its log. Exhausted identities become zero and
cannot admit current navigation. The GUI rejects a different database,
function, generation or missing query identity.

The source guard compares the captured instruction bytes (at most 16 bytes)
and its current function owner. Matching bytes permit navigation only. They
do not revalidate all formula dependencies, SSA definitions, assumptions or
the current IR. Restoring bytes can restore navigation to a historical query;
it cannot promote the query into a current rewrite proof. No SMT result adds
a CFG edge. Capture and viewing do not enqueue model inputs for native replay.

## Bounds and complexity

The collector retains at most 16 functions per database, evicting by first
admission order, and 128 queries per function. The database payload cap is
4,194,304 bytes of map key/value text. Counts expose omitted queries and evicted
functions. This is not a total heap-memory bound: container overhead, multiple
open databases and temporary serialization allocations are additional.

Formula admission allows at most 64 assertions, 512 AST tree occurrences,
depth 64, Boolean/bitvector sorts up to 64 bits and printable ASCII identifiers
up to 128 bytes. Arrays and quantifiers are omitted. Complete SMT-LIB is
materialized after that guard; at most 16,384 bytes are retained, with an
explicit completeness flag. The prefix limit does not bound the temporary
Z3 serialization string. SAT capture attempts at most 32 model constants and
reports omitted constants/functions; UNKNOWN reasons retain at most 512 bytes.
JSON control-byte escapes preserve exact formula newlines. This is not an
arbitrary-Unicode serialization contract.

For A admitted AST occurrences, M attempted constants and F emitted formula
bytes, observer traversal/format work is O(A + M + F), excluding solver and Z3
serialization internals. No polynomial solver-time claim follows. Full
inspection copies O(K + P) retained records/payload, with K<=128; compact
polling copies O(K) fields and checks at most 16K instruction bytes, excluding
IDA ownership lookup costs. Retained text is capped per database; maximum
latency and total process peak memory remain unmeasured. Reported `elapsed_ns`
measures the solver check, not observation, serialization or GUI overhead.

## Assumption register and verification

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| S1 | Z3 serialization describes the actual completed query. Formula replay depends on this. | Replay complete SAT/UNSAT formulas in a separate Z3 process; reject disagreements or malformed replies. The verifier accepts trusted producer artifacts, not arbitrary hostile SMT scripts. |
| S2 | Captured typed assignments satisfy that formula. Counterexample display depends on this. | Assert every retained complete assignment and require SAT; alter an independently constrained assignment and require UNSAT. |
| S3 | Observation must not influence solver behavior. | Unit checks preserve assertions, push/pop, SAT/UNSAT results and models; a throwing collector cannot change the result. UNKNOWN/resource exhaustion has a reason and no borrowed model. |
| S4 | A retained identity is immutable within the loaded plugin instance. Navigation depends on this. | Reject foreign database/generation, patch an instruction, restore it, and decompile anew. C++ unload/reload, rebase, undo and multiple live databases remain outside the completed GUI matrix. |
| S5 | Source-byte correspondence is weaker than current-query applicability. | The API and GUI expose this distinction explicitly; no query-derived CFG edge or automatic native input is published. Whole dependency freshness remains unverified. |
| S6 | Independent x64 arithmetic fixtures exercise these production paths. | Nonlinear fits produce actual SAT mismatches; a valid linear identity produces UNSAT. Two native fixed-input checks pass. Protected-program, x86 and exhaustive input coverage are not inferred. |
| S7 | Truncation must remain visible. | Unit tests exceed AST depth, formula bytes and model count. Database function/record/payload caps are implemented but their full saturation matrix has not yet been executed. Incomplete formulas are not replayed. |

`tests/z3_tests.cpp` exercises the observer directly. The fixture
`tests/vmp_native/solver_queries.c` reaches actual production MBA queries with
the optional affine pass enabled. `tests/ida_solver_evidence_probe.py` inspects
the real IDC API, source guards, generation replacement, exact formula
newlines, optional Qt widgets and scrolling. `tests/verify_solver_evidence.py`
independently replays complete formulas and assignments using a separately
hashed Z3 executable. This is process/build independence, not solver-family
diversity. It does not replay elapsed time or reproduce resource-limited UNKNOWN.

Reproduce with installation artifacts supplied through local shell variables:

```sh
cmake --build build -j 2
ctest --test-dir build --output-on-failure
python3 -B tests/run_ida_smoke.py build/vmp-solver-queries \
  tests/ida_solver_evidence_probe.py --ida "$IDA_TERMINAL" --plugin "$PLUGIN" \
  --output-dir build/solver-inspection-terminal --set CHERNOBOG_MBA_AFFINE=1 \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py"
python3 -B tests/verify_solver_evidence.py \
  build/solver-inspection-terminal/solver_evidence.json \
  --output build/solver-inspection-terminal/replay.json
```

Build the C fixture as x86-64 Mach-O with `-O1 -g0` and the macOS SDK. The GUI
variant uses `IDA_GUI` and `QT_QPA_PLATFORM=offscreen`. Each run needs a fresh
output directory. Rax is disabled for these query probes. Exact run counts,
source/artifact hashes, companion correspondence and regression results are
recorded in the manifest.

The final C++ build passes 13/13 CTest targets (13.88 s in that single run,
not a latency benchmark). The final companion passes 21 terminal and 28 GUI
query checks, plus 47 native-proof GUI and 31 lifetime-workspace GUI regression
checks. Each query probe captures 26 complete formulas: 25 SAT and one UNSAT.
Standalone replay confirms all 26 results and all 25 assignments, including
six SAT mismatch counterexamples; the altered-assignment control is UNSAT.
These are 26 queries per run of the same fixture, not 52 distinct formulas.
The production fixture contains no UNKNOWN outcome; that path is covered by
the resource-limited observer unit test. Predicate UNKNOWN classification has
no separate production-fixture test at this checkpoint.

## Bounded expansion and quality gates

| Impact | Finding | Consequence |
|---|---|---|
| High | A satisfying sample can coexist with a SAT mismatch to the proposed generalization. | Display samples and exclusion queries with their distinct roles. |
| High | Matching one instruction's bytes does not establish current SSA/dependency equivalence. | Historical formula validity and source navigation are separate properties. |
| Medium | UNKNOWN was previously classified as input dependence when neither polarity was UNSAT. | Require two SAT results for that classification; retain uncertainty otherwise. |
| Medium | Polling large immutable formulas repeats avoidable copies and can reset reading position. | Poll identities/source guards and retain the displayed formula and scroll state. |

QG1: no normative premise. QG2: assumptions and falsification probes are above.
QG3: this checkpoint covers bounded actual-query inspection; full ledger
completion is not asserted. QG4: exact Boolean/bitvector values, byte limits and
nanosecond measurements are distinguished. QG5: capture failures, unsupported
sorts, incomplete transcripts and applicability/lifecycle limits are explicit.
QG6: local production source and independently executed artifacts are hashed.
QG7: bounded adjacent findings are listed. Recovery rates, protected-example
coverage, maximum-size responsiveness and total peak memory remain unknown.
