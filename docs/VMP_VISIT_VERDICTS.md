# Repeated-visit verdict coverage and solver failure diagnostics

The native-observation quota tests previously asserted visit, attempt and query
counts without checking every retained semantic verdict. Two completed queries
can yield a counterexample or an unresolved second query as well as
corroboration. Counts alone therefore did not establish the stated repeated-visit
correctness coverage.

The tests now check each of the first 16 retained visits for its expected verdict,
two queries and a check identity. Every remaining retained visit must be explicitly
unchecked due to the attempt budget and must have no query count or check identity.
This covers 17-visit x86/x64 contiguous and split paths and the 130-visit row-cap
fixture, of which 128 visits are retained.

A negative fixture changes one output GPR on the ninth dispatch. Its 17 rows,
16 attempts and 32 queries are unchanged, while exactly that attempted visit
must report a modeled counterexample. All other attempted visits must remain
corroborated. This demonstrates why query counts cannot substitute for verdicts
and exercises the separation of repeated visits.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| D1 | Each retained visit has its own semantic verdict. | Corrupt only the ninth dispatch output in each architecture/path fixture. Require a counterexample only at that visit and unchanged aggregate counts. |
| D2 | Test failures preserve enough local evidence to distinguish an abstention from a mismatch. | Deliberately fail a resource-exhaustion assertion and a repeated-visit verdict assertion in separate diagnostic copies. Inspect their exit status, query counts and returned reasons. |
| D3 | A passing run establishes correctness only for its exercised assertions and runtime. | Preserve the earlier failed logs, source hashes and budget settings; do not infer their cause from a later successful run. |

## Diagnostics and validation

Transition-test failures now include the check index, mode, candidate bounds,
direction, key register, stack-dispatch flag, configured timeout/resource limit,
elapsed call time in microseconds, query count, returned result and reason, plus
input/output registers and ordered data accesses. Native-projection failures
include the most recent projection's dimensions, elapsed call time, quotas and
each retained visit's identity, verdict, query count and reason. The diagnostic
labels say "last" because an assertion may concern an earlier stored result.

The solver limits remain 100 ms and 200,000 resource units per query. The explicit
exhaustion control retains its 1 ms/one-resource-unit settings. No assertion is
relaxed and no automatic retry is introduced. These changes affect tests only;
production transition checking and its rejection behavior are unchanged.

The final full CTest run passes 20/20 suites in 11.07 s, including 1,328 transition
checks and 362 native-observation checks. The latter count is exactly
`94 + 4 * (17 + 1 + 17) + 128 = 362`. The build and language formatter checks pass.
Source, binary and artifact hashes are recorded in
[VMP_VISIT_VERDICTS_EVIDENCE.json](VMP_VISIT_VERDICTS_EVIDENCE.json).

The preceding lifecycle checkpoint's two full-suite failures remain historical
failures with unknown causes. Their assertions did not capture the decisive
solver results. This successful run does not establish that those failures were
timeouts or that the suite is insensitive to host load. A separate intermediate
run with diagnostics alone also passed 20/20 in 10.92 s; it is not the final
source checkpoint used for the strengthened coverage claim.

Reproduce the accepted test suite with:

```sh
cmake --build build --target chernobog_vm_transition_tests \
  chernobog_vm_native_observation_tests -j 2
ctest --test-dir build --output-on-failure -V -j 1
clang-format --style=file --dry-run --Werror \
  tests/vm_transition_tests.cpp tests/vm_native_observation_tests.cpp
```

The two deliberate failures use copies under `build/`, linked against the same
production objects. One reverses the expected result of the existing explicit
resource-exhaustion control; the other demands corroboration for the deliberately
corrupted ninth visit. Both must exit 1 and emit the corresponding result and
reason. They are diagnostic controls, not failed accepted regression runs.

## Scope and quality gates

Diagnostic retention costs O(G + A) for G scalar registers and A data accesses
in the transition test, and O(V) records for V retained native visits, excluding
bounded string serialization. The repeated-verdict checks are O(V) time and
O(1) extra working space. All these inputs retain their existing fixture bounds.

- **High:** aggregate solver activity does not prove semantic success. Benchmark
  consumers must inspect per-result verdicts before counting corroboration.
- **Medium:** historical failure causes and behavior under broader host-load
  conditions remain unknown. The original evidence is retained.
- **Medium:** these local fixtures do not establish full-handler semantics,
  protected-corpus completeness or persistent logical VM identity.

QG1: technical test/evidence scope. QG2: D1–D3 and explicit probes. QG3: verdict
coverage and actionable failure records supplied; the complete review remains
open. QG4: units and check counts explicit. QG5: counted queries cannot mask a
wrong expected visit verdict. QG6: source and artifacts hash bound. QG7: limits
and adjacent benchmark implications stated.
