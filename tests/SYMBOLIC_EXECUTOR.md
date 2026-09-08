# Recurrence state and temporary feasibility queries

The production symbolic executor now exposes two operations needed to distinguish
entry facts from facts that hold on every loop iteration:

- `invalidate_all_values()` removes current register and memory bindings from
  both executor and translator caches. It retains path assumptions and the
  monotonically increasing symbolic-name counter. A later read receives a fresh
  value; a constraint on an earlier value cannot constrain it accidentally.
- `check_feasibility_with(condition)` checks the persistent path assumptions
  together with one temporary Boolean condition. It does not retain that
  condition. A foreign Z3 context, empty AST, or non-Boolean condition returns
  `unknown`.

The caller must prove any recurrence invariant before restoring it after
invalidation. In particular, proving that a register survives calls does not
prove that ordinary loop instructions never write it.

## Example and algorithm

For an unsigned 64-bit selector `s`, the condition `s > 7` can be feasible even
when `s <= 7` is also feasible. A successful query for the continuation alone
does not establish that the other edge is unreachable. A transformation that
removes that other edge requires an UNSAT result for it:

```text
execute(entry)
save only independently proved invariant values
invalidate all current bindings
restore proved invariants
model an incoming case and execute its body
require SAT(path)
require UNSAT(path AND unsigned_selector > 7)
```

The final two requirements are distinct. An inconsistent path cannot establish
reachability, and SAT of one successor does not establish exclusivity. Unknown
solver results do not establish either requirement.

With `E` executor bindings and `T` translator cache entries, invalidation visits
`O(E + T)` container entries and uses `O(1)` additional container storage.
Destruction of the associated Z3 expression graphs may have additional cost.
Each feasibility query resets the solver and adds `A` stored assumptions plus
at most one temporary condition: `O(A)` API submissions. SMT solving time and
internal memory depend on the formulas and are not bounded by this container
analysis. These operations introduce no new machine-word arithmetic.

## Reproduction and observations

```sh
cmake --build build --target chernobog_symbolic_executor_tests
ctest --test-dir build -R '^chernobog.symbolic_executor$' --output-on-failure
```

The target compiles the actual
[executor implementation](../src/deobf/analysis/z3_solver.cpp) and links the
configured Z3 library. The SDK shim only erases storage-free register/global
operands; unsupported SDK operations and database fallbacks abort.

The [22 assertions](symbolic_executor_tests.cpp) cover fresh register and memory
values, retained entry constraints, isolated SAT and UNSAT queries, invalid
queries, independently restored invariants, guard-edge exclusivity, and
infeasible paths remaining infeasible after invalidation. Running the same
executable with `--memory-only-control` substitutes the previous memory-only
invalidation and fails four assertions. This control tests the missing register
invalidation directly.

On 2026-09-08 the focused CTest passed. A separate compilation of the actual
executor and test translation units with AddressSanitizer and
UndefinedBehaviorSanitizer also passed; the retained result is
`/tmp/chernobog-symbolic-executor-sanitized/run.json`. Leak detection was disabled
for that run. This test covers the state/query API, not arbitrary microcode
translation or a complete decompiler transformation.

## Assumption register and boundaries

| Assumption | Falsification probe | Dependent result |
|---|---|---|
| S1: Fresh symbolic names remain distinct across invalidation. | Constrain the entry value to 7, then require later values 8 and 9 to remain independently feasible. | Recurrence values do not inherit entry constraints. |
| S2: Temporary conditions do not alter stored assumptions. | Alternate contradictory temporary queries, then check persistent feasibility. | Independent guard-edge queries. |
| S3: Path assumptions must survive value invalidation. | Invalidate an inconsistent path and require it to remain infeasible. | No resurrection of impossible paths. |
| S4: The SDK shim is sufficient only for the constructed operand subset. | Abort on every other dispatch operation or owned operand. | Standalone API-test attribution. |
| S5: Restored invariants are proved by the caller. | The recurrence fixture changes a formerly constant register during a later iteration. | Sound use by the recurrent-switch handler; the API alone supplies no invariant proof. |

High-impact boundary: retaining mutable entry-register values can produce an
incorrect loop-transition proof. High-impact boundary: selecting a feasible
successor without excluding the other can remove a feasible loop. Medium-impact
limitation: these API tests do not validate the complete instruction translator.
Low-impact limitation: no latency improvement is inferred from these tests.

Provenance is the linked production implementation, configured Z3 dependency,
installed SDK declarations, and executable assertions. QG1–QG7: descriptive
content; assumptions S1–S5 have explicit probes; both APIs and their failure
boundaries are covered; operand widths and operation bounds are explicit;
temporary and persistent constraints are distinguished; provenance is local
and reproducible; impact-labeled scope boundaries are stated.
