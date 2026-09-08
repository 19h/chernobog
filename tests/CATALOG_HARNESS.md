# Standalone MBA catalog harness

`chernobog.mba_catalog` links the production AST, registry, rules and Z3 verifier
against the IDA SDK link library. It does not initialize IDA or Hex-Rays.

## Failure and correction

The macOS arm64 SDK library used in the 2026-09-08 investigation implements
`get_hexdsp` as a bare return instruction. Calling through its result is not a
valid decompiler operation. The observed SIGBUS stack was:

```text
invalid instruction address
AstNode::~AstNode
RuleRegistry::rebuild_storage_locked
RuleRegistry::initialize
main
```

The dispatch opcode was `hx_mop_t_erase` (`0x114` in this SDK). Retaining accepted
patterns or matcher fixtures does not cover a rejected pattern: its local AST is
destroyed during registry construction. The original rejected rule and rejection
reason are unknown. A solver timeout can reach this cleanup path, but the crash
alone does not establish that a timeout occurred.

The integrated harness based on `b3b5b03` uses the upstream
`tests/catalog_hexdsp.h`, force-included before SDK headers in every catalog
translation unit. It redirects `HEXDSP` to the C-linkage
`chernobog_catalog_hexdsp` function in `tests/catalog_tests.cpp`. Uniform
redirection keeps SDK inline definitions consistent across translation units and
avoids relying on `get_hexdsp` symbol interposition. The unused executable
`get_hexdsp` override was removed.

The redirected entry point accepts only `hx_mop_t_erase` on a nonnull `mop_t`
whose type is `mop_z`, calls `zero()`, and counts the operation. Every other opcode
or nonempty operand aborts with a diagnostic. The upstream repeated-destruction
and exception-unwind checks, ordinary matcher destruction, deliberate rule
rejection and registry clear all use this same entry point. Plugin targets do
not compile the test source or force-include its dispatcher header.

## Focused checks

Use an existing configured build with the intended SDK and architecture:

```sh
cmake --build build --target chernobog_catalog_tests -j 2
ctest --test-dir build -R '^chernobog\.mba_catalog$' --output-on-failure
```

CTest supplies the SDK library search path on macOS and Linux. The unchanged
catalog is checked first. Then the harness registers the deliberately invalid
rule `x + 1 -> x`, rebuilds the registry, checks its rejection, and clears all
counts. The focused build and CTest passed after integration with `b3b5b03` on
macOS arm64 (3.27 s reported total test time). All 13 catalog translation units
were checked in `build/compile_commands.json` for the same forced include. The
retained focused CTest log is
`/tmp/chernobog-catalog-b3b5b03-focused-ctest.log`.

| Check | Registered | Verified | Rejected | Result |
| --- | ---: | ---: | ---: | --- |
| Production catalog | 108 | 108 | 0 | Focused CTest passed |
| Catalog plus invalid rule | 109 | 108 | 1 | 108 stored patterns; cleanup counter increased |
| Registry clear | 0 | 0 | 0 | Zero stored patterns |

The implementation uses the measured initial catalog count for the second-phase
assertions and requires at least 100 initial rules; it does not hardcode 108.
An isolated executable built from the unmodified `b3b5b03` test source exited 1
despite printing the expected catalog and rejection counts: the upstream no-op
entry point bypassed the strict dispatcher's erase counter. Routing that entry
point through the strict implementation restores the counter assertion.

Historical verification before the upstream integration included three isolated
successful runs with the same counts.
The pre-rebase integrated CTest run passed all 10 entries in 8.28 s, including the
corrected catalog target; its historical retained log is
`/tmp/chernobog-cfstring-catalog-final-ctest.log`.

The focused guard controls call the current redirected entry point before normal
tests:

```cpp
chernobog_catalog_hexdsp(-1); // Aborts: unsupported catalog SDK operation: -1
```

```cpp
mop_t operand;
operand.t = mop_r;
chernobog_catalog_hexdsp(hx_mop_t_erase, &operand);
// Aborts: catalog SDK erase requires a nonnull empty operand
```

Both current controls terminated with SIGABRT (Python subprocess return code
`-6`) and the stated diagnostic. They were compiled with the test entry from
`build/compile_commands.json` and linked with existing catalog objects and the Z3
archive, without modifying shared build outputs. The baseline and current guard
sources, executables and `runs.json` are retained under
`/var/folders/m5/xcy1lpz12mb19rld1y8vxphh0000gn/T/chernobog-catalog-integration-hcil8912`.

## Deterministic baseline control

The pre-correction harness from commit `80c1444` was copied to a temporary source.
The same invalid rule was added and registered immediately before
`registry.initialize()`. Its rejected pattern reproduced SIGBUS independently
of any production-rule timeout. The isolated baseline reused the current native
catalog objects, changing only the test translation unit. LLDB confirmed the
destructor/registry stack above and opcode `0x114`.

Local investigation artifacts, outside the repository, were recorded under:

```text
/var/folders/m5/xcy1lpz12mb19rld1y8vxphh0000gn/T/
  chernobog-catalog-rejection-_8pvmc_j/  # Baseline source, executable, run.json
  chernobog-catalog-after-_e3xhlfq/      # Corrected executable, runs.json
  chernobog-catalog-guards-a8uyxpri/     # Guard variants, sources, runs.json
```

The baseline debugger command was:

```sh
lldb --batch \
  -o 'settings set target.env-vars DYLD_LIBRARY_PATH=/Users/int/dev/ida-sdk/src/lib/arm64_mac_64' \
  -o run -k bt -k 'register read x0 x1 x8 pc lr' \
  /var/folders/m5/xcy1lpz12mb19rld1y8vxphh0000gn/T/chernobog-catalog-rejection-_8pvmc_j/catalog_rejection_before
```

## Assumptions and scope

| Assumption | Stress test or falsification probe | Dependent result |
| --- | --- | --- |
| Catalog-only AST cleanup needs only empty-operand erasure. | Nonempty operands and unsupported opcodes abort; both guard branches were exercised. | The shim supports catalog destruction, not general microcode execution. |
| Every catalog translation unit receives the same dispatcher redirection. | Check the force-include flag in compile commands; require the erase counter to increase during rejection rebuild. | The upstream routing covers separately compiled AST/registry code; other host/compiler execution remains unverified here. |
| Every production rule proves within the CI correctness budget. | Initial verification requires all registered rules verified and zero rejected; resource exhaustion is tested separately. | Any rejection remains a normal test failure; this is not a runtime latency guarantee. |

The verifier's runtime default remains 250 ms (0.250 s) per solver check.
The standalone catalog target now uses a separate 10,000 ms (10 s) correctness
budget; the previous shared-budget failure and its reproduction are described
below. Both modes require the same equivalence proofs at 8, 16, 32, and 64 bits.
A timeout remains `UNKNOWN`, is never admitted, and still fails the catalog
test. The empty-operand guard also exposes future accidental dependencies on
nonempty SDK operands (medium impact). No production speedup is claimed.

## CI run 102: separate correctness from the runtime deadline

[Run 102](https://github.com/19h/chernobog/actions/runs/34187192158), at
`dd726bd540d3aa1c558c80fd49b7024e778741d4`, compiled all six platform targets.
Five jobs passed; macOS x86-64 failed only `chernobog.mba_catalog` with
`108 registered, 107 verified, 1 rejected`. This was a normal test failure,
not the earlier SDK-dispatch crash. The old test-specific registry build
suppressed rejection diagnostics, so the exact rejected CI rule and its reason
are unknown from that log.

The identified scheduling-sensitive failure mode is that a correctness test
requires every identity to prove within the runtime's 0.250 s deadline.
Profiling the unchanged verifier on macOS arm64 measured individual successful
proof intervals up to approximately 0.128 s. A controlled scheduling probe
then paused only its child test process for a nominal 80 ms after each nominal
20 ms running interval. This models lost execution opportunity; it does not
reproduce or measure the GitHub runner's exact load.

| Controlled probe | Production catalog | Deliberately invalid rule | Process exit |
|---|---|---|---:|
| Original 0.250 s budget, periodically paused | 98 verified; 10 `UNKNOWN (timeout)` rejections | Not reached | 1 |
| CI 10 s budget, periodically paused | 108 verified; zero rejected | Rejected; 108 stored patterns and cleanup counter increased | 0 |

The baseline logged timeouts for `Add_OllvmRule_3`,
`Add_SpecialConstantRule_1`, `Add_SpecialConstantRule_2`, `Add_FactorRule_1`,
`Sub_HackersDelightRule_3`, `Sub_HackersDelightRule_4`,
`Sub_SpecialConstantRule_1`, `Xor_HackersDelightRule_4`,
`Xor_HackersDelightRule_5`, and `Xor_SpecialConstantRule_1`.
These names identify the local controlled failures, not the unidentified CI
failure. Both executions used the same catalog and bundled Z3 4.16.0 library;
the baseline registry additionally printed per-rule timings. This is a
functional deadline test, not a performance comparison. Retained outputs:
`/var/folders/m5/xcy1lpz12mb19rld1y8vxphh0000gn/T/chernobog-ci102-paused-y5mugn02/results.json`.

The final full native build and all 11 CTest targets passed; the catalog
target took 3.12 s within a 7.56 s suite run. Compiler-command inspection
confirmed the test macro is present only in catalog objects, not plugin
objects. Logs: `/tmp/chernobog-ci102-final-build.log` and
`/tmp/chernobog-ci102-final-ctest.log`.

The fix changes only the standalone registry's timeout selection. Plugin
targets do not define `CHERNOBOG_CATALOG_TEST` and still construct the default
0.250 s verifier. Test rejections now print the rule name, verification status,
operand width, and solver reason to stderr. Aggregate and cleanup failures also
print their failing state.

An optional Z3 resource limit supports a scheduling-independent exhaustion
control. At resource limit 1, the existing `Sub_HackersDelightRule_3` identity
must return `UNKNOWN`, include a reason, and remain unverified. Additional
controls require an unsupported opcode to remain `UNSUPPORTED` and require
`2^32 == 0` to be disproved specifically at 64 bits, despite equivalence after
truncation to 8, 16, and 32 bits. The deliberately invalid `x + 1 -> x` rule
still exercises actual registry rejection and destruction. No retry or
acceptance of `UNKNOWN` is introduced. Resource limit zero leaves Z3's resource
policy unchanged; the optional limit is unused by production callers.
Parameter semantics follow the [primary Z3 documentation](https://microsoft.github.io/z3guide/programming/Parameters/).

| Assumption | Stress test / falsification probe | Scope |
|---|---|---|
| A1: Lost execution time can cause valid proofs to exceed the old deadline. | Periodically paused baseline rejects ten rules with explicit timeout reasons. | Reproduces the failure class; exact CI rule and scheduler state remain unknown. |
| A2: The CI correctness budget allows the supported catalog to finish. | Full catalog and rejection rebuild pass both normally and with the pause schedule. | Finite 10 s per solver check; more severe stalls can still fail, with diagnostics. |
| A3: Resource exhaustion cannot certify a rule. | Resource-limit-1 control requires `UNKNOWN` and `verified() == false`. | Tested with pinned Z3 4.16.0; no wall-clock race is used to force the result. |
| A4: The larger budget does not alter bit-vector semantics or runtime policy. | Same AST translation/solver/admission code; counterexample and unsupported controls; plugin compile flags omit the test macro. | Runtime default remains 0.250 s; CI is not a production latency assertion. |

For `R` catalog rules and AST size `N`, the added diagnostics and policy
selection contribute `O(R)` operations and `O(1)` auxiliary state; AST
translation remains `O(N)` per width, excluding map costs and SMT solving.
SMT complexity is unchanged and no polynomial solving-time bound is claimed.
The budget conversion is exact: `10,000 ms × 10^-3 s/ms = 10 s`; both the
solver timeout and pause intervals are scheduling-dependent wall-clock limits,
not calibrated execution-time guarantees. High-impact finding: catalog
correctness was coupled to runtime availability. Medium-impact finding:
suppressed diagnostics made ordinary proof rejections resemble prior crashes.
QG1–QG7 apply to the bounded observations and assumptions above.
