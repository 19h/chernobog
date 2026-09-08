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

The test executable now overrides `get_hexdsp` with a restricted dispatcher. It
accepts only `hx_mop_t_erase` on a nonnull `mop_t` whose type is `mop_z`, calls
`zero()`, and counts the operation. Every other opcode or nonempty operand aborts
with a diagnostic. Matcher fixtures use ordinary destruction, and the test also
clears the registry. Only `tests/catalog_tests.cpp` defines this override; plugin
targets do not compile that file.

## Focused checks

Use an existing configured build with the intended SDK and architecture:

```sh
cmake --build build --target chernobog_catalog_tests -j 2
ctest --test-dir build -R '^chernobog\.mba_catalog$' --output-on-failure
```

CTest supplies the SDK library search path on macOS and Linux. The unchanged
catalog is checked first. Then the harness registers the deliberately invalid
rule `x + 1 -> x`, rebuilds the registry, checks its rejection, and clears all
counts. Observed results on macOS arm64, with three isolated executions:

| Check | Registered | Verified | Rejected | Result |
| --- | ---: | ---: | ---: | --- |
| Production catalog | 108 | 108 | 0 | Exit 0 in all three runs |
| Catalog plus invalid rule | 109 | 108 | 1 | 108 stored patterns; cleanup counter increased |
| Registry clear | 0 | 0 | 0 | Zero stored patterns |

The implementation uses the measured initial catalog count for the second-phase
assertions and requires at least 100 initial rules; it does not hardcode 108.
The final integrated CTest run passed all 10 entries in 8.28 s, including the
corrected catalog target; its retained log is
`/tmp/chernobog-cfstring-catalog-final-ctest.log`.

Two isolated source variants also called the dispatcher before normal tests:

```cpp
catalog_dispatcher(-1); // Aborts: unsupported catalog SDK operation: -1
```

```cpp
mop_t operand;
operand.t = mop_r;
catalog_dispatcher(hx_mop_t_erase, &operand);
// Aborts: catalog SDK erase requires a nonnull empty operand
```

Both terminated with SIGABRT (Python subprocess return code `-6`). These variants
were compiled with the catalog entry from `build/compile_commands.json` and
linked with the existing catalog objects and Z3 archive; shared build outputs
were not modified.

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
| The executable override intercepts SDK calls from separately compiled AST/registry code. | Native arm64 build, ordinary fixture destruction, rejection rebuild and registry clear all complete. | Confirmed for this host/linker; other host/linker behavior is unverified. |
| Every production rule proves within the production budget. | Initial verification requires all registered rules verified and zero rejected. | Any rejection remains a normal test failure. |

The verifier's default budget remains 250 ms (0.250 s) per solver check, and its
fail-closed behavior is unchanged. A timeout is neither converted to acceptance
nor hidden by a larger test budget. Under load, a valid rule may therefore still
fail the catalog test; this correction removes the SDK-stub crash on its cleanup
path. Impact: the same guard also exposes future accidental dependencies on
nonempty SDK operands (medium). No production semantic change or speedup is
claimed.
