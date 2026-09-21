# Typed MBA instances and observed canonicalization failures

Chernobog now proves the actual typed value expression before accepting a
catalog replacement, chain fold, or optional affine reconstruction. The catalog
theorem remains the first filter; it no longer substitutes for checking the
instantiated operands and conversions. A bounded bottom-up walk also reaches
identities exposed beneath a conversion by later Hex-Rays optimization.

The motivating observed failure was the x64 fixture's 32-bit carry expression:

```text
xdu.8(add.4(or.4(x, y), and.4(x, y)))
    -> xdu.8(add.4(x, y))
```

The inner result still wraps at 32 bits before zero-extension. Earlier code
matched only the outer `xdu` at this stage and missed the existing ADD rule.
The matched x64-width variant already simplified. No new algebraic identity
was needed. The retained initial captures show this discrepancy; final paired
captures verify the change with the same input, plugin, probe and IDA hashes.

This advances review 4a/4b. The ten native routines are independent x64 fixtures,
not VMP-emitted or protected programs. Source-emitted/held-out protected coverage,
other architectures, and complete instruction/flag/exception benchmarks remain
incomplete. The full implementation goal remains active.

**Source and scope**

The review's local primary references remain relevant:
`vmp/core/intel.cc:17336–17536` maintains/restores register and stack state and
optimizes operand forms in the native obfuscation path; it does not establish
that this independent corpus represents all generated shapes. Existing
`rules_and.h`, `rules_or.h`, and `rules_add.h` supply the identities used here.
The SDK defines typed microcode operands, explicit extension/extraction
operations, instruction properties, and ownership of stack/local references.
The inspected SDK's `lvar_ref_t` and `stkvar_ref_t` include a parent `mba_t`;
the new proof therefore includes that owner in local/stack symbol identity.
Hashes are in [VMP_MBA_EVIDENCE.json](VMP_MBA_EVIDENCE.json).

| Component | Change |
|---|---|
| `rules/rule_verifier.*` | A separate `verify_instance` path translates original/proposed microcode directly, preserving every supported operand/result width |
| `rules/pattern_rule.cpp` | Builds the replacement off-tree and returns it only after the instance proof succeeds |
| `analysis/chain_simplify.cpp` | Constructs each proposed fold on a copy; swaps it into the live instruction only after proof |
| `handlers/mba_simplify.cpp` | Applies the same check to emitted affine microcode; visits supported value trees bottom-up with explicit budgets |
| `plugin/idc_api.cpp` | Adds process-local verified/disproved/unsupported/unknown instance counters to `chernobog_rule_stats()`; resets them with rule statistics |

Paths in this table are relative to `src/deobf`, except `plugin/idc_api.cpp`,
which is relative to `src`. Diagnostic counters are atomic, transient, and
aggregate attempts, including repeated decompilation. They do not establish
unique recovered-expression counts or persistent evidence freshness. A snapshot
or reset concurrent with other work need not represent one atomic epoch.

**Typed proof contract**

The supported language consists of integer `mov`, `bnot`, `neg`, `add`, `sub`,
`mul`, `and`, `or`, `xor`, `xdu`, `xds`, `low`, and `high`, with explicit operand
widths of 1–8 bytes. Arithmetic/bitwise inputs must match the result width.
Extension and extraction have separately checked source/result widths; an
implicit narrowing or widening is rejected. Numeric leaves are truncated to
their declared width. Register, global, stack and local leaves are keyed by
kind, exact identity and width; stack/local identities also include their
owning microcode object. AST hashes and printed operand names are not used as
proof identities.

The two trees share one symbolic input map at one program point. Different
register widths and potentially overlapping storage ranges are independent
symbols unless their exact keys match. This can reject a valid rewrite that
requires alias relations; it cannot use an unproved alias relation to accept
one. No reaching definition or memory value is propagated across instructions.
Different snapshots must remain different register/value operands, as in the
intervening-write fixtures.

Nested calls, indirect loads/stores, unsupported operators, undefined values,
floating/aggregate operands, and barred/persistent/assertion instructions reject
the proof. Scalar global/stack/local leaves are ordinary stable values within
one admitted value expression. Concurrent mutation, volatile-access elision,
fault equivalence, MMIO semantics, and proof across an intervening write are
outside that contract. The enclosing instruction's destination is preserved by
each production caller; the verifier itself certifies the result value, not
arbitrary destination or control-flow changes.

```text
collect supported value nodes in postorder, before any mutation
reject a cycle, shared ownership anomaly, or collection-budget failure
for each node, children before parent:
    build a proposed simplification separately
    translate original and proposal with their actual widths
    reject unsupported effects, identities, widths, or translation budgets
    if simplified equality is true: accept
    otherwise solve original != proposal:
        UNSAT -> accept
        SAT -> reject: counterexample exists
        UNKNOWN -> reject: retain the solver reason
    commit only the accepted proposal, keeping the original destination
```

Collection admits at most 256 instruction nodes and depth 64. Translation has
a joint budget of 512 operand/instruction visits and depth 64 across both trees.
The normal solver timeout is 250 ms; deterministic resource-limit exhaustion is
tested separately. The timeout applies to the solver query, not all allocation,
translation, simplification, or function-wide work.

Collection costs O(N log N) time and O(N) space using the visited-node set.
Translation/identity construction costs O(D) expected map work for each proposal,
with bounded-width terms; repeated subtree proposals may sum to O(N²) visits.
SMT search is a separate bounded attempt, with no polynomial-time claim. The
new validation does not establish a function-wide latency or peak-memory bound.

**Captured corpus and failure classification**

Each production run captures `MMAT_GENERATED`, `MMAT_PREOPTIMIZED`,
`MMAT_LOCOPT`, and `MMAT_GLBOPT1`, followed by ctree. Plugin-disabled and enabled
copies use identical fixture/plugin/probe/IDA artifacts. The disabled run is a
Hex-Rays baseline, not a different original executable.

| Fixture | Classification and observed result |
|---|---|
| `mba_demorgan32` | Existing identity/recognition: the baseline retains NOT/OR; the enabled pass produces AND with an instance proof |
| `mba_carry32` | Rewrite ordering/nested recognition: the identity appears under `xdu` at GLBOPT1; the new traversal simplifies its inner 32-bit ADD and preserves extension |
| `mba_carry64` | Existing same-width recognition: OR+AND becomes ADD; no new identity |
| `mba_stack32` | Reaching definitions and existing recognition: Hex-Rays resolves the independent stack inputs; Chernobog simplifies the exposed expression, without introducing memory propagation |
| `mba_truncate8` | Width conversion control: 8-bit addition still truncates before extension |
| `mba_extend_not` | Width conversion control: byte NOT before zero-extension remains distinct from wide NOT |
| `mba_not_extend` | Width conversion control: NOT after zero-extension preserves its high one bits |
| `mba_alias_write` | Intervening full-width write: original load, store, and later load remain semantically distinct; result is the old/new XOR |
| `mba_alias_partial` | Partial alias write: the low-word update changes only two bytes; return and final cell are checked independently |
| `mba_order32` | Rewrite ordering: Hex-Rays removes the redundant XOR pair; Chernobog simplifies the remaining carry identity |

This corpus establishes a concrete nested-recognition miss and its fix. It does
not establish a missing algebraic identity or implement general cross-block
reaching-definition recovery. Unsupported proof shapes retain the original
expression. Existing source and fixture categories remain visible instead of
being counted as successful protected-code recovery.

**Validation and independent oracles**

| Evidence | Measured scope |
|---|---|
| CTest | 13 suites pass, including the existing 108-rule catalog and deliberately false catalog-rule rejection |
| Typed instance controls | 25 checks: 8/16/32/64-bit carry identities/counterexamples, explicit truncation, signed/unsigned extension, low/high extraction, distinct reaching values, implicit-width rejection, undefined/floating values, memory barriers, nested stores, cycle bounds, separate frame owners, and resource exhaustion |
| Native executable | 70,656 comparisons across ten x64 routines, with seed values `0x390fe14891` and `0x9827136ab5`, corner cases, and all 65,536 byte-add input pairs |
| Independent captured-IR interpreter | 70,656 result/memory cases for each of the disabled and enabled GLBOPT1 captures; 141,312 total |
| Production probe | Ten unchanged-native-byte assertions in each run; five additional checks that enabled positive routines actually invoke the typed verifier |
| String regression | The existing rotate/add/XOR production fixture checks byte/word recognition and freshness under the changed shared MBA pipeline |

The native harness compares declared 32/64-bit function results and both alias
fixtures' final cells. The independent Python interpreter checks the complete
64-bit return register and the four-byte observable cell for each captured
case. It models little-endian byte-addressed registers and memory, rejects every
unhandled opcode, and does not call the production translator or Z3. Both
recorded seeds are exercised after implementation; neither is represented as a
strictly sequestered held-out seed. These finite oracles do not prove all native
flags, exceptions, stack effects, or protected-program behavior.

The 25 standalone instance checks use a narrow SDK shim for instruction
initialization and allocation-free cleanup; they do not substitute for the
production decompiler runs. Conversely, passing the production probe alone
does not prove semantic equivalence: its captures are separately interpreted.
The new corpus adds no assertion that the supplied protected hello-world has
been recovered.

Reproduction:

```sh
cmake --build build --target chernobog chernobog_catalog_tests -j 4
ctest --test-dir build --output-on-failure
clang -arch x86_64 -isysroot "$(xcrun --sdk macosx --show-sdk-path)" -O1 \
  tests/vmp_native/mba_shapes.S tests/vmp_native/mba_shapes_oracle.c \
  -o build/vmp-mba-shapes
build/vmp-mba-shapes
```

Run `tests/run_ida_smoke.py` twice using `tests/ida_mba_shapes_probe.py`, the
configured IDA/plugin locations and separate output directories. Set
`CHERNOBOG_DISABLE=1` in the baseline and `CHERNOBOG_EXPECT_MBA_PROOFS=1` in the
enabled run through the runner's `--set` argument. Then run:

```sh
python3 tests/verify_mba_shapes.py BASELINE_ARTIFACT_DIRECTORY ENABLED_ARTIFACT_DIRECTORY
```

**Assumptions, falsification probes and bounded expansion**

| ID | Assumption and dependent results | Probe |
|---|---|---|
| M1 | The captured SDK microcode represents the supplied native fixture; all production conclusions depend on this | Hash input/SDK/tool artifacts, retain four maturity stages, execute the native oracle and compare independently interpreted output/memory |
| M2 | Pure scalar leaves describe one stable value snapshot; all instance proofs depend on this | Reject effectful nested trees and barrier/undefined properties; verify full and partial intervening writes retain old/new values |
| M3 | Explicit bitvector widths encode the intended conversions | Counterexamples for lost truncation and crossed NOT/extension; exhaustive native and captured-IR byte-add cases |
| M4 | Frame-local values are interpreted in the same owning microcode object | Equal-offset different-owner unit control disproves cancellation; ownership participates in proof identity |
| M5 | The independent fixture and tested IR subset are bounded evidence, not a complete protected corpus | Treat unhandled interpreter instructions as failures; retain architecture, source-emission, flags, exception and performance coverage as incomplete |

High impact: a valid uniform-width identity can be invalid after an incorrectly
placed extension; the instantiated proof closes that acceptance gap. Medium
impact: optimization maturity can expose an existing rule too late for a root
matcher, so capture ordering before adding identities. Medium impact: the
direct-microcode proof makes AST hashing an indexing/matching aid rather than
an equality oracle. Low impact: stricter effect/operator admission can reduce
coverage; each extension needs its own typed semantics and tests.

QG1: technical scope only. QG2: M1–M5 have falsification probes. QG3: the bounded
4a/4b implementation and corpus are verified; the full requirements remain in
progress. QG4: comparisons are exact integers; byte widths, bit widths and
elapsed seconds are separate. QG5: unsupported memory/ISA/lifecycle claims are
explicit. QG6: local primary sources and executable/capture hashes are recorded.
QG7: adjacent opportunities and limits are bounded above.
