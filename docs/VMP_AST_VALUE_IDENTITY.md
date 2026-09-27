# AST operand snapshot identity

This checkpoint advances review rows 4a, 4b and V. The AST cache and repeated
pattern-variable comparison now distinguish SDK operand snapshots by value
number, operand properties and stack/local frame owner. It preserves the full
SDK operand size. This establishes a component identity correction; protected
simplification yield and complete review implementation remain in progress.

## Identity contract and implementation

The primary contract is the SDK `hexrays.hpp`: `mop_t` has an 8-bit `oprops`,
16-bit `valnum` and signed `int size`. Value number zero denotes unknown;
equal value numbers denote equal values. Different numbers do not establish
unequal runtime values. `lvar_ref_t` and `stkvar_ref_t` retain their parent
`mba_t`; a local index or stack offset alone does not identify that frame.
The header hash is pinned in `VMP_AST_VALUE_IDENTITY_EVIDENCE.json`.

`MopKey` previously omitted these properties and frame identity, and narrowed
size to an unsigned 16-bit field. It now retains them in its hash, equality
and ordering. Exact scalar field comparison distinguishes the tested scalar
keys even when their final hashes are deliberately made equal. Nested hashes
also include source operand metadata, destination value number/properties
and instruction properties. Frame addresses are transient process identities;
they are neither serialized proof identities nor dereferenced by the key.

`mops_equal_strict` checks type, full size, value number and properties before
its existing leaf comparisons. Stack/local references require the same frame
owner. Nested instructions require equal opcode and instruction properties,
then recursively compare destination, left and right operands. Explicit loads
also require the same source EA. Address operands use the same recursive
comparison. Calls and unsupported operand kinds retain conservative rejection.
This avoids delegating nested metadata equality to SDK instruction comparison.

The comparison admits depth at most 64 and at most 512 operand-pair visits.
Exceeding either bound returns false. A cycle reaches the depth bound; a large
balanced tree reaches the visit bound. These outcomes reject a pattern binding
and do not certify value inequality. Comparison cost is
`O(min(T, 513))` calls and `O(min(D + 1, 66))` call frames for a comparison with
`T` visited operand pairs and nesting depth `D`, excluding helper/string byte
comparisons. The rejecting call may be visit 513 or depth 65; these bounds
include that call. Text comparisons retain their existing linear text cost.

The measured key size is 64 bytes, previously 32 bytes, with 32-byte alignment.
The increase is `64 - 32 = 32` bytes per key and `64 / 32 = 2` times the prior
key size. For `N` live keys, the key payload increase is `32 N` bytes; container
and allocator costs are additional and unmeasured. Lookup remains expected
`O(1)` under the existing hash-container assumptions; adversarial collisions
can require `O(N)` comparisons. Recursive key construction retains its existing
tree traversal and nesting behavior; this change does not add a hash recursion
budget.

Composite keys still summarize nested operands with hashes. Their equality is
an index decision, not a collision-free semantic proof. The independent typed
instance verifier remains the acceptance gate for actual replacements. Its
existing scalar identities already include value number and frame owner, and
its effect admission remains unchanged. No previously accepted unsound rewrite
is established by these measurements. This checkpoint adds neither reaching
definitions across instructions nor an alias, ordering or hardware-fault proof.

## Source-control counterfactual

The current test source is compiled against the exact predecessor AST sources
from revision `f534cbdc2caa836f25b03fdb4399fe65332e696a`. The source-control
binary stops at the leaf identity test: 1,184 failures in 1,232 checks, exit 1,
and a measured 32-byte key. This is a component source control, not an execution
of the predecessor plugin. The remaining linked catalog objects are unchanged
components; the early return prevents their later tests from running.

The corrected catalog binary passes all 1,247 checks with a 64-byte key.
The 1,232 leaf checks cover widths 1, 2, 4 and 8 bytes; register, global,
stack and local operands; value numbers 1 and 65,535 versus zero; each property
bit and the combined byte; distinct frame owners; widths separated by 65,536;
positive identity; cache separation; and forced final-hash collisions. Fifteen
additional checks cover nested metadata, explicit-load EA identity, a cycle and
balanced-tree comparison budgets. Dummy frame pointers are never dereferenced.
Borrowed SDK payloads are cleared before fixture destruction.

All 108 registered catalog rules verify. The deliberately false 109th rule
rejects. The 190 typed controls retain 25 verified, 18 disproved, 146 unsupported
and one unknown initial result, with quota/reset controls passing. All 22 CTest
suites pass. The failing counterfactual attributes the omitted identity fields
at component scope; it does not measure protected recovery gain.

## Production evidence

The candidate plugin runs all 40 original/mutation/virtualization/combined
profiles across x86-64 and i386, with seeds 0, 1 and 12,648,430 and paired
enabled/disabled transformations. The native engine is enabled in the 20
transformation-enabled processes. All processes pass; 602 corrupted captures
are rejected. The independent preservation audit retains 152 native rows,
456 SDK stage outcomes and 454 typed CFG captures. Two outcomes remain SDK
refusals. All 456 complete matching diagnostics also match the recorded
constraint-binding matrix from revision `266d59e9`.

That complete matrix reference precedes two native REP checkpoints. A separate
fresh reserved-seed i386 combined run executes the actual immediately preceding
installed plugin from `f534cbdc`. It matches the candidate on all four native
rows, 16 SDK outcomes/typed captures, 16 complete matching diagnostics,
1,888 attempts and one existing verified application. This distinguishes the
immediate plugin comparison from the older complete matrix comparison.

Across the full current matrix, all 14,065 attempts and five existing verified
applications are preserved. There are no disproved, unsupported or unknown
instance attempts in this population. The 1,483 constant-gate events and 6,953
unrecorded diagnostic events remain unchanged. The existing constraint auditor
also repeats 196,608 finite 8-bit family comparisons and rejects eleven
corruptions; these remain rule-family evidence, not new instance proofs.
Ownership availability and the two SDK refusals remain explicit outcomes.

A separate ten-routine x86-64 fixture preserves every native byte in both
enabled and disabled captures, and the enabled run records five actual typed
production proofs. Its native oracle passes 70,656 result/final-memory cases.
An independent byte-array interpreter of the two actual SDK captures passes
`2 × 70,656 = 141,312` cases, comparing 64 result bits and a 4-byte memory cell.
The seeds are `0x390fe14891` and `0x9827136ab5`. This interpreter does not call
the production translator or solver. Native x86-64 execution uses macOS
translation on an arm64 host; independent physical x86-64 execution is unknown.

The full matrix's maximum recorded runner duration is 26,913,515,041 ns and
maximum recorded process peak resident size is 203,227,136 bytes. The shapes
processes record 1,048,288,291 ns disabled and 2,769,836,500 ns enabled. These
single-run durations include startup and concurrent scheduling. They establish
no latency improvement or attribution of total memory use to key size.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | The pinned SDK snapshot describes operands observed by this build. Identity contract and production comparisons depend on it. | Inspect field widths and frame contract; reject a changed SDK hash or ABI. |
| A2 | Distinct metadata requires distinct matching snapshots, without inferring unequal runtime values. Component correction depends on it. | Positive identical operands, all property bits, unknown/nonzero value numbers, frame changes and forced key-hash collisions. Cross-instruction equivalence remains unknown. |
| A3 | Valid production operands fit the comparison budget; excessive/cyclic comparisons may conservatively reject. Production yield depends on this bound. | Equal balanced depth-5 trees pass; depth-7 trees and self-cycles reject; all observed matrix outcomes and diagnostics remain equal. Larger unmeasured populations remain unknown. |
| A4 | Composite hashes provide indexing and the typed verifier independently gates replacements. Acceptance interpretation depends on both. | Existing typed rejection controls and 108-rule validation pass; actual shapes proof checks and captured-IR oracle pass. Collision-free composite identity is not established. |
| A5 | Reports, plugin, binaries and probe bytes remain pinned. Attribution depends on their receipts. | Verify source/artifact hashes, fresh disposable IDBs, unchanged native chunks and matched enabled/disabled profiles. |
| A6 | Enumerated and seeded behavior checks cover only their stated observable contract. Behavior conclusions depend on it. | Independent result/final-cell comparisons and malformed-capture rejection; general flags, aliasing and hardware exceptions remain unknown. |

## Bounded opportunities and remaining scope

- **High impact:** preserving value metadata removes demonstrated AST snapshot
  conflation before candidate verification. The measured protected corpus has
  no additional application; broader matching and reaching definitions remain
  open review work.
- **Medium impact:** doubled key payload may affect large expression caches.
  This report measures per-key size only; cache populations and attributable
  allocator/latency costs remain unknown.
- **Medium impact:** conservative comparison budgets and composite hash
  indexing can withhold matches. The current population is unchanged; complete
  collision resistance and bounded hash recursion remain separate work.
- **Low impact:** frame identity is valid only within the process and SDK
  ownership lifetime. It cannot serve as a persistent proof or navigation key.

Native CFG scalability, protected function ownership, causal miss classification,
full memory/ordering/flag contracts, VM semantic recovery and the complete
review completion audit remain in progress. This checkpoint does not change
those completion states.

## Reproduction and provenance

Use the repository-configured SDK and IDA text executable. The runner verifies
the exact candidate bytes and uses disposable inputs and IDA user directories.

```sh
clang-format --dry-run --Werror src/deobf/analysis/ast.cpp src/deobf/analysis/ast_builder.cpp src/deobf/analysis/ast_builder.h tests/catalog_tests.cpp
ctest --test-dir build --output-on-failure --parallel 8
xcrun clang -arch x86_64 -O1 tests/vmp_native/mba_shapes.S tests/vmp_native/mba_shapes_oracle.c -o build/ast-value-mba-shapes
build/ast-value-mba-shapes
python3 -B tests/verify_mba_shapes.py build/ast-value-shapes-off build/ast-value-shapes-on
python3 -B tests/run_protected_mba_corpus.py --corpus-report build/vmp-mba-corpus-x64/corpus.json --corpus-report build/vmp-mba-corpus-i386/corpus.json --ida "$CHERNOBOG_IDAT" --plugin build/ast-value-candidate.dylib --output-dir build/ast-value-protected-reproduction --native-analysis
python3 -B tests/verify_mba_constraint_capture.py --current build/ast-value-protected-final/protected_mba_analysis.json --baseline build/mba-constraint-protected-accepted/protected_mba_analysis.json --output build/ast-value-protected-audit-reproduction.json
```

For the predecessor component control, extract the entire predecessor `src`
tree with `git archive` into `build/ast-value-legacy`; use the catalog target's
`build/compile_commands.json` entries. Compile the current `catalog_tests.cpp`
with the extracted include directory first, and compile predecessor `ast.cpp`
and `ast_builder.cpp` with those headers. Substitute these three objects in the
catalog target's generated link command. Run with the same CTest SDK library
environment. Exit 1 and the 1,232-check/1,184-failure leaf result are expected.
Source and binary hashes identify this counterfactual exactly.

Primary provenance consists of the local SDK operand/frame definitions, actual
production AST and verifier sources, Git predecessor source snapshots and fresh
runner/SDK captures. The evidence manifest pins these sources and generated
reports without rewriting historical evidence hashes.

## Quality gates

QG1: no normative content is required. QG2: A1-A6 give assumptions, dependencies
and falsification probes. QG3: the stated snapshot-identity changeset is covered;
full review completion remains explicitly open. QG4: counts, byte sizes, widths
and nanosecond observations are reproducible without rounded comparisons.
QG5: value-number meaning, collision limits, budget rejection, prior-artifact
attribution and unavailable SDK outcomes are distinguished. QG6: primary source
and artifact hashes are recorded. QG7: bounded cache cost, lifetime and remaining
analysis opportunities are documented. These gates apply to this changeset.
