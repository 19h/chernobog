# Bounded SDK operand traversal for AST construction

This checkpoint advances review rows 4a, 4b and V. Public operand-key hashing
and microcode-to-AST construction now audit recursive operand ownership before
hashing or copying SDK operands. Excessive or cyclic input produces an explicit
abstention. This closes the previously unbounded input traversal in the AST
builder; causal miss classification and the complete review remain in progress.

## Admission contract

The audit visits all nonempty left, right and destination operands, nested
instructions, address operands, call arguments and return operands, and operand
pairs. It also bounds call-argument, return-operand, attribute, scattered-location
and switch-case container cardinalities. Floating-point payloads retain their
existing opaque representation. Known SDK operand types remain admissible;
an unknown type tag or missing required payload rejects the whole input.

An active-path pointer set detects cycles. A repeated child on a different
path remains admissible and consumes a new expansion budget. The guard never
interprets pointer equality as value equality or a semantic proof.

| Bound | Exact admission |
|---|---|
| Nesting | Root depth 0; depth at most 64; rejecting depth may be 65 |
| Visits | At most 1,024 instruction/operand visits plus charged container entries |
| One checked string | At most 4,095 payload bytes plus its terminating NUL |
| Total checked strings | At most 65,536 bytes, including each terminator |
| Cache key payload | 64 bytes, unchanged from the preceding checkpoint |

Checked strings include helpers, immediate strings, formal argument names and
scattered operand names. Container charging includes empty elements, so an
oversized vector of empty operands cannot bypass the visit budget. A failed
visit charge does not exceed 1,024 recorded visits. Depth records may include
the first rejected level.

`AstBuildReport` distinguishes a complete structural audit, null instruction,
malformed payload, unknown operand tag, cycle, depth exhaustion, visit exhaustion
and text exhaustion. Structural completion establishes neither ISA semantics
nor replacement equivalence. The existing typed instance verifier still gates
every actual catalog replacement.

An incomplete `MopKey` is never inserted or retrieved by `AstBuilderContext`.
The public instruction hash returns zero on rejection; callers needing admission
status use its report, since a hash value alone is not a proof or status code.
Admitted keys retain the preceding hash construction and metadata identity.
Composite hash equality remains an index decision under the typed verifier.

`minsn_to_ast` returns no AST after a failed audit. It cannot turn an over-budget
subtree into an opaque leaf or publish a partial AST. `find_match` retains its
existing `no_ast` outcome and records the bounded rejection reason in the
existing diagnostic detail. `find_all_matches` returns an empty result on the
same rejection. The ordinary non-MBA opcode exclusion remains separate from
these structural rejection reasons.

```text
audit root and all owned recursive operand payloads
    charge depth, visits, container entries and checked string bytes
    reject any active-path cycle, missing payload or exceeded bound
if audit failed:
    return no AST / incomplete key / rejected hash report
hash admitted immutable payloads
convert using the existing deduplication context
match and verify with the existing typed replacement gate
```

For `V <= 1024` charged visits, active depth `D <= 64` and checked string work
`B`, auditing costs `O(V log(D + 1) + B)` time and `O(D)` active-set space.
The rejecting text scan reads at most 4,096 bytes of that string. Admitted
hashing of one payload is linear in its expanded operand structure and checked
text. Building keys for overlapping subtrees and retaining SDK operand copies
can still incur quadratic expanded-tree work. The guard bounds the repository
traversal; it does not establish constant-time conversion or a whole-process
latency bound.

SDK type metadata, register/memory lists, custom location implementations,
allocator behavior and SDK-internal copy costs remain external costs. Their
validity follows the SDK ownership contract, not this audit. Instruction list
links, frame owners and type-system references are not followed as owned
operand subtrees. Concurrent payload mutation or arbitrary invalid pointers
are outside that existing synchronous SDK contract.

## Component controls and counterfactual

The corrected standalone catalog passes 108 new controls. They cover exact
depth 64 versus 65, visits 1,024 versus the next charge, one-string and total
text boundaries, repeated acyclic children, instruction/address/call/pair
cycles, null payloads, unknown tags, and bounded call/pair/case/float payloads.
An ordinary ADD converts with its widths and two register operands intact.
The cycle rejection occurs before any SDK operand copy. An initialized actual
registry reports `no_ast` with `cyclic_operand_payload`, no indexed pattern
and no match; its all-matches entry point also rejects.

The component SDK dispatcher copies only empty, register and global operands.
It rejects recursive-copy requests. Borrowed SDK container views expose C++
fixture storage through `inject` and detach it with `extract` before destruction.
These controls test the guard's reads without invoking unsupported kernel
allocation or argument-location copies. Actual SDK construction/copy behavior is exercised by the
production captures rather than emulated by this dispatcher.

A separate source control links exact predecessor builder and registry sources
from `8a1d4ee990c18b210a8983fd6b08efea7240b936`. Its isolated cyclic-operand hash
process exits on signal 11. The corrected process returns hash zero and exits 0.
Both use the same cycle shape and component dispatcher. This establishes an
unbounded-recursion failure at component scope; no production protected fixture
is claimed to contain a cyclic SDK operand.

The existing 1,247 value-identity checks, 190 typed controls, all 108 registered
rules and the deliberately rejected 109th rule retain their expected results.
All 22 configured CTest suites pass for the final guard.

## Production controls and rejected trial

The first guard rejected call arguments as opaque. Its complete protected run
preserved the 152 native rows, 456 SDK outcomes, 454 typed captures and five
verified applications, but changed 18 matching diagnostic stages and recorded
133 `no_ast` events. That trial is not the accepted implementation. The final
guard traverses the SDK containers and retains their prior AST representation.
The first artifact and its diagnostic differences remain historical evidence.

The accepted matrix and its exact preservation audit are recorded in
`VMP_AST_CONSTRUCTION_BOUNDS_EVIDENCE.json`. The matrix includes original,
mutation, virtualization and combined profiles, x86-64 and i386, seeds 0, 1
and 12,648,430, and enabled/disabled transformations. RAX is disabled and the
native engine is enabled in transformation-enabled profiles. SDK refusals remain
explicit outcomes. The actual immediately preceding installed module also has
a fresh reserved-seed i386 combined control on the same binary.

All 40 final processes pass and reject 602 corrupted captures. The complete
audit preserves 152 native rows, 456 SDK stage outcomes, 454 typed captures
and all 456 matching diagnostics. The immediately preceding installed held-out
control independently preserves four native rows and all 16 SDK captures and
diagnostics. The final population retains 14,065 attempts, 1,483 constant-gate
events and five verified applications. It contains zero `no_ast` events: the
adversarial construction rejections are component controls, not observed
protected recovery gains. Two SDK refusals remain.

The final matrix's maximum recorded runner duration is 51,089,830,625 ns and
maximum process peak resident size is 203,505,664 bytes. These values do not
attribute total latency or memory to the guard.

Single-run runner durations and peak resident bytes are observations with startup
and scheduling included. No protected simplification gain, general speedup,
full alias/reaching-definition proof or hardware-exception contract is inferred.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| A1 | SDK payloads and auxiliary metadata satisfy their declared ownership and remain immutable during a synchronous call. Structural admission depends on this. | Pinned SDK definitions, direct recursive-payload controls and real SDK captures; arbitrary invalid pointers and SDK metadata corruption are outside this contract. |
| A2 | Every expanded owned operand path and relevant container cardinality is charged. Traversal bounds depend on this. | Exact visit/depth boundaries, repeated children, empty argument vectors, address/call/pair cycles and case cardinality controls. |
| A3 | Incomplete traversal cannot supply a usable AST cache entry or partial tree. Rejection claims depend on this. | Incomplete-key insert/get controls, null AST after each structural budget failure, and the before-copy cycle control. |
| A4 | Structural admission is distinct from semantic replacement verification. Rewrite interpretation depends on this. | Existing typed rejection controls, catalog verification, retained production proofs and captured typed trees. |
| A5 | Artifacts, profiles and predecessor sources identify the compared implementations. Attribution depends on this. | Exact source/module/report hashes, fresh disposable IDBs, unchanged native bytes, source control and the actual installed predecessor capture. |

## Bounded expansion and remaining requirements

- **High impact:** public builder and hash entry points now abstain on a
  demonstrated recursive input failure before SDK operand copying. Ordinary
  SDK call containers remain admitted under explicit traversal bounds.
- **Medium impact:** overlapping subtree hashing and copying retain quadratic
  work. Shared summaries would need exact identity and lifetime evidence;
  this guard does not add a persistent cache.
- **Medium impact:** the repository traversal cap does not bound opaque SDK
  metadata or SDK-internal work. Those costs need separate measurement and
  admission contracts before a whole-process bound can be claimed.
- **Low impact:** budget reasons identify construction abstention, not a missing
  identity, a false rule or the cause of an unresolved reaching definition.

Complete causal miss classification, protected recovery metrics, full native
and VM ownership, temporal heap evidence and the complete review remain open.

## Reproduction and primary provenance

```sh
clang-format --dry-run --Werror src/deobf/analysis/ast_builder.cpp src/deobf/analysis/ast_builder.h src/deobf/rules/rule_registry.cpp tests/catalog_tests.cpp
cmake --build build --target chernobog_catalog_tests chernobog -j 20
ctest --test-dir build --output-on-failure --parallel 8
python3 -B tests/run_protected_mba_corpus.py --corpus-report build/vmp-mba-corpus-x64/corpus.json --corpus-report build/vmp-mba-corpus-i386/corpus.json --ida "$CHERNOBOG_IDAT" --plugin build/ast-bounds-complete-candidate.dylib --output-dir build/ast-bounds-reproduction --native-analysis
```

The evidence JSON pins the production guard and registry, component fixtures,
exact predecessor source snapshots and binaries, actual IDA captures, SDK
operand/container definitions and runner receipts. Historical evidence hashes
remain unchanged.

QG1: no normative content required. QG2: A1-A5 register dependencies and probes.
QG3: input traversal and preservation are the scope of this changeset; complete
review implementation remains open. QG4: depth, visit, byte and process units
are explicit. QG5: the rejected opaque-call trial, SDK costs and component-only
cycle failure are distinguished. QG6: primary source and artifact hashes are
recorded. QG7: bounded sharing, SDK cost and diagnostic opportunities are stated.
