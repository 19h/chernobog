# Semantic MBA synthesis

The catalog remains the instruction-level fast path. A bounded function pass
also executes typed integer expressions symbolically, searches replacement
expressions, and checks the emitted microcode against the same CFG snapshot.
`CHERNOBOG_MBA_SMT=0` (IDC option `mba_smt`) disables the new pass.

The proposed [CoBRA MBA backend](MBA_COBRA_SPEC.md) replaces algebraic candidate
generation while retaining this pass's Z3 proof gates and contextual analysis.

| Entry point | Additional semantic-analysis budget per decompilation |
|---|---:|
| Ordinary deobfuscation / automatic processing | 1 s |
| Deep deobfuscation (Chernobog) | 30 s |

Headless equivalents are `chernobog_deep_deobfuscate(ea)` and
`chernobog_deep_deobfuscate_text(ea)`. The latter returns pseudocode. The deep
profile is scoped to that call. `chernobog_mba_smt_stats(ea)` returns JSON for
the latest generation; proof counters count attempts, not unique recovered
expressions. `applied` counts actual rewrites. Budgets include adapter work and
are shared across maturities. Solver timeouts are capped by remaining work;
allocation, SDK work and total decompiler runtime have no hard real-time bound.
Every function reserves part of that budget for final scalar reconstruction,
including caller-context analysis and expressions already inlined into ctree.
Callee decompilation is separate SDK work and is excluded from the
caller's analysis timer. If learning callee prototypes changes the argument
layout, the caller is regenerated once, starting a fresh generation and budget.

## Model and admission

The core represents scalar widths of 1 through 8 bytes, explicit conversions,
arithmetic, bitwise operations, byte-count shifts, branch conditions, overlapping
register views and byte-addressed memory. Stores update exact bytes in target
endianness, including symbolic aliases. Stack/local bases are unconstrained
stable frame addresses in the same memory array, without disjointness assumptions.
Unsupported instructions invalidate mutable registers and memory. Local value
trees retain register value numbers as distinct input identities. Pure local
trees also represent stack and local-variable operands as typed symbols, keyed
by their owner, offset, width and value number. Distinct overlapping views are
independent when their relationship is unavailable. Cross-block
propagation rejects numbered snapshots whose reaching definitions are not
established; it also rejects unsupported effects, segmentation and widths.

Definition-derived polynomial templates of degree at most two, finite memory
relations, branch predicates, constants and scalar relations are proposed at
block entries. A Houdini elimination loop proves function-entry initiation and
every CFG transition. Facts are used only after reaching a fixed point. An
interrupted proof discards inferred facts. This handles cycles without assuming
that bounded unrolling proves a loop invariant. It does not infer quantified
heap invariants or enumerate every polynomial relation.

Candidate search first reduces Boolean words over up to four symbolic inputs,
including subexpressions such as `x ^ constant`. A bounded truth-table search
uses AND, OR, XOR and NOT; every candidate requires a full-width equality proof.
Completed unconditional equalities are retained within that snapshot and
composed in later checks. The final emitted-code check may substitute only
those proved equalities, never sampled relationships or unproved assumptions.

Linear reconstruction also runs from the leaves upward. Each arithmetic
subexpression is sampled over up to four word inputs, reconstructed in the
conjunction basis, and accepted only after an unconditional full-width proof.
This can expose identities across arithmetic and bitwise boundaries, such as
`(z | ~x) + x + 1 == (x & z)`. Equal modular coefficients share a factor, so
`2*x + 2*y` is emitted as `2*(x+y)`. A local reduction must strictly lower cost;
its proof remains in the same immutable snapshot as the enclosing reduction.
Eight additional word-valued samples reject false linear fits caused by carries
before they consume a solver timeout. These samples can reject a candidate but
cannot authorize one.
For larger expressions, Boolean regions are also reconstructed as proof-only
arithmetic expansions. A word such as `x+y` inside `x ^ (x+y)` is an atom during
reconstruction, with its actual definition restored in the equality proof.
These proved expansions expose cancellation between distant summands in an
associative chain. They may increase proof-expression size but are never emitted
as a larger replacement.

The remaining search reconstructs a conjunction basis from up to 16 Boolean-word
evaluations, fits arbitrary modular affine coefficients using solver
counterexamples, and enumerates a typed operator grammar. Samples filter search;
only UNSAT of the full-context mismatch authorizes a replacement. The emitted
SDK expression is independently translated and rechecked. SAT, UNKNOWN,
unsupported cases and exhausted budgets preserve the original. New rewrites
reduce a structural cost estimate and preserve explicit memory
instructions and destinations. The expression pass preserves calls and control
flow; the caller-context pass described below can remove proved pure calls and
constant branches. Ordinary owned frame-value
operands can simplify under the normal-completion memory model; their implicit
read multiplicity is not an observable in that model. Volatile or unresolved
memory operands remain unsupported. After each rewrite, old snapshot receipts
are discarded before further analysis.

Unsigned division is admitted only with a nonzero constant divisor. Known bits
and conservative unsigned ranges can replace a constant quotient or a quotient
with two adjacent possible values by a comparison. Ordinary operations cost one;
division costs eight, so this can increase the instruction count while removing
division. These weights guide search and are not a target-specific latency model.
Known-bit threshold reduction then walks a comparison from its most significant
bit. A fixed bit can settle the suffix of that comparison, leaving an equality
or inequality on just the relevant unknown bits. Constant masks and extensions
are removed only from bits the resulting test does not observe. The replacement
still requires an unconditional SMT proof and the emitted-code verification.

Mask normalization also tracks known zero and one bits through constant shifts,
extensions, extraction and multiplication by powers of two. XOR becomes OR
when the operands' possible set bits are disjoint. An observation mask can
distribute through OR or XOR when that removes redundant masks; nested constant
masks combine. These structural candidates require the same full-width proof
as synthesized candidates and must lower the complete replacement cost.

For example, with `low = input & 1` and
`high = (input & 0x11) == 0x11`, the expression
`(high << 6) | (((flags & 0xFFFFFFF7u) ^ (8u * (input & 1))) & 0xFFFFFFBFu)`
becomes `(flags & 0xFFFFFFB7u) | (low << 3) | (high << 6)`.
Only bits 3 and 6 change. If an insertion can overlap a retained bit, its XOR
semantics remain necessary. The native mask fixtures test both cases, preserve
conditional stores and observer calls, and check destinations aliased by an
observer as well as volatile destinations. Captured normal and deep pseudocode
is compiled by `tests/verify_mba_masks.py` and checked against a separate oracle.
`tests/ida_mba_flag_store_probe.py` also captures the extracted
`GreProtectSpriteContent` function's baseline, normal and deep field store.
Run it through the isolated smoke runner with `--allow-database`; the runner
copies the supplied IDB and verifies the original input hash, while the probe
checks that the function's native instruction bytes remain unchanged.

Private scalar bindings remain available while simplifying a plain store's
RHS. Address-side writes isolate that analysis from incoming scalar facts;
unresolved writes still discard context afterward. The store address and memory
operations are preserved. Existing eligible locals can represent expressions
such as `input & 1`, avoiding a second computation of an already available flag.
The microcode semantic pass declines functions whose parameter types expose
volatile scalar, pointed or array data. Its ordinary-memory equalities cannot
justify coalescing volatile accesses. The final ctree pass can still simplify
eligible pure scalars while retaining the volatile operations.

Cross-block limits are 64 blocks, 256 statements and 64 scalar storage regions.
Local tree analysis remains available when a complete CFG exceeds these limits;
it visits at most 256 expression nodes. Synthesis uses at most eight candidate
inputs and eight candidate operations. Boolean reduction explores at most
65,536 candidates per table; structural reductions can retain a larger existing
subexpression when the complete replacement still lowers cost. The existing
catalog is unaffected.
Array query capture remains bounded;
`formula_complete=false` identifies omitted or truncated receipts.

For N statements, R storage regions, B blocks, E edges and K retained invariant
templates per block, snapshots require O(N R) register references. Invariant
elimination performs at most O(B K E) solver calls: each unsuccessful round
removes at least one candidate. Boolean-word reconstruction evaluates O(2^V)
assignments with V <= 4. General expression search remains exponential in its
grammar bound; solver work is additional and is stopped by the shared budget.
The conjunction coefficients use a subset transform with O(V * 2^V) arithmetic
work and O(2^V) coefficient storage. At most 512 expression nodes are visited
by the local rewrite walk. Repeated subtree sampling can take O(N^2 * 2^V)
tree work for N nodes, excluding solver work; the shared budget still applies.
A threshold reduction visits its operand tree and scans at most 64 bit positions;
its equality proof remains subject to the shared solver budget.
Known-bit inference takes O(N) tree work for N nodes. A mask-normalization call
may revisit subtrees in O(N^2) work, and the complete recursive algebraic walk
has an O(N^3) structural upper bound with O(N) recursion and intermediate storage.
The existing node and depth limits apply; SMT work is additional.

## Validation and assumptions

The symbolic-expression fixtures include these reductions. `x`, `y`, and `z`
denote unconstrained input values; byte results are truncated to 8 bits.

| Fixture | Equivalent result |
|---|---|
| `mba_transform_2` | `(uint8_t)(x ^ y)` |
| `mba_transform_1` | `(uint8_t)~(y ^ (x & (y ^ z)))` |
| `opaque_predicate_2` | `(0x5A75D737u * ((x ^ 0xC6C0AACCu) & (y ^ 0x5E909F27u))) \| 0x55588C79u` |
| `opaque_predicate_1` | `2 + ((difference & 0x50000000u) == 0x50000000u)` |

For the last row, `difference` is the 32-bit value
`((y ^ 0x3FA3EB91u) | (x ^ 0x29D81B96u)) - 0x1F206DEDu`.
Only bits 30 and 28 affect its quotient. Both opaque examples are nonzero but
value-dependent; replacing either complete result with a single constant would
be incorrect. In particular, `opaque_predicate_1` returns 2 for
`(0xE3A1F254, 0x3FA3EB91)` and 3 for `(0x36F8767A, 0x3FA3EB91)`.
`opaque_predicate_2` returns `0x55588C79` for `(0xC6C0AACC, 0x5E909F27)`
and `0xFFFFFFFF` for `(0xC5E2DBB5, 0x5DB2EE5E)`.

The nested fixtures in `tests/vmp_native/mba_nested.c` model 32-bit wrapping
arithmetic followed by a zero extension to the 64-bit return value:

| Fixture | Equivalent 32-bit result before zero extension |
|---|---|
| `mba_nested_1` | `2*z - x` |
| `mba_nested_2` | `2*x + y` |
| `mba_nested_3` | `x + y - z` |
| `mba_nested_combined` | `2*(x+y) + z` |
| `mba_nested_solve` | `2*(2*(x+y) + z)` |
| `mba_nested_caller` | `2*(2*(x+y) + z)` |

These are bit-vector equalities, including overflow; they do not assume C signed
overflow is defined. The standalone core regressions require compact results at
8, 16, 32 and 64 bits and reject a nested nonlinear sampling collision. The IDA
probe `tests/ida_mba_nested_probe.py` requires both normal and deep pseudocode
to remove the bitwise encoding and the pure helper call. Running
`tests/verify_mba_nested.py CAPTURE --output-dir OUTPUT` compiles both captured
profiles and checks 607,986 full-return comparisons per profile against an
unsigned arithmetic oracle, including all combinations of 11 boundary values
and 100,000 deterministic input triples. This tests generated C promotions and
return conversions separately from the solver's expression model.

Constant arguments at a call site do not constrain a separately decompiled
helper's parameters. A separate caller-context pass instantiates the helper's
expression with the actual arguments. It admits only complete scalar bodies
consisting of assignments and a return. Every expression and nested call must
be supported: pointer accesses, global accesses, volatile operands, assembly,
loops, recursion, variadic functions and custom calling conventions are rejected.
Argument and return widths must agree with the callee's prototype. No user
declaration is overwritten; a caller can be refreshed once when decompiling a
callee refines an earlier guessed prototype.

One solver model proposes a constant value. An unsatisfiable full-context
mismatch must then prove that value for every argument valuation. If the result
varies, the expression synthesizer can propose a smaller symbolic expression.
A second check validates the emitted ctree expression, including every cast and
integer promotion. Replacements must lower the displayed operation cost;
integer casts cost zero, scalar operations cost one, calls cost four, and
division costs eight. A proved constant may also replace a local-variable read.
These are readability weights, not a processor latency model. The helper's
standalone body retains its general behavior.
An already compact callee body is itself a replacement candidate. Its emitted
form is proved before searching for a smaller expression. This verified fallback
can still be installed if later synthesis exhausts its budget, because the
original expression and context remain unchanged throughout the search.

| Caller expression | Proved result |
|---|---|
| `mba_transform_1(77, 169, 86)` | `27` |
| `mba_transform_2(19, 19)` | `0` |
| `opaque_predicate_1(0xDEADBEEF, 0xCAFEBABE)` | `3` |
| `opaque_predicate_2(0x12345678, 0x9ABCDEF0)` | `0x75FAAFFD` |
| `opaque_predicate_1(x, y) == 0x9E432F2E` | `false` |
| `opaque_predicate_2(x, y) != 0` | `true` |

Scalar expressions propagate through local assignments as immutable value
versions. Reassigning a local creates a new value without changing earlier
expressions or path facts. Private scalar values remain valid across calls;
address-taken, shared, overlapped and volatile locals are excluded. SDK variable
mapping destinations use their canonical ctree index; mapping alone does not
imply shared storage. Both edges
of an effect-free condition supply path facts. A join retains structurally equal
incoming values and common assumptions; if one branch returns, only the continuing
branch supplies facts. Labels, loop boundaries, and writes with unresolved
ordering discard context. Only an effect-free constant condition can remove a
branch, and branches containing labels are preserved. Calls with effects remain
present.
If the decompiler separates an argument's side effect into an earlier statement,
the resulting pure call may simplify while that statement remains intact.

Each proof query compacts the referenced value versions and represents its path
facts as a guarded CFG edge. The existing invariant checker must prove these
facts at the rewrite site. Unsatisfiable contexts cannot authorize a rewrite.
The emitter can reference only currently available locals, even if the solver
knows a relation involving an older value. It never substitutes a historical
symbol using a local that has since changed. Context snapshots share expression
nodes; the expression visit and depth limits also bound expanded expressions.
At most 16 path conditions and three propagation rounds are used per invocation.
Individual queries are capped at 250 ms in normal mode and 1000 ms in deep mode,
within the shared function budget. A path condition alone enables constant
queries. General synthesis requires an expanded call, a derived local value,
or an arithmetic/bitwise mixture costing at least four operations. This last
case admits an already inlined expression without requiring caller facts.
For `L` locals and at most `N` expanded expression nodes, context copies take
`O(L)` space and time; comparing bindings at a join takes `O(L * (N + log L))` plus the
bounded path-condition intersection. Expression nodes remain shared. Synthesis
and SMT solving have exponential worst cases and retain their explicit budgets.

A bounded structural walk precedes these searches. It reuses current locals and
normalizes flag-field expressions before earlier predicates can exhaust the
function budget. This walk does not expand callees or use path conditions:
emitted expressions must prove equal for every valuation of their expanded
bindings. Each proof is capped at 25 ms within the same function budget.
Context-dependent constant queries and synthesis retain their guarded proofs.

The ctree emitter prints dense 32-/64-bit clearing masks as complements, power-of-two
field insertions as shifts, and complete field updates with the retained bits
first, followed by insertions in increasing bit position. Bitwise operations
use C integer promotions without redundant same-width sign casts. A signed left
shift requires a known nonnegative operand whose maximum possible value is at
most `INT_MAX >> shift` at the promoted width; other left shifts retain unsigned
operands. Arithmetic overflow, signed comparisons, right-shift semantics and
conversion order still require explicit types. Every emitted expression is
retranslated and proved before installation.

Replacements first minimize operation cost. At equal cost, a strictly decreasing
presentation score counts casts, twice the remaining power-of-two
multiplications, uncomplemented dense clearing masks, and leading field
insertions. This score prevents later searches from replacing a readable update
with an equal-cost multiplication or redundant cast. It estimates presentation,
not runtime performance. Constant complements add no operation cost. Emission
can take `O(N^2 log N)` time and `O(N)` temporary space when nested OR trees
require repeated field collection and sorting; the existing 512-node and
64-level limits bound this work.

Examples include `mba_transform_2(x, 0)` becoming `(uint8_t)x`, a constant-selector
call becoming `(uint8_t)(x ^ 0x56)`, and eliminating an impossible comparison
after assigning a varying helper return to a local. Branchy callee bodies and
memory-effect summaries remain outside this pass.

This pass runs after decompilation returns, through Chernobog's text APIs,
manual actions and pseudocode views. Hex-Rays does not permit nested callee
decompilation inside a maturity callback. View updates are deferred until
navigation completes and use the SDK's view-switch operation to keep the
displayed function and its microcode together. The pass edits an uncached
function, preserving its analysis profile, before switching the view. Text API
queries also use private function objects so they cannot invalidate an open
view's item pointers or text anchors. Pending updates are discarded
when the view changes function or the plugin shuts down. Summaries live for one invocation;
there is no persistent result cache. Limits are 16 callees, three nested callee
levels, 4096 native bytes per callee, 512 expanded expression nodes, and 128
expression queries per phase (structural emission and search), in addition to
the time and scalar-program limits. Constant
queries run before symbolic expression enumeration. Tree traversal and repeated
subtree translation can take quadratic time in expression size; solver work
and the bounded callee decompilations are additional.

`chernobog.mba_smt` tests scalar byte widths, CFG joins and guards, quadratic
induction and invalid bases/backedges, symbolic aliases, partial writes, byte
order, cancellation, exhaustion and solver UNKNOWN. The native control in
`tests/vmp_native/mba_smt.c` checks arithmetic, arbitrary loop counts and equal/
distinct pointer cases, including the two-bit quotient identity. Threshold tests
cover both comparison directions, both fixed-bit outcomes, exact boundaries,
and 8-, 16-, 32- and 64-bit operands. `tests/ida_mba_smt_probe.py` exercises the
installed plugin, both profiles and restoration in a fresh fixture database. Native
control execution alone does not prove that the plugin rewrote these functions.
The probe's `CHERNOBOG_MBA_PROBE_FUNCTIONS` setting accepts a comma-separated
subset of the listed fixture names so the same checks can exercise an existing
binary with those functions, without modifying its original database.
`tests/ida_mba_calls_probe.py` checks caller constants, symbolic replacements,
return ranges across calls, both branch edges, joins, overwritten values,
conversion order, and retained varying/impure/memory calls.
`tests/mba_smt_context_tests.cpp` independently checks value versioning, guarded
proof queries, contradictory paths, merge behavior, query compaction and limits.
`tests/verify_mba_context_capture.py` compiles the captured normal/deep pseudocode
and compares its return values, observer effects, and pointer updates with the
original native functions over all byte pairs, boundary values, and deterministic
32-bit inputs. It tests the emitted C, not a separately reconstructed replacement.
Its `CHERNOBOG_MBA_CALL_PROBE=foo` mode checks `main` and
`block_decrypt_strings` in the supplied binary. `CHERNOBOG_MBA_CALL_VIEWS=1`
exercises actual pseudocode views instead of the text APIs.
The view probe navigates forward and backward through its function list.

| ID | Assumption / dependent results | Falsification probe |
|---|---|---|
| A1 | SDK scalar semantics match the adapter; all rewrites depend on this. | Differential widths, conversions, overlapping registers and shift boundaries. |
| A2 | Memory is ordinary sequential, normal-completion memory. | Preserve accesses; invalidate barriers/calls and reject unresolved selectors and volatile properties. |
| A3 | Completed Z3 results are correct; SMT admission depends on this. | Replay bounded queries, inspect SAT witnesses, force UNKNOWN and resource exhaustion. |
| A4 | The bounded search finds useful reductions. Coverage remains corpus-specific. | Compare catalog-only and semantic modes, report unsupported and exhausted populations. |
| A5 | Admitted callee ctrees completely represent their scalar effects and ABI. Caller specialization depends on this. | Reject unsupported statements and width mismatches; test volatile writes, pointer reads, escaped locals, loops and narrow results. |
| A6 | A caller fact refers to the correct immutable value version and every incoming path. Contextual rewrites depend on this. | Test overwrites, equal and unequal joins, false edges, contradictory guards, labels, and loop barriers; retranslate every emitted expression against the same snapshot. |
| A7 | The supplied nested examples use 32-bit wrapping arithmetic and zero-extend their final result to 64 bits. The example reductions depend on this interpretation. | Compile unsigned fixtures, inspect captured return conversions, and compare complete 64-bit results at overflow boundaries; a different width or sign extension in the original binary would invalidate this interpretation. |
| A8 | The flag-store example uses a 32-bit field and the shown definitions of its two Boolean flags. Its compact displayed form depends on A1, A3, A6 and this interpretation. | Prove the masked identity at every scalar byte width; test all byte inputs, retained-bit overlap, boundary words, observer aliases and volatile destinations; compile captured ARM64 and x86-64 pseudocode. |
| A9 | Removing a signed cast from a field shift requires a nonnegative operand and a result representable in the promoted signed type. Readable field emission depends on this bound. | Test all flag-byte inputs, negative signed bytes, full-width boundary patterns, and two-bit fields shifted into the sign bit; compile and execute captured normal/deep pseudocode with undefined-behavior sanitization. |

Bounded findings: **high**, incomplete effects or predecessors can manufacture
proofs and must invalidate facts; **medium**, nonlinear/array queries may exhaust
the budget without a rewrite; **low**, sample collisions can reduce search
coverage but cannot authorize an unproved replacement.
For field presentation, **high**, dropping an unsigned conversion can introduce
C signed-shift undefined behavior even when bitvector equality holds; the range
check and compiled sanitizer probes cover that distinction. **Medium**, a proof
timeout can leave an expression unchanged; structural emission shares the
existing budget and never bypasses proof admission.
**Medium**, rewriting arbitrary multiplication as shifts before synthesis can
obscure algebraic MBA identities; presentation converts multiplication only
inside recognized field updates, and the nested-MBA regression checks both
profiles.

Primary references: [SMT-LIB bitvectors](https://smt-lib.org/theories-FixedSizeBitVectors.shtml),
[functional arrays](https://smt-lib.org/theories-ArraysEx.shtml), and
[counterexample-guided synthesis](https://people.csail.mit.edu/asolar/SynthesisCourse2020/Lecture10.htm).

The source-hashed [validation receipt](MBA_SMT_VALIDATION.json) records the native
control comparisons, complete CTest result, and actual IDA normal/deep/normal
captures. It describes the recorded artifact, including remaining unsupported
cases; it is not an assertion about every protected binary.
