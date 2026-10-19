# Semantic MBA synthesis

The catalog remains the instruction-level fast path. A bounded function pass
also executes typed integer expressions symbolically, searches replacement
expressions, and checks the emitted microcode against the same CFG snapshot.
`CHERNOBOG_MBA_SMT=0` (IDC option `mba_smt`) disables the new pass.

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
Functions containing calls reserve part of that budget for caller-context
analysis. Callee decompilation is separate SDK work and is excluded from the
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
A threshold reduction visits its operand tree and scans at most 64 bit positions;
its equality proof remains subject to the shared solver budget.

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
mismatch must then prove that value for every argument valuation. A second
check validates the emitted literal. This folds calls with constant arguments,
relations such as equal XOR arguments, and constant comparisons of otherwise
variable return values. A varying call remains a call. The helper's standalone
body retains its general behavior.

| Caller expression | Proved result |
|---|---|
| `mba_transform_1(77, 169, 86)` | `27` |
| `mba_transform_2(19, 19)` | `0` |
| `opaque_predicate_1(0xDEADBEEF, 0xCAFEBABE)` | `3` |
| `opaque_predicate_2(0x12345678, 0x9ABCDEF0)` | `0x75FAAFFD` |
| `opaque_predicate_1(x, y) == 0x9E432F2E` | `false` |
| `opaque_predicate_2(x, y) != 0` | `true` |

Closed scalar constants also propagate through a caller's straight-line local
assignments. Address-taken, shared, overlapped and volatile locals are excluded.
Facts are cleared at labels, joins, writes with unresolved ordering, and loop
boundaries. Only an effect-free constant condition can remove a branch, and
branches containing labels are preserved. Calls with effects remain present.

This pass runs after decompilation returns, through Chernobog's text APIs,
manual actions and pseudocode views. Hex-Rays does not permit nested callee
decompilation inside a maturity callback. Summaries live for one invocation;
there is no persistent result cache. Limits are 16 callees, three nested callee
levels, 4096 native bytes per callee, 512 expanded expression nodes, and 128
constant queries, in addition to the time and scalar-program limits. Constant
queries avoid general expression enumeration. Tree traversal and repeated
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
`tests/ida_mba_calls_probe.py` checks caller constants, symbolic predicates,
equal arguments, conversion order, and retained varying/impure/memory calls.
Its `CHERNOBOG_MBA_CALL_PROBE=foo` mode checks `main` and
`block_decrypt_strings` in the supplied binary. `CHERNOBOG_MBA_CALL_VIEWS=1`
exercises actual pseudocode views instead of the text APIs.

| ID | Assumption / dependent results | Falsification probe |
|---|---|---|
| A1 | SDK scalar semantics match the adapter; all rewrites depend on this. | Differential widths, conversions, overlapping registers and shift boundaries. |
| A2 | Memory is ordinary sequential, normal-completion memory. | Preserve accesses; invalidate barriers/calls and reject unresolved selectors and volatile properties. |
| A3 | Completed Z3 results are correct; SMT admission depends on this. | Replay bounded queries, inspect SAT witnesses, force UNKNOWN and resource exhaustion. |
| A4 | The bounded search finds useful reductions. Coverage remains corpus-specific. | Compare catalog-only and semantic modes, report unsupported and exhausted populations. |
| A5 | Admitted callee ctrees completely represent their scalar effects and ABI. Caller specialization depends on this. | Reject unsupported statements and width mismatches; test volatile writes, pointer reads, escaped locals, loops and narrow results. |

Bounded findings: **high**, incomplete effects or predecessors can manufacture
proofs and must invalidate facts; **medium**, nonlinear/array queries may exhaust
the budget without a rewrite; **low**, sample collisions can reduce search
coverage but cannot authorize an unproved replacement.

Primary references: [SMT-LIB bitvectors](https://smt-lib.org/theories-FixedSizeBitVectors.shtml),
[functional arrays](https://smt-lib.org/theories-ArraysEx.shtml), and
[counterexample-guided synthesis](https://people.csail.mit.edu/asolar/SynthesisCourse2020/Lecture10.htm).

The source-hashed [validation receipt](MBA_SMT_VALIDATION.json) records the native
control comparisons, complete CTest result, and actual IDA normal/deep/normal
captures. It describes the recorded artifact, including remaining unsupported
cases; it is not an assertion about every protected binary.
