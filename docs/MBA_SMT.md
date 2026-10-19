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
instructions, calls, destinations and control flow. Ordinary owned frame-value
operands can simplify under the normal-completion memory model; their implicit
read multiplicity is not an observable in that model. Volatile or unresolved
memory operands remain unsupported. After each rewrite, old snapshot receipts
are discarded before further analysis.

Unsigned division is admitted only with a nonzero constant divisor. Known bits
and conservative unsigned ranges can replace a constant quotient or a quotient
with two adjacent possible values by a comparison. Ordinary operations cost one;
division costs eight, so this can increase the instruction count while removing
division. These weights guide search and are not a target-specific latency model.

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

## Validation and assumptions

The symbolic-expression fixtures include these reductions. `x`, `y`, and `z`
denote unconstrained input values; byte results are truncated to 8 bits.

| Fixture | Equivalent result |
|---|---|
| `mba_transform_2` | `(uint8_t)(x ^ y)` |
| `mba_transform_1` | `(uint8_t)~(y ^ (x & (y ^ z)))` |
| `opaque_predicate_2` | `(0x5A75D737u * ((x ^ 0xC6C0AACCu) & (y ^ 0x5E909F27u))) \| 0x55588C79u` |
| `opaque_predicate_1` | `2 + (numerator >= 0xF805721Au)` |

For the last row, `numerator` is the original masked 32-bit numerator, extended
unsigned to 64 bits. Both opaque examples are nonzero but value-dependent;
replacing either complete result with a single constant would be incorrect.

`chernobog.mba_smt` tests scalar byte widths, CFG joins and guards, quadratic
induction and invalid bases/backedges, symbolic aliases, partial writes, byte
order, cancellation, exhaustion and solver UNKNOWN. The native control in
`tests/vmp_native/mba_smt.c` checks arithmetic, arbitrary loop counts and equal/
distinct pointer cases. `tests/ida_mba_smt_probe.py` exercises the installed
plugin, both profiles and restoration in a fresh fixture database. Native
control execution alone does not prove that the plugin rewrote these functions.

| ID | Assumption / dependent results | Falsification probe |
|---|---|---|
| A1 | SDK scalar semantics match the adapter; all rewrites depend on this. | Differential widths, conversions, overlapping registers and shift boundaries. |
| A2 | Memory is ordinary sequential, normal-completion memory. | Preserve accesses; invalidate barriers/calls and reject unresolved selectors and volatile properties. |
| A3 | Completed Z3 results are correct; SMT admission depends on this. | Replay bounded queries, inspect SAT witnesses, force UNKNOWN and resource exhaustion. |
| A4 | The bounded search finds useful reductions. Coverage remains corpus-specific. | Compare catalog-only and semantic modes, report unsupported and exhausted populations. |

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
