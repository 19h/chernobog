# CoBRA MBA simplification specification

Status: proposed implementation. This specification does not describe an
implemented backend or measured performance improvement.

Use CoBRA to generate simplified MBA expressions, then use the existing Z3
infrastructure to prove the candidate and the actual emitted replacement.
Retain the static MBA catalog as the instruction-level fast path. Z3 continues
to handle symbolic execution, path feasibility, invariants, memory relations,
control-flow recovery, and other existing analyses.

The upstream baseline is `trailofbits/CoBRA` revision
`af44b8ad7c8ec548d431463475e93b0118e77a29`.

## Scope and ownership

| Responsibility | Implementation after integration |
|---|---|
| Existing MBA catalog and concrete applicability checks | Existing implementation |
| Candidate reconstruction for eligible pure MBA regions | CoBRA through a typed adapter |
| Cheap known-bit, mask, and structural reductions | Existing implementation |
| Candidate and emitted-expression equivalence | Existing Z3 proof infrastructure |
| Contextual constant solving, CFG facts, invariants, and memory reasoning | Existing Z3 analysis |
| Microcode and ctree emission and presentation | Existing adapters |

CoBRA becomes the primary algebraic candidate engine for admitted MBA regions.
It replaces the legacy Boolean/signature reconstruction, affine fitting, and
grammar search on that route. Retain the legacy backend as a selectable
comparison and rollback implementation. Do not automatically run both candidate
engines on the same region after one exhausts its budget.

Unsupported outer operators can retain the existing specialized reductions and
contain independently eligible MBA children. Replacing the algebraic backend
does not remove contextual analysis or the existing division/comparison and
field-update handling.

This change does not introduce a Python bridge, CLI subprocess, LLVM lifting
pipeline, replacement SMT solver, general equality-saturation engine, or worker
service. Compositional proof-trace export is outside the initial integration.

## Assumption register

| ID | Assumption and dependent behavior | Stress test or falsification probe |
|---|---|---|
| A1 | Candidate generation is untrusted. Replacement requires the existing candidate and independent emitted-expression proof boundaries. All application behavior depends on this. | Inject a false signature fit and a separately corrupted emission; neither reaches mutation. |
| A2 | Normal and deep analysis retain the shared cooperative budgets documented in [MBA_SMT.md](MBA_SMT.md). Admission and cancellation depend on this contract. | Cancel during traversal, signature evaluation, polynomial recovery, verification, and cleanup; record overshoot and reject late results. |
| A3 | Every candidate belongs to an immutable typed snapshot with established operand identity and effect admission. Region extraction and proof reuse depend on this. | Exercise conversions, repeated expressions with different value numbers, explicit read occurrences, intervening writes, and stale generations. |
| A4 | The pinned CoBRA core and adapter can be built with the supported native toolchains. Build integration depends on this; compatibility is unverified until the platform checks pass. | Compile, link, load, and run the adapter on every existing release target. |

## Integration points

Add an SDK-independent adapter at
`src/deobf/analysis/mba_cobra.hpp` and `mba_cobra.cpp`. Its public header exposes
chernobog terms, adapter outcomes, and budget/cancellation inputs; CoBRA types
remain private to the implementation.

Refactor the algebraic candidate interface used by
`mba_smt_synthesis.cpp` and `mba_smt_algebra.cpp` so backend selection covers
both top-level synthesis and nested reconstruction. Updating only
`CandidateSynthesis::run()` is insufficient: nested algebraic rewrites also call
`reconstruct_linear_mba()` directly.

Keep `mba_smt_semantics.cpp`, `rule_verifier.*`, and the microcode/ctree adapters
as proof and effect authorities. CoBRA cannot issue a mutation receipt.
SDK callbacks, live operands, and live database access never enter CoBRA.

```text
Immutable typed snapshot and remaining function budget
                       |
             Existing catalog fast path
                       |
                Unmatched MBA region
                       |
         Cheap existing structural reductions
                       |
             Admission and typed slicing
                       |
                CoBRA candidate
                       |
           Z3 candidate equivalence proof
                       |
          Emit temporary microcode or ctree
                       |
      Independently translate and prove emitted code
                       |
       Recheck generation, effects, cost, deadline
                       |
                 Apply replacement
```

Catalog hits keep their existing width-specific rule proof and concrete
instance verification. The new backend does not create a catalog bypass.

## Typed region extraction

Visit eligible regions bottom-up, with bounded traversal and memoization within
one snapshot. Each CoBRA invocation uses one result width. Initial admission
covers the existing scalar widths of 8, 16, 24, 32, 40, 48, 56, and 64 bits;
the independent fixture matrix includes all of them.

| Typed operation | CoBRA representation |
|---|---|
| Constant | `Expr::Constant(value & width_mask)` |
| Stable scalar leaf | Interned `Expr::Variable(index)` |
| Add, Mul, And, Or, Xor | Corresponding CoBRA operation |
| Sub | Add with Negate on the right operand |
| Neg, Not | Negate, BitwiseNot |
| Shl by a constant smaller than the width | Multiplication by the modular power of two |
| Logical Shr by a constant smaller than the width | `Expr::LogicalShr` |
| Shl or logical Shr by a constant at least the width | Zero, following the existing typed shift semantics |
| ZeroExtend, SignExtend, Low, High | Typed boundary; preserve the conversion/extraction |
| Sar, variable shift, division, comparison, other unsupported operator | Typed boundary; eligible children can be simplified separately |
| Explicit load or effectful expression | Existing effect admission controls the region; no generic address-based interning |

Shift counts retain the existing byte-width interpretation. Constant handling
must not execute an undefined host shift, including `1ULL << 64`.

A boundary is represented as an opaque variable of the region width only when
its typed result is a valid pure input at that site. Recurse into its operands
at each operand's native width, prove any child rewrite, and preserve the
enclosing conversion. Do not move arithmetic across truncation or extension.

Interning keys include the snapshot generation, operand kind, width, and the
existing value-number/owner identity. Structural hashes are lookup accelerators;
collisions require exact identity comparison. Explicit load occurrences retain
the existing read-occurrence and memory-version contracts. Equal addresses alone
do not justify sharing, eliminating, or duplicating reads. Volatile, unresolved,
or unsupported effects remain excluded.

For a pure zero-extension boundary `u = zext(y, low_width, region_width)`, map
the synthetic variable back to the complete original typed term `u`, and expose
it to CoBRA as `V_u & low_mask`. This conveys known upper zero bits without
changing the width of arithmetic inside `y`. Construct the mask without an
undefined host shift. Other known-bit constraints can be added later through
separately verified encodings.

Count the tree occurrences that lowering will materialize, not just unique
nodes in the shared chernobog term DAG. Stop before cloning a DAG into an
oversized CoBRA tree.

## CoBRA invocation and reconstruction

Use the actual pinned interface:

```text
cobra::Options
cobra::Simplify(signature, variable_names, input_expr, options)
    -> cobra::Result<cobra::SimplifyOutcome>
```

Set `bitwidth` to the region width, `max_vars` to the admitted profile limit,
and `spot_check` to true. Compute any supplied signature according to CoBRA's
own Boolean-input convention, using its evaluator. Do not pass chernobog's
all-one-word signature as though it were CoBRA's zero/one signature.

Assign deterministic unique names to interned leaves. Reconstruct every output
variable through `outcome.real_vars[expr.var_index]` and the original name-to-term
table. Reject an invalid index, duplicate/unknown mapping, malformed expression,
unsupported node, width mismatch, or oversized output.

Require a successful result, `kind == kSimplified`, a non-null expression, and
`verified == true` for the configured spot-check path. This flag records a
candidate filter, never formal acceptance. A constant output with no remaining
variables is valid input to the proof gates.

Measure cost after restoring opaque typed terms. Neither a shorter rendered
string nor a smaller CoBRA tree establishes a cheaper chernobog expression.
Require strict reduction under the existing site-specific cost model and again
under the emitted representation's cost model.

The adapter algorithm is:

```text
for each admitted region in bounded bottom-up order:
    check snapshot, effects, widths, raw leaves, expanded nodes, and budget
    lower the region and retain its typed leaf map
    run CoBRA with the inherited deadline and cancellation callback
    validate the outcome and restore typed leaves through real_vars
    reject unless candidate cost decreases and candidate equality is proved
    emit temporary operands; independently translate and prove their equality
    recheck snapshot, effects, emitted cost, cancellation, and deadline
    apply once; invalidate this snapshot's proposals
```

For N materialized region nodes, extraction and reconstruction require expected
O(N) time with hash-based interning and O(N) adapter storage. Adversarial hash
collisions can make exact identity comparisons take O(N^2) time; the same
cancellation and node limits apply. The linear signature/transform stage takes
O((N + t) * 2^t) work and O(N + 2^t) storage. These bounds do not describe all
CoBRA polynomial/semilinear passes or Z3 proof complexity.

## Admission and cooperative budgets

| Initial policy | Normal | Deep |
|---|---:|---:|
| Existing function analysis budget | 1,000 ms | 30,000 ms |
| Raw interned leaves per invocation | At most 8 | At most 12 |
| Materialized input tree nodes | At most 512 | At most 512 |
| Expression depth | At most 64 | At most 64 |
| Reconstructed output tree nodes | At most 512 | At most 512 |

These are initial admission policies, not throughput predictions. Tighter
existing caller/site limits take precedence. The function's existing ctree
reservation and per-expression limits remain effective; a nested solve does not
receive a fresh function budget.

Check raw variable, node, depth, width, and cancellation limits before building
the CoBRA tree or allocating a signature. `Options::max_vars` alone does not
provide this pre-allocation admission gate. A vector of 64-bit signature entries
uses `8 * 2^t` B: 2,048 B at eight variables and 32,768 B at twelve. These counts
exclude ASTs, alternative candidates, grids, matrices, and allocator overhead.

Maintain a small recorded patch series against the pinned upstream revision
for cooperative cancellation. Add one scoped budget context carrying the
remaining invocation deadline and the existing cancellation callback. Nested
calls inherit the earlier deadline. If TLS carries this context, an RAII guard
restores the previous context on every exit, including exceptions.

Check cancellation during worklist dispatch, input/signature construction, ANF
and coefficient transforms, auxiliary-variable elimination, polynomial grids,
finite differences, modular linear solving, decomposition/lifting, full-width
checks, cloning, hashing, and recursive structural processing. Check allocation
dimensions for overflow and configured resource limits before allocation.
Propagate cancellation to the adapter as `Exhausted`; never publish an
incomplete candidate as successful.

Reserve remaining budget for both proof boundaries and emission using the
existing caller/site budget policy. If no verification budget remains, skip
candidate generation. Charge extraction, CoBRA, reconstruction, proofs, emission,
and cleanup to the existing function accounting. Check cancellation and remaining
budget after each stage and immediately before mutation.

Do not claim hard preemption, a fixed cancellation latency, or a process-wide
memory bound. Uninterrupted allocations, library operations, SDK work, cleanup,
and scheduling can overshoot. Measure this overshoot explicitly. Detached work
that continues after a timeout is excluded from this design.

## Proof and mutation contract

The candidate proof compares the restored typed candidate with the original
snapshot term through the existing Z3 semantics. Preserve the existing distinction
between unconditional equalities and site-specific proofs under validated path
facts. Only unconditional proved equalities enter the reusable rewrite cache;
contextual receipts retain their exact site and domain.

Emit into temporary owned operands. Independently translate the actual emitted
microcode or ctree, including casts, promotions, widths, and loads, and prove it
equal to the original snapshot expression. Reuse the current emission verification
paths; textual rendering and CoBRA's evaluator cannot replace this boundary.

Only UNSAT mismatch checks authorize either proof boundary. SAT, UNKNOWN,
infeasible/unsupported sites, malformed inputs, exhausted budgets, or unsupported
effects preserve the original. Immediately before mutation, validate the snapshot
generation, operand/effect applicability, final cost, cancellation state, and
remaining budget. A proof that finishes after the budget is exhausted cannot
authorize a new CoBRA rewrite.

Destroy proposal state and invalidate snapshot-scoped caches after mutation.
No CoBRA AST, variable map, or proof receipt survives into another generation.

## Build and backend selection

Pin CoBRA under `vendor/cobra` using the repository's explicit source-revision
checks. Record local patches separately from the upstream revision. Pin Abseil
and Highway to exact revisions and retain their license notices. CoBRA core is
Apache-2.0; upstream benchmark datasets have separate provenance/licenses and
are not production library dependencies.

Build `cobra-core` as a position-independent static library and compile its
private adapter with C++23. The public adapter header stays compatible with the
existing project standard. Scope compiler-standard and warning settings to
these targets; do not import upstream directory-wide flags into unrelated code.
Use the same C++ runtime, architecture, deployment target, and Windows runtime
selection as the plugin. Build only the core and required dependencies; LLVM,
the CoBRA CLI, and CoBRA's separate Z3 verifier are not plugin dependencies.

Introduce an internal backend selector `CHERNOBOG_MBA_BACKEND=legacy|cobra` for
comparison and rollback. Before release acceptance, legacy remains the default;
after acceptance, cobra becomes the default algebraic backend. An invalid value
uses the current release default and records a diagnostic. The existing
`CHERNOBOG_MBA_SMT=0` disable behavior remains intact. Building without CoBRA
retains the legacy backend and reports an unavailable explicit cobra selection.

## Diagnostics and validation

Extend existing MBA statistics without changing the meaning of current fields.
Record backend/revision, admitted/rejected regions, rejection reason, raw leaf
count, materialized nodes, input/output cost, CoBRA outcome, spot-check result,
each proof verdict, actual applications, cancellation stage, and deadline
overshoot. Record extraction, candidate, reconstruction, proof, emission, and
cleanup elapsed times in ns; reports may convert them to ms. Existing bounded
query/evidence capture policies continue to apply.

| Validation group | Required evidence |
|---|---|
| Adapter semantics | Exhaustive small-width replay and independent word evaluator checks at every admitted width; boundary wraparound, sign extension, extraction, and oversized shifts |
| Algebraic coverage | Linear, masked semilinear, polynomial, mixed-product, constant, and nested MBA fixtures with proved smaller outputs for a designated positive set |
| Candidate rejection | `x*(x+1)` false zero fit; deliberately corrupted candidate; sparse-disagreement and nonlinear signature collisions |
| Emission rejection | Correct candidate followed by an injected wrong cast, shift, width, destination, or load occurrence; no mutation |
| Identity and effects | Distinct value numbers, hash collisions, equal-address independent reads, intervening stores, volatile operands, and stale generations |
| Remapping | Elimination of first/middle/last variables, reordered support, zero variables, and invalid returned mappings |
| Budgets and resource handling | Deterministic cancellation injection in each stage; nested/TLS restoration; pre-allocation rejection; overflow rejection; overshoot and peak-memory measurements |
| Existing behavior | Catalog, nested MBA, masks, caller context, field presentation, symbolic executor, invariant, and memory regressions |
| Shipped path | Installed-plugin normal/deep captures, independently compiled pseudocode/native oracle checks, preserved effects, and installation identity verification |
| Platforms | Native build/load evidence for existing release targets; cross-compilation evidence reported separately |

Compare legacy and CoBRA on identical immutable fixtures, IDA versions, analysis
profiles, and machine conditions. Report solved/applied counts, proof outcomes,
phase timing distributions, maximum observed overshoot, and peak memory. Existing
required reductions must remain covered by CoBRA or the retained specialized
paths. An expression whose proof times out remains unchanged.

Upstream aggregate simplification rates are not acceptance thresholds for
chernobog. Runtime improvement and corpus coverage are unknown until measured.
Do not require a global speedup as a mathematical property of a smaller candidate.

## Implementation sequence and completion gates

1. Add pinned core/dependencies and the private C++23 build boundary. Establish
   native build/load compatibility before changing the default backend.
2. Implement typed slicing, pre-allocation admission, interning, remapping, and
   bounded reconstruction with SDK-independent fixtures.
3. Add and validate cooperative cancellation throughout the invoked core paths.
4. Connect backend selection to top-level and nested MBA candidate generation,
   preserving both proof boundaries and the existing effect/cost checks.
5. Add diagnostics, fault injection, corpus comparisons, and installed-plugin
   validation; then promote the CoBRA default through the repository workflow.

Completion requires the validation matrix above, exact dependency/patch
provenance, preserved existing required fixture behavior, and verified plugin
installation. Backend integration is incomplete while either proof boundary,
generation validation, or cancellation propagation is bypassed.

## Bounded scope expansion

| Impact | Opportunity or risk and boundary |
|---|---|
| High | Shared-term DAGs can expand during tree cloning. Admission counts materialized occurrences and reconstruction enforces the same bound. |
| High | Faster candidates can still leave expensive UNSAT proofs. Keep the remaining-budget gate and report candidate/proof time separately. |
| Medium | Masking zero-extension atoms can recover simplifications lost by unconstrained abstraction. Preserve the original typed substitution and test its proof boundary. |
| Medium | Subtree proof reuse can reduce repeated work. Cache only proved equalities within the exact snapshot/domain; intermediate CoBRA lemma export is deferred. |
| Low | Backend comparison can expose corpus-specific gaps. Keep rollback selection internal to the existing analysis controls. |

## Provenance and quality gates

Current behavior and integration points are defined by [MBA_SMT.md](MBA_SMT.md),
[typed terms](../src/deobf/analysis/mba_smt.hpp),
[candidate synthesis](../src/deobf/analysis/mba_smt_synthesis.cpp),
[nested algebra](../src/deobf/analysis/mba_smt_algebra.cpp),
[semantic verification](../src/deobf/analysis/mba_smt_semantics.cpp), and
[concrete rule verification](../src/deobf/rules/rule_verifier.h).

Pinned upstream primary sources:

- [Public simplifier interface](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/include/cobra/core/Simplifier.h)
- [Expression vocabulary](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/include/cobra/core/Expr.h)
- [Outcome and variable mapping](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/include/cobra/core/SimplifyOutcome.h)
- [Core dependencies](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/lib/core/CMakeLists.txt)
- [Build configuration](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/CMakeLists.txt)
- [Worklist and admission behavior](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/lib/core/Orchestrator.cpp)
- [Full-width candidate checks](https://github.com/trailofbits/CoBRA/blob/af44b8ad7c8ec548d431463475e93b0118e77a29/lib/core/SignatureChecker.cpp)

Specification quality gates: descriptive engineering scope (QG1); assumptions
and falsification probes (QG2); component ownership and acceptance coverage
(QG3); explicit widths, byte counts, and cooperative time units (QG4); failure
and boundary behavior (QG5); repository and pinned upstream provenance (QG6);
impact-bounded expansion (QG7). Implementation and runtime gates remain separate
from completion of this specification.
