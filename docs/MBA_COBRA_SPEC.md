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
| A1 | The current solver, microcode/ctree handlers, function accounting, and dependency checks are the integration baseline. The infrastructure changes below depend on this baseline. | Reinspect the implementation branch and rerun the compiled expiry/cancellation probe before merge. |
| A2 | Cancellation and scheduling delays can occur after the final host poll, during a solver query, or before mutation. Strict acceptance and cooperative budgets depend on this timing model. | Inject post-poll cancellation and a 150 ms pause under a 100 ms allowance; require `Exhausted` and zero microcode/ctree mutations. |
| A3 | The preverified legacy fallback in [MBA_SMT.md](MBA_SMT.md#legacy-fallback-and-proposed-strict-acceptance) remains intentional. Only its deadline exception is preserved. | Exhaust later synthesis and retain the unchanged, preverified legacy fallback; cancellation, stale snapshots, frame mismatches, and CoBRA-origin fallbacks must still reject. |
| A4 | Native compatibility and runtime performance are unknown until measured. Default promotion depends on native build/load and paired backend evidence. | Run both profiles and both backends on every existing release target before promotion; report cross-builds separately. |
| A5 | Candidate generation is untrusted. All applications require candidate and independent emitted-expression proof boundaries. | Inject a false signature fit and a separately corrupted emission; neither reaches mutation. |
| A6 | Typed snapshots establish operand identity, effect admission, and snapshot-specific mutation identity. Region extraction and proof reuse depend on these facts. | Exercise conversions, distinct value numbers, explicit read occurrences, intervening writes, same-generation edits, and stale generations. |
| A7 | The final eligibility check and swap run serially on the owning IDA thread, without intervening callbacks or yielding. The cooperative commit contract depends on this ownership. | Force reentrant or intervening edits before the final check and reject their receipts; exercise cancellation arriving on either side of the final poll. |
| A8 | Frozen fixtures use the exact typed modular expressions and counting rules below. Their reference reductions depend on those definitions. | Independently evaluate boundary inputs and byte domains, verify the reference identities with Z3, and check actual emitted code with unsigned native oracles and sanitizers. |

## Integration points

Add an SDK-independent adapter at
`src/deobf/analysis/mba_cobra.hpp` and `mba_cobra.cpp`. Its public header exposes
chernobog terms, adapter outcomes, and budget/cancellation inputs; CoBRA types
remain private to the implementation.

Use the existing `chernobog::mba_smt` namespace and `Term` type from
`mba_smt.hpp`. `Term` is `std::shared_ptr<const Expression>`; no existing
`TypedSnapshot` or `TypedTermRef` abstraction is assumed. Define any additional
snapshot-view structure before storing it by value. A forward declaration is
insufficient for a by-value data member.

The public header excludes CoBRA, Abseil, Highway, and `<expected>` headers and
must compile in a C++17 consumer independently of the C++23 implementation.
Budget callbacks and adapter statuses use standard types. Allocation failures
and recoverable upstream exceptions preserve the original expression. Declare
the generator `noexcept` only if its implementation catches and translates all
such exceptions into an adapter failure without allocating on the failure path.

Refactor the algebraic candidate interface used by
`mba_smt_synthesis.cpp` and `mba_smt_algebra.cpp` so backend selection covers
both top-level synthesis and nested reconstruction. Updating only
`CandidateSynthesis::run()` is insufficient: nested algebraic rewrites also call
`reconstruct_linear_mba()` directly.

Keep `mba_smt_semantics.cpp`, `rule_verifier.*`, and the microcode/ctree adapters
as proof and effect authorities, with the strict acceptance and structural frame
checks specified below. Reusing them unmodified is insufficient: the current
solver wrapper polls before queries, successful mismatch proofs can return
`Verified` without a post-query budget check, and emitted-value proofs do not
independently compare destination identity. These checks are required integration
work, not descriptions of implemented behavior. CoBRA cannot issue a mutation
receipt.
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
       Check frame, snapshot, effects, cost, budget
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
existing value-number/owner identity. Snapshot identity also distinguishes edits
within one lifecycle generation; that generation alone is not a mutation epoch.
Structural hashes are lookup accelerators;
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

Validate the scalar width before calling a mask helper; mapping every width
greater than or equal to 64 to an all-one mask does not admit invalid widths.
Exercise semilinear partitioning, signature evaluation, and full-width checks
at 24, 40, 48, and 56 bits as well as the other admitted widths.

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

Assign deterministic unique names to interned leaves. At the pinned revision,
`outcome.real_vars` is `std::vector<std::string>` and `Expr::var_index` is
`uint32_t`. It is a compact-index-to-name map, not an integer permutation of
the original leaf indices. Bounds-check `expr.var_index`, obtain the name from
`outcome.real_vars[expr.var_index]`, and look that name up in the original
name-to-term table. Reject an invalid index, duplicate/unknown mapping, malformed
expression, unsupported node, width mismatch, or oversized output. Do not infer
the original index from the compact index or assume an identity ordering on a
fast path.

Require a successful result, `kind == kSimplified`, a non-null expression, and
`verified == true` for the configured spot-check path. This flag records a
candidate filter, never formal acceptance. A constant output with no remaining
variables is valid input to the proof gates. No variable node is valid when
`real_vars` is empty; a constant expression does not require a dummy variable.

Validate the entire returned mapping before removing unused entries. Build a
canonical adapter support map from the variables actually used by the validated
output, then restore typed leaves through that map. A constant has empty
canonical support even if the raw upstream `real_vars` vector retained unused
names. Keep the raw vector in diagnostics; canonicalization cannot repair an
invalid index, duplicate/unknown name, or malformed expression.

After restoring typed leaves, remove structurally redundant masks on pure
zero-extension terms before measuring candidate cost. For
`zext(y) & mask`, the AND is redundant when the width-masked `mask` contains
every bit of the extension's `low_mask`. Otherwise retain it. This prevents the
injected constraint wrapper from inflating the restored expression's cost.
The normalized candidate still passes the candidate proof gate; this fold does
not create a proof receipt by itself.

Measure cost after restoring opaque typed terms. Neither a shorter rendered
string nor a smaller CoBRA tree establishes a cheaper chernobog expression.
Require strict reduction under the existing site-specific cost model and again
under the emitted representation's cost model.

The adapter algorithm is:

```text
for each admitted region in bounded bottom-up order:
    check snapshot, effects, widths, raw leaves, expanded nodes, and site budget
    lower the region and retain its typed leaf map
    run CoBRA within the reserved candidate deadline and inherited cancellation
    validate the outcome and restore typed leaves through real_vars
    reject unless candidate cost decreases and candidate equality is proved
    emit temporary operands; validate their frame and independently prove equality
    check frame, snapshot, effects, and emitted cost; poll cancellation
    sample the clock and recheck snapshot identity without callbacks or yielding
    reject cancellation, stale state, or an expired strict deadline
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

### Deadline interface and site reservation

Extend `SolverSession` with the following C++17-compatible interface. The clock
accessors allocate nothing and are `noexcept`; arbitrary cancellation callbacks
do not inherit that exception guarantee. A callback failure preserves the original.

```cpp
std::chrono::steady_clock::time_point deadline() const noexcept;
std::chrono::nanoseconds remaining_budget(
    std::chrono::steady_clock::time_point now) const noexcept;
bool is_deadline_expired(
    std::chrono::steady_clock::time_point now) const noexcept;
bool is_cancelled();
```

`remaining_budget(now)` clamps negative durations to zero. Expiry means
`now >= deadline()`. Poll cancellation before sampling `now`, so time spent in
the callback cannot escape the deadline check. Deadlines use the existing charged
analysis accounting: the function's excluded callee-decompiler work and its
microcode/ctree partition remain as documented in [MBA_SMT.md](MBA_SMT.md).
The ctree reservation is not a reservation for the two proof boundaries.

For each site, obtain remaining charged phase time `B_rem` after polling
cancellation and sampling `now`. Let `B_expr` be any active expression limit,
or `B_rem` if no tighter limit applies. All calculations below use integer ns;
division truncates toward zero and deadline construction checks duration overflow.

```text
B_site       = min(B_rem, B_expr)
B_verify_min = 5,000,000 ns
if B_site < 10,000,000 ns:
    skip CoBRA with kBudgetExhaustedPreFlight
B_cand       = min(B_site / 2, B_site - B_verify_min)
D_site       = now + B_site
D_cand       = min(now + B_cand, inherited candidate deadline, D_site)
```

An absent inherited candidate deadline imposes no additional cap. Extraction,
lowering, signature construction, CoBRA generation, restoration, and associated
candidate cleanup consume `B_cand`; do not start a fresh timer at `Simplify()`.
Reject a result reaching `D_cand` or `D_site`, including a result delayed during
cleanup. If a candidate completes in time, its candidate proof, temporary emission,
and emitted-expression proof share the remaining `D_site` allowance sequentially.
Each solver timeout remains capped by its query limit and the remaining site time.
Nested calls inherit the earlier deadline and restore scoped/TLS state on every
exit. Charge all stages and cleanup to the existing function accounting.

At the 10 ms admission boundary, `B_cand` is 5 ms and at least 5 ms of allowance
is reserved for verification and emission if candidate work returns in time.
This is an allowance floor, not a guarantee of two completed proofs. Cooperative
overshoot can exhaust it; late results cannot authorize a CoBRA replacement.
The preflight rule applies to CoBRA generation, not catalog or retained specialized
reductions. Check cancellation and remaining budget after every stage.

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
effects preserve the original. Solver equality, structural applicability, and
permission to commit within the budget are separate predicates.

### Post-proof and commit eligibility

Every CoBRA-originated verification request, including nested reconstruction,
uses strict-budget acceptance. Other requests can explicitly select the same
policy. Immediately after an UNSAT mismatch result, poll cancellation and then
sample the clock. Cancellation or expiry converts acceptance to `Exhausted`.
Record the post-proof stage (`kPostProofExpiry`), its cancellation/deadline cause,
and `deadline_overshoot_ns = max(0 ns, now - deadline())`. Keep the observed UNSAT
solver verdict separate from the failed acceptance verdict. The final commit
check also covers solver destruction, emission, and cleanup after this poll.

After both proof boundaries, independently validate the emitted frame, effects,
final cost, lifecycle generation, snapshot mutation identity, and the exact source
expression/parent target against the receipt's domain. A lifecycle generation
comparison alone does not detect an edit within that generation. Complete SDK
callbacks and structural work before the final cancellation poll. Then sample
the clock and recheck snapshot identity using non-reentrant operations immediately
before swapping on the owning IDA thread. No callbacks, yielding, or solver work
may intervene between this final eligibility check and the swap.

This is a cooperative commit gate, not atomic cancellation through mutation
completion. A signal arriving after the final poll may follow the commit. The
contract does not introduce a synchronized cancellation-producer/commit protocol.
Reject stale state or cancellation for every replacement. Reject an expired
deadline with `kPostProofDeadlineOrCancel` unless the receipt is the specifically
tagged, preverified legacy fallback described in
[MBA_SMT.md](MBA_SMT.md#legacy-fallback-and-proposed-strict-acceptance).
That exception bypasses only expiry: both proofs must have been accepted before
expiry, and source/context, frame, effects, cancellation, and cost checks must
still pass. A CoBRA proposal cannot acquire the exception by being saved before
later search exhausts its allowance.

### Structural emission invariant

Add `verify_emitted_instruction_frame()` alongside the emitted-value proof.
For microcode, independently compare destination operand kind, exact width,
register/value-number identity, stack/local owner and offset, global address,
and applicable nested operand structure. Compare source EA and retained
instruction properties, including tail/assertion flags. Reapply effect admission;
no new memory, control-flow, or implicit condition-code effects are allowed.
Proved changes of value opcode remain permitted; the check does not require
identical opcodes or forbid an admitted scalar comparison merely because it uses
an `m_set*` instruction.

For ctree, bind the receipt to the replacement position and its parent. Preserve
the parent assignment target/lvalue address, surrounding effects, and root
expression type contract, including width, signedness, and qualifiers. Internal
casts and operators may change only through the typed proof and existing emission
rules. Do not compare an SDK object by pointer alone or treat an RHS equality as
a proof about the assignment destination. Reject a changed frame with
`kEmittedDestinationOrFrameMismatch` before mutation. Frame traversal obeys the
existing node/depth and cancellation limits.

Destroy proposal state and invalidate snapshot-scoped caches after mutation.
No CoBRA AST, variable map, or proof receipt survives into another generation.

## Build and backend selection

Pin CoBRA under `vendor/cobra` with a clean-tree provenance check that accounts
for the recorded local patches. The proposed `vendor/cobra.provenance.cmake`
manifest contains:

| Field | Required value |
|---|---|
| `COBRA_UPSTREAM_BASE_COMMIT` | `af44b8ad7c8ec548d431463475e93b0118e77a29` |
| `COBRA_PATCH_SERIES` | Ordered repository-relative patch paths under `patches/cobra/`, each paired with its exact SHA-256 digest |
| `COBRA_EXPECTED_TREE_HASH` | Git tree object ID produced by replaying that exact series on the upstream base |

During configuration, verify every patch digest and independently replay the
series on the base using an isolated temporary Git index/object store in build
storage. Compare the replayed tree with both `COBRA_EXPECTED_TREE_HASH` and
`git rev-parse HEAD^{tree}` in `vendor/cobra`. Also require the base to be an
ancestor of vendor HEAD and require `git status --porcelain --untracked-files=all`
to be empty. Net changed paths from base to HEAD must be confined to paths touched
by the recorded series, accounting for additions, removals, and renames. Matching
only digests or changed path names does not prove that the patches produced HEAD.
Missing objects, replay failures, extra changes, or a dirty tree fail configuration.
Replay does not modify the source checkout or its index.

The Git tree object ID uses the repository's object format; it is distinct from
patch-file SHA-256. Different commit metadata is acceptable when the base ancestry
and exact replayed tree match. Pin Abseil and Highway separately to exact,
unmodified upstream commit SHAs and require clean worktrees. Include the manifest,
patches, dependency pins, and replayed tree identity in build provenance. Their
actual pins and patched tree ID are established during implementation, not
fabricated in this proposed specification. Retain all license notices. CoBRA core
is Apache-2.0; upstream benchmark datasets have separate provenance/licenses and
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
overshoot. Include strict/legacy receipt origin, frame rejection, snapshot
identity, raw variable mapping, canonical support, and solver-versus-acceptance
verdicts without changing existing legacy counter meanings. Record extraction,
candidate, reconstruction, proof, emission, and
cleanup elapsed times in ns; reports may convert them to ms. Existing bounded
query/evidence capture policies continue to apply.

| Validation group | Required evidence |
|---|---|
| Adapter semantics | Exhaustive small-width replay and independent word evaluator checks at every admitted width; boundary wraparound, sign extension, extraction, oversized shifts, and restored zero-extension masks before cost comparison |
| Algebraic coverage | All 42 frozen positive fixtures below, with attributed CoBRA candidates, accepted proofs, and smaller actual emitted replacements in both profiles |
| Candidate rejection | Legacy all-one-word collision `x*(x+1)` and CoBRA zero/one collision `x*(x-1)` proposed as false zeroes; deliberately corrupted candidates; sparse-disagreement and nonlinear collisions |
| Emission rejection | Correct candidate followed by an injected wrong cast, shift, width, destination, or load occurrence; no mutation |
| Identity and effects | Distinct value numbers, hash collisions, equal-address independent reads, intervening stores, volatile operands, stale generations, and edits within the same generation |
| Remapping | Elimination of first/middle/last variables, reordered support, zero variables, and invalid returned mappings |
| Budgets and resource handling | Deterministic cancellation injection in each stage; nested/TLS restoration; pre-allocation rejection; overflow rejection; overshoot and peak-memory measurements |
| Existing behavior | Catalog, nested MBA, masks, caller context, field presentation, symbolic executor, invariant, and memory regressions |
| Shipped path | Installed-plugin normal/deep captures, independently compiled pseudocode/native oracle checks, preserved effects, and installation identity verification |
| Platforms | Native build/load evidence for existing release targets; cross-compilation evidence reported separately |
| Header and failure isolation | Standalone C++17 public-header consumer, private C++23 implementation, and injected allocation/upstream exceptions converted to unchanged results |

Acceptance faults include cancellation immediately after the final pre-query
poll, a 150 ms injected pause under a 100 ms allowance, cancellation/expiry after
UNSAT or during cleanup, and stale state before either mutation site. Require
`Exhausted` for late strict verification and zero microcode/ctree mutations.
The baseline transient core probe observed late `Verified` at 155 ms in the pause
case; 155 ms is an observation, not a portable timing assertion. Use a controllable
clock/scheduler seam for deterministic acceptance tests. Separately test signals
arriving after the final commit poll according to the cooperative contract.

Exercise site allowances of 9,999,999 ns, 10,000,000 ns, and 10,000,001 ns,
expiry exactly at the deadline, earlier inherited deadlines, and nested/TLS
restoration after cancellation and exceptions. A legacy fallback verified before
expiry remains usable after later search exhausts time; cancelling it or changing
its frame/snapshot must reject it. New CoBRA receipts remain strict.

Inject a same-width different destination register, a wrong width, changed
instruction properties/source EA, and changed ctree parent lvalue/type. Require
the frame rejection reason and zero mutations even when RHS equality is UNSAT.
Provenance tests cover changed patch bytes, an incorrect replay tree, vendor edits
within otherwise permitted paths, extra paths, and dirty sources. A matching tree
with different commit metadata must pass if ancestry and patch replay also pass.

### Frozen positive fixture set

This section freezes 42 cases in six categories. A later implementation
transcribes them into `tests/fixtures/mba_cobra_positive_manifest.json` with each
ID's exact typed input AST, typed reference AST, widths, profile limits, counting
rules, and thresholds. Freeze that manifest and its source hash before collecting
promotion results; do not substitute easier inputs or relax thresholds in response
to failures. The definitions here, not a backend's rendered text, identify the cases.

All variables are unconstrained at their stated widths, and every arithmetic
operation wraps at its own result width. Distinct names denote distinct variables.
Define the following AST constructors at width `w`:

```text
M_w         = 2^w - 1
A_w         = sum(2^j for even j in [0, w))
S_w(a,b)    = (a ^ b) + (2 * (a & b))
J_w(a)      = (a + ~a) + 1
L_w(x,y)    = (((x | y) + (x & y)) - x) - y
P_w(u)      = (u & A_w) + (u & (M_w ^ A_w))
R_w(x,y,z)  = (x + y) + z
```

All constructor constants have width `w`. `M_w`, `A_w`, and `M_w ^ A_w` are
precomputed constant literals, not runtime mask-construction ASTs. Construct them
without undefined host shifts. The other helpers expand literally into typed
terms; they are not opaque calls or pre-simplified identities. Sums associate
left, `a^2` as a power means `a*a`, and
`a^3` as a power means `(a*a)*a`; table degree parameters use those multiplications,
not XOR. Materialized nodes count every occurrence, including constants and
conversions, even when the input uses shared DAG nodes. Reference ASTs are fixed
oracles; a backend can produce a different equivalent output meeting every gate.

Input families and their reference ASTs are:

| Family | Exact input | Reference |
|---|---|---|
| LIN | Start with `S_w(S_w(x,y),z)`; for `j=4..t`, append `+ J_w(q_j)` in increasing `j` | `R_w(x,y,z)` |
| SEMI | `P_w(u)`; `u=x:w` for `native`, or `u=zext(y:w-8 -> w)` for `zext` | The complete typed term `u` |
| POLY | Degree `d` power of `S_w(x,y)` expanded as above | Same expanded power of `(x+y)` |
| MIXP-A | `(x ^ y) * ((x & z) + (x \| z))` | `(x ^ y) * (x + z)` |
| MIXP-B | `S_w(x,y) * S_w(z,q)` | `(x+y) * (z+q)` |
| OPAQ | `L_w(x,y) + k`, including the explicit addition when `k=0` | `Constant(k,w)` |
| NEST-Z | `S_W(zext(S_w(x,y):w -> W), z:W)` | `zext((x+y):w -> W) + z` |
| NEST-S | `S_W(sar_W(sext(S_w(x,y):w -> W),1), z:W)` | `sar_W(sext((x+y):w -> W),1) + z` |

For NEST, `x` and `y` have inner width `w`, `z` has outer width `W`, and the
SAR count is the 8-bit constant one. The `1` is a bit shift count, not a byte
displacement. NEST-Z and NEST-S preserve their conversion and SAR boundaries.

The following term costs use the current core model: constants/variables cost
zero; each operator, including a conversion, costs one. The node column counts
the reference AST before SDK emission. Emitted costs use the existing site model
on both sides; ctree integer casts cost zero. Do not compare costs from different
models or count CoBRA's opaque variables instead of the restored typed terms.

| Fixture ID | Width `w` or `w -> W` | Family and parameter | Input term cost | Reference term cost | Reference nodes |
|---|---|---|---:|---:|---:|
| POS-LIN-01 | 8 | LIN, t=3 | 12 | 2 | 5 |
| POS-LIN-02 | 16 | LIN, t=4 | 16 | 2 | 5 |
| POS-LIN-03 | 24 | LIN, t=5 | 20 | 2 | 5 |
| POS-LIN-04 | 32 | LIN, t=6 | 24 | 2 | 5 |
| POS-LIN-05 | 40 | LIN, t=7 | 28 | 2 | 5 |
| POS-LIN-06 | 48 | LIN, t=8 | 32 | 2 | 5 |
| POS-LIN-07 | 56 | LIN, t=7 | 28 | 2 | 5 |
| POS-LIN-08 | 64 | LIN, t=8 | 32 | 2 | 5 |
| POS-SEMI-01 | 8 | SEMI, native | 3 | 0 | 1 |
| POS-SEMI-02 | 16 | SEMI, zext | 5 | 1 | 2 |
| POS-SEMI-03 | 24 | SEMI, native | 3 | 0 | 1 |
| POS-SEMI-04 | 32 | SEMI, zext | 5 | 1 | 2 |
| POS-SEMI-05 | 40 | SEMI, native | 3 | 0 | 1 |
| POS-SEMI-06 | 48 | SEMI, zext | 5 | 1 | 2 |
| POS-SEMI-07 | 56 | SEMI, native | 3 | 0 | 1 |
| POS-SEMI-08 | 64 | SEMI, zext | 5 | 1 | 2 |
| POS-POLY-01 | 8 | POLY, d=2 | 9 | 3 | 7 |
| POS-POLY-02 | 16 | POLY, d=3 | 14 | 5 | 11 |
| POS-POLY-03 | 24 | POLY, d=2 | 9 | 3 | 7 |
| POS-POLY-04 | 32 | POLY, d=3 | 14 | 5 | 11 |
| POS-POLY-05 | 40 | POLY, d=2 | 9 | 3 | 7 |
| POS-POLY-06 | 48 | POLY, d=3 | 14 | 5 | 11 |
| POS-POLY-07 | 56 | POLY, d=2 | 9 | 3 | 7 |
| POS-POLY-08 | 64 | POLY, d=3 | 14 | 5 | 11 |
| POS-MIXP-01 | 16 | MIXP-A | 5 | 3 | 7 |
| POS-MIXP-02 | 16 | MIXP-B | 9 | 3 | 7 |
| POS-MIXP-03 | 32 | MIXP-A | 5 | 3 | 7 |
| POS-MIXP-04 | 32 | MIXP-B | 9 | 3 | 7 |
| POS-MIXP-05 | 64 | MIXP-A | 5 | 3 | 7 |
| POS-MIXP-06 | 64 | MIXP-B | 9 | 3 | 7 |
| POS-OPAQ-01 | 8 | OPAQ, k=0 | 6 | 0 | 1 |
| POS-OPAQ-02 | 16 | OPAQ, k=0x5A | 6 | 0 | 1 |
| POS-OPAQ-03 | 32 | OPAQ, k=0 | 6 | 0 | 1 |
| POS-OPAQ-04 | 64 | OPAQ, k=0xA5 | 6 | 0 | 1 |
| POS-OPAQ-05 | 32 | OPAQ, k=M_32 | 6 | 0 | 1 |
| POS-OPAQ-06 | 64 | OPAQ, k=M_64 | 6 | 0 | 1 |
| POS-NEST-01 | 8 -> 64 | NEST-Z | 14 | 3 | 6 |
| POS-NEST-02 | 8 -> 64 | NEST-S | 16 | 4 | 8 |
| POS-NEST-03 | 16 -> 32 | NEST-Z | 14 | 3 | 6 |
| POS-NEST-04 | 16 -> 32 | NEST-S | 16 | 4 | 8 |
| POS-NEST-05 | 32 -> 64 | NEST-Z | 14 | 3 | 6 |
| POS-NEST-06 | 32 -> 64 | NEST-S | 16 | 4 | 8 |

For every case, require an attributed CoBRA candidate (`has_candidate=true`),
accepted UNSAT mismatches at the candidate and actual emitted-expression
boundaries, strict reduction under both term and emitted cost models, and
preserved effects. A catalog hit or retained specialized reduction alone does
not count as a CoBRA success. The fixed raw input costs above precede optimization;
also check strict reduction against the actual unchanged site at application.
Use actual SDK emission for the emitted boundary, not a second term renderer.
Report each exercised emission route and its widths; an unsupported required
case is a failed promotion gate, not a pass or an unreported skip.

LIN outputs have at most seven restored materialized nodes. Their extra raw
inputs cancel, so this bound does not require representing eight surviving
independent inputs in seven nodes. SEMI outputs retain the full typed input and
contain no redundant zero-extension mask after restoration. POLY requires
`2 * C_out <= C_in` separately in both cost models, without floating-point ratios.
MIXP requires strict reduction, with no additional ratio. OPAQ outputs have one
restored node and empty canonical adapter support; raw upstream names remain
subject to validation. NEST requires independently proved inner and outer region
reductions and a proof of the actual emitted complete expression; arithmetic
cannot move across conversions or SAR to satisfy the node/cost target.

During specification planning, a transient independent word evaluator checked
212,992 comparisons: all 65,536 byte pairs for each of POS-POLY-01 and
POS-OPAQ-01, plus 2,048 deterministic word assignments for each other fixture.
For replay, visit the table in order with one Python `random.Random(0xC0B4A)`;
generate each non-exhaustive assignment with `getrandbits(native_width)` in
variable order `x,y,z,q` or `x,y,z,q_4,...,q_t`, omitting absent names. Exhaustive
byte pairs visit `x` then `y` in increasing order and do not consume RNG values.
These checks establish neither CoBRA coverage nor emitted-code equivalence.
The harness was transient; this observation is not a source-hashed validation
receipt and does not update historical artifacts. The implementation must obtain
its own formal and shipped-path evidence for the frozen definitions.

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

Default promotion requires all 42 frozen positives to pass in both normal
(1,000 ms) and deep (30,000 ms) profiles on each existing release target, 100%
rejection of negative fault-injection probes, and zero regressions in existing
required legacy fixtures. These are acceptance criteria, not claims that the
proposed adapter can already meet them. Freeze inputs and thresholds before
measuring; failures keep legacy as the default.

Completion also requires the validation matrix above, exact dependency/patch
provenance, preserved existing required fixture behavior, and verified plugin
installation. Backend integration is incomplete while either proof boundary,
generation validation, or cancellation propagation is bypassed.

## Bounded scope expansion

| Impact | Opportunity or risk and boundary |
|---|---|
| High | Shared-term DAGs can expand during tree cloning. Admission counts materialized occurrences and reconstruction enforces the same bound. |
| High | Faster candidates can still leave expensive UNSAT proofs. Keep the remaining-budget gate and report candidate/proof time separately. |
| High | A lifecycle generation can remain unchanged across an IR edit. Bind receipts to snapshot mutation identity and the exact current source/frame as well. |
| Medium | Patch digests and allowed path names do not establish the patched tree. Independently replay the series and compare its Git tree identity. |
| Medium | Cancellation can arrive after the final poll. State the cooperative commit boundary explicitly; no atomic cancellation guarantee is inferred. |
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
