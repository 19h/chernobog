# Recurrent-switch implementation and proof boundary

The implementation in [recurrent_switch.cpp](../src/deobf/handlers/recurrent_switch.cpp)
removes an encoded recurrent switch at `MMAT_LOCOPT` when every modeled initial
and recurrent transition has a unique explicit switch target. Its supported
dispatcher route contains one-way blocks, unsigned register/constant `m_ja`
self-loop guards, and the switch block's complete prelude. A guard compares
equal-width operands of 8, 16, 32, or 64 bit; the switch selector is a direct
register operand of one of those widths. The classifier still supplies the
candidate, with at least eight explicit normalized switch values required;
classification alone authorizes no rewrite.

The measured reference is `obfuscator_sample!0x82AF0`, whose original LOCOPT
microcode has 610 blocks, a guarded dispatcher at block 11, and a 249-state
switch at block 12. The resulting proof is conditional on the representation
and call/storage contracts registered below. It is not an independent proof
of the machine-code semantics of every external callee.

| Assumption | Dependent results | Stress test or falsification probe |
|---|---|---|
| A1. Hex-Rays CFG edges, operand widths, instruction semantics, and explicit or inferred call-spoil information describe the modeled execution. | Symbolic execution, register induction, and successor proofs. | Completed native/interpreter fixtures compare call-free register, storage, and global effects. Altered call-spoil/callee-memory fixtures remain prospective probes. Unsupported proof opcodes reject the complete plan by source contract. |
| A2. Selector storage represented as direct stack/local operands is private under the executor's call contract; relevant address-taking is visible to the operand visitor. | Retaining those storage bindings across calls. | The escaped-state fixture exposes the slot's address and requires rejection. The visitor is a representation-level escape check, not a whole-program proof against arbitrary computed-pointer aliases or arbitrary callee writes. |
| A3. The enumerated acyclic entry route and bounded case routes cover the admitted CFG topology. | Completeness of rewritten transitions. | Source gates reject middle-prefix entry, cyclic entry provenance, repeated case blocks, unrepresented case transfers, or exceeded bounds, and protect terminal-prefix edges. The frozen middle-entry and entry-cycle fixtures reject during classification, so they do not independently exercise those later proof gates. |
| A4. SDK fictional-address allocation and its reverse mapping satisfy their documented uniqueness/provenance contract. | Distinct copied definitions during lvar allocation. | Record all top-level and nested instruction addresses before/after; map fictional addresses back to original native instruction locations; run microcode verification and final decompilation. |
| A5. The pinned Z3 4.16.0 bit-vector operations and simplification preserve the represented formulas. | Guard exclusion, recurrence identities, and unique selectors. | The bundled-Z3 regression independently proves the observed recurrence formula equals 141 and tests corrupted and unconstrained variants. `UNKNOWN` never establishes a rewrite. |
| A6. A controlled run compares the same input, probe, IDA configuration, and workload, changing the plugin artifact. | Causal timing and output comparisons. | Verify SHA-256 identities and native function chunks before/after each process. Concurrent workload and warm-process state are reported separately from native execution. |

For a path condition `C`, a dispatcher self-edge predicate `G`, selector `S`,
and candidate value `v`, a resolved transition requires:

```text
SAT(C)
UNSAT(C AND G)                 for each actual dispatcher guard
UNSAT(C AND S != v)            unless S already simplifies to numeral v
v belongs to the explicit normalized switch map
```

A Boolean guard that simplifies to false already supplies its exclusion
proof; final path feasibility is still required. For a nonconstant actual
guard, the executor checks path feasibility before querying its self-edge.
Only after exclusion does it add the continuation condition. A satisfiable
or unknown self-edge is unresolved, not an infeasible path. Thus a late
out-of-range return cannot disappear by assuming that it exits the dispatcher.
The switch's default edge is not an explicit state target; reaching a default
index also prevents a complete rewrite. These conclusions depend on A1–A3 and
A5.

There are three explicit execution modes:

| Mode | Incoming assumptions | Use |
|---|---|---|
| `actual_return` | No unproved guard-exit assumption. | Initial entry and every actual case return. |
| `unconstrained_case` | Executes the complete incoming prelude without assuming a guard exit or selector equality. | First transition attempt; an overapproximation of states reaching the case. |
| `hypothetical_case` | Executes the complete incoming prelude and assumes the guard continuation and `S == case`. | Retry only if the stronger attempt is unresolved; also defines the incoming domain for a register-induction check. |

A resolved or infeasible result from the stronger domain is sufficient for
the narrower case domain. An unresolved result retries the conditioned model;
it does not supply a target. Both modes execute the full case route and then
use `actual_return` for the outgoing dispatcher. The reference corpus resolved
all 441 enumerated return paths through the stronger mode without a retry.

The acceptance sequence is:

```text
decode candidate; enumerate bounded entry, returning, and terminal routes
validate proof semantics, private-storage and call-preservation contracts
derive register invariants; resolve initial entry using actual_return
for each returning route:
    resolve with unconstrained_case followed by actual_return
    if unresolved: retry with hypothetical_case followed by actual_return
    if still unresolved or deadline expired: reject complete plan
require complete state/edge coverage and conflict-free, copyable rewrites
snapshot affected blocks; apply all effect-preserving rewrites
retire physically unreachable dispatcher blocks; verify
assign unique copied instruction addresses; verify; commit
```

Recurrence boundaries forget every mutable register and storage binding.
They retain old entry-path constraints, but new mutable bindings receive
monotonically fresh symbolic names. The handler reinstalls only proven
register invariants, separately from its register call-preservation set.
Consequently, a callee-preserved register may remain stable across one call
without being pinned to its original entry value across all cases.

The first register-invariance test excludes any overlapping write throughout
the dispatcher and returning case region and verifies call preservation. A
fallback considers selector-live register operands that are temporarily
written. For each affected route it starts an independent, fully fresh
executor without entry-specific assumptions, captures candidate `r_before`,
executes the hypothetical dispatcher/case route, and proves
`UNSAT(C_route AND r_after != r_before)`. Routes without an overlapping write
use the syntactic proof. These identity results establish an induction step;
the real entry supplies the base value. Widths remain exact: the reference
case saves R14d to RBP, temporarily reuses R14, then restores R14d. Its 32-bit
identity does not assert preservation of arbitrary upper 32 bit. The
restored/corrupted R10d fixtures test the save/overwrite/restore induction
identity and its violation; they do not test arbitrary nonzero upper halves.
This argument depends on A1–A3 and A5.

The handler normalizes guard and selector formulas with
`bv_sort_ac=true` before ordinary bit-vector expansion. The pinned Z3 parameter
sorts associative/commutative operands and defaults to false. Sorting exposes
the repeated XOR terms in the encoded-state recurrence before extraction and
width rewrites obscure their cancellation. This changes simplification order,
not the proof obligations. Nonconstant expressions retain the solver-based
uniqueness and exclusion checks. The parameter definition is in the
[Z3 4.16.0 primary source](https://github.com/Z3Prover/z3/blob/z3-4.16.0/src/params/bv_rewriter_params.pyg).

The exact reference state-0 calculation is reproduced in
[z3_tests.cpp](z3_tests.cpp). Every operation below has unsigned 32-bit
bit-vector semantics; multiplication, addition, and subtraction reduce modulo
`2^32`, and `LShR` is logical right shift:

```text
R12 = 0xBE816175 * ((SP + 12) XOR 0xF978AD7D)
R14 = ROL32(0xC2CC86A3 * ((SP + 8) XOR 0x4AE62630), 7)
u   = 0x279D2A17 * (s XOR 0x50256DAE) - 0x2E6FD155
s'  = u XOR LShR(u, 11)
a'  = (s' XOR R12 XOR R14) XOR LShR(s', 13) XOR 0x318EA088
S'  = 0x83DAC1F1 * ((a' XOR (R14 XOR ((R12 XOR s')
      XOR LShR(s', 13)))) XOR 0x2ED4B00E) - 0x0E5A9399
    = 141
```

`SP` and `s` are arbitrary in this calculation. The test verifies the numeral,
independently checks `S' != 141` is unsatisfiable, verifies the valid guard is
false, and verifies that corrupted and unconstrained dependencies retain their
guard behavior. It links the same bundled `libz3` as the plugin. No floating
point approximation or numerical error bound enters this bit-vector result.

Rewrites retain effects as well as control targets. Every rewritten initial
or recurrent edge executes a copy of all noncontrol dispatcher instructions,
including the switch prelude before `m_jtbl`. This preserves selector capture,
table loads, flags, register outputs, global writes, and private-state writes
under A1–A3. Direct cuts use only the final case edge. Frontier specialization
and split plans copy the complete intervening body instead of deleting its
state definitions. Edges belonging to a terminal path cannot become cuts.
An ordered source/write preflight permits copying an original body before a
later specialization, but rejects a second writer or a copy from a body an
earlier plan has already changed.

Every copied dispatcher, frontier, or suffix rejects real calls requiring
call-site duplication support. The existing exactly modeled rotate helpers
remain admissible. This is an IR capability boundary; it is not a conclusion
that real calls have no effects. The local SDK's `MBA2_NO_DUP_CALLS` contract
is recorded in `hexrays.hpp`; the call-duplication gate is established here by
source review, not by an executed
call-prefix fixture.

The transaction snapshots affected block metadata, predecessor/successor
sets, and complete instruction contents. After applying the entire plan, a
graph traversal from block 0 identifies physically unreachable dispatcher
blocks. Each such block becomes an acyclic one-way jump to the existing exit.
No blocks are deleted or renumbered, and no global optimizer is called from
inside the callback. This prevents the retired dispatcher SCC from remaining
attached as an unreachable predecessor of live cases. Physical reachability,
not an additional symbolic assumption, authorizes this retirement.

After structural verification, explicitly tracked copied roots and all their
subinstructions receive
`alloc_fict_ea(map_fict_ea(original_ea))`. The handler dirties chains, verifies
again, and commits. Original instruction addresses remain unchanged. The SDK
API provides unique fictional addresses and reverse native provenance, as
documented in the [primary `mba_t` API](https://cpp.docs.hex-rays.com/classmba__t.html).
The linked online reference identifies SDK 9.2; the compiled target and local
header/implementation checked for this change are SDK 9.4.
The local primary implementation in `plugins/vd/switch.cpp` identifies
duplicate copied definition addresses as a cause of `INTERR 50342`; the
reference corpus reproduced that failure until its copies received distinct
addresses. No verifier assertion or flag was disabled.

Rollback restores the CFG, block metadata, and instruction contents. The SDK
fictional-address pool is private, monotonic, and has no public undo API.
Address allocation is therefore delayed until the complete structural rewrite
has verified. An exceptional allocation or subsequent verification failure
can leave unreferenced entries in that pool even though all graph/instruction
changes are restored. This allocator-metadata limitation is distinct from
committing a partial CFG rewrite.

The structural and proof limits are explicit:

| Quantity | Limit or behavior |
|---|---|
| Dispatcher/entry/case route length | At most 32 blocks per route. |
| Return paths per explicit case | At most 256. |
| Total recorded return paths | At most 4096. |
| Entry search or one-case enumeration work | At most 4096 work items. |
| Individual solver timeout | Nominal maximum 1 s, reduced to remaining proof time. |
| Proof acceptance deadline | 30 s for invariant/initial/transition proofs; an expired deadline rejects the plan. |
| Solver failure | `UNKNOWN`, unsupported semantics, nonunique/default targets, or incomplete proof rejects. |

These are acceptance and query limits, not a universal hard bound on total
decompilation latency. CFG discovery, symbolic-expression construction,
simplification, SDK calls, and later decompiler stages also consume time.

For complexity, let `B` and `E` be input blocks/edges, `C` explicit states,
`P` recorded return paths, `L <= 32` maximum route length, `W <= 4096` the
per-case work-item cap, `Delta` maximum successor count, `D` maximum predecessor
count at a split suffix, `R` candidate registers,
`Rs` selector-live registers requiring identity analysis, `I` input instruction
and operand nodes, and `F` copied instruction/operand nodes. Enumeration uses
`O(C W Delta L)` path/edge operations, with ordered-set lookup factors where
used. Validation/call-preservation scans contribute `O(R I)`. Main symbolic
input traversal contributes `O(P (I_entry + 2 I_dispatcher + I_route))`, with
at most two transition attempts per route; identity analysis adds at most
`O(Rs P (I_dispatcher + I_route))`. Edge-suffix inspection contributes a
further route-length factor, bounded by `O(P L I_route)`. Split candidate
classification contributes `O(C D^2)` predecessor-pair inspections, in addition
to `O(P L)` common-suffix/path checks. Retirement uses `O(B + E)` graph operations;
its ordered visited set adds a `log B` factor. Structural storage is
`O(B + E + I + P L + F)`, plus live symbolic-expression/solver storage. SMT and
bit-vector simplification costs are data-dependent and have no polynomial
bound claimed here.

The verification workloads are separate. [RECURRENT_GUARDS.md](RECURRENT_GUARDS.md)
documents native checksums/side effects, bounded loop observations, the
independent microcode interpreter, rejection controls, fictional-address
provenance, native-byte hashes, and the matched fixture pair. The main corpus
probe verifies three uncached decompilations, disappearance of the dispatcher,
converged output identity, resolver-argument behavior, and unchanged native
function chunks. These checks do not establish native runtime speedup or a
whole-program equivalence theorem.

The final corpus comparison used three sequential before/after process pairs,
each with three `DECOMP_NO_CACHE` calls to `decompile_function`. Each process
started from the same raw input in a fresh IDA user directory. rax was disabled
and verbose plugin logging was enabled. No other agent build, test, or IDA
workloads ran concurrently. The order was fixed as before then after for each
pair; ambient OS load was not quantified. The elapsed-call timer stops before
`get_pseudocode` and tag removal. Whole-process wall time additionally includes
startup, analysis, pseudocode rendering, checks, and shutdown.

| Pair | Artifact | Three uncached call durations (s), in order | Whole-process duration (s) |
|---|---|---|---|
| 1 | Before | 37.066903708, 34.517217208, 34.460279833 | 110.872370959 |
| 1 | After | 4.043908958, 3.977417000, 3.982400167 | 16.614371375 |
| 2 | Before | 36.211389041, 37.161061375, 35.055698083 | 113.278552875 |
| 2 | After | 3.979281333, 3.866545625, 3.901837833 | 16.306964833 |
| 3 | Before | 48.515111709, 66.676236375, 37.219209083 | 157.420460250 |
| 3 | After | 4.001127250, 3.989642958, 4.261636250 | 16.851661958 |

The pooled nine-call medians are `37.066903708 s` before and
`3.982400167 s` after, a dimensionless ratio of `9.307679327`. The corresponding
observed ranges are `34.460279833–66.676236375 s` and
`3.866545625–4.261636250 s`. Keeping within-process observations grouped, the
median of the three process medians is `36.211389041 s` before and
`3.982400167 s` after, ratio `9.092855445`. The individual paired-median ratios
are `8.667440679`, `9.280598167`, and `12.125360849`. Whole-process medians are
`113.278552875 s` and `16.614371375 s`, ratio `6.818106464`.

These are descriptive ratios for this input/configuration under A6. The nine
calls per artifact are clustered within three processes, and the third
baseline process is visibly variable. No confidence interval, universal
latency bound, independent-sample interpretation, or native execution speedup
is inferred. Displayed durations are rounded to `10^-9 s`; this formatting
precision does not establish clock accuracy, whose calibration error is
unknown. The ratio calculation is `T_before / T_after`, so the pooled median
reduction is `(1 - 3.982400167 s / 37.066903708 s) × 100 = 89.256183 %`.

All nine after calls proved 441 return paths: 323 feasible and 118 infeasible,
with zero conditioned fallbacks. Each rewrote 317 edges using one frontier
specialization and 68 split plans and retired two dispatcher blocks. All nine
after outputs contained 2094 pseudocode lines and zero case labels, versus
4247 lines and 249 case labels before. All 38 measured resolver arguments were
neutralized in each after output. Runs 2 and 3 were byte-identical within each
process after type propagation. All baseline processes returned the expected
probe code 5 because the dispatcher remained; all after processes returned
code 0 and the required PASS marker. Baseline rejection is a measured control
outcome, not a successful dispatcher-removal assertion.

The native function chunk `[0x82AF0, 0x8A302)` contains
`0x8A302 - 0x82AF0 = 30738` bytes. Its SHA-256 was unchanged before/after every
process, and all six processes used matching input, IDA, probe, and explicit
plugin-environment identities:

| Object | SHA-256 |
|---|---|
| Raw `obfuscator_sample.uu.unpacked.elf` | `0504e7c58519da9bc2f45f84e4a264c5a3ba03ae4683e372570ba15999d0b17d` |
| Before plugin, clean upstream `b3b5b03c81b5` | `e1333736fc6e1cc5c9b8853731b14c9691f77a02f5e5fcfa4f9f3a38ad0b432e` |
| After plugin | `4cc611242a0844b0d622e92791ab1d627b79772b3180b56fd98ed8fb9c1f9100` |
| Frozen `ida_cff_plugin_probe.py` | `87989ee25bd48e6423ce30584e5b86173af0e3151a6a46e8aed2781197ae71a3` |
| IDA executable | `5f75ebbf4ff6424ebdec1c5d72b1e9d669d04e25b4d5f7b2aec35ad4fea1c7fa` |
| Explicit Chernobog environment | `b1256521b6d90be3a772eaba3cc9473b6ff7f0d173e2ce2e8b32b1347b0cf8c7` |
| Native function chunk | `d81b4d3f5e974bf4a3942c0fe971cbf2fa430a2f2b8d190615c9fb15cac5a640` |

The retained directories are
`/tmp/chernobog-guarded-benchmark-{before,after}-{01,02,03}`. Each contains
`run.json`, `cff_decompilation.json`, the frozen probe and plugin, native
input/database, per-call pseudocode, and the complete log. The aggregate and
summary are `/tmp/chernobog-guarded-benchmark-results.json` and
`/tmp/chernobog-guarded-benchmark-summary.json`; the runner/probe used for
reproduction are [run_ida_smoke.py](run_ida_smoke.py) and
[ida_cff_plugin_probe.py](ida_cff_plugin_probe.py).

Bounded findings beyond the initial guard support are: **high impact** —
entry-value reuse for mutable registers can exclude a real later case;
whole-state freshness plus register induction addresses it. **High impact** —
an unreachable dispatcher SCC and duplicate copied definition addresses can
respectively stall optimization and break lvar allocation despite a correct
reachable CFG; retirement and fictional addresses address those lifecycle
failures. **Medium impact** — broader conditional cuts, pointer-alias proofs,
and real copied-call support require additional representation/proof work and
remain outside this admitted subset. **Low impact** — sorting equivalent
bit-vector terms can remove unnecessary solver work without weakening the
obligations.

The delivery audit checks non-normative scope (QG1), assumptions and explicit
falsification probes (QG2), the complete admitted transition/effect/lifecycle
requirements (QG3), exact bit widths and SI timing units (QG4), separate
infeasible/unknown/default/alias boundaries (QG5), implementation plus primary
SDK/Z3 and retained run provenance (QG6), and the bounded findings above (QG7).
Its proof claims remain tagged by A1–A5 and its comparative measurement claims
by A6.
