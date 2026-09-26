# Universal branch filtering for native target recovery

Review row 1b now has a bounded refinement of correlated target analysis.
A Jcc successor is excluded only when every completion of every converged
alternative input has the same branch outcome [F1]. Unknown or conflicting
outcomes retain both successors. The filtered graph is then solved again;
only converged, reached inputs supply new exact targets or destination sets.

## Proof and admission [F1, F2]

The first alternative analysis uses the original graph reconstructed from
instruction bytes, including both architectural Jcc successors. Its state
set overapproximates represented normal completions. If the condition is
true in every represented state, the fallthrough edge has no represented
completion; the analogous argument excludes the taken edge for universal
false. Decisions come exclusively from this converged, unfiltered analysis.
The second analysis uses those fixed decisions; provisional inputs never
remove another edge. No iterative predicate refinement is performed.

The original unknown entries and predecessor-free entries survive filtering.
A node that loses its only predecessor becomes graph bottom, rather than a
new unknown entry. External entries into an excluded arm therefore remain
inputs to the target join. An unentered cycle remains bottom. Empty refined
inputs cannot establish a new scalar value or a complete destination set.
The original must analysis and public condition facts retain their existing
semantics; refinement supplies the alternative retry for unknown targets.

A compound predicate can be universal without any common decisive flag bit.
For example, alternatives with CF=1/ZF=0 and CF=0/ZF=1 universally satisfy
JBE. Their joined CF and ZF remain unknown. Filtering evaluates each partial
flag profile over all its completions, and never fabricates common flag bits.
Differing outcomes around a changing loop retain both successors [F1, F3].

All original instruction support remains attached to a recovered target,
including excluded branch bodies. Current recognition reruns the analysis
before accepting a stored publication. Predicate bytes, source definitions,
entries and ownership therefore remain part of validity. The UI's existing
exact snapshot comparison also rejects changed results [F2].

The admission audit additionally found that owned graph and linear prefix
analysis did not reject code references into instruction interiors. Both now
scan every encoded byte and reject an interior code entry or more than 256
incoming references per instruction. Ownerless inspection already enforced
this boundary. An interior entry into a local literal definition cannot
bypass graph rejection through the prefix fallback [F2, F3]. Direct near
destinations are converted through the instruction's code segment in both
graph construction and filtering.

## Algorithm and bounds [F1]

```text
original_inputs := converged alternatives on the unfiltered graph
if convergence fails: return unavailable
for each Jcc:
    decision := common known outcome over all completions of all alternatives
preserve every original entry
remove only successors contradicted by a known decision
if an edge changed:
    inputs := converged explicit-entry analysis of the fixed filtered graph
else:
    inputs := original_inputs
if query input is bottom: return unavailable
read scalar / containing set from the query input
retain support from the original graph
```

The alternative cap K=8, owned node cap N=64, ownerless node cap N=128,
and per-pass round cap R=128 remain unchanged. Overflow conservatively joins
every state. With F=6 modeled status flags, deciding all branches costs
O(N·K·2^F) time; copying and filtering the graph costs O(N+E) time and space.
A fixed-point pass costs
O(R·(E·K²·S + N·(K·T + K²·S))) time and O(N·K·S+E) space,
where S is base-state comparison/join cost and T is transfer cost.
An unknown scalar query can execute the must pass, unfiltered alternative
pass and filtered alternative pass: at most three R-bounded passes, rather
than a total 128-round budget. Ownerless inspection reuses its lazy
alternative analysis across transfer records. These are dimensionless
algorithm budgets; interactive latency and broader scaling are unknown.

## Measurements and independent controls [F3, F4]

Named source labels provide the target oracle independently of plugin
outputs. Executed C contracts cover 37 constant-target fixtures, one dynamic
compound predicate and one changing loop over 512 inputs, −256 through 255.
All 64 complete flag profiles exercise each of 16 dynamic Jcc fixtures.
The count is (37+2)·512 + 64·16 = 20,992 checks per architecture, or 41,984
per plugin profile. The preceding and current plugins inspect matching binary
hashes in fresh IDA databases.

| Cohort | Preceding target result | Current target result |
|---|---|---|
| True and false profiles for all 16 Jcc codes: 32 fixtures | Unknown scalar; complete two-member set | Exact named destination; singleton set |
| Two local memory and two tracked stack fixtures | Unknown scalar; complete two-member set | Exact named destination with existing source basis |
| Universal JBE across differing CF/ZF alternatives | Unknown scalar; complete two-member set | Exact named destination; public joined flag facts remain unknown |
| 16 dynamic Jcc profiles and one dynamic compound predicate | Unknown scalar; complete two-member set | Same unresolved scalar and complete two-member set |
| Loop with STC entry and CLC back edge | Existing exact destination; unknown loop condition | Same exact destination and unknown condition |

The 37 recovered fixture targets occur on two architectures and two query
paths: 148 additional exact-target observations. The 17 dynamic controls
produce 68 unresolved observations. This is a selected-fixture measurement,
not a score for protected programs. Production probes pass 886 checks per
architecture for the preceding plugin and 1,056 for the current plugin,
2,112 current checks in total.

Controls patch the flag-setting literal, require immediate revocation of the
old owned publication, and recover the independently specified other target
after analysis. Restoration recovers the original target. An external entry
into the inactive arm restores a two-member containing set and revokes the
unique edge. Instruction-interior entries invalidate both the branch proof
and a direct local literal proof; restoration reestablishes admission.
Owned and ownerless queries preserve the inspected IDB inventory. Disposable
mutation tests restore actual function owners, including owners whose starts
lie outside the original fixture range [F2, F3].

Portable tests compare 746,496 alternative condition unions against an
independent concrete truth oracle: 729 partial flag profiles × 64 concrete
profiles × 16 conditions. Additional controls cover orphaned nodes, explicit
external entries, unentered cycles, changing loops, insufficient round
budgets, empty alternatives and invalid condition codes. All 21 CTest suites
pass. The existing owned corpus retains 453/386 production checks and
37,630/36,350 native checks on x86-64/i386. The existing ownerless corpus
retains 1,730/1,680 production checks and its corrupted-oracle controls.

The preceding containing-set fixtures pass 297 production checks per
architecture before refinement and 293 afterward. The difference is four
checks specific to nonunique results: `cv_infeasible` now has the exact
`cv_seven` destination and a singleton set on both query paths. Historical
two-member-set evidence remains unchanged; it describes the preceding
revision. The other containing-set contracts remain unchanged.

The supplied VMP initializer remains identical across matched profiles:
75 nodes, 77 edges, three unresolved facts and 8/8 inspection checks.
No protected gain is measured there. Execution uses macOS x86-64 translation
on the arm64 host and QEMU i386 in the recorded Linux image; physical x86
hardware equivalence is unknown [F4]. Observation and source hashes are
retained in `VMP_BRANCH_FEASIBILITY_EVIDENCE.json`.

## Reproduction

```sh
python3 -B tests/run_branch_feasibility.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/feasibility-reproduction \
  --linux32-image chernobog-vmp-linux32:test
ctest --test-dir build --output-on-failure
```

Use a new output directory. `--baseline` checks the preceding two-member
contracts. `tests/run_target_cover.py --branch-feasibility-baseline` retains
the preceding `cv_infeasible` expectation separately from its older
`--baseline` API-absence mode. Runners bind source, probe, binary, plugin,
IDA and report identities and verify them after measurement.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| F1 | Existing abstract transfers overapproximate represented normal completions; universal exclusion and new target proofs depend on this. | Independent truth enumeration, 17 dynamic controls, changing-loop back edge, explicit-entry/bottom tests, eight-state widening and nonconvergence abstention. |
| F2 | Current bytes, entries, ownership and existing normal-completion model describe the scoped graph; publication freshness depends on this. | Patch the predicate literal, inject inactive-arm and instruction-interior entries, reject stale UI captures, restore owners explicitly and compare query inventories. |
| F3 | Literal labels and executed contracts independently specify targets; selected-fixture counts depend on this. | Exercise both predicate outcomes for every Jcc code, register/memory/stack sources and all 64 complete flag profiles; retain report errors and matched binary hashes. |
| F4 | Recorded translated executions and tool identities are the measurement environment; cross-profile comparisons depend on this. | Verify source/tool/binary hashes before and after, compare protected reports and retain existing corrupted-oracle controls. Physical hardware and whole-program coverage remain unknown. |

## Bounded scope expansion

- **High impact:** Instruction-interior entries previously admitted by owned
  graph/prefix analysis can invalidate an apparently local source proof.
  The added guards and mutation controls address this concrete boundary.
- **Medium impact:** One universal filtering stage can miss predicates that
  become decidable only after another branch is excluded. Conditional input
  predicates, exact feasible-member sets and whole-program reachability
  remain unknown.
- **Medium impact:** Extra fixed-point passes add bounded work. Widening,
  aliases, opaque calls, node limits and round limits retain conservative
  loss of precision; no interactive latency guarantee is established.
- **Medium impact:** The historical edge scorer has older fixture pins.
  A current score from it remains unknown; new fixture observations do not
  rewrite historical scores or establish broader protected effectiveness.

## Self-red-team and quality gates

QG1 passes: no normative content is needed. QG2 passes: F1–F4 enumerate
assumptions and falsification probes. QG3 passes for this bounded target
refinement on both architectures and query paths; full review work remains
in progress. QG4 passes: counts, bit widths, byte effects and per-pass bounds
are explicit. QG5 passes: external entries, bottom, cycles, changing loops,
compound predicates, prefix fallback and historical evidence are bounded
consistently. QG6 passes: primary source and observation hashes bind the
measurements. QG7 passes: remaining opportunities and risks have impact labels.
