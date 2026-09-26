# Exact transfer targets across correlated joins

Review row 1b requires exact register and memory targets while preserving
unresolved candidates. The preceding must-analysis independently joined each
register, stack word and locally written byte. It lost relationships such as
`(EAX, ECX) = (0, 7)` or `(7, 0)`, even though both products are zero [J1, J2].

## Contract and derivation [J1–J3]

Production first runs the existing must-analysis. An exact value query that
remains unknown in a graph containing a join retries with at most eight
alternative abstract states. Each instruction transfers each state separately;
equal results are deduplicated. Distinct states preserve relationships between
registers, tracked stack words, flags and local writable bytes. Both syntactic
Jcc successors remain represented; branch feasibility is not inferred.

At a join, alternatives are unioned. If their number exceeds eight, every
alternative is joined into one conservative state. Subsequent joins retain
this widening state. No path is discarded to fit the budget. An unconditional
overwrite can establish a new exact value after widening. An external entry
contributes an unknown state. Initial writable image bytes remain unknown.

For a set of abstract states A, let gamma(A) be the union of their concrete
states. Union and deduplication preserve gamma(A). Widening replaces A by
`join(A)`, whose concretization contains gamma(A), using the existing sound
known-bit, flag, stack and byte-map joins. Instruction transfer operates on
each alternative with the existing normal-completion contract. Therefore,
converged graph inputs still cover every represented normal execution. A
scalar result is returned only from the common join of all alternatives.
Different destinations remain unresolved. Membership in an alternative does
not establish that its path is feasible [J1–J3].

Owned-function queries retain the 64-node and 128-round limits and all graph
support addresses. Existing proof receipts and recognizer freshness checks
cover these addresses. Ownerless queries retain the 128-node and 128-round
limits, compute the alternative graph lazily at most once per query, and
retain the existing read-only API. An incomplete fixed-point iteration returns
no alternative-derived fact. Existing must facts remain available if the
retry fails [J1, J2].

```text
input := union of predecessor alternatives and any unknown entry
if input exceeds K states: input := {join every state}; mark widened
output := deduplicate {instruction_transfer(s) for s in input}
repeat within R rounds until every output is unchanged
if not converged: abstain from alternative-derived facts
exact value := read(join every converged input alternative)
```

For N nodes, E predecessor edges, K alternatives, R rounds, base-state
comparison/join cost S and base transfer cost T, the analysis costs
O(R·(E·K²·S + N·(K·T + K²·S))) time and O(N·K·S + E) space. A union can
temporarily hold at most 2K states before widening. Here K = 8, R ≤ 128;
base states retain the existing 16 register slots, 64 stack words and 128
local memory bytes. Incoming-reference admission remains capped at 256 per
instruction. These are algorithmic bounds, not an interactive latency
guarantee [J1].

## Executed and production evidence [J2, J3]

The same fixture binaries were executed and inspected with the preceding and
current plugins in fresh IDA databases. Source labels provide the independent
destination oracle; plugin target fields do not generate that oracle.

| Fixture | Correlation and final source | Prior unique target | Current unique target |
|---|---|---|---|
| `jc_register` | Two register products; PUSH register | Unknown | Named destination |
| `jc_memory` | Locally stored target and offset; PUSH memory | Unknown | Named destination |
| `jc_stack` | Pushed target and offset; final PUSH [SP] | Unknown | Named destination |
| `jc_dynamic` | Two actual destinations | Unknown | Unknown |
| `jc_cap` | Nine distinct correlated states | Unknown | Unknown after conservative widening |
| `jc_initial_memory` | Unestablished writable word | Unknown | Unknown |

Each positive recovers one unique destination per architecture and per owned
or ownerless path: three targets on each path, twelve observations total.
Every positive has zero net stack displacement for its selected PUSH/RET
pair. The stack fixture separately removes its earlier pushed word at the
destination. No dynamic alternative is published as a unique edge.

Each x86-64 and i386 binary executes 2,560 checks over inputs −256 through
255. All 5,120 checks per plugin profile pass. Current production probes
pass 49/49 checks per architecture; preceding probes pass 32/32. Controls
include source-basis classification, full predecessor dependencies, immediate
publication revocation after a changed predecessor, disagreement after
reanalysis, restoration, external-entry invalidation, and unchanged ownerless
bytes/items/ownership/comments/references.

Portable checks enumerate 16⁴ = 65,536 independently calculated concrete
operand pairs, using eight-bit words and products at most 225. They check
every represented result, exact agreement, disagreement, permutation and
duplicate paths. Additional controls cover overflow, coverage of every
predecessor after widening, subsequent overwrites, unknown entries, changing
loops, preserved loop invariants and incomplete iteration budgets. All 21
CTest suites pass [J3].

The existing owned corpus passes 37,630 x86-64 and 36,350 i386 native checks
and 453/386 production checks. The existing ownerless corpus passes 1,730/
1,680 production checks, including its corrupted native oracle controls.
The historical edge scorer rejects the current fixture hashes before scoring;
a current score from that frozen scorer is unknown. Earlier recorded edge
scores are historical evidence and are not rewritten [J2, J3].

The supplied VMP initializer reports are identical between the two plugins:
75 nodes, 77 edges and three unresolved facts, with 8/8 inspection checks.
No protected recovery gain is measured in that region. Artifact identities
are recorded in `VMP_CORRELATED_JOINS_EVIDENCE.json`. Fixture execution uses a macOS x86-64
process translated on arm64 hosts and QEMU i386 in the recorded Linux image.
These are process observations under translation, not physical x86 hardware
measurements [J2].

## Reproduction

```sh
python3 -B tests/run_join.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/join-reproduction \
  --linux32-image chernobog-vmp-linux32:test
ctest --test-dir build --output-on-failure
```

Use a new output directory. `--baseline` checks the preceding plugin contract.
The runner pins sources, tools, binaries, archived IDA scripts and reports
before and after the observation. Generated reports redact local paths.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| J1 | Existing state joins and instruction transfers cover normal completions. The derived scalar soundness and complexity depend on this. | Enumerate independent concrete outcomes, retain unknown inputs, widen all overflowing predecessors, and reject unfinished iterations. Unsupported instructions preserve their existing conservative boundaries. |
| J2 | The admitted graph and current dependencies describe the queried bytes, entries, ownership and normal-return contract. Production targets depend on this. | Mutate a predecessor, add an external entry, restore each change, verify immediate proof revocation and inspect ownerless inventory before/after. Larger/incomplete graphs abstain. |
| J3 | Matched source, binary and tool identities isolate this feature; source labels and executed outputs are independent of plugin targets. Measured recovery depends on this. | Compare prior/current binary hashes, verify all source hashes after runs, execute both input domains, retain native corruption controls and require every reported check to pass. |

## Bounded scope expansion

- **High impact:** Conditional destination sets and path predicates remain
  unknown. The three historical dynamic edge fixtures still require a separate
  representation of conditional targets; this feature returns scalar facts.
- **Medium impact:** Nine or more distinct states can lose useful correlations
  after widening. `jc_cap` demonstrates deliberate abstention despite a common
  concrete result. Larger budgets and relational domains require separate
  effectiveness and latency evidence.
- **Medium impact:** A current historical edge score is unavailable because
  its frozen source/probe pins predate the current corpus. Revalidating that
  oracle is a separate semantic change; existing evidence remains preserved.
- **Low impact:** Executable file permissions do not change file format.
  The supplied ELF samples remain Linux targets; the continued corpus work
  verifies the available container execution route.

## Self-red-team and quality gates

QG1 passes: no normative content is required. QG2 passes: J1–J3 enumerate
assumptions and probes. QG3 passes for this bounded scalar-target change:
all three source kinds, both architectures, both query paths and invalidation
controls are covered; full review completion is not claimed. QG4 passes:
counts and dimensionless algorithm budgets are reproducible, native widths
are in bits and stack displacement is in bytes. QG5 passes: disagreement,
widening, unknown entries, incomplete iterations, translation and scorer
abstention are explicit. QG6 passes: source, binary, tool and report hashes
bind the primary local evidence. QG7 passes: remaining opportunities and
limits have impact labels. Full protected recovery, conditional edges and
the complete review remain in progress.
