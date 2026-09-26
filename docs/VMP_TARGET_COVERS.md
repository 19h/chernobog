# Bounded destination sets for unresolved native transfers

Review rows 1b and 5 require unresolved transfer metadata and evidence-linked
inspection without invented unique edges. Correlated scalar recovery now
has a separate containing-set result for PUSH/RET candidates. A complete
set contains the destination of every represented normal completion [T1–T3].

## Meaning and API contract [T1, T2]

The native proof API and ownerless native-region API attach `target_cover_*`
fields to existing transfer records. They retain the existing scalar target,
proof/candidate status, stack effects, ownership and publication semantics.
Multiple members do not become unconditional edges. A complete set is a
bound on destinations; it does not establish that any member is reachable.

| Field | Meaning |
|---|---|
| `target_cover_status` | `complete`, `partial`, `unresolved` or `unavailable` |
| `target_cover_complete` | Every represented input supplied an exact source |
| `target_cover_values`, `target_cover_count` | Sorted, deduplicated destination values and their number |
| `target_cover_unknown_inputs` | Alternative inputs whose source word remained unknown |
| `target_cover_widened` | The alternative analysis used conservative widening |
| `target_cover_support` | Supporting instruction EAs and their current encoded bytes |
| `target_cover_reason` | Exact-source, partial-source, widening or admission explanation |
| `target_cover_validation` | `recomputed`; the set is a current query result |
| `target_cover_scope` | Normal-completion coverage, unasserted member reachability and no edge publication |

A partial result lists known values from some alternatives. It does not
bound the destinations of unknown alternatives. An unresolved result has
no exact members. An unavailable result means that the bounded graph was
not admitted or did not converge. Existing current scalar proofs/facts supply
singleton sets with their existing dependencies and model assumptions;
alternative-analysis widening is reported when that analysis supplies the
set. Initial writable bytes are never imported into the abstract state.

Register operands, tracked words at SP and locally established writable
words are read per alternative. Different exact local memory addresses may
therefore supply one complete set even when no common address exists at the
join. PUSH reads [SP] before its decrement. Immediate values retain the
existing natural-width normalization. Unsupported widths, addresses, graph
inventories and execution modes retain their existing boundaries [T1, T2].

Owned results are appended only to a currently recognized transfer record.
Its stored proof/candidate validity remains separate from the recomputed
containing set. No set is persisted as a unique publication. Ownerless
results are recomputed in the existing read-only, unpublished region query.
The UI shows, for example, `unknown; complete cover {0x..., 0x...}`; the
scalar target remains unknown. Existing exact-record comparisons invalidate
a captured UI result when completeness, support bytes, members or the
scoped graph changes [T2].

## Algorithm and bounds [T1]

The alternative domain and fixed-point admission are those documented in
`VMP_CORRELATED_JOINS.md`: at most eight alternatives; 64 owned or 128
ownerless nodes; 128 rounds; and 256 incoming references per instruction.
Overflow joins all states conservatively. No path is discarded. Ownerless
inspection reuses one lazily computed alternative graph across its candidate
records. Owned inspection runs the alternative query only for an unresolved
transfer while constructing requested details, rather than adding it to
ordinary proof validity checks.

```text
members := empty set; unknown := 0
for every converged alternative input:
    source := exact PUSH source in that alternative
    if source is unknown: unknown := unknown + 1
    else: insert normalized source into members
complete := (unknown = 0)
return sorted members, complete, widening state and graph support
```

If K is the number of alternatives, reading and collecting members costs
O(K·L + K·log K) time and O(K) additional space, where L is the bounded
source-address/word lookup cost. Support serialization costs O(N·B) time
and output space for N instructions with at most B = 15 encoded bytes each.
The preceding fixed-point analysis costs
O(R·(E·K²·S + N·(K·T + K²·S))) time and O(N·K·S + E) space, with base
comparison/join cost S and transfer cost T. These dimensionless algorithm
budgets are not a measured interactive latency guarantee.

## Independent controls and measurements [T2, T3]

The frozen historical assembly is linked unchanged with additional controls
and the preceding correlated-join fixtures. Named literal labels supply the
member oracle independently of plugin target fields. Native execution checks
13 contracts over 512 inputs, −256 through 255: 6,656 checks per binary and
13,312 per two-architecture plugin profile.

| Cohort | Expected containing-set result | Scalar result |
|---|---|---|
| Historical dynamic stack, conflicting byte and conflicting full-store fixtures | Complete, two members each | Unresolved |
| Dynamic register fixture | Complete, two members | Unresolved |
| Two distinct locally written addresses | Complete, two members | Unresolved |
| Known-false branch retaining both syntactic successors | Complete, two members, including an infeasible member | Unresolved |
| Three correlated register/memory/stack scalar fixtures | Complete singleton each | Existing exact destination |
| Unknown register argument and potentially aliasing memory write | Partial; one known member each | Unresolved |
| Nine-state widening, unestablished writable memory and opaque call | Unresolved | Unresolved |

The three historical dynamic fixtures have complete two-member sets on both
architectures and both query paths: 12 set observations. This adds destination
bounds; it does not add six proved conditional edges to an edge score. The
infeasible-member control demonstrates why a containing set cannot establish
member reachability. Conditional predicates and exact feasible sets remain
unknown.

Matched preceding/current plugins inspect the same binary hashes in fresh
IDA databases. The preceding API lacks these fields and passes 148 checks
per architecture. The current API and UI helper pass 297 checks per
architecture, 594 total. Every transfer is checked for its independent member
contract, scalar status, completeness, unknown sources, current byte support
and nonpublication scope. Controls verify read-only inventory, nine-state
widening, external-entry invalidation, member changes after a literal patch,
restoration and rejection of stale UI captures.

IDA can assign an injected external entry to a tail owned by the source
function. Owned restoration explicitly reconstructs the original function
range. Ownerless restoration removes the actual owners of the queried
instruction spans, including an owner whose start lies outside that range.
These fixture mutations occur only in disposable databases. Queries remain
read-only; the tests do not treat deleting one external reference as proof
that ownership has automatically reverted [T2].

The existing owned corpus passes 37,630/36,350 native checks and 453/386
production checks on x86-64/i386. The existing ownerless corpus passes its
native and corrupted-oracle controls and 1,730/1,680 production checks.
All 21 CTest suites pass. Supplied-initializer reports are identical: 75 nodes,
77 edges, three unresolved facts and 8/8 inspection checks. No protected
gain is measured in that region. Artifact identities are retained in
`VMP_TARGET_COVERS_EVIDENCE.json`. Execution uses
macOS x86-64 translation on this arm64 host and QEMU i386 in the recorded
Linux image; physical x86 hardware equivalence is not claimed [T3].

## Reproduction

```sh
python3 -B tests/run_target_cover.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/cover-reproduction \
  --linux32-image chernobog-vmp-linux32:test
ctest --test-dir build --output-on-failure
```

Use a new output directory. `--baseline` checks absence of the new metadata
while retaining the existing scalar contract. The runner verifies source,
binary, plugin, IDA, archived probe and report identities before/after runs.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| T1 | Existing state transfers and joins cover represented normal completions. Closed-set soundness and resource bounds depend on this. | Retain every variant or widen all of them; test nine distinct states, partial sources, aliases, opaque calls and an infeasible branch. No provisional fixed-point output is used. |
| T2 | Current scoped graph, source bytes, ownership and normal-return assumptions describe this query. API/UI validity depends on this. | Inject an external entry, inspect the changed ownership, restore owners explicitly, patch one literal address, restore its bytes and require old captured results to become invalid. Compare inventory before/after each ordinary query. |
| T3 | Source labels and executed contracts are independent of plugin outputs, with matched binaries and tools. Measured set recovery depends on this. | Execute both input domains, verify every source/tool/binary/report hash after measurement, preserve historical fixture hashes, and retain the existing corrupted-oracle checks. |

## Bounded scope expansion

- **High impact:** Conditional input predicates and feasible-member proofs
  remain unknown. Publishing every set member as a native edge would exceed
  this contract; the infeasible-member control exposes that distinction.
- **Medium impact:** More than eight distinct states can lose a useful bound
  after widening. Unknown source-address/alias effects and opaque calls can
  also leave partial or empty results.
- **Medium impact:** Cross-function tail ownership is observable after entry
  mutations. Fresh inspection must admit the current ownership graph;
  reference restoration alone does not restore that graph.
- **Medium impact:** The frozen historical edge scorer retains earlier
  source/probe pins. A current score from it is unknown; historical evidence
  remains preserved. Closed sets are a separate measurement from proved edges.

## Self-red-team and quality gates

QG1 passes: no normative content is needed. QG2 passes: T1–T3 enumerate
assumptions and probes. QG3 passes for this containing-set feature across
source kinds, both architectures, both query paths and UI freshness; the
complete review remains in progress. QG4 passes: bit widths, byte effects,
counts and algorithmic resource bounds are explicit. QG5 passes: partial
sets, infeasible members, widening, entry/tail changes, normal completion
and translated execution are bounded explicitly. QG6 passes: primary local
source and observation hashes bind every reported measurement. QG7 passes:
remaining opportunities and limits have impact labels. Broader protected
effectiveness, exact conditional edges and the full review remain unproved.
