# Checked temporal native states for ownerless VM candidates

Baseline: `6cbfd62cc8c0639b0264de866023f2ded62af10b`. This checkpoint adds
the explicit `chernobog_vm_trace_temporal_check(ea, seed, input_json,
bindings_json)` query. It combines the named-model temporal native walk with
opt-in instruction-entry register sampling and bounded local VM transition
checks. The existing temporal query keeps its prior sampling behavior. Neither
query publishes ordinary function evidence or assigns a VM identity.

The earlier ownerless scaffold is reached by the fixed-seed generated VMP
strings fixture even though IDA marks its instructions as data. The new query
captures 2,876 entered instructions and 2,876 corresponding instruction-entry
states. Thirty instruction-entry samples elsewhere lack at least one scalar
register value, so `native_state_capture_complete` is false. The temporal event
prefix is complete, and all required candidate entry, internal transfer and
exit states are present. The candidate at `0x1000d64db` has five ordered direct
memory accesses and an observed jump target `0x100007031`. Its modeled input
constraints are satisfiable; the conjunction with a mismatch in modeled GPRs,
defined status flags, ordered accesses, or dispatch is unsatisfiable. The two
bounded Z3 queries therefore corroborate this **captured local transition**.
They do not establish a complete handler, unique dispatch target for other
inputs, or a general VM identity.

The four-seed paired matrix executes 40 isolated IDA captures. Every sampled
run has one instruction-entry state record per entered instruction; in each
run, a same-seed unsampled query has identical entered sites, planned heads,
edges and data events. Across the matrix, 80 retained syntax candidate rows
produce 116 distinct captured candidate visits. All 116 checked visits pass
the two-query local transition check, totaling 232 solver queries. The 16
original/native-mutation captures return zero candidate rows and zero checks.
All 24 protected captures remain execution-incomplete. Four `combined-12648430`
captures reach the 4,096-instruction budget without a complete temporal prefix
and have incomplete register sampling; they retain three syntax candidates
per seed but perform zero transition queries. The full matrix has 1,676
instruction-entry samples with at least one unavailable scalar field, and
does not label them globally complete. Exact hashes, per-variant counts, four
target rows and all abstentions are in
[`VMP_TEMPORAL_STATE_EVIDENCE.json`](VMP_TEMPORAL_STATE_EVIDENCE.json). The
raw per-run reports and runner manifests are retained in
[`VMP_TEMPORAL_STATE_CAPTURE.json.gz`](VMP_TEMPORAL_STATE_CAPTURE.json.gz);
`tests/verify_vm_temporal_state_archive.py` restores and checks their hashes
and aggregate counts without a current plugin binary.

## Admission and limits

The projection requires the exact native region identity, checked instruction
sizes, monotonically ordered entered events and one entry sample per entered
instruction. A complete instruction-entry sample run is admissible. A sampled
run with missing register fields is admissible only when the temporal event
prefix is complete. Register values missing at a candidate endpoint cause its
transition check to abstain. Direct internal transfers require matching
adjacent entered instructions, edge and transfer-target state; the dispatch
requires its own exact edge. Ordered candidate memory events are checked by
the transition solver. Named ABI call models may produce edges or memory
events outside an entered local candidate, so global event attribution is
restricted to order and run identity. Calls cannot enter the local scaffold
recognizer. An event within the candidate whose source, order, width, value
or kind conflicts with its model rejects corroboration.

The native walk caps execution at 4,096 instructions and sampled states at
12,289 records. The local projector caps path scanning at 8,192 steps,
retained observations at 128 and transition attempts at 16. A transition
uses at most 64 direct memory events. Each Z3 query has a 100 ms timeout and
200,000 resource limit. Sampling costs O(N·R) time and space for N entered
instructions and R = 18 scalar register/flag fields, excluding bounded
transfer and predicate snapshots. The projection's existing path and solver
budgets apply in addition. These limits are admission boundaries, not
measured worst-case latency or memory.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | The source-generated paired strings corpus and pinned IDA/RAX artifacts identify the compared binaries. All matrix counts depend on those exact inputs. | Rehash the corpus, executable, plugin and runner artifacts. The verifier checks each of 10 binary and 10 capture hashes. |
| A2 | A complete temporal event prefix retains every entered instruction and ordered event through its cutoff. Local checks using partial register samples depend on this. | Clear prefix completeness while leaving missing registers; portable and live controls require state projection to abstain. The 4,096-instruction combined variant exercises this boundary. |
| A3 | A candidate's entry and exit state, direct transfers, and memory events are complete enough for a fixed-input normal-completion comparison. The 116 corroborations depend on this. | Remove an endpoint register, alter an internal edge, reorder an access, or change an output; portable controls reject or produce a counterexample. The paired probe checks equal sampled/unsampled native paths. |
| A4 | The local x86 symbolic model and the RAX execution observation use the recorded scalar semantics. No cross-input or full-handler conclusion follows. | Compare a different entry state, key, bytecode memory, or alternate entry independently; any mismatch refutes generalization. Intel-defined and undefined flag bits remain distinct as in the prior VM semantics contract. |

## Bounded risks and quality gates

| Impact | Remaining risk or opportunity | Bound |
|---|---|---|
| High | The same native address can be reached with another VM context, key, bytecode value or memory epoch. | Every result carries a visit identity and fixed captured state. No cross-visit merge or dispatch uniqueness is inferred. |
| Medium | Some backend register fields are unavailable and modeled imports have no entered callee. | Missing candidate endpoint values abstain; modeled-call events outside candidates do not supply local proof. |
| Low | The execution or solver budget can stop an otherwise useful path. | Prefix, sample and query status remain separate; four final combined captures explicitly perform no check. |

QG1: no normative judgment is required. QG2: assumptions and falsification
probes are explicit. QG3: this checkpoint covers sampled temporal local
transitions while the review ledger retains incomplete requirements. QG4:
integer instruction, state, event and query counts are verified against exact
artifacts. QG5: incomplete global sampling and the combined-variant abstentions
remain explicit. QG6: source hashes, IDA/fixture identities and the prior
[Intel x86 instruction reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
bound the semantic claims. QG7: the impact table covers adjacent risks. The
portable regression suite, full paired state matrix and installed-plugin
checks establish this local result; full review completion remains open.
