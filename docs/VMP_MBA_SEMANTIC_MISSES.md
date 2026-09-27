# Typed semantic checks on actual catalog rejections

Subsequent integer flag/predicate support requires original instruction metadata;
the fresh audit refutes reductions for 4,595 retained events and leaves 666
unsupported. See [VMP_INTEGER_FLAGS.md](VMP_INTEGER_FLAGS.md). Historical
observations and source hashes below remain unchanged.

This checkpoint advances review row 4a using the immutable match-time inputs
captured by commit `3b21e98c842ee4f179aa0b3d25e0ea7920fcea9b`. An independent
tool checks simpler scalar values and three rejected replacements on actual
captured operands. Plugin matching, predicates, transformations and proof
admission are unchanged. Full causal classification and review remain open.

## Input contract

The checker first independently replays the actual matcher input and certified
catalog. It accepts a single scalar arithmetic/conversion root with immediate
value operands: ADD, SUB, MUL, AND, OR, XOR, bitwise NOT, NEG, MOV, zero/sign
extension and low/high extraction. Binary arithmetic and MOV retain width;
conversions have explicit input/output widths. Unexpected arity, properties,
nested arithmetic, unsupported operators and effects remain unsupported.

Overlapping register reads with the same value number share exactly their
byte microregisters. Different value numbers remain independent. Stack/local
snapshots include event-local owner tokens; globals retain binary addresses.
Exact overlap within a storage class shares bytes. No alias relation between
storage classes is inferred. Reserved/condition microregisters below eight
remain unsupported because the captured projection supplies no Boolean state.

Admitted explicit loads retain selector/address/width/source projections and
separate independent read occurrences. Equal addresses/EAs do not equate reads.
Implicit memory in a load address, malformed payloads and unmodeled nested
values remain unsupported. This retains the production verifier's read-occurrence
contract; it does not establish memory stability, address validity or faults.

The domain is unconstrained snapshot bytes under normal completion. Additional
CFG facts, source-language invariants, heap relations, native reachability and
asynchronous/fault behavior are unknown. A counterexample refutes an unconditional
value reduction in this domain and need not be a reachable native state. No
result supplies authority for a live rewrite or absence of every other identity.

## Queries and witnesses

For each supported root, the tool asks whether two snapshot assignments can
produce different results. SAT supplies two integer-checked examples and
refutes replacement by any fixed constant. It also asks whether the root can
differ from each immediate operand of the same result width. SAT refutes a MOV
of that operand. Width-changing MOV candidates are excluded explicitly.

UNSAT identifies a potential value reduction within the contract. UNKNOWN
proves neither equality nor inequality. Refutation requires SAT and a checked
witness for every eligible query. The candidate set contains constants and
current operands; arbitrary instruction sequences and identities are not searched.
These results do not establish a globally minimal expression.

Each SAT model retains exact input bytes, operand values and result. A separate
integer evaluator assembles x86 little-endian bytes and repeats masked arithmetic
without another solver query. Shared cells keep overlapping reads consistent.
Six corruption controls reject changed results/proposals, lost/out-of-domain
bytes, extra operands and false solver states.
Nine additional controls reject corrupted saved constraint bindings, widths,
gates, bound paths, proof states and results, plus a width-changing MOV target.
Constraint witness replay repeats validation of the captured numeric binding.

The prior family audit lacked the actual `x` expression. The new checker uses
the captured operands/widths and actual certified templates for:

| Rejected rule | Counterfactual replacement |
|---|---|
| `Sub1_FactorRule_2` | `x + c` to `x - 1` |
| `And_Rule_3` | `x & c` to `x` |
| `Mul_Rule_4` | `x * c` to `-x` |

The recorded `c_minus_1` width/raw value must equal the actual numeric operand,
including commuted MUL. A claimed rejection whose masked constant is all ones
is refused. Integer replay checks the complete instantiated primitive expression.
Native reachability and additional state facts remain outside the contract.

## Measurements

The source-pinned x86-64/i386 matrix retains all 40 original, mutation,
virtualization and combined processes, including reserved seed 12648430. Its
14,065 attempts retain 3,950 keys representing 5,266 events; 8,799 events lack
retained payloads. The matcher audit preserves all 456 SDK outcomes, 454 typed
captures and historical diagnostics. This analysis reuses immutable observations;
it does not present them as newly generated protected executions.

| Classification of retained events | Events |
|---|---:|
| Refuted constant/current-operand reduction | 1,845 |
| Unsupported semantic input | 3,421 |
| Total | 5,266 |

Unsupported includes 3,401 roots outside the operator model, eight nested
arithmetic subtrees, six unmodeled nested/load contracts and six condition-register
cases. Unsupported does not imply that no reduction exists. Retained gate
counts are 1,214 structural, 521 constant and 3,531 unindexed events; these
are neither missed identities nor unique native instruction counts.

All 521 retained constant events have actual typed counterexamples to their
rejected replacement. Reduction queries supply 5,273 event-weighted SAT witnesses,
with 521 additional constraint witnesses. Integer replay checks every witness.
No production value reduction or UNKNOWN result occurs in the supported retained
population. Omitted inputs remain unclassified. No protected recovery gain or
complete causal diagnosis is established.

The existing conservative local-constant analyzer finds no eligible complete
literal fact in any of these 3,950 rejection inputs. This does not exclude
partial known bits, inter-block relations or other state invariants. The
semantic audit process takes 1,462,765,750 ns and peaks at 202,539,008 resident
bytes; the 93-control process takes 515,253,708 ns and peaks at 118,882,304
bytes. These are scoped single-run measurements, with repeatability error
bounds unknown.

## Controls, bounds and provenance

Ninety-three controls cover scalar widths, equal/distinct operands, value numbers,
register overlap, owner tokens, properties, condition state, conversions and
invalid conversions, separate loads and false numeric bindings. The particular
value `0 & 3` equals `0` despite failing the universal all-ones family contract;
this demonstrates why a family rejection alone cannot classify every instance.
It is a component result, not an observed production miss.

An actual Z3 resource limit of one returns UNKNOWN and never becomes a proof.
Ordinary component budgets are 1,000 ms and 1,000,000 resource units per query;
production analysis uses 250 ms and 100,000 units. A free 64-bit multiplication
control exhausts the smaller limit and resolves at the component budget.
Resource units are engine counters, not instructions or SI time units.

The tool pins Python `z3-solver` 4.16.0.0, engine 4.16.0, API files and the
shared library retained by its actual ctypes dispatcher. The package contains
multiple operating systems' libraries; an initial filename-enumeration ambiguity
was corrected by binding the loaded library. Initial receipts are preserved.
Source, engine or captured-artifact changes invalidate the analysis receipt.

Two operands of at most eight bytes need at most 16 symbolic byte cells. A
primitive uses at most three queries; a rejected rule adds one. For K inputs,
V matcher visits and solver costs S_i, work is O(V + K + sum S_i), excluding
retained witness serialization. Independent commutative matching can explore
exponentially many branches. Per-query caps do not establish a whole-process
time or memory bound. Counts/masking are exact; timing error bounds are unknown.

Primary provenance includes local SDK byte/condition-register and operand
contracts, captured certified templates, repository rule/bitvector/instance
implementations, actual module/corpus receipts and the loaded solver. Hashes
are in [VMP_MBA_SEMANTIC_MISSES_EVIDENCE.json](VMP_MBA_SEMANTIC_MISSES_EVIDENCE.json).

Reproduce with the pinned Python package and retained source-pinned capture:

```sh
python3 -B tests/mba_semantic_miss_tests.py --fixtures build/match-input-component-fixtures.json
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/match-input-protected/protected_mba_analysis.json \
  --output build/mba-semantic-audit-reproduced.json
```

## Assumptions and bounded expansion

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| A1 | Pinned captures identify intended matcher inputs; counts depend on this. | Check source/module/artifact hashes, independently replay templates/inputs and check ownership, maturity and event accounting. |
| A2 | Normal-completion snapshot bytes define the stated domain; semantic results depend on this. | Check widths/conversions, shared bytes, versions, owners and separate reads; leave flags, further CFG facts, cross-class aliases and faults unknown. |
| A3 | Pinned solver and integer evaluator implement their contracts; proof claims depend on this. | Hash the loaded library, retain budgets, replay SAT values, test resource UNKNOWN and reject corrupted witnesses. UNSAT is not independently certified here. |
| A4 | Quota-retained inputs define only the measured population; coverage depends on this. | Retain all 8,799 omissions and unsupported denominators; do not extrapolate classifications. |

Bounded opportunities: **medium**, actual typed counterexamples distinguish
invalid reductions from evidence of missing identities; **medium**, shared-byte
inputs expose width/overlap errors; **low**, cached proofs reduce repeated work
while retaining event witnesses. CFG definitions/aliases, flags, arbitrary
identities, ordering causes, reachability and protected effectiveness remain.

QG1: technical work, no normative content required. QG2: A1–A4 with probes.
QG3: semantic-analysis scope is implemented; full review remains open. QG4:
integer masking/counts are exact, widths use bytes/bits, query time uses ms and
process timing uses ns. QG5: UNKNOWN, unsupported effects/state and omissions
are explicit. QG6: primary SDK, source, module observations and solver are pinned.
QG7: bounded expansion and remaining requirements are explicit. These gates
establish this checkpoint, not full review completion.
