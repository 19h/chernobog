# Transient matcher inputs and local definition analysis

This checkpoint advances review row 4a. The plugin captures the actual input
before each admitted catalog scan. An independent Python implementation replays
structural matching against the exact certified templates and checks the failed
rule, longest-prefix witness and structural match count. The existing matcher,
rule predicates, typed replacement proofs and transformations retain their
admission decisions. Full causal classification and the complete review remain
in progress.

## Capture contract

`chernobog_rule_patterns()` returns schema-1 templates in registration order,
the local SDK opcode/operand tags, and initialization status. Only templates
whose catalog proof passed are included. Disabled profiles retain an explicit
`not_initialized` snapshot with no templates.

`chernobog_rule_inputs()` returns a separate schema-1 inventory of match-time
inputs. Its events are recorded under the same mutex as historical diagnostics.
Each key includes the existing event fields, capture status and owned payload.
Repeated keys increment after the quota fills; omitted events and all status
counts remain explicit. The existing inventory retains its original keys and
aggregation. Ordinary statistics queries do not copy the new payload inventory.
Separate API queries do not constitute a transactional cross-query snapshot;
the process probes query after synchronous generation and check equal totals.

An input contains the candidate AST, the enclosing top-level instruction, its
binary EA, and a consecutive predecessor suffix from the same current block.
The predecessor walk checks both links and cycles. A broken link discards the
entire suffix. Traversal or byte exhaustion retains only complete nearest
predecessors and names the frontier; it never skips an internal instruction.
Enclosing-instruction exhaustion preserves the root but supplies no context.
Root exhaustion supplies an explicit status and no payload.

The SDK projection preserves every field consulted by structural matching or
strict comparison: operand kind, size, value number, properties, storage
identity, numeric value, owner identity, nested instruction metadata and text.
Frame owners become event-local tokens, with zero denoting null. Host pointers
never enter a payload. Helper/string bytes use hexadecimal encoding. Opaque
operand kinds carry only common metadata and an opaque marker because strict
comparison refuses their payloads unconditionally. This is a matcher projection;
it is not a complete call, memory or execution-state representation.

## Independent replay

The Python implementation uses the captured templates and operands without SDK
or C++ matcher calls. It retains width masking, repeated-binding comparison,
the eight-binding capacity, exact arity, lazy commutation, binding/count rollback,
first ties and successful-path clearing. Nested strict comparison visits
destination before left and right; explicit loads also compare their EA.
Both-null payloads retain the existing comparison behavior. Unsupported operand
kinds and depth/visit exhaustion remain rejections.

All indexed patterns are replayed for failed scans. Accepted scans stop at the
recorded accepted rule, preserving the production traversal count. Candidate
and constant predicates and typed replacement proofs are not independently
executed: their attribution remains the production record. Agreement between
implementations and mutation controls is measured evidence at this scope, not
a proof that both implementations lack every possible shared defect.

## Local byte definitions

The read-only analyst starts with unknown incoming values. Under normal
completion of the captured consecutive prefix, exact scalar register writes
invalidate their overlapping byte microregisters. Supported literal and pure
arithmetic writes establish new byte values. A read requires all bytes, matching
last-write value numbers and zero operand properties. Partial writes, unknown
values and differing metadata preserve unknown bytes. Unsupported instructions,
calls, nonzero instruction properties and possible effects clear all facts.
Pure flag assignments invalidate their destination without erasing disjoint
register facts. No memory fact or inter-block reaching definition is inferred.

Facts are used only when the enclosing expression is pure and nested
expressions have no register destination. Thus unrepresented sibling effects
cannot supply a local constant claim. The measured architectures are i386 and
x86-64; byte assembly uses their little-endian order. Faults, asynchronous
effects and whole-program execution equivalence are outside this analysis.

Known register leaves can be replaced in an owned counterfactual AST by numeric
values of the same width. Nested SDK operand projections are updated alongside
their children. Existing patterns are then rematched structurally. This does
not execute a live rewrite, validate rule predicates, establish a missing
identity, or show that a later SDK pass fails to simplify the expression.

## Bounds and complexity

Each input is limited to 8,192 bytes, depth 64, 512 encoding visits and 64
predecessor heads. The catalog is limited to 32,768 bytes, depth 64 and 8,192
template visits. Each inventory retains 64 keys. The combined maximum retained
text payload is `64 × 384 + 64 × (8,192 + 384) = 573,440 bytes`, excluding
allocator capacity, object metadata, temporary snapshots and AST/SDK storage.
Catalog payload adds at most 32,768 bytes. The process report cap is 8,388,608
bytes; it is a report limit, not a whole-process memory bound.

For bounded encoding visits V and text bytes B, ordered pointer/token tracking
costs O(V log V + B) time and O(V + B) space. Recorder key lookup costs
O(K B), K ≤ 64, in the worst case; snapshots own O(K B) payload. Independent
commutative matching can explore exponentially many branches in the number of
commutative pattern nodes. Local byte analysis costs O(P + W + A) time for
visited prefix operands P, assigned byte widths W and candidate visits A;
each scalar width is at most eight bytes. Its state uses O(W) space. No
whole-process latency or memory guarantee is asserted.

## Controls and provenance

The complete original, mutation, virtualization and combined x86-64/i386
matrix passes all 40 processes, including reserved protector seed 12648430.
Independent comparison preserves 152 native rows, all 456 SDK stage outcomes,
454 captured CFG/typed value trees, every historical diagnostic inventory and
all 14,065 terminal catalog outcomes, including five existing applications.
The two existing SDK refusals remain. A fresh run with the actual preceding
installed module reproduces all 16 held-out i386 historical inventories.

The new inventory retains 3,950 distinct inputs representing 5,266 events and
omits 8,799 events under the 64-key quota. Every retained input independently
replays successfully. Producer status counters report complete roots for all
14,065 attempts; omitted payloads are not independently replayed. Retained
prefix frontiers represent 3,382 block-entry events, 1,816 broken-link events
and 68 missing-anchor events. Broken/missing context supplies no local facts.
The conservative analyst finds no eligible local constant fact in the retained
structural-failure population. The demonstrated zero-definition counterfactual
is a component result; no production simplification gain is established.

Nine corrupted production input/site/index/witness fields are rejected. All
40 live module tags match source fingerprint `b8d275904cc1`, independently
recomputed from 217 build inputs. The largest measured matrix process uses
51,643,327,833 ns and 203,816,960 resident bytes. These are single-process
observations; scheduling/repeatability error bounds and comparative performance
effects are unknown.

All 23 CTest suites pass. Sixteen exported component candidates compare actual
C++ match results and failure witnesses with independent replay. Ten borrowed
SDK operand pairs check owner tokens, offsets, text, opaque calls, load EAs,
destination-before-left comparison and nested properties. Five corrupted input
schemas/fields are rejected. Twelve capture-bound controls and paired recorder
quota, snapshot/reset and concurrent accounting controls pass. Component SDK
copying remains limited to empty/register/global operands; borrowed descriptors
do not emulate SDK allocation or recursive copying. The initial component
trial used SDK allocation for linked fixtures; it was corrected by allocating
ordinary wrappers containing value-only instructions, retaining the original
dispatcher refusal and trial log.

Primary provenance includes the pinned local SDK `hexrays.hpp` microregister
contract (each microregister is eight bits; adjacent registers represent larger
processor registers), operand definitions and instruction descriptions; the
repository bitvector/matcher implementations; exact module/source hashes; and
the retained process artifacts. Evidence is recorded in
[VMP_MBA_INPUT_REPLAY_EVIDENCE.json](VMP_MBA_INPUT_REPLAY_EVIDENCE.json).

## Assumptions and bounded expansion

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| A1 | Recorded modules and sources identify the compared implementations; all comparative claims depend on this. | Hash immutable candidates and current source inputs, recompute the build fingerprint, check live tags, and execute the actual prior installed module. |
| A2 | The captured SDK projection preserves the matcher fields; replay claims depend on this. | Compare actual C++ fixtures and strict differences, reject malformed projections, and independently replay every retained complete production input. Opaque semantics remain unknown. |
| A3 | Consecutive pure normal-completion x86 microcode supports the stated local byte facts; local findings depend on this. | Check overlapping writes, calls, stale value numbers, insufficient bytes and operand properties. Reject impure/missing enclosing expressions; start every suffix with unknown input. |
| A4 | Selected entries and current bounded inventories define the measured population; production counts depend on this. | Compare ownership, bytes, typed trees, all historical diagnostics and profile populations; retain omitted denominators and SDK refusals. Broader protected coverage is unknown. |

Bounded opportunities: **medium**, independent transient replay makes actual
shape/metadata failures reproducible; **medium**, an available local constant
can identify a concrete structural counterfactual for investigation; **low**,
larger per-key payloads distinguish more events and lower retained coverage
under the unchanged key quota. Full CFG definitions, aliases, width/order
counterfactuals, absent identities and protected recovery gains remain open.

QG1: technical work, no normative content required. QG2: A1–A4 and probes above.
QG3: capture/replay/local-analysis scope is implemented; full review remains
open. QG4: byte bounds and dimensionless counts are reproducible; measured
timing uses ns and resident size uses bytes. QG5: context frontiers, opaque
fields, effects, predicates and omitted events are explicit. QG6: primary SDK,
source and actual module/process artifacts are pinned. QG7: bounded expansion
and remaining scope are explicit. These gates apply to this checkpoint.
