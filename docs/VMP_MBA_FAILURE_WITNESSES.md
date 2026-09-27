# Actual catalog matching failure witnesses

This checkpoint advances review row 4a. A failed catalog scan now retains one
actual failed matcher branch, its rule, and the operand check that refused it.
An empty opcode bucket identifies the unindexed root explicitly. The production
matcher, binding rollback, rule constraints and typed replacement proofs retain
their admission decisions. Full causal miss classification and the complete
review remain in progress.

## Matcher contract

`match_pattern` accepts an optional `MatchFailure` output. A failed node check
or repeated-binding comparison records its actual reason. The matcher keeps
the failure with the greatest number of preceding successful node checks in
that branch. Backtracking restores that count alongside the existing binding
count. Equal counts keep the first failure in traversal order. An eventual
successful match clears the entire failure output, including failures from
discarded commuted branches. `find_match` selects the same maximum across
failed indexed patterns while no structural match has been found. Candidate
and constant failures retain the existing furthest-gate attribution; success
clears the rejected-rule fields.

The prefix score counts node checks, including a parent's accepted opcode and
arity before its children finish. It is neither tree edit distance nor a count
of wholly matched subtrees. The selected failure witnesses one failed branch;
changing its field does not establish that the complete rule will match, that
other branches fail for that reason, or that the program should simplify.

`mops_equal_strict` also accepts an optional first-difference output. Its
ordered comparisons retain operand kind, width, value number, properties,
storage identity and frame owner. Nested comparisons retain instruction opcode,
properties, destination and operands; explicit loads retain their source EA.
The existing depth-64/512-visit comparison limit remains a rejection. Both-null
payload comparisons retain their previous equality behavior; public AST
construction separately rejects malformed null payloads before SDK copying.

The witness distinguishes shape checks, fixed constant checks, repeated-value
metadata differences, unsupported operand comparison, and binding/comparison
limits. It stores no SDK pointer, operand, binding name or AST. Frame-owner
differences have no emitted pointer values. Other fields report unsigned
64-bit values; a negative signed metadata field is represented modulo `2^64`.
Fixed constant checks record the values after the existing operand-width mask;
repeated number comparisons retain the existing raw SDK values.

## Schema, paths and bounds

The existing schema-1 `matching_diagnostics` inventory supplies `rule` and
`reason`. Structural failures use:

```text
match_failed;kind=CAUSE;p=PATTERN_PATH;c=CANDIDATE_PATH;nodes=COUNT[;e=0xEXPECTED;a=0xACTUAL];cut=0_or_1
```

Paths contain `L`/`R`, or `-` for the root. They follow the actual pattern and
candidate separately through every commuted alternative. Each path retains
at most 64 bytes; `cut=1` identifies omitted suffixes. Path truncation changes
diagnostic representation only. A repeated binding's paths identify its
current AST occurrence, while its first differing SDK field may lie inside
the bound composite operand. The first binding's origin path is not retained.
Numeric fields occur only for checks that directly compare numeric metadata.

An empty root bucket reports `root_opcode_unindexed;opcode=N` with no rule.
Historical captures with empty structural/unindexed attribution remain
accepted by the generic validator. The new audit requires complete witnesses
and rule membership in the captured enabled, wholly certified catalog.
Disabled profiles retain registered names but do not initialize the catalog.

At maximum name length 18, two 64-byte paths, a 20-digit count and two
16-digit hexadecimal values, a complete detail occupies 245 bytes. The
existing 256-byte detail, 128-byte rule and 64-key inventory bounds suffice.
An improving failure copies at most two bounded paths. For `V` actual matcher
visits and diagnostic path bound `D=64`, added work is `O(V D)` and bounded
path payload is `O(D)` per live witness. This does not make the existing
commutative backtracking algorithm linear: its branch exploration can be
exponential in the number of commutative pattern nodes. SDK copies, allocator
capacity, existing AST storage and recursion costs are outside the diagnostic
payload bound. No whole-process time or memory bound is asserted.

## Production measurements and controls

The complete x86-64/i386 original, mutation, virtualization and combined
matrix passes all 40 processes, including reserved protector seed 12648430.
Against the preceding AST-construction checkpoint, the independent audit
preserves 152 native rows, 456 SDK outcomes, 454 captured CFG/typed value trees,
all 14,065 terminal catalog outcomes and five existing verified applications.
The two existing SDK refusals remain. A fresh reserved-seed i386 run with the
actual preceding installed module reproduces all 16 archived diagnostics and
retains the same typed captures and terminal counts as the candidate.

| Retained witness | Events |
|---|---:|
| Unindexed root opcode | 4,469 |
| Pattern requires a numeric operand | 463 |
| Pattern requires an operation node | 1,451 |
| Fixed constant differs | 24 |
| Total attributed matching failures | 6,407 |

The 1,938 structural events name seven existing rules. For example, a retained
one-byte `Xor_Rule_2` check requires `0` but observes `0x7d` at path `R`.
Its detail records `constant_value`, expected `0`, actual `125`, and two
preceding successful checks. Another ADD event identifies an absent node at
`Add_CarryFreeOrRule` path `R`. These records do not establish a missing
identity or an unavailable reaching definition. No width, value-number,
frame-owner, commuted-path or truncated-path witness is observed in this
retained production population; those cases have explicit component controls.

The inventory retains 7,069 total events and omits 6,996. More detailed keys
change aggregation: the previous checkpoint omitted 6,953 events. Therefore
the retained cause counts cannot be extrapolated to all 4,474 structural or
8,103 unindexed-root events. The audit rejects 14 corruptions of rule membership,
cause/field grammar, paths, prefix count, truncation and root-opcode attribution.

The catalog executable passes 184 new witness checks plus two initialized
registry attribution controls, retaining 108 AST-bound checks, 1,247 operand
identity checks, 190 typed-instance results, all 108 certified rules and the
intentionally false 109th rule rejection. All 22 CTest suites pass. Component
SDK copying remains limited to allocation-free empty/register/global operands;
borrowed stack/local/nested descriptors exercise comparison without emulating
the SDK allocator or recursive copier.

The largest measured matrix process uses 51,795,749,833 ns and 203,341,824
resident bytes. These are scoped single-process observations, with scheduling
and repeatability error bounds unknown. No latency improvement or protected
simplification gain is established. Receipts, source/module hashes and the
local SDK primary contract are pinned in
[VMP_MBA_FAILURE_WITNESSES_EVIDENCE.json](VMP_MBA_FAILURE_WITNESSES_EVIDENCE.json).

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| A1 | The recorded candidate and prior modules identify the intended source states. All comparative claims depend on this. | Hash modules/probes/captures, verify current source fingerprint, run the actual prior installed module on the reserved-seed input, and reject changed artifacts. |
| A2 | Existing catalog order defines tie attribution. Rule/path identity depends on this order. | Exercise equal-prefix failures, a longer commuted prefix and successful commutation that clears failures; retain the actual registered rule-name inventory. |
| A3 | Component operand fixtures exercise the SDK comparison fields used here. Component metadata claims depend on this. | Fail on unsupported SDK operations, borrow immutable frame-owner descriptors, and separately execute the real IDA matrix. These fixtures do not establish SDK allocation behavior. |
| A4 | The selected entries and existing one-hop owners define the measured population. Population counts depend on this. | Compare native ownership, bytes, stage populations, CFG and typed operands; retain unavailable owners and SDK refusals. Broader protected coverage is unknown. |

Final SDK captures are observations after generation, while matching failures
may arise earlier within that generation. They cannot independently reconstruct
every transient candidate or replay its complete matcher path. The audit
validates representation, actual catalog membership, source attribution and
preservation; it does not upgrade those records to a complete causal proof.
Exact reaching-definition/alias provenance, width/order counterfactuals and
demonstrated absent identities remain required review work.

Bounded opportunities: **medium**, an actual failed path can select a concrete
definition or conversion for subsequent investigation; **medium**, preserving
value-number/frame-owner differences makes an identity mismatch inspectable
without inferring an alias relation; **low**, finer keys reduce retained event
coverage under the fixed quota and require the explicit unrecorded denominator.

QG1: technical work, no normative content required. QG2: A1–A4 and probes above.
QG3: the complete witness feature is implemented and measured; full review
requirements remain explicitly open. QG4: counts are dimensionless, path/text
payloads use bytes, timing uses ns, and arithmetic bounds are exact. QG5:
rollback, ties, successful-path clearing, pointer exclusion and quota changes
are explicit; transient-input reconstruction remains unavailable. QG6: local
SDK/source hashes, actual module captures and immutable preceding receipts
provide primary provenance. QG7: bounded opportunities and remaining scope are
identified. These gates establish this checkpoint, not full review completion.
