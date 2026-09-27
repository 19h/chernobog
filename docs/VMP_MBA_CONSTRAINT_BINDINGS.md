# Rejected catalog rules and bound constants

This checkpoint advances review row 4a: distinguish an implemented constraint
rejection from evidence of a missing identity. The existing matching inventory
now identifies the final rejected rule at the furthest reached gate and records
its numeric bindings. It adds no rule, replacement, matcher invocation or solver
query. Full review completion remains in progress.

## Production behavior and bounds

`find_match` records a rejected rule only when the existing candidate or constant
check returns false. A later candidate rejection cannot replace an earlier
constant-gate attribution. A later constant rejection replaces the preceding
constant attribution. Success clears the rejection fields; applied/replacement
records continue to name the accepted rule and retain the actual verifier detail.
Gate counts still cover the complete scan. One terminal sample does not describe
every rejected candidate in that scan.

`chernobog_rule_stats().matching_diagnostics` keeps schema 1. A failed candidate
names its rule and reports `candidate_check_failed`. A failed constant check
uses this bounded grammar in `reason`:

```text
constant_check_failed;numeric=name:width_bytes:0xraw_value[,more];omitted=count
```

Bindings are the actual numeric operands with nonnull number payloads in the
matched map. Values retain the raw unsigned 64-bit SDK value; no masking occurs
during recording. Widths are copied only when representable as unsigned 16-bit
metadata; an unrepresentable width contributes an omitted binding. This is a
representation bound, not scalar-width semantic admission. Identifiers contain
ASCII letters, digits or underscore and at most 20 bytes. The formatter retains
at most four eligible bindings and counts quota/name/width exclusions. An
omitted binding does not establish its value. No operand, AST or SDK pointer is
retained in the diagnostic record.

The matcher provides at most eight bindings. The temporary vector borrows name
views only during formatting. With `G` rejected structural matches and `B <= 8`
bindings, added work is `O(G B)` with `O(B)` temporary space, excluding existing
matching and snapshot costs. A standalone formatter with a 64-bit omitted count
emits at most `29 + 4 × 45 + 3 + 9 + 20 = 241` bytes. The existing 256-byte
detail and 128-byte rule caps therefore remain sufficient; four complete
maximal descriptors fit without partial numeric records. The existing 64-key
inventory and its event accounting remain unchanged.

Historical schema-1 captures with empty failed-rule fields remain accepted by
the generic validator. The new constraint audit requires complete, attributed
samples in its explicitly supported rule population. Samples remain transient
stage observations, with the process/database/reset limitations documented in
`VMP_MBA_MATCHING_DIAGNOSTICS.md`; these are not persistent proof receipts or
current-IR navigation authority.

## Independent constraint audit

The protected capture retains failed checks from three rule families:

| Rule | Admitted family replacement | Required bound constant |
|---|---|---|
| `Sub1_FactorRule_2` | `x + c -> x - 1` | All ones at the constant width |
| `And_Rule_3` | `x & c -> x` | All ones at the constant width |
| `Mul_Rule_4` | `x * c -> -x` | All ones at the constant width |

For a `w`-bit family, `M = 2^w - 1`. The audit independently evaluates
`c = raw_value & M` and rejects a reported failure if `c == M`. It checks the
rule's SDK opcode and the exact `c_minus_1` binding, complete capture, scalar
constant width, canonical grammar and unique identifiers.

When `c != M`, the unconstrained family has a direct counterexample:

- ADD: `x = 0` gives original `c` and proposed `M`.
- AND: `x = M XOR c` gives original `0` and proposed nonzero `x`.
- MUL: `x = 1` gives original `c` and proposed `M`.

These are rule-family counterexamples. They do not establish a counterexample
for the concrete captured expression, whose `x` may have additional facts, and
do not prove that another rewrite cannot simplify it. The audit also enumerates
all `256 × 256 × 3 = 196,608` 8-bit family comparisons: each replacement is
universal over `x` exactly when `c == 255`. Wider recorded counterexamples use
exact Python integer arithmetic and explicit masks, without floating-point
rounding. Counts are dimensionless; widths and text caps are measured in bytes.

Primary contracts are `rules_sub.h`, `rules_and.h`, `rules_misc.h`, and the
`is_minus_1` implementation in `pattern_rule.cpp`. Opcode values come from the
local SDK `hexrays.hpp`. Their hashes and the live artifact receipts are pinned
in `VMP_MBA_CONSTRAINT_BINDINGS_EVIDENCE.json` and the audit report.

## Measurements

Forty x86-64/i386 original, mutation, virtualization and combined processes pass.
The independent preservation audit compares 152 native rows, 456 SDK outcomes
and 454 captured CFG/typed value trees against the prior recorded matrix. Trees,
ownership and verifier outcomes match. All 14,065 catalog attempts remain
accounted for, including 1,483 constant-gate events and five existing verified
applications. This feature establishes no protected simplification gain.

The retained samples attribute 662 constant-gate events through 452 keys:
557 events/419 keys for subtraction-by-one, 90/27 for AND, and 15/6 for
multiplication by minus one. Every retained numeric constraint is false and
receives an independent family counterexample. The other 821 constant events
are outside retained samples and have no rule/binding attribution. Overall,
6,953 events exceed the sample quota. Event counts include repeated attempts
and are not counts of unique native instructions or missed identities.

The audit rejects eleven binding/rule corruptions, including a constant whose
low-width bits actually satisfy the constraint despite nonzero high bits.
The protected producer's existing capture corruption controls remain active.
The recorder suite passes 146 assertions, including four new formatting/bound
controls; all 22 CTest suites pass. A same-binary held-out i386 comparison with
the copied installed `e19349f60147` predecessor provides a separate immediate
predecessor control. The full-matrix reference predates the DF checkpoint; its
identity is preserved rather than rewritten.

Reproduce the audit after generating the current matrix:

```sh
python3 -B tests/verify_mba_constraint_capture.py \
  --current build/mba-constraint-protected-accepted/protected_mba_analysis.json \
  --baseline build/mba-matching-diagnostics-protected-attempt-final/protected_mba_analysis.json \
  --output build/mba-constraint-protected-accepted-audit.json
```

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| C1 | The captured rule/bindings belong to the actual failed check; attribution depends on this. | Record inside the existing false-return branch; retain the furthest gate, clear on acceptance, compare terminal counts and actual source ranges. No second checker runs in production. |
| C2 | The three pinned all-ones contracts describe the audited families; counterexamples depend on this. | Check rule/opcode/binding/width, evaluate exact masked arithmetic, exhaust all 8-bit x/c pairs, and reject actually satisfied constraints including high-bit cases. |
| C3 | Matched names are unique and the recording quotas are explicit; parsed metadata depends on this. | Existing map identity, four-binding/maximal-value/name/empty controls and malformed/duplicate/omitted-width capture corruptions. Unsupported or incomplete constraints cannot support this audit. |
| C4 | Source bytes, artifacts and selected SDK stages remain those recorded; preservation depends on this. | Rehash all input/capture reports, compare every recorded typed CFG and verifier result, and use the immediate-predecessor held-out binary control. Complete compiled-source reproducibility is unknown. |
| C5 | Transient observations and family counterexamples remain scoped; interpretation depends on this. | Keep unrecorded counts visible, report 821 unattributed constant events, distinguish family variables from concrete program facts, and retain existing reset/database limitations. |

High impact: these three constraints explain why their recorded constants fail
the existing families; relaxing them would admit invalid family rewrites.
Medium impact: binding capture can guide separate width or reaching-definition
investigations, but does not establish those causes. Low impact: different
failed candidates can share one terminal event; recording every candidate would
need additional quotas and attribution. Full alias, ordering, missing-identity,
flags/exception, lifecycle and review coverage remain incomplete.

QG1 passes for technical observations and exact arithmetic. QG2 passes through
C1–C5. QG3 passes for this constraint-attribution changeset; full review coverage
remains open. QG4 passes through explicit units, bounds and reproduction. QG5
passes within C1–C5 through preservation, negative controls and the family versus
instance distinction. QG6 passes through primary source/artifact hashes and
live receipts; full build attestation remains unknown. QG7 passes through the
bounded opportunities and remaining causes above.
