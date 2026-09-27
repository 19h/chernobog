# Catalog matching diagnostics at actual microcode sites

Review row 4a now has bounded production diagnostics for the matching stage
that an actual catalog attempt reaches. `chernobog_rule_stats()` exposes the
JSON string `matching_diagnostics`; `chernobog_rule_reset_stats()` resets it.
The block-level handler's existing reset also clears this inventory.

The recorder runs on the existing catalog path after chain/optional affine
processing. It performs no extra AST construction, matching, solver query or
rewrite. Each actual `find_match` attempt has one terminal outcome. Null input
and an uninitialized registry do not enter the attempt denominator. A separate
flag distinguishes failed replacement construction from a completed instance
check, including an unsupported result whose reported bit width is zero.

## Outcomes and interpretation

| Outcome | Recorded condition |
|---|---|
| `no_ast` | An actual attempt could not convert its root to an AST. |
| `no_indexed_pattern` | The converted root has no entries in the active pattern index. |
| `structural_mismatch` | Indexed entries exist, but none matches the current tree. |
| `candidate_constraint` | Structural matches exist; all fail their candidate checks. |
| `constant_constraint` | At least one structural match reaches and fails its constant check; no binding is accepted. |
| `replacement_unavailable` | An accepted binding cannot produce a replacement before instance checking. |
| `instance_disproved` | The actual proposed replacement has a typed counterexample. |
| `instance_unsupported` | The actual instance checker rejects unsupported effects, widths or values. |
| `instance_unknown` | The actual instance checker does not establish equivalence. |
| `catalog_applied` | A typed instance is verified and the catalog replacement is applied. |

If a scan rejects different candidates at different gates, its terminal
classification records the furthest gate reached. Each sample also retains
the number of indexed entries, structural matches, candidate rejections and
constant rejections. An accepted binding has exactly one additional structural
match beyond those rejected candidates. Existing successful-match counters
still count accepted bindings before replacement verification.

An absent indexed pattern or a structural mismatch does not establish a
missing algebraic identity. Reaching definitions, aliasing, conversions and
optimization ordering can affect the presented tree. These remain separate
investigations using the actual stage captures. A constraint rejection states
which implemented gate stopped this attempt; it does not establish that the
original expression should simplify. Scalar width admission and the existing
tree traversal guards occur before this catalog inventory. Chain/affine-only
rewrites, unsupported root widths, unowned bodies and SDK refusals are outside
its attempt denominator.

## Retention and attribution

One locked process-local inventory retains ten outcome counts, a total event
count, at most 64 distinct sample keys and an unrecorded-event count. A key
contains the microcode entry, source EA, maturity, block serial, opcode, result
width in bytes, gate counts, outcome, bounded verifier detail and rule name.
Repeated retained keys increment after the quota fills. Other events still
increment their outcome and the unrecorded count. The following exact
identities hold for a complete snapshot:

```text
events = sum(outcome counts)
events = sum(retained sample counts) + unrecorded
events = total_matches                     # serialized fixture collection
accepted bindings = sum(outcomes from replacement_unavailable through catalog_applied)
```

Verifier detail is capped at 256 bytes and the rule name at 128 bytes. The
maximum retained string content is `64 × (256 + 128) = 24,576 bytes`, excluding
C++ object/allocator overhead and copied snapshots. No IDA object or operand
pointer is retained. A snapshot owns its strings and remains valid after
updates/reset. For `A` events, `S ≤ 64` retained keys and bounded string length
`B ≤ 384 bytes`, recording takes `O(A S B)` time and `O(S B)` retained content,
excluding existing matcher/solver costs. Snapshot copying takes `O(S B)`.

Samples are references to the observed optimization stage. They are not
persistent proof receipts, current IR applicability or navigation authority.
The inventory is process-local and lacks a database/run identity. It can mix
earlier generations or database contexts unless reset. Individual diagnostics
are snapshotted under one lock; the separate registry and instance statistics
do not form a joint atomic transaction with that snapshot. The fixture resets
before each generation in a fresh isolated IDA process and queries after that
generation completes.

The independent audit checks each retained source EA against the selected
native chunks, permitting SDK `BADADDR` for a synthetic source. A range check
does not prove that a reference still identifies the same native instruction
after a later database edit. Captured native bytes and tool/report hashes
provide the separate measurement attribution.

## Measurement scope

The complete x86-64/i386 original, mutation, virtualization and combined
matrix preserves all 152 native rows, 456 SDK outcomes and 454 captured CFG/
typed value trees from the preceding checkpoint. It adds five verified catalog
application observations to the diagnostic count, while the pipeline's
existing five typed verifications remain unchanged. These are observations of
the existing pipeline; this feature adds no simplification or protected
recovery gain.

All 40 processes pass. The 14,065 actual catalog attempts comprise 8,103
index absences, 4,474 structural mismatches, 1,483 constant-constraint
rejections and five verified applications. These add exactly to 14,065.
The 3,507 retained sample keys account for 7,112 events; another 6,953 events
exceed sample retention, and `7,112 + 6,953 = 14,065`. These are repeated
optimization attempts, not unique missed expressions or native instructions.
Zero observations in the other six outcome categories establish no corpus
coverage for those paths.

The paired ten-routine x86-64 shape corpus covers De Morgan/carry forms,
stack definitions, truncation/extension, full/partial intervening memory
writes and optimization ordering. Prior/current captures and pseudocode match.
The independently executed native oracle checks 70,656 cases. The existing
scalar IR interpreter checks 70,656 result/memory cases for each enabled
artifact: 141,312 comparisons of the complete 64-bit result and four-byte
observable cell. Its same-plugin off/on command retains its artifact-equality
guard; the prior/current audit invokes its interpreter with separately checked
distinct module identities. No flag, exception or complete protected-body
equivalence follows from these finite comparisons.

The separate recorder suite checks quota boundaries, retained-key increments
after saturation, owned snapshots, reset and concurrent recording. The catalog
suite also checks null input and an uninitialized registry. Production capture
audits reject corrupted totals, owners, source references, maturity, widths,
gate counts, text limits and duplicate samples. Exact counts, source pins,
primary SDK contracts, module identities and reports are recorded in
[VMP_MBA_MATCHING_DIAGNOSTICS_EVIDENCE.json](VMP_MBA_MATCHING_DIAGNOSTICS_EVIDENCE.json).
Historical source pins and reports remain unchanged. Compiled-source
reproducibility remains unknown; a capture-time worktree snapshot does not
identify the source compiled into a historical module.

All 22 CTest suites pass, including 142 recorder assertions and two catalog
admission controls. The matrix rejects 602 capture mutations; the separate
matching audit rejects nine additional corruptions. The maximum observed
process duration is recorded in the evidence JSON in nanoseconds and seconds.
It includes startup, analysis and concurrent capture; no speedup or general
latency distribution is inferred. IDA's gooMBA plugin is loaded, so the capture
does not isolate Hex-Rays alone.

Reproduce the independent matrix audit after generating the current capture:

```sh
python3 -B tests/verify_mba_matching_capture.py \
  --current build/mba-matching-diagnostics-protected-attempt-final/protected_mba_analysis.json \
  --baseline build/direct-jump-flow-protected-final/protected_mba_analysis.json \
  --output build/mba-matching-diagnostics-protected-attempt-audit.json
```

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| D1 | Outcomes identify the actual implemented gate, rather than a semantic cause. Stage classification depends on this. | Record the original scan counts without an extra matcher; retain zero-observation categories and do not infer a missing identity from index absence. |
| D2 | The sampled optimization metadata names the measured selected microcode. Site attribution depends on this. | Reset per generation, check entry/maturity/scalar widths and native source ranges, and reject corrupted owner/source references. Current applicability after edits remains unknown. |
| D3 | The fixture serializes generation and statistic queries in one fresh database context. Cross-counter accounting depends on this. | Compare totals and per-outcome/sample sums, enforce disabled-profile zeros, test concurrent recorder updates and retained snapshots; concurrent cross-subsystem resets remain outside this measurement. |
| D4 | The catalog denominator contains actual attempts after preprocessing. Event accounting depends on this. | Add null/uninitialized-registry controls; separately retain SDK/ownership/traversal limits and the unrecorded-event count. |
| D5 | Pinned artifacts and finite independent oracles establish the stated measurement scope. Preservation depends on these identities. | Rehash raw captures and source scripts, compare every recorded typed tree/CFG/verifier outcome, reject corrupted diagnostics and independently interpret both ten-routine captures. Compiled-source reproducibility and full ISA effects remain unknown. |

**High impact:** record the gate and actual stage before proposing another
identity; structurally absent definitions or an explicit conversion can present
the same terminal mismatch. **Medium impact:** first-seen sample quotas can
omit later sites while preserving all outcome counts; unrecorded events must
remain visible. **Low impact:** automatic causal classification of reaching
definitions, aliases and rewrite ordering remains an expansion requiring its
own source/stage evidence. Full review completion remains in progress.

QG1: technical scope. QG2: D1–D5 state dependencies and falsification probes.
QG3: catalog gate reporting, production capture attribution, retention and
preservation are covered; full review requirements remain open. QG4: bytes,
counts and algorithm bounds are explicit. QG5: ignored inputs, gate versus
cause, capped sites and prior/current artifact identities are distinguished.
QG6: primary local SDK contracts and measured reports are hash-linked.
QG7: wider causal classification, ownership and ISA effects remain bounded.
