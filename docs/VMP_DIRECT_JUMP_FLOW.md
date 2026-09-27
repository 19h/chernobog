# Reanalysis of partially decoded direct-jump targets

The direct-jump metadata pass now schedules ordinary processor reanalysis
after admitting a target in an executable `SEG_DATA` segment. It also handles
an existing ownerless code head followed by loaded, undecoded instruction bytes.
This advances review rows 1b, 4a and V. The pass changes code-item discovery
and analysis queues. It preserves machine bytes and segment permissions;
function membership and proven edges retain their respective existing contracts.

## Admission and scheduling

The existing admission requires an exact decoded near JMP, its current
non-user jump reference, matching non-16-bit source/target segment modes and
an executable data segment. Unknown target bytes retain the original
loaded-byte, item and interior-label guards before `create_insn`.

For an existing target head, its item extent must match the decoded instruction
and all its bytes must be loaded. The head must have no function owner and
neither `CF_STOP` nor `CF_CALL`. Its fallthrough must also be ownerless, unknown,
loaded and separately decodable within the same segment. Every byte in that
next instruction must remain unknown and loaded, with no interior user label.
Defined data, tails, existing owners, invalid/unloaded bytes and incompatible
modes retain abstention. A label at the exact admitted entry remains permitted.

The pass schedules that admitted fallthrough with `auto_make_code`, then the
head with `plan_ea`. Explicit successor scheduling matters when IDA retains an
old flow reference after the successor item was undefined. Both operations
enqueue ordinary IDA analysis. This code creates no function or tail, changes
no segment type, and supplies no native execution or unique-target proof.
IDA remains responsible for subsequent decoding and ownership decisions.

The additive `chernobog_native_stats().direct_jump_heads_reanalyzed` field
counts scheduling requests from this pass, including newly created target heads.
It counts neither unique heads nor completed processor operations. The existing
target-creation count remains separate. The configured cumulative attempt cap
is unchanged: default 256, hard maximum 4,096. Scheduling adds no persistent
cache or receipt format. A script driving item edits must run the native pass
and drain its queued analysis before checking the result; a read-only statistics
snapshot does not run the pass.

## Counterfactual and rejection controls

In two staged executable-data regions, the fixture retains a five-byte MOV
head but undefines its following RET. Reanalysis of the source jump and an
explicit native pass leave both successors unknown under the preceding
installed module. The corrected artifact restores both RET code heads without
creating another target head or forcing a function owner. The corresponding
native bytes remain unchanged.

The current default probe passes 70 checks. It covers those two repairs, the
original 12 admission cases, and three successor guards: defined successor data,
data inside the prospective successor and an interior user label. The guards
preserve item definitions and bytes and add no reanalysis request. Separate
zero-cap, one-cap and disabled profiles pass 53, 53 and 51 checks: 227 current
checks total. The predecessor's version-compatible probe passes 66 checks,
including its two explicit unresolved-successor observations. Numeric telemetry
is sampled from one IDC object per query rather than rerunning native analysis
once per counter.

## Protected microcode evidence and attribution

An initial ownerless protected x86-64 snippet returned microcode for only its
first existing code head despite decoding seven native instruction sites across
the two selected prefixes. Splitting ranges did not change that result. A later
analysis wave exposes those sites. The completed paired experiment drains two
ordinary IDA analysis waves for both artifacts and records identical prefix
inventories and GENERATED source sites. Consequently, this checkpoint reports
**no measured protected recovery gain** from the production scheduling change.
The verified gain is the two deliberately undefined-successor repairs above.
Earlier discovery observations are retained as experiments, not that paired gain.

The new bounded snippet harness captures ownerless protected prefixes without
creating functions. Each prefix ends at its first branch, call or return, or
at 16 instructions/128 bytes. A snippet uses explicit SDK ranges with no extra
returned-register list. It is not the complete protected body or an executable
semantic summary. In particular, an empty late optimized snippet can reflect
its absent output contract; it cannot count as canonicalization success.

The full x86-64 original plus nine protection/seed variants produce 20
prior/current processes, 20 paired prefixes and 160 SDK stage captures at
GENERATED, PREOPTIMIZED, LOCOPT and GLBOPT1. Independent Mach-O segment mapping
and Capstone 5.0.7 decoding verify 102 recorded instruction extents and their
exact file bytes. Ten corrupted captures reject. Snapshot digests of loaded
bytes/masks, items, owners/chunks, names, comments, segment modes/permissions
and outgoing references remain unchanged across each snippet query. This
inventory is not a digest of every IDB attribute or SDK cache.

The ordinary x86-64/i386 protected matrix passes all 40 processes under its
120 s cap, including 20 actual native-enabled processes and 20 global-disable
controls. Its 152 native rows, 456 SDK outcomes, 454 captured stages, CFGs,
typed expression trees and verifier statistics match the preceding checkpoint.
The existing five typed verifications remain; none is added by this feature.
The 18 ownerless x86-64 body entries, one i386 target inside another owner and
one SDK refusal per profile remain. The matrix rejects 472 capture mutations.
All 21 CTest suites pass. Existing native producer records are revalidated;
this checkpoint adds no native behavioral run of rewritten microcode.

The maximum recorded matrix process duration is 43.011 s; the prefix experiment
maximum is 3.612 s. Conversion is `t_s = t_ns / 10^9`, rounded to 0.001 s.
These observations include startup, analysis and capture under concurrent work;
they establish no general latency distribution or speedup. IDA's gooMBA plugin
is loaded, so this is not an isolated Hex-Rays measurement.

Exact sources, SDK contracts, modules, reports, process measurements and
counterfactual observations are pinned in
[VMP_DIRECT_JUMP_FLOW_EVIDENCE.json](VMP_DIRECT_JUMP_FLOW_EVIDENCE.json).
Historical reports/source hashes remain unchanged. The predecessor artifact
is associated with revision `9f0e8576`; its reproducible compiled-source
attestation remains unknown. Capture-time worktree snapshots do not identify
the source compiled into a historical module.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| F1 | SDK instruction extents and `CF_STOP`/`CF_CALL` distinguish the admitted metadata fallthrough. Scheduling depends on that declaration. | Pin `idp.hpp`, `ua.hpp`, `bytes.hpp` and `auto.hpp`; retain near-jump, mode, permission, data/tail, unloaded and label controls. This is not proof of normal completion or hardware exception behavior. |
| F2 | Current source bytes, references, owners and segment attributes are stable during admission. Byte/item preservation depends on this snapshot. | Recheck the source JMP/reference and target bytes before scheduling; reject prospective successor data/labels; compare native bytes and owners after completion. Concurrent or notification-bypassing writers remain unknown. |
| F3 | Queued SDK work must be drained before measuring repair. Completion observations depend on that sequencing. | Undefine a successor, reanalyze the source, run the explicit native pass, drain its queues, then inspect items. Read-only diagnostics use `chernobog_native_stats`; counters describe requests rather than completions. |
| F4 | An explicit snippet represents only the selected code items and declared output contract. Protected shape observations depend on that scope. | Preserve the partial first-wave observation, compare split ranges, and drain equal analysis waves in the paired experiment. Late emptiness and ownerless function coverage remain explicit limits. |
| F5 | The paired artifacts, files, SDK components and scripts identify the measured processes. Attribution depends on those identities. | Check hashes before/after capture, independently map/decode all 102 instructions, reject ten corruptions, and compare all ordinary stage outcomes and typed trees. Compiled-source reproducibility remains unknown. |

For `T` pending attempts and architectural maximum instruction width
`W = 15 bytes`, local admission/scheduling takes `O(T W + T log T)` time and
`O(T)` pending-set space, excluding SDK decoder and database API costs.
`T` is bounded by the unchanged configured attempt cap. Subsequent ordinary
IDA analysis can discover more than `T` heads and has no new bound from this
feature. Prefix inspection has two uses per process, at most 16 instructions
and 128 bytes each. The inventory retains the existing 64 MiB byte, 1,048,576
head and 2,097,152 outgoing-reference limits. SDK generation and solver costs
remain separate from these source/inspection bounds.

**High impact:** item discovery and snippet maturity can masquerade as a missing
MBA shape unless code inventory and output contracts are recorded. **Medium
impact:** a retained flow reference can prevent a deleted successor from being
rediscovered through head reanalysis alone. **Low impact:** complete protected
body ownership, wider prefix/CFG shape classification and native fault contracts
remain expansion opportunities with unmeasured coverage.

QG1: technical scope. QG2: F1–F5 state dependencies and falsification probes.
QG3: scheduling, repair, admission/rejection, quotas and the measured protected
pipeline are covered; the full review remains in progress. QG4: byte/count caps,
time conversion and algorithm bounds are explicit. QG5: queued versus completed
work, unchanged paired protected prefixes and late snippet emptiness are
distinguished. QG6: local primary SDK contracts and measured artifacts are
hash-linked. QG7: further inventory, ownership and exception work is bounded.
