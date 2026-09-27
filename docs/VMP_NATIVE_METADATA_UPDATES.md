# Native proof revalidation on function metadata updates

The previous installed plugin did not complete the i386
`virtualization-12648430` protected-corpus probe within its 120 s process cap.
The corrected artifact completed the same input, IDA executable and enabled
native-analysis profile in 30.860 s. The prior observation is censored at
120.022 s; its completion time is unknown. These are individual observations,
with no claim about a latency distribution or universal speedup.

## Callback contract and implementation

IDA SDK 9.40 `funcs.hpp` documents that `update_func()` changes function
information and cannot change its start or end addresses. Boundary changes
use separate APIs and notifications. `idp.hpp` distinguishes routine
`func_updated`/`function_updated` notifications from function creation,
boundary changes, deletion, tail membership and tail ownership.

For a routine update, the engine snapshots the chunk range and owner before
receipt recovery can mutate function objects. For a shared tail it includes
every reported parent, up to 4,096. Missing, invalid or excessive parent
information falls back to the original global revalidation. Older SDKs fall
back globally for tails. The scope includes proof sources, sites, contextual
calls, exact-byte dependencies and donor/noreturn ownership leases.

Unrelated proofs are skipped. Related condition, stack-transfer and static
materialization proofs reuse their publication because their recognizers
consume bytes, code inventory, owners, segment attributes and references.
They do not consume function attributes such as `FUNC_LIB` or
`FUNC_SP_READY`. A value proof carrying a contextual call, donor lease or
noreturn lease cannot take this reuse path. CALL/RET leases still rederive
their current conclusions because SP, prototypes and inferred noreturn
metadata can affect them.

Code inventory changes have separate invalidation. A new or differently sized
code item revokes affected value proofs before its creation completes. Small
item spans collect every crossed owner and shared-tail parent; ambiguous or
large spans revoke all value proofs. Data creation replacing code receives
the same treatment. Recreating an unchanged code item preserves its facts.
Existing byte-patch, item-destruction, reference, segment, ownership, save,
undo and relocation handling remains active. Explicit analysis and evidence
inspection still rederive conclusions; this reuse is confined to routine
metadata notifications.

`chernobog_native_stats()` snapshots the same cumulative per-database counters
as `chernobog_native_analysis()` without invoking analysis. Its `ran` field is
zero. Counters distinguish scoped/global function notifications, checked,
skipped and reused proofs, and item-inventory revocations. Optional
`CHERNOBOG_IDA_REVALIDATION_TRACE=1` logs at powers of two of the
revalidation count. Counts describe notifications and proof visits; paired
legacy/current SDK notifications are not unique user update requests.

## Recorded verification

| Check | Observed result |
|---|---|
| CTest | 21/21 suites |
| Live metadata and code-inventory controls | 19/19 per architecture; 38 total |
| Existing owned dataflow controls | 479 x86-64 and 412 i386; 891 total |
| Get-PC persistence and lease controls | 16 processes, 146 assertions |
| Condition persistence, two relocation modes and undo/redo | 14 processes, 14,050 assertions and 3,528 independent IR effect checks |
| Protected corpus, original plus nine protection/seed variants per architecture, disabled/enabled profiles | 40/40 processes within 120 s; maximum 30.860 s |

The protected driver now accepts `--native-analysis`; its existing default
continues to select the earlier native-disabled measurement. The global
`CHERNOBOG_DISABLE=1` control disables the native engine as well as the
decompiler transformations, so the new matrix contains 20 actual native-enabled
processes and 20 disabled controls. A read-only engine snapshot verifies this
attribution, and 472 corrupted-capture controls are rejected.

The SDK produced 454 of 456 requested stage captures across both profiles.
It refused one selected i386 stage in each profile. Eighteen x86-64 protected
body entries remained ownerless, and one i386 body entry lay inside a different
owner. The driver records those outcomes without forcing ownership. Among
227 paired captured stages, 222 recorded shapes matched and five changed.
Shape comparison does not establish semantic equivalence, alias identity,
complete protected-function recovery or logical VM semantics.

In the formerly stalled case, the candidate observed 141,564 scoped and two
global function notifications, 420,021 proof checks, 27,725,302 skipped proof
visits, 9,502,530 metadata reuses and 207,070 item-inventory revocations. Full
rechecks and conservative revocations therefore remain observable. The live
padding control deliberately changes code inventory without changing bytes;
it revokes the old publication and abstains until the original ownership
boundary is restored. Repeated unchanged creation preserves an independent
proof and causes no additional item-inventory invalidation.

Exact sources, SDK contracts, plugin identities, process measurements and raw
report hashes are recorded in
[VMP_NATIVE_METADATA_UPDATES_EVIDENCE.json](VMP_NATIVE_METADATA_UPDATES_EVIDENCE.json).
The IDA application components include gooMBA; this is not an isolated
Hex-Rays-only result. Elapsed values convert recorded integer nanoseconds by
`t_s = t_ns / 10^9`; displayed seconds are rounded to 0.001 s. Recorded peak
resident bytes are runner observations, not total process-tree memory.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| M1 | A routine SDK function update cannot change boundaries or tail membership. Metadata reuse depends on that notification contract. | Primary `funcs.hpp`/`idp.hpp` contracts are hash-pinned. Boundary, tail removal, donor restoration and shared ownership controls retain global invalidation/revalidation. Other SDK implementations remain unknown. |
| M2 | Ordinary value recognizers do not read function attributes. Reusing those publications depends on their current implementation. | Toggle `FUNC_LIB` and `FUNC_SP_READY` through actual `update_func` callbacks; assert preserved publication IDs and increased reuse counts. Revalidate CALL/RET leases separately. A future attribute-dependent value recognizer must leave this reuse class. |
| M3 | Premise-changing edits emit the SDK notifications handled by the engine. Synchronous revocation depends on active callbacks. | Create a new code head in previously unknown owned padding without patching bytes; assert immediate revocation. Existing dataflow, reference, byte and lifecycle controls exercise separate notifications. Direct database mutations bypassing notifications remain unknown. |
| M4 | A counter query has no analysis side effect. The recorded visit counts depend on this property. | Two consecutive object snapshots are identical and have `ran=0`; explicit native analysis increases proof-check counts. |
| M5 | Process, binary and tool identities match the recorded experiment. The bounded latency observation depends on this attribution. | Pin inputs and source/tool components before and after all captures. Repeat the same formerly stalled input with the prior installed artifact and a 120 s cap. Physical x86 execution and general latency distributions remain unknown. |

Let `P <= 4096` be retained proofs, `D` the maximum stored dependency count,
`R <= 4096` shared-tail parents, and `K` the recognizer cost. Building a scope
costs `O(R log(R + 2))` time and `O(R + 1)` temporary space. Filtering costs
`O(P D log(R + 2))` time, followed by `O(A K)` for `A` affected lease/other proofs.
Ordinary value reuses avoid their recognizer cost. Item scopes inspect at most
16 bytes and conservatively invalidate affected publications. Global fallback
retains the existing `O(P (D + K))` work. These bounds exclude IDA API costs and
revocation scheduling; no persistent cache of scopes or conclusions is added.

**High impact:** the recorded default-profile timeout is removed while native
analysis remains enabled. **Medium impact:** the 27 million skipped visits
still expose an opportunity for a reverse dependency index, requiring separate
ownership/invalidation validation. **Low impact:** uncompiled older SDK paths
and notification-bypassing database writers remain explicit coverage gaps.

QG1: technical scope. QG2: M1–M5 register assumptions and falsification probes.
QG3: callback filtering, reuse, invalidation, diagnostics and the observed
timeout have direct controls; the complete review remains in progress. QG4:
counts, time conversion, byte bounds and complexity are explicit. QG5: censored
prior latency, disabled engine controls, incomplete owners and SDK refusals are
reported. QG6: local primary SDK contracts and measured artifacts are
hash-linked. QG7: additional indexing opportunities and coverage gaps are bounded.
