# WARBIRD recovery implementation status

The current extension provides **diagnostic exploration only**. It does not
replace Hex-Rays pseudocode, certify equivalence, or claim complete recovery of
any corpus entry. `pseudocode_eligible` and `semantic_equivalence_checked` are
always false. The normal-view lowering and equivalence gates in the approved
plan remain unimplemented. Recovered state/effect relations are now retained for
those later stages; retention itself does not satisfy the gates.

## Implemented path

```text
IDA main thread: snapshot + profile admission + revision lease
                    |
                    v
in-process worker: RAX scalar SMIR -> symbolic native/VM exploration
                    |
                    v
IDA main thread: exact dependency recheck -> diagnostic JSON
```

There is no external worker, guest native execution, LLVM/Remill dependency,
file export, or recompilation in this path. The standalone corpus executable is
a development probe, not a runtime dependency.

The three profiles contain all eleven documented keys. Admission checks native
dispatch instructions, the table mask and entries, executable permissions, and
exact context-initialization instructions. Names and source-file hashes alone
cannot admit a profile. The native initialization does **not** zero all 56
context slots. Uninitialized bytes remain symbolic. Native setup instructions
now execute through the RAX SMIR interpreter before
handler entry. Their stores initialize the argument slots, virtual-stack slots,
minimum-stack slot 55 and initial zero stack word. ClipSp's initial 24-byte stack
copy retains its source-memory relationship and native read/write order.

Native handler boundaries now execute the admitted dispatcher instructions.
Registers and vectors that those instructions leave untouched remain related
across handlers; the index-mask instruction produces the incoming arithmetic
flags. The unverified stack-probe path retains conservative volatile clobbers.
The explorer distinguishes full 64-bit keys, follows bounded native calls with
per-path return stacks, retains unknown branch alternatives, and only closes a
loop on an identical complete symbolic state. It does not merge states merely
because they share a key or native address. A finite key may now be split into
several guarded successors. Algebraic covers propagate constant alternatives
through bit-vector operations; general model enumeration is accepted only after
a final UNSAT check proves that no other key exists. Every edge retains its
key-equality condition internally. A model prefix is never treated as complete.

Byte memory uses a copy-on-write concrete-byte overlay. Symbolic reads see that overlay; symbolic writes commit possibly aliased cells
and retain only proven-disjoint cells, preserving aliases and write order. Coalescing the
memory state does not authorize eliminating faulting or volatile instructions
from a future recovered program; those checks remain outstanding. Immutable loaded bytes may be folded; writable sections are not
concretized by section name. Potential writes to a writable dispatch table stop
subsequent dispatch. A zero key terminates without reading table slot zero.
A potentially corrupted native return retains an explicit nonlocal-transfer
frontier while the ordinary continuation is explored under an equality guard.
No ordinary return is assumed from an unknown return address.

The symbolic scalar interpreter now covers ADC/SBB, rotate through carry, and
complete AX results from byte MUL/IMUL. Unselected flag updates are preserved.
The scalar interpreter also covers BT/BTS/BTR/BTC, including memory operands
exported by RAX as ordered loads, updates and flag operations. The semantic
model version is 11, independent of the SMIR record ABI version.

The optional scalar SMIR ABI is versioned and pointer-free. Unsupported operations
and insufficient capacity publish no executable prefix. It retains instruction
addresses, widths, flags, operands, address-size/segment semantics, and the
legacy high-byte extension hint. It is a supported scalar subset, not a claim
that every RAX operation is exportable.

## IDA interface

The following IDC functions return JSON strings. Addresses identify an existing
function; keys are unsigned hexadecimal strings. Profile indices are 0 = ci,
1 = ClipSp, and 2 = PEAuth.

```text
chernobog_warbird_profiles()
chernobog_warbird_start(function_ea, profile_index, hexadecimal_key)
chernobog_warbird_poll()
chernobog_warbird_cancel()
```

Only one job can run per IDA process. Workers own immutable snapshots and no
IDA objects. Any IDB notification cancels the session and invalidates retained
results. Polling rechecks image identity, image base, revision, exact bytes and
permissions, and canonical import identities and byte-availability masks. Closing a database cancels and joins its worker. There are no
patches, new segments, function merges, comments, or persisted local types.

Snapshots are limited to 64 MiB before allocation. The exploration limits are 4096 states, 65536 instructions, 1000000 SMIR operations, a
256 MiB *estimated* symbolic-work budget, and a 60 s job deadline checked at instruction boundaries. Individual Z3
simplification and solver work is bounded. The memory budget is not a hard
allocator sandbox, and an in-process plugin cannot guarantee process-level
crash isolation. Dispatcher growth has a separate 65536-byte reservation limit. Quotas and
unsupported semantics produce explicit frontiers.

## Acceptance gates still outstanding

- Parametric handler summaries and sound joins/PHIs for loops.
- Memory-derived key specialization beyond the current bounded symbolic walk.
- Complete native-helper/environment semantics and fault/definedness models.
- Detached MBA lowering, normal-view switching, original-view restoration, and
  protection against persistence of generated locals.
- Independent original/SMIR/lowered-microcode equivalence checks for every entry,
  including at least 1024 deterministic inputs per key and edge coverage.
- Complete recovery of all eleven keys. The current corpus results are partial.

## Assumption register

| ID | Assumption and dependent result | Probe | Status |
| --- | --- | --- | --- |
| A1 | Profile dispatch and initialization describe the loaded image | Reject modified mask, table, permissions, or setup bytes | Checked on fixtures and corpus |
| A2 | Snapshot is still current when results are consumed | IDB revision, rebase and exact dependency recheck | Passed IDA byte/function non-mutation and comment-change invalidation probes |
| A3 | Uninitialized context can be zero-filled | Compare native initialization stores | Falsified; no zero-fill |
| A4 | Writable table entries remain unchanged during a path | Track possible writes before every dispatch | Conditional; uncertain writes stop exploration |
| A5 | The current scalar pipeline covers all handlers | Run every key and retain unsupported frontiers | Falsified for complete recovery |
| A6 | A bounded diagnostic walk proves equivalence | Compare original and recovered behavior with independent execution | Rejected; no checked presentation |
| A7 | An enumerated key prefix covers every successor | Require algebraic coverage or a final UNSAT check; test unbounded keys | Rejected unless the completeness check succeeds |
| A8 | Concrete byte overlays preserve aliases after symbolic stores | Compare materialized arrays, overlapping writes, forked states and symbolic reads | Verified on representative SMT and byte-level controls |

## Bounded findings

| Impact | Finding | Consequence |
| --- | --- | --- |
| High | NoWarbird's zero-filled context differs from native setup | Do not import this initialization |
| High | ClipSp's handler table is writable | Do not assume immutable dispatch |
| High | Partial/looping NoWarbird LLVM output is not an oracle | Keep the all-entry equivalence gate |
| Medium | Z3 expression growth can precede the instruction limit | Per-rewrite limits and explicit frontiers; hard memory isolation remains unavailable |

Primary local provenance is the supplied `NoWarbird` source and binaries, the
native dispatcher bytes checked by `model.cpp`, the RAX lifter/interpreter source,
and the IDA SDK headers. No NoWarbird implementation code was imported. Its
LLVM outputs are not used as correctness references.

## Validation record

`docs/evidence/warbird-initial.json` records the exact source hashes, RAX
revision, tested plugin hash, and all eleven partial corpus reports. The full
26-test CTest suite and 63 RAX C API tests pass. A controlled key-transition
fixture passes 1024 direct-interpreter comparisons. These 1024 cases are **not**
corpus equivalence cases. The isolated IDA probe confirms that diagnostics do
not change bytes or function ownership and that a comment edit invalidates an
otherwise byte-identical result.

## Model 2 validation scope

The new finite-domain and byte-memory controls are exercised in the complete
WARBIRD test binary. Eleven scalar programs are each compared against direct
RAX interpretation for 1024 deterministic inputs and seven boundary inputs
(11341 comparisons). These are controlled native-handler comparisons, not
whole-corpus equivalence checks. Additional controls reject incomplete key
sets, retain both conditional successors, preserve aliased byte stores and
forked memory states, and retain a nonlocal-return frontier.

The concrete-byte overlay uses O(w log n) lookup/update for an access of w bytes
in n cached bytes. A fork shares state until mutation; its first write may copy
O(n) entries. Symbolic access materializes O(n) byte stores. Finite key covers
are capped at 4096 DAG nodes and 10000 constant evaluations; fallback enumeration
uses at most 17 solver checks for the default 16-value limit.

The model-2 report set is `docs/evidence/warbird-model2.jsonl`, with source
hashes and validation metadata in `docs/evidence/warbird-model2.json`. This
sweep uses an explicit 5 s per-entry deadline and discovers 294 keys summed
across entries; it does not establish complete recovery for any entry. The
initial evidence remains unchanged. Native `BTC` instructions at CI RVAs
`0x79de6` and `0xa80bd` are verified candidates for the next scalar-bridge
extension. Native import/helper models and loop summaries remain required.

## Model 3 validation scope

The scalar bridge exports BT/BTS/BTR/BTC without changing the SMIR record
layout. Locked memory forms remain unsupported and publish no prefix. Nineteen
controlled native programs are each compared against direct RAX interpretation
for 1024 deterministic inputs and seven boundary inputs (19589 comparisons).
The new controls cover 16/32/64-bit register behavior, memory updates, negative
memory bit indices, and carry flags.

The full 26-test CTest suite, 65 RAX C API tests, C/C++ API examples, and enabled
and disabled IDA probes pass. The IDA probes confirm byte/function preservation
and invalidation after a comment-only change. The 5 s per-entry corpus sweep
has no scalar-lift-unavailable frontier; all eleven entries remain incomplete.
Timed key counts are workload-sensitive and are not a performance comparison.
Exact source hashes and reports are recorded in
`docs/evidence/warbird-model3.json` and `docs/evidence/warbird-model3.jsonl`.

The next verified boundary is import resolution. PEAuth's file IAT contains
import-name RVAs, including `0x41556` for `ExAllocatePoolWithTag`. Executing these
as native addresses would be incorrect. Import metadata and external effects
must be modeled explicitly before recovery can pass that boundary.

## Model 4: import identity and bounded pool effects

Import records contain the IAT slot, canonical module, case-sensitive export or
ordinal, and an eight-bit availability mask with the available pointer bytes.
The IDA main thread captures and rechecks these records. IDA deliberately leaves
these corpus IAT slots unloaded; their names remain available. Missing pointer
bytes are never fabricated. The PE development reader instead parses bounded
import descriptors and lookup tables, with ordinal, overflow, missing-terminator,
name-length, and overlapping-slot checks. IDA's `ntoskrnl` module spelling is
normalized to `ntoskrnl.exe`. Other unknown imports remain explicit frontiers.
A possible IAT write invalidates import use on that path. Loaded immutable local
helper code remains eligible for native exploration.

The initial pool relation covers the following normal returns. Every modeled
call also retains a frontier for unresolved runtime binding, IRQL, and external
kernel effects. These relations are diagnostic assumptions, not checked helper
summaries or authority to replace calls in recovered pseudocode.

| Import | Normal-return relation | Retained boundaries |
| --- | --- | --- |
| ExAllocatePoolWithTag | Failure returns zero; success returns a fresh symbolic, aligned, non-wrapping region disjoint from live allocations and the image/private regions | Only base pool types 0, 1, 512; unsupported flags, zero size/tag, and environment effects remain frontiers |
| ExFreePoolWithTag | Match a live allocation's exact base and 32-bit tag; retire its lifetime; leave the void return register unconstrained | Unknown pointers, wrong tags, repeated free, and environment effects remain frontiers |

Allocation and free replace the affected byte interval with fresh symbolic
contents. Address reuse is possible after free. No allocator zero-fill is
assumed. The model preserves nonvolatile integer registers, invalidates volatile
integer registers and flags, invalidates the 32-byte Win64 home area, and checks
saved return addresses through the existing native-return path. IAT memory calls and
native helpers ending in an IAT memory tail jump share that return path. Handler
entry RSP is eight modulo sixteen. Floating-point/vector state, pool flags,
exception paths, full lifetime-aware memory fault checks, and kernel-global
effects remain unsupported; `memory_faults_checked` stays false.

The pool state retains at most 64 allocation generations per path. Allocation
cost is O(L), and free outcome construction is O(L^2) because each candidate
copies up to L lifetime records, where L <= 64. Import canonicalization and
sorting cost O(B + N log N), with N <= 4096 and at most 512 bytes per name.
Range replacement builds a symbolic array expression after O(M) materialization
of the current concrete-byte overlay; it does not allocate the guest region.

Additional assumptions and falsification probes:

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A9 | Import bytes are loaded whenever import names exist | Falsified by the IDA corpus; preserve availability masks and revalidate names and bytes |
| A10 | A declaration identifies the actual runtime helper | Unproven; retain a binding/environment frontier on every modeled call |
| A11 | Allocation returns initialized zeros or a permanent unique address | Rejected; fresh-array controls permit nonzero bytes and reuse after free |
| A12 | Pool ownership and ordinary returns suffice for memory-fault equivalence | Rejected; unknown frees, unsupported flags and unverified fault behavior remain boundaries |
| A13 | Handler entry stack is sixteen-byte aligned | Falsified by the Win64 call convention; regression requires entry RSP modulo 16 = 8 |

The new controls exercise 112 pool type/size/alignment combinations, live-region
overlap, free tag/lifetime checks, address reuse, exact and symbolic byte-range
replacement, unresolved IAT bytes, and native call/tail-call/allocate-free
sequences. They supplement the 19589 direct native-handler comparisons; they
are not whole-corpus or kernel-execution equivalence evidence.

Primary API/ABI references:

- [ExAllocatePoolWithTag](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepoolwithtag)
- [ExFreePoolWithTag](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreepoolwithtag)
- [POOL_TYPE](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type)
- [Microsoft x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)

Exact model-4 sources, test results, and the bounded eleven-entry corpus sweep
are recorded separately in `docs/evidence/warbird-model4.json` and
`docs/evidence/warbird-model4.jsonl`. Historical evidence remains unchanged.

## Model 5: legacy XMM memory paths

The RAX bridge now has a distinct XMM operand bank and explicit operations for
legacy 128-bit moves, loads/stores, bitwise XOR, scalar lane insertion/extraction,
MOVD/MOVQ, and temporary broadcast. It retains ordered alignment checks before
aligned accesses. VEX/EVEX vector encodings, MMX, floating-point arithmetic, masked operations and
unrecognized widths remain unsupported as complete instructions; no executable
prefix is published. Existing SMIR record layouts and ABI version are unchanged.
The public RAX C API version is 1.6.

The explorer carries sixteen 128-bit values independently from integer
registers. Instruction-local vector temporaries are defined before use. Partial
lane writes preserve other bits, and legacy register writes preserve backing
state above bit 127 by contract; no instruction reading that upper state is
admitted. The byte memory now supports a full 16-byte access, including overlap
with scalar stores. Immutable 128-bit reads are assembled byte by byte rather
than through a 64-bit host accumulator. External modeled calls and handler
boundaries invalidate XMM0-XMM5; XMM6-XMM15 remain nonvolatile.

Misalignment produces an explicit frontier; when alignment is symbolic, the
ordinary continuation carries an alignment guard and the possible fault remains
visible. These checks do not establish complete memory-fault equivalence or
hardware feature-state coverage. The native PEAuth memory-fill path at RVA
`0x29e30` is no longer rejected merely because it starts with a MOVQ into XMM0.
It still requires bounded control-flow and semantic-equivalence analysis.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A14 | XMM values can share the scalar register bank | Rejected; a distinct operand kind and sixteen 128-bit state values prevent aliasing |
| A15 | An aligned vector move can be split into unchecked scalar stores | Rejected; preserve the alignment check and full-width memory access |
| A16 | Legacy SSE and VEX/EVEX have identical upper-register effects | Rejected; VEX/EVEX remain unsupported, with atomic export rejection |
| A17 | A raw FFI byte array has the intended byte representation | Explicit u8 fixture types; capacity/unsupported tests exercise the actual encodings |

The architectural references are the local x86 specification entries
`movd_movq.txt`, `movlhps.txt`, `movaps.txt`, `movups.txt` and `movq.txt`, together
with the RAX legacy SSE lifter and interpreter. Comparisons against the direct
RAX decoder/interpreter test the separate exporter/symbolic-execution path;
they are not a substitute for whole-corpus equivalence.

The allocator range operation also preserves concrete overlays in explicitly
excluded image and private-stack/context intervals. The normal allocation
relation already constrains returned regions to be disjoint from those exact
intervals; free retains those constraints from its matching allocation. This
avoids burying known context bytes inside array conditionals. The general range
operation still models aliases outside the excluded intervals. An independent
SMT comparison checks that the excluded form equals the original operation at
an arbitrary symbolic byte address under the same non-overlap constraint.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A18 | Preserving excluded concrete bytes changes an allocator range effect | Compare both arrays at an arbitrary address under explicit disjointness; require UNSAT for a difference |

Primary architectural provenance is the bundled Intel SDM
`vendor/rax/docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`,
Volume 2B: MOVAPS pp. 4-48 through 4-51; MOVD/MOVQ pp. 4-62 through 4-65;
MOVLHPS pp. 4-86 through 4-87; MOVUPS pp. 4-134 through 4-137. The text entries
listed above are convenience extracts, not independent oracles.

Model-5 validation compares 32 controlled native programs against direct RAX
execution on 1024 deterministic inputs and seven boundary inputs each (32992
comparisons). It includes 8/16/32/64-bit lane behavior, register aliasing, aligned
and unaligned 128-bit transfers, MOVSS/MOVQ zeroing and preservation, immutable
wide reads, and flag preservation. Additional controls exercise both ordinary
and potentially faulting alignment paths, overlapping 128-bit/scalar writes,
XMM volatility across modeled pool calls, and excluded-range equivalence.

A live PEAuth IDA probe requires a positive vector-operation count, rejects a
lift frontier at RVA `0x29e30`, verifies unchanged bytes/function ownership, and
invalidates the result after a comment-only edit. The first attempt exposed a
next-key solver frontier after allocation; preserving the proven-disjoint
private overlay made this actual in-IDA vector path reachable. That observation
is distinct from claiming complete entry recovery. All eleven entries remain
incomplete. The exact record is `docs/evidence/warbird-model5.json`, with the
bounded corpus reports in `docs/evidence/warbird-model5.jsonl`.

## Model 6: guarded writes and alias proofs

The explorer separates possible writes to immutable image bytes, a writable
handler table, and writable import slots from a continuation constrained not to
write those regions. Each possible mutation/fault remains an explicit frontier.
This extends the existing guarded-native-return strategy; it does not treat an
unproved mutation as impossible. Concrete writes retain their previous behavior,
including invalidating an actually modified dispatch/import table.

A bounded alias oracle can additionally prove that a symbolic write does not
intersect the private context or stack regions. Only UNSAT authorizes retaining
those concrete byte cells. SAT and unknown leave the ordinary fully alias-aware
memory update in place. The no-overlap proof includes the entire write, rather
than only its first address. A modular interval expression is checked against
an independent byte-by-byte definition for every width from one through sixteen
bytes, including ranges near address-space wraparound.

The oracle is local to one Z3 context and one job. Its proof cache holds the
address and domain AST references, and includes the access width and complete
range set in its key. The explorer also retains the AST roots used in visited
state identities. Z3's `ast_manager::delete_node` can recycle expression IDs when
`RECYCLE_FREE_AST_INDICES` is enabled; an unowned numeric ID cannot authenticate
a persistent proof or state identity. Retained roots are deduplicated, and their
estimated storage is included in the existing identity quota.

The alias oracle performs at most 256 solver checks per job. Each check requests
a 10 ms timeout and 20000 resource units. An unknown result never becomes a
no-overlap proof. Range matching costs O(R) for R merged ranges, with R <= 256;
the separately tested byte-by-byte definition costs O(RW) for W access bytes.
The solver limits are bounded work controls, not a process memory sandbox.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A19 | A possible table write invalidates all successors | Retain the mutation frontier and test a second keyed handler under the complementary guard |
| A20 | Checking a write's starting address proves no overlap | Rejected; compare modular intervals against all written byte addresses, including wraparound |
| A21 | Z3 AST IDs remain unique after referenced ASTs are destroyed | Rejected; hold AST roots in the proof cache and visited-state set; reject foreign contexts |
| A22 | A solver timeout authorizes no-alias treatment | Rejected; a zero-query-budget control returns unknown and authorizes no private-cell retention |
| A23 | Retaining concrete cells is correct without the guard | Counterexample deliberately aliases a retained cell; equivalence holds only with the no-overlap constraint |

These guards preserve the diagnostic status: potential dynamic table changes,
unknown imports, external effects and unproved memory faults still prevent
checked pseudocode admission. The all-entry recovery and lowering requirements
remain open.

Model-6 validation retains all 32992 native comparisons and adds 48 symbolic
comparisons of the compact overlap formula with its byte-wise definition,
proof-cache context/lifetime controls, and a counterexample showing why the
symbolic-write guard is necessary. A controlled mutable-table fixture both
continues under a no-write guard and rejects a definite table mutation.

Live IDA probes cover guarded ClipSp continuation, PEAuth SIMD execution, and
CI with RAX enabled and disabled. Each checks preservation of bytes/functions
and the applicable stale-result behavior. Source hashes and the partial
11-entry sweep are recorded in `docs/evidence/warbird-model6.json` and
`docs/evidence/warbird-model6.jsonl`. No corpus entry is claimed complete.


## Model 7: native initialization and shared stack storage

The three supplied AMD64 dispatchers clear `[RBP+0x1c8]` before their first
handler call. Their context starts at `RBP+0x10`, so this is context offset
440 bytes, slot 55. Admission derives that destination from the actual
`AND qword [RBP+disp32],0` instruction and rejects a changed displacement,
nonzero immediate, overlapping argument/stack slot, or altered byte witness.
No other context slot acquires an implicit zero value.

The native and virtual stacks share storage. The model now preserves that
relationship, including the frame's position relative to the context. Admission
retains the complete entry-to-setup byte sequence as a dependency and checks the
prologue, reservation sequence, alignment and maintenance instructions. The
following offsets apply on the first handler entry:

| Profile | Context minus virtual floor (bytes) | Virtual floor minus handler RSP (bytes) |
| --- | ---: | ---: |
| ci | 96 | 40 |
| ClipSp | 112 | 40 |
| PEAuth | 96 | 40 |

```text
lower addresses                                       higher addresses
handler RSP -- 8-byte return -- 32-byte home area -- virtual floor -- context
```

The 40-byte relation is preserved when the dispatcher reserves more stack.
For a nonzero requested minimum below the current floor, it truncates the
floor/minimum difference to 32 bits, adds 15, rounds down to a multiple of
16 bytes, and subtracts that size from the native stack. The new virtual floor
is the resulting handler-entry RSP plus 40 bytes. The minimum slot is then
cleared. A zero or higher minimum leaves these values unchanged. The model
preserves the native arithmetic while refusing diagnostic growth whose full
64-bit distance or rounded reservation exceeds the remaining quota. Thus a
large distance cannot pass the quota by truncating to a small 32-bit value.
Each update builds O(1) symbolic expressions and allocates no guest stack.

Handler return checks retain a frontier if RBP, RBX or RSP could violate the
admitted frame relation. Every growing path also retains a frontier for the
unverified native stack-probe helper. The continuation models normal-return
bookkeeping only; guard pages, exception behavior, runtime binding and the
initial setup's external effects remain unverified. `memory_faults_checked`,
`semantic_equivalence_checked` and `pseudocode_eligible` remain false.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A24 | All initial context bytes may be zeroed | Rejected; derive only the native zero slot and retain an unknown neighboring slot in a controlled fixture |
| A25 | Native stack, virtual stack and context can use independent address spaces | Rejected; check their native frame offsets and test cross-alias reads after a 32-byte growth |
| A26 | Low 32-bit truncation suffices for resource accounting | Rejected; check the full distance and test requests beyond 2^32 bytes |
| A27 | Normal integer bookkeeping proves stack-probe fault behavior | Rejected; every growing path retains an unverified-probe frontier |

The controlled validation includes 33 native-handler programs with 1031 inputs
each (34023 comparisons), plus 1031 direct-RAX executions of a separate native
integer sequence for the stack bookkeeping. The latter cover zero/higher/lower
minima, 16-byte rounding, 32-bit truncation, and quota rejection. These are
fixture comparisons, not whole-corpus equivalence results. A two-handler fixture
checks shared stack/context aliases, minimum clearing, and rejection of an
insufficient quota. Mutated frame/maintenance witnesses and inconsistent stack
relations are rejected.

Model-7 source hashes, IDA lifecycle probes and the bounded eleven-entry sweep
are recorded in `docs/evidence/warbird-model7.json` and
`docs/evidence/warbird-model7.jsonl`. Every corpus entry remains partial. The
higher-priority next boundaries remain native helper/fault semantics, bounded
loop summaries, and the all-entry equivalence and ordinary-pseudocode gates.


## Model 8: execute the admitted native setup

The explorer now runs the straight-line initialization window through the same
RAX SMIR interpreter used for handlers. It no longer assigns independent
symbolic values to native-profile argument slots. The first register argument,
the remaining incoming registers and the original caller-stack memory supply
the setup's actual loads and stores. A later read of a stack-passed argument
therefore sees the same bytes as its context-slot copy.

For ClipSp, the window includes the native 16-byte load/store followed by the
8-byte load/store for its fifth argument. The second load happens after the
first store. This order matters when the source and destination overlap; it
cannot be replaced by a snapshot of all 24 source bytes. The copy remains an
in-process symbolic memory operation and never dereferences a host pointer.
Uninitialized source bytes remain symbolic, with their aliases retained.

The window starts after the wrapper's external setup and argument shuffle and
ends before dispatcher maintenance. Admission already retains exact frame and
setup bytes. The new execution path admits at most 256 bytes and 64 straight-line
instructions, shares the existing instruction/operation/time budgets, and
requires the final key, RBP, RBX, RSP and minimum-slot invariants before entering
a handler. Branches, calls, incomplete lifts and failed invariants leave an
explicit frontier with no handler execution. Copy metadata must agree with the
admitted native frame. The small abstract fixtures retain their explicit-input
contract; actual corpus profiles use native setup execution.

This removes a specific initialization approximation. It does not verify the
wrapper's earlier external effects, arbitrary pointer fault behavior, native
stack probes, helper bindings or final whole-entry equivalence. The three
checked-presentation flags remain false.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A28 | A 24-byte copy can snapshot all source bytes before writing | Rejected; direct native comparisons include forward overlap that changes the second load |
| A29 | A context argument and its caller-stack source can be independent symbols | Rejected; a handler XORs both reads and must return zero |
| A30 | Matching setup bytes permit unrestricted execution | Rejected; an injected branch stops initialization, and an instruction-quota control reaches no handler |
| A31 | Native setup execution verifies earlier wrapper effects or pointer faults | Rejected; the execution window excludes those effects and checked presentation remains disabled |

The native comparison matrix now contains 38 programs, each exercised with
1024 deterministic inputs and seven boundary inputs (39178 comparisons). It
includes the full admitted initialization window for each of the three corpus
profiles, plus overlapping and disjoint 16-byte/8-byte copies. The existing
1031 stack-bookkeeping and 48 overlap-formula comparisons remain. These checks
cover the controlled initialization and instruction semantics, not complete
corpus entries or kernel execution.

Instruction-dispatch overhead is O(I + M), where I <= 64 is the number of
native instructions and M is the number of exported SMIR operations, subject
to the existing global operation budget. Symbolic-expression and byte-memory
work retains the existing bounds and costs; this is not a constant-time solver
guarantee. Copies use the same copy-on-write storage and alias rules as handler
execution. Native reads and stores are performed in instruction order.

Source hashes, four isolated IDA probes and the partial eleven-entry sweep are
recorded in `docs/evidence/warbird-model8.json` and
`docs/evidence/warbird-model8.jsonl`. The IDA probes require native setup
execution on all three profiles and exactly 24 copied bytes on ClipSp. No
whole-entry recovery or normal-view lowering is claimed.


## Model 9: retain native semantics and guarded relations

Exploration now returns an immutable recovery artifact alongside the diagnostic
report. Previously, the worker discarded its expressions after producing key
edges and counters. The artifact retains the material needed for subsequent
summary comparison, control-flow joins and detached lowering:

```text
Recovery: owning Z3 arena + lease
  +-- native bytes and complete SMIR records, indexed by address
  +-- ordered effect nodes: previous index + origin + address/value/width
  +-- snapshots: SMIR register bank, vectors, flags, byte memory, stack and pool state
  +-- relations: input snapshot -> output snapshot, guard, next-key expression
  +-- native control-flow edges and their path guards
```

A relation describes one normal handler-return path before the next dispatcher
entry. It retains a symbolic next key even when bounded key enumeration cannot
finish. Memory snapshots use the existing copy-on-write byte model. An output
write cannot modify a retained input snapshot. Immutable-image reads and
intermediate writes remain explicit effects even if their values simplify;
this layer does not authorize dropping a potentially faulting access.

Effect origins distinguish native instructions, admitted setup, dispatcher
bookkeeping and external models. Calls, branches and returns retain path guards.
A return edge specifically requires the saved return address to equal its target;
a possible nonlocal transfer remains a frontier. External edges identify an
import slot, not an invented runtime address. Native, modeled and unverified
behavior therefore remain distinguishable when constructing a later lowering.

Each artifact owns its Z3 context, declared before its expression-bearing
members so it outlives them. Arena ownership is immutable, and value assignment
and move construction are disabled: replacing the arena before old expressions
are released would invalidate those expressions. Copy construction retains the
same owner. Publication occurs after the worker finishes;
consumers must serialize access to that context. The IDA session retains the
complete report after freshness checks and releases it on invalidation,
cancellation or replacement. Starting another job releases completed artifacts
across sessions, including ready but unpolled futures. Closing a database still
joins its worker before releasing its snapshot.

The default retention budget is 32 MiB of estimated storage, also capped at one
quarter of the job's workspace budget. A zero retention budget is supported.
Exhaustion stops capture, sets `capture_complete=false`, and records an omission;
it does not silently truncate a purported complete artifact or change the
native diagnostic walk. The estimate includes records and conservatively
charges snapshot overlays; it is not a hard bound on Z3's allocator or shared
expression DAG storage. Existing job deadlines and expression limits still apply.

Effect append and path fork cost O(1) amortized. Branches share a previous-effect
index rather than copying histories. Recovering one ordered path costs O(Ep),
where Ep is that path's effect count. A flat vector avoids recursive destruction
of long histories. Native instruction insertion costs O(log N). Structural
validation checks expression contexts/sorts, register-bank sizes and acyclic
effect ancestry; it re-lifts native bytes and compares the stored SMIR records. It does not prove instruction
semantics, memory-fault equivalence or eligibility for pseudocode replacement.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A32 | Expressions remain valid after the explorer is destroyed | Retain the owning arena; read output expressions and memory after worker-local owners have gone |
| A33 | Forked paths may concatenate their effect lists | Rejected; verify a common prefix, distinct successors, mutually exclusive guards and complete branch coverage |
| A34 | Every native return edge is unconditional | Rejected; require UNSAT for a retained return edge whose saved target differs |
| A35 | A full retention budget may silently drop records | Rejected; zero-budget capture is explicitly incomplete while diagnostic execution still runs |
| A36 | A well-formed retained artifact proves equivalence | Rejected; semantic, fault, coverage, ownership and lowering gates remain separate |
| A37 | A normalized native return address is interchangeable with the original callsite for address-sensitive handlers | Rejected by model-10 controls; admitted tail-dispatch snapshots now use the real callsite return address |

Validation retains the 39178 native comparisons and checks every compared next
key against its retained relation. Additional fixtures check input/output memory
independence, overwritten-write order, foreign-context rejection, malformed state
banks, cyclic ancestry, a 16384-effect chain, and guarded native returns. IDA
probes verify retained graph counts and eviction of a completed result after a
comment-only edit, in addition to the existing in-flight stale-result checks.

The development corpus reader structurally validates each retained artifact,
re-lifts its recorded instruction bytes, and checks its lease and exploration
status against the report before publishing a record. A retained relation is
not proof that a selected caller function invokes that entry key; caller binding
and checked presentation remain separate gates.

The exact source record and the partial eleven-entry sweep are
`docs/evidence/warbird-model9.json` and `docs/evidence/warbird-model9.jsonl`.
Loop/PHI construction, complete helper/fault semantics, independent whole-entry
equivalence and normal-view lowering remain required. No retained artifact is
authority to replace ordinary pseudocode.


Model-9 arena-ownership follow-up: `docs/evidence/warbird-model9-ownership.json`
and `docs/evidence/warbird-model9-ownership.jsonl` record the non-assignable,
non-movable owner contract and last-owner destruction checks. The original
model-9 source hashes and reports remain historical evidence for their revision.


## Model 10: native dispatcher call-return addresses

The admitted corpus dispatchers call through a loaded pointer to an immutable
`JMP RAX` instruction. `CALL` pushes its fallthrough address; the tail jump does
not push another return address. The handler therefore observes the native
callsite return address, including when it reads `[RSP]`. The native profiles
now use this value instead of the abstract fixture return marker.

| Profile | Dispatch pointer RVA | Tail-jump RVA | Handler return RVA |
| --- | --- | --- | --- |
| ci | 0x3e7d0 | 0x29670 | 0xb28d0 |
| ClipSp | 0xa72e8 | 0x31560 | 0xd9df5 |
| PEAuth | 0x41228 | 0x29a60 | 0xad11b |

```text
CALL [dispatch pointer] -> JMP RAX -> handler -> RET
push callsite return      no push               pop callsite return
```

Admission derives the pointer from the validated RIP-relative call, checks all
eight pointer bytes, requires an immutable executable `FF E0` target, and
retains both regions as dependencies. An unavailable pointer, another thunk
shape or pointer-address overflow rejects the contract. The return address is
derived from the call's native fallthrough and the current image base.

A writable dispatch pointer is handled conditionally: entry requires its value
to equal the admitted target. An unresolved alternative remains a frontier.
Normalization under that equality makes subsequent memory reads coherent; it
is not recorded as a guest write. An independent arbitrary-byte comparison is
UNSAT under the binding equality and has a SAT counterexample without it.
Potential writes to the pointer retain their mutation frontier and a guarded non-overlap continuation. A definite pointer
write prevents entry into another handler. The pointer's unchanged-state bit
is retained in state identities and recovery snapshots.

This proves the transfer shape for the current snapshot. It does not prove a
Windows loader or another external agent left the runtime CFG binding intact.
Normal-view admission still requires the broader runtime, fault and equivalence
checks. Abstract control fixtures explicitly select their separate handler ABI;
that marker is not used for native-profile admission.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A38 | A CALL through the admitted tail jump pushes a second return address | Rejected; native CALL/JMP RAX execution and an address-reading handler observe the call fallthrough |
| A39 | The dispatch pointer may be omitted from freshness and write checks | Rejected; changed bytes invalidate dependencies, and a definite write stops the next dispatch |
| A40 | Any executable thunk has the same calling behavior | Rejected; a RET thunk and an unloaded pointer fail admission |
| A41 | The stored CFG binding is necessarily the live kernel binding | Unproved; snapshot transfer evidence is not runtime binding evidence |

The direct native/SMIR matrix now covers 39 programs with 1031 inputs each
(40209 comparisons), including a CALL-to-JMP-RAX chain whose return-address
observation contributes to its result. A separate admitted-dispatch fixture
reads its actual saved return address. Further controls cover pointer mutation,
missing bytes, unsuitable thunks and guarded pointer writes. IDA probes assert
the corpus-specific return addresses and loaded tail-jump bytes.

The additional fixed contract read is eight pointer bytes plus two instruction
bytes. Pointer-overlap checks share the existing bounded range/alias machinery.
Source hashes and the eleven-entry snapshot validation are recorded in
`docs/evidence/warbird-model10.json` and `docs/evidence/warbird-model10.jsonl`.
All entries remain partial; no checked pseudocode presentation is enabled.

## Model 11: execute dispatcher state propagation

The native profiles now execute the five dispatcher instructions, the indirect
call, and the admitted `JMP RAX` tail transfer through the RAX SMIR interpreter.
The return marker and argument registers are no longer sufficient substitutes
for these operations: registers and XMM values untouched by the dispatcher must
remain related to their preceding values, while `AND EAX,mask` changes the
arithmetic flags. Every completed dispatch accounts for seven native instructions.

```text
handler return -> index-mask/table load -> CALL -> JMP RAX -> next handler
                 exact flag updates     push    no push
```

The selected table slot is bound to its admitted value under the unchanged-table
contract. For writable tables, that equality is retained in the path domain
before the byte-memory representation is normalized. Earlier aliases must agree
with it. The indirect-call pointer is read and checked at the call instruction,
then the native return address is pushed. The completed boundary must prove its
handler target, RCX context, RDX key and RSP relation before the next handler is
queued. Unexpected control flow, unsupported operations, quota exhaustion or
failed output invariants stop that path.

The native dispatch window preserves R8-R11, XMM state and the direction flag
unless an earlier modeled operation changes them. On a stack-growth path, the
unverified probe helper still introduces conservative volatile GPR/XMM/flag
values. These clobbers are conditional on growth; the no-growth alternative keeps
its exact relationships. Native handler returns also check the frame-pointer
and stack-pointer contract before another dispatch. Bare abstract test fixtures
retain their explicitly selected abstract ABI.

Native dispatch uses the existing job instruction, operation and time quotas.
Its fixed window contains five straight-line instructions and two transfers;
work outside that window is not silently included. Memory effects retain
dispatcher origin tags; control-flow edges retain source addresses and guards.
The recovery artifact retains the native bytes.

| ID | Assumption or boundary | Probe and disposition |
| --- | --- | --- |
| A42 | A call boundary automatically destroys every volatile register | Rejected for the admitted dispatcher; two-handler tests preserve R8-R11 and XMM0/XMM5 |
| A43 | Dispatcher flags can be copied from the preceding handler | Rejected; a handler sets CF, then the next handler observes the index mask's CF/ZF/SF/PF values |
| A44 | An unverified stack probe preserves the same values as a no-growth dispatch | Rejected; growth retains an uncertainty frontier and conservative clobbers |
| A45 | A partly executed dispatcher may be published as a handler entry | Rejected; a quota control stops inside the dispatch window before any handler is queued |

The native matrix now contains 40 programs with 1031 inputs each (41240
comparisons). The additional full dispatcher scaffold has an independent closed
form checked against native RAX execution and the retained SMIR relation. The
fixture exercises both table indices, flag-dependent output, indirect call,
tail transfer and vector preservation. These are controlled comparisons, not
whole-entry or kernel-runtime equivalence claims.

The exact source, IDA probes and partial corpus sweep are recorded in
`docs/evidence/warbird-model11.json` and `docs/evidence/warbird-model11.jsonl`.
Runtime helper semantics, loop/PHI construction, caller binding and checked
normal-view lowering remain required. Pseudocode replacement remains disabled.
