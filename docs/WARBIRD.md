# WARBIRD recovery implementation status

The current extension provides **diagnostic exploration only**. It does not
replace Hex-Rays pseudocode, certify equivalence, or claim complete recovery of
any corpus entry. `pseudocode_eligible` and `semantic_equivalence_checked` are
always false. The normal-view lowering and equivalence gates in the approved
plan remain unimplemented.

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
context slots. Uninitialized bytes remain symbolic. Only the four native
argument slots, two virtual-stack slots, and initial zero stack word are seeded.
ClipSp's initial 24-byte stack copy remains symbolic in this diagnostic model.

Caller-saved registers and incoming flags are fresh symbolic values at each
handler boundary; no values are carried through an unmodeled dispatch thunk.
The explorer distinguishes full 64-bit keys, follows bounded native calls with
per-path return stacks, retains unknown branch alternatives, and only closes a
loop on an identical complete symbolic state. It does not merge states merely
because they share a key or native address. Byte-array memory retains overlapping
stores. Immutable loaded bytes may be folded; writable sections are not
concretized by section name. Potential writes to a writable dispatch table stop
subsequent dispatch. A zero key terminates without reading table slot zero.

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
results. Polling rechecks image identity, image base, revision, and exact bytes
and permissions. Closing a database cancels and joins its worker. There are no
patches, new segments, function merges, comments, or persisted local types.

Snapshots are limited to 64 MiB before allocation. The exploration limits are 4096 states, 65536 instructions, 1000000 SMIR operations, a
256 MiB *estimated* symbolic-work budget, and 60 s per job. Individual Z3
simplification and solver work is bounded. The memory budget is not a hard
allocator sandbox, and an in-process plugin cannot guarantee process-level
crash isolation. Quotas and unsupported semantics produce explicit frontiers.

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
| A5 | RAX scalar semantics suffice for all handlers | Run every key and retain unsupported frontiers | Falsified for complete recovery |
| A6 | A bounded diagnostic walk proves equivalence | Compare original and recovered behavior with independent execution | Rejected; no checked presentation |

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
