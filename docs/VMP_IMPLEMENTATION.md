# VMP review implementation and completion ledger

Objective: implement every point of `VMP_REVIEW.md`, with production integration
and verification at the scope of each claim. This ledger is not a replacement
for that specification. An unchecked item remains incomplete even if a narrower
test passes. All source and documentation edits use the file-editing tool.

Baseline: commit `c4440677e39f296e18bbd6f82eab50b878cebead`; the preexisting
untracked worktree content is retained. Source assumptions A1–A5 and their
falsification probes remain those in `VMP_REVIEW.md`.

| Requirement | Implementation / evidence | Status |
|---|---|---|
| 0a. Correct Boolean, select-mask, SETcc, and x64-width mapping errors | Corrected `ATHENA_MAPPING.md`; exhaustive identities, select counterexample, and executed SETcc control in `x86_abstract_tests.cpp` | Implemented |
| 0b. Independent paired corpus; provenance, seeds, held-out seeds, native oracle | Nine variants per architecture cover x64 Mach-O and x86 ELF, with repeated deterministic generation, reserved seeds and 33,600 primary behavior records. ELF32 executes under independent QEMU translation; see `VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. The supplied packed hello-world pair has three matched no-argument process observations (`VMP_SUPPLIED_SAMPLES.md`), separate from the generated matrix. Two user-attributed Morok ELFs and one Hikari arm64 Mach-O provide matched enabled/disabled selected-entry inventories (`VMP_MOROK_ENTRY_CONTROL.md`, `VMP_HIKARI_ENTRY_CONTROL.md`). Exact-file Morok audit passes the supplied keygen's native-pack and sealed-manifest checks but rejects the supplied `boo` file's mismatched build ID and missing finalized pack/seal manifests (`VMP_SUPPLIED_MOROK_AUDIT.md`); the latter cannot count as a verified packed fixture. A **fresh** source-controlled Morok `boo` ELF64 pair has two byte-identical fixed-seed protected builds, verified native packing and nine matching no-argument process observations (`VMP_MOROK_PAIRED_CONTROL.md`). A second fresh keygen pair injects fixed time and matches 30 valid/rejection-path process observations across five stdin cases, with a one-second shifted-time negative control (`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md`). Fresh-IDA inspection finds the clean keygen application entry as code but the packed application trampoline as a data item with no owner under either plugin profile (`VMP_MOROK_KEYGEN_IDA_BOUNDARY.md`). Explicit read-only candidate decoding yields matching conditional graphs from two protected keygen builds (`VMP_NATIVE_CANDIDATE_REGION.md`). A later runtime-shadow checkpoint checks 198 bounded protected transition occurrences against QEMU/GDB on one valid path (`VMP_NATIVE_RUNTIME_SHADOW.md`). Both fresh pairs are distinct from the supplied Morok ELFs. Broader fixture shapes, other protected paths and recovery metrics remain | In progress |
| 1a. Portable stack-transfer classification with widths, stack effects, dependencies | `classify_push_return`, 32/64-bit core controls, x64 and linked ELF32 IDA fixtures; matched ELF32 rejected-case baseline. A separate i386 ELF32 process checks get-PC/stack positive shapes and a negative result control under pinned QEMU (`VMP_GET_PC32_EXECUTION.md`). A second same-binary process/IDA control checks dynamic register/memory targets, alternate entry, and RET adjustment (`VMP_GET_PC32_REJECTIONS.md`). Exact local `PUSH [SP]; RET` targets carry a distinct stack-word proof and preserve the read/write/return effects (`VMP_STACK_WORD_TRANSFERS.md`); an exact full-word store to `[SP]` now replaces the tracked word (`VMP_STACK_TOP_STORES.md`). The IDA block-end regression is repaired (`VMP_GET_PC32_BLOCK_END.md`); wider paired, width/far, and exceptional execution controls remain | In progress |
| 1b. Exact register and memory target recovery; unknown candidates preserved | Bounded local replay, immutable-memory dependencies, and persisted ownership receipts implemented. Separate-process save/reopen, both tested rebase modes, Jcc undo/redo, and stack-pointer replacement controls pass; see `NATIVE_PROOF_OWNERSHIP.md`. Bounded owned-function joins and loop fixed points support register targets (`VMP_NATIVE_DATAFLOW.md`). A prior known word at `[SP]` supplies an exact memory-sourced target (`VMP_STACK_WORD_TRANSFERS.md`). Full-word stores to exact mapped writable addresses establish four owned and ownerless transfer targets per architecture (`VMP_WRITABLE_MEMORY_TRANSFERS.md`); bytewise local stores add three targets (`VMP_PARTIAL_WRITABLE_MEMORY.md`); local register/memory `XCHG` adds three memory targets and one register target (`VMP_WRITABLE_EXCHANGE.md`); exact local `MOV` loads add two register targets and restore one byte read-then-write memory target (`VMP_WRITABLE_LOADS.md`); and `MOVZX`/`MOVSX` byte/word loads add four register targets (`VMP_WRITABLE_EXTENDED_LOADS.md`). `STOS` preserves an unrelated register target and `LODS` preserves a locally stored memory target under the bounded state (`VMP_STRING_IO_FLAGS.md`). Normal-completion `REP STOS` and `REP LODS` now establish a zero count and two further fixed transfer targets (`VMP_STRING_REPEAT_COUNT.md`). Exact zero-count `REP MOVS` preserves local memory and proves one target on each architecture; exact one-count x86-64 `REP MOVS` proves one more disjoint target (`VMP_REP_MOVS_LOCAL_MEMORY.md`). Known-count REPE/REPNE SCAS and CMPS now prove two count-derived targets per architecture (`VMP_REP_COMPARE_LOCAL.md`). Incomplete bytes, aliases and conflicting paths remain unresolved. A same-binary i386 oracle reaches two register and two externally written memory targets while production IDA retains both as unresolved candidates (`VMP_GET_PC32_REJECTIONS.md`). Ownerless inspection admits 128 nodes and completes one 75-node supplied VMP initializer region, but its three facts remain unresolved (`VMP_OWNERLESS_128.md`). Dynamic heap identity, other writable-memory operations, larger graphs, complete topology and legacy/plugin-absent metadata attribution remain | In progress |
| 1c. Push-based get-PC forms and call-as-jump summaries | Both source-emitted forms, stack replay, return-address provenance/effects, and owned native facts implemented (`VMP_GET_PC.md`). The 32-bit PUSH-next proof survives IDA's block-end metadata (`VMP_GET_PC32_BLOCK_END.md`). RET lowering preserves the POP; 1,792 scoped IR-effect comparisons and six entry/region guards pass (`VMP_MICROCODE.md`). Bounded inferred noreturn repair has persisted flag ownership (`VMP_GET_PC_NORETURN.md`). Automatic transfer of closed, automatic x86/x64 gadget functions preserves original stack metadata and restores donor ownership across patch, rename, tail deletion, save/reopen, and user-exclusion controls (`VMP_GET_PC_REGIONS.md`). Re-inferred flags and later explicit caller contracts now have owned-lease repair or revocation (`VMP_GET_PC_LEASES.md`). More general region ownership and the full protected-corpus lifecycle matrix remain | In progress |
| 2a. Per-flag abstract interpretation and complete condition evaluation | `x86_abstract.h`, production `x86_analysis.cpp`; exhaustive 8-bit arithmetic, defined shift flags, 729 partial flag profiles, width/alias controls. Owned-function direct CFG joins and loop fixed points are integrated (`VMP_NATIVE_DATAFLOW.md`). `CLD` and `STD` preserve the six tracked status flags (`VMP_DIRECTION_FLAGS.md`). Bounded `PUSHF*`/`POPF*` replay restores individually known status bits; matched prior/new, executed x64/i386 and explicit-root ownerless controls pass (`VMP_SAVED_FLAGS.md`, `VMP_SAVED_FLAGS_OWNERLESS.md`). Local signed-extension memory loads supply byte and word `MOVSX` conditions per architecture and one `MOVSXD` condition in long mode (`VMP_WRITABLE_EXTENDED_LOADS.md`); exact local writable-memory arithmetic adds two conditions (`VMP_WRITABLE_ALU.md`). Plain and repeated `MOVS` preserve the six modeled status bits (`VMP_MOVS_FLAGS.md`); `STOS` and `LODS` add three more proved conditions per architecture while invalidating their implicit writes (`VMP_STRING_IO_FLAGS.md`). Repeated `STOS` and `LODS` now retain the exact natural-address-size count-zero postcondition while preserving the same six status bits (`VMP_STRING_REPEAT_COUNT.md`). Zero-count `REP MOVS` preserves a local destination condition on both architectures, and one-count x86-64 `REP MOVS` establishes a copied byte condition (`VMP_REP_MOVS_LOCAL_MEMORY.md`). Exact zero-count REPE/REPNE SCAS and CMPS preserve prior flags on both architectures; one-count x86-64 comparisons add four local CF/ZF facts (`VMP_REP_COMPARE_LOCAL.md`). A 128-node ownerless cap admits one supplied protected 75-node region, with zero proved conditions (`VMP_OWNERLESS_128.md`); larger graphs and protected effectiveness remain | In progress |
| 2b. Native CFG integration and SETcc/CMOV value/microcode consumers | Native Jcc edges and SETcc/CMOV value facts implemented. Persisted ownership, Jcc rebase/undo, and reopened value-fact invalidation controls pass. Consumers pass 12,288 independent x86/x64 effect comparisons and 192 read-fault checks (`VMP_CMOV_MEMORY.md`). Forty matched protected-corpus runs now measure zero lowering events: ten x64 condition sites are ownerless and three owned i386 sites remain unchanged (`VMP_CONDITION_CORPUS.md`). Protected region/state coverage, effectiveness and complete microcode lifecycle coverage remain | In progress |
| 3a. Bounded use-site snapshots, allocation generations, contexts, temporal ordering | Integrated bounded lifetime ledger, first-fit reuse, executed-read and modeled-argument snapshots. Erase/reuse, address changes, pre-write RMW, overlap, invalid free/use and cap controls pass. Contiguous-address streams preserve separate read-only interleavings, writes to another allocation, and same-allocation writes outside the completed observed string span (`VMP_INTERLEAVED_READS.md`, `VMP_HEAP_WRITE_STREAMS.md`, `VMP_SAME_OBJECT_WRITE_STREAMS.md`). Permuted exact heap reads covering contiguous addresses reconstruct with duplicate, hole, internal-NUL and overlapping-write controls on x86-64 and arm64 (`VMP_PERMUTED_READ_STREAMS.md`). Different read schedules across runs reach consensus while retaining original fragments and anchor occurrences (`VMP_VARIABLE_READ_ORDER.md`). Allocation-wide grouping reconstructs permuted contiguous spans observed at multiple instruction sites (`VMP_MULTISITE_READ_STREAMS.md`); two disjoint complete spans within one allocation remain independent (`VMP_DISJOINT_READ_STRINGS.md`). Exact stack-scope writes outside the heap object no longer interrupt its read stream (`VMP_STACK_WRITE_READ_STREAMS.md`). Other architectures/protected corpus, spatially incomplete components and writes overlapping the candidate span remain unresolved; see also `VMP_TEMPORAL_STRINGS.md` | In progress |
| 3b. Cross-run semantic-use consensus and ctree display | Address/generation-independent matching, strict corpus/duplicate/lifetime checks, current IDC API, and transient direct-call annotations implemented. Exact native pointer/index-expression annotations and a linked read-stream table retain original source witnesses; console and actual Qt controls validate freshness and navigation (`VMP_NATIVE_READ_STRINGS.md`). Same-allocation disjoint writes retain two use-site annotations while overlapping writes veto the affected string (`VMP_SAME_OBJECT_WRITE_STREAMS.md`). Permuted heap reads report span start, execution-order fragments and an exact indexed-read ctree annotation (`VMP_PERMUTED_READ_STREAMS.md`). Variable-order x86-64/arm64 runs agree on one observed value across four/six complete inputs (`VMP_VARIABLE_READ_ORDER.md`). When Hex-Rays eliminates an anchor expression, a common surviving exact fragment site receives one transient annotation (`VMP_MULTISITE_READ_STREAMS.md`). Two complete spans in one allocation yield separate x86-64/arm64 read-stream rows and ctree annotations (`VMP_DISJOINT_READ_STRINGS.md`); stack-hash variants retain both use annotations (`VMP_STACK_WRITE_READ_STREAMS.md`). Exact-site indirect-call display labels the observed target; same-binary previous-plugin controls pass for x86-64 and ARM64 `BLR` (`VMP_INDIRECT_USE_STRINGS.md`, `VMP_INDIRECT_USE_STRINGS_ARM64.md`). Wider lifecycle matrix and protected fixtures remain; see also `VMP_TEMPORAL_STRINGS.md` | In progress |
| 3c. Separate byte/word string transform recognition and encoding validation | Typed finite-index symbolic proof and independent UTF-8/UTF-16 validation; transient exact-shape/byte-checked ctree annotations. x64 Mach-O and x86 ELF each pass 51 production checks; byte-encrypted UTF-16 retains byte units. Source-routine identity is not inferred from an identical formula. Protected corpus, broader loop shapes, dynamic provenance, and full lifecycle matrix remain; see `VMP_ROTATING_STRINGS.md` | In progress |
| 4a. Representative microcode corpus and categorized canonicalization failures | Ten independent x64 native routines captured at four real SDK maturities with a matched disabled baseline. A late identity under zero-extension exposed a nested-recognition/order miss, now fixed. Width, stack-definition and full/partial-alias controls are categorized; source-emitted protected and wider architecture corpora remain. See `VMP_MBA_CANONICALIZATION.md` | In progress |
| 4b. Typed transformations and rejection controls in production | Actual microcode instance proofs gate catalog, chain and optional affine proposals before mutation. Typed counterexamples, unsupported effects, distinct frame owners and solver exhaustion reject. Native and independent captured-IR result/memory oracles pass; wider operations, flags/exception contracts and corpus remain. See `VMP_MBA_CANONICALIZATION.md` | In progress |
| 5. Linked CFG, lifetime timeline, proof detail with live provenance | Bounded JSON/Qt workspace links edges, lifetimes, run stops and native proofs. Actual scoped SMT checks now expose formulas, SAT assignments, UNSAT exclusions and UNKNOWN reasons; independent replay validates recorded counterexamples. Query navigation guards do not assert current IR applicability. A separate conditional byte graph renders the packed Morok entry without IDA retyping (`VMP_NATIVE_CANDIDATE_GUI.md`). The supplied VMP hello call-use now has a separate live Qt graph/table with exact shadow-file and result recomputation (`VMP_HELLO_CALL_USE_GUI.md`). Protected counterexamples, full quota/lifecycle coverage and performance measurements remain; see `VMP_EVIDENCE_VIEW.md`, `VMP_NATIVE_EVIDENCE_VIEW.md` and `VMP_SOLVER_EVIDENCE_VIEW.md` | In progress |
| 6a. Separate bounded VM-region and logical-state model | Separate `src/vm` descriptors and logical-state comparison; local recognition supports role permutations, both directions, clones, table/relative dispatch and stateful decoding. Boundary auditing distinguishes side entries and shared/foreign ownership (`VMP_REGION_BOUNDARIES.md`). A separate native-region capture API executes bounded prefixes across existing owners with exact-byte admission and no ordinary function publication; 120 paired captures include 72 checked PUSH/CALL prefixes, and an independent decoder verifies 5,325 entered instruction records (`VMP_NATIVE_REGION_CAPTURE.md`). Explicit packed-entry byte decoding yields one conditional Morok graph without IDA retyping (`VMP_NATIVE_CANDIDATE_REGION.md`); a synthetic capture records a 4,096-entry file-byte Morok prefix (`VMP_NATIVE_CANDIDATE_TRACE.md`). A runtime-shadow variant overlays independently captured mapped bytes in an ephemeral image, reaches a 4,096-instruction protected valid-input prefix and matches 198 finite transition occurrences to QEMU/GDB after two bounded observation gaps (`VMP_NATIVE_RUNTIME_SHADOW.md`). A separate observed-memory replay overlays the protected process's 1,696 data bytes and translated 1,152 stack bytes, matching 131,008 aligned GPR values and 5,696 boundary bytes across two runs; 693 intermediate RFLAGS entries per run differ in its cross-process comparison (`VMP_NATIVE_MEMORY_REPLAY.md`). A same-process follow-up matches 37,622 architecturally defined status-bit values across the pair; 676 raw RFLAGS entries per run still differ only in undefined bits (`VMP_NATIVE_DEFINED_FLAGS.md`). VM context, complete memory identity, logical VM ownership and persistent lifecycle remain unresolved; see also `VMP_VM_REGIONS.md` and `VMP_VM_OBSERVATIONS.md` | In progress |
| 6b. Candidate recognition, visualization, and validated semantic summaries | Candidate inspection includes local normal-completion register/flag/memory/dispatch summaries. A symbolic array retains data aliasing and ordered stack writes; independent executed x64 oracle cases and x86/x64 IDA probes validate admitted scaffolds. Complete captured table/relative/boundary transitions now receive nonvacuous SMT checks, linked to their exact visit and query identities. Full-handler effects, VM input-state recovery, exceptions and admitted VM-region transitions remain; see `VMP_VM_SEMANTICS.md` and `VMP_VM_TRANSITIONS.md` | In progress |
| 6c. Proven normalized-summary reuse | Local modeled-effect references are shared only after UNSAT under a bijective register-role map; SAT, UNKNOWN and incompatible access/flag contracts prevent reuse. Production clone and distinct-syntax controls pass. Whole-handler summaries, cross-region ownership and persistent execution-cache reuse remain; see `VMP_VM_SEMANTICS.md` | In progress |
| V. Complete benchmark and completion audit | Paired x64 and x86 result/selected-memory/stack/defined-flag checks and scoped process elapsed time/peak bytes are recorded in `VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. The supplied hello-world pair adds exact process output/exit comparisons and scoped elapsed/peak measurements (`VMP_SUPPLIED_SAMPLES.md`). A bounded process-runner error observed during corpus validation has a checked-group/leader fallback, deterministic failure injection and a repeated supplied-pair control (`VMP_PROCESS_TERMINATION.md`). A scoped native x86-64/i386 source oracle initially scored 26/34 correct edges, zero false edges and five unresolved eligible sites per owned or ownerless path (`VMP_NATIVE_EDGE_BENCHMARK.md`). Matched REP MOVS count and exact stack-top store improvements raise this to 28/34, zero false edges and three unresolved eligible sites (`VMP_REP_MOVS_COUNT.md`, `VMP_STACK_TOP_STORES.md`). Two added repeated-string count sites are proved, yielding 30/36 correct edges with zero false and three unresolved eligible sites (`VMP_STRING_REPEAT_COUNT.md`). A later 48-edge scoped oracle scores exact zero/one `REP MOVS` local effects at 40/48 correct x86-64 edges and 31/48 i386 edges per analysis path, with zero false edges (`VMP_REP_MOVS_LOCAL_MEMORY.md`). A subsequent 50-edge known-count comparison oracle scores 42/50 x86-64 and 33/50 i386 correct edges per path with zero false edges (`VMP_REP_COMPARE_LOCAL.md`). A protected Morok valid-input prefix has 198 candidate transition occurrences matching the adjusted QEMU/GDB observation multiset, with no ordinary function publication (`VMP_NATIVE_RUNTIME_SHADOW.md`). The observed-memory replay adds exact aligned GPR and boundary-window measurements with explicit flag mismatches and mutation controls (`VMP_NATIVE_MEMORY_REPLAY.md`). The same-process flag follow-up compares 37,622 architecturally defined status bits and explicitly excludes 901 differing undefined bits per run (`VMP_NATIVE_DEFINED_FLAGS.md`). Protected-mode recovery/error/abstention rates, literal accuracy, solver rejection reasons, broader fixtures and full completion audit remain | In progress |

The review explicitly treats full bytecode lifting as a subsequent project;
this ledger retains the requested separate VM model, recognition, and validated
semantic summaries without claiming that they constitute full devirtualization.
Packing, licensing, anti-debugging, and .NET IL execution are excluded by the
review. Unsupported execution modes and unproved transformations retain explicit
abstentions; they cannot be counted as successful recovery.

Quality gates are applied to each completed change and again to the complete
objective. Neither baseline test success nor this ledger proves completion.

Protected hello call-use checkpoint for rows 3a, 3b, 6a and V: an explicit
bounded shadow query joins one observed CALL edge, its same-sequence argument
register state and loaded read-only NUL-terminated bytes. Two current IDA
runs return the 12-byte `Hello World\0` payload at `0x10000145c`; LLVM and
Apple LLDB each observe the same pointer and bytes at `printf` in two
protected process runs. Wrong selectors and incomplete bytes abstain, an
in-memory shadow mutation changes the result, the independent verifier rejects
pointer/byte/source mutations, and the matched prior plugin lacks the query.
The native trace and selected IDA inventory remain unchanged; all 21 CTest
suites pass. See `VMP_HELLO_CALL_USE.md` and its evidence JSON. Other calls,
heap objects, callee semantics and the full review remain in progress.

Supplied VMP hello runtime-shadow checkpoint for rows 0b, 6a and V: LLVM and
Apple LLDB each observe two original and two protected `printf` stops. The
protected process restores an exact 40-byte original code/stub/literal window
across its zero-fill file sections. An explicit unloaded, code-referenced
root and two contiguous read-only image segments allow the current plugin to
plan nine heads and enter six instructions in an ephemeral shadow; a matched
prior plugin abstains. Independent Capstone decoding, byte/mask counts,
negative controls, the Morok shadow regression and all 21 CTest suites pass.
The trace stops at the indirect import environment frontier. See
`VMP_HELLO_RUNTIME_SHADOW.md` and its evidence JSON. Full protected-path and
VM recovery remain in progress.

Supplied VMP hello observed-entry checkpoint for rows 0b, 6a and V: LLVM
and Apple LLDB stop at the protected entry stub after restoration, then at
`_main`, and single-step six instruction entries. Two fresh IDA replays use
the observed entry registers, flags and 128 stack bytes with explicit
stack-relative annotations. All 108 GPR/RIP/RFLAGS values per debugger match
after stack translation, 216/216 total; the 16-byte call/frame stack write
also matches each process. Negative requests, three verifier mutations and
selected IDA inventory controls pass. The replay stops at the indirect
import stub, while LLDB reaches `printf`; later paths and VM recovery remain
unknown. See `VMP_HELLO_OBSERVED_ENTRY_REPLAY.md` and its evidence JSON.

Packed-keygen runtime checkpoint: two fixed-seed Morok protected processes
start at the recorded ELF entry, reach the application callback with live stack
arguments, and match all 4,096 addresses and entered instruction bytes of the
earlier synthetic candidate prefix under QEMU/GDB. File-mapped and runtime
bytes agree; the next PC is `0x419896` in both process traces and the candidate.
This validates one bounded empty-input prefix, not later unpacking or protected
recovery effectiveness. See `VMP_MOROK_RUNTIME_TRACE.md` and its evidence JSON.

Packed-keygen execution-state checkpoint: on the fixed valid-v14.1 input,
both protected processes reach `0x430000` after the callback. Their
65,536-byte mapped packed ranges match the file at ELF entry and callback,
then agree with each other at first packed execution while differing from the
file in 65,274 positions. Separate completed QEMU runs of the clean and both
protected builds match exact stdout and stderr. This supplies a runtime byte
oracle; native edge recovery and VM semantics remain incomplete. See
`VMP_MOROK_UNPACKED_ENTRY.md` and its evidence JSON.

Runtime-shadow native checkpoint: an explicit read-only candidate API overlays
that independently captured 65,536-byte mapped dump on an ephemeral x86-64
snapshot. Two fresh protected IDA runs agree on 16,335 planned heads and a
4,096-instruction prefix; all head and entered bytes pass independent Capstone
checks. Two QEMU/GDB runs align to the candidate stop after accounting for two
linear instruction entries omitted by the debugger. The 198 candidate
nonfallthrough transition occurrences equal the adjusted QEMU/GDB multiset.
The plan remains truncated, no ordinary function evidence is published, and
full VM semantics remain unknown. See `VMP_NATIVE_RUNTIME_SHADOW.md` and its
evidence JSON.

Runtime-shadow instruction-state checkpoint for rows 6a and V: a separate
read-only API captures the 16 x86-64 general-purpose registers, RIP and RFLAGS
at each of 4,096 admitted instructions without extending the native plan.
Two fresh protected IDA reports are byte-identical and retain the prior
head/path/edge arrays. Two QEMU/GDB register runs align 4,094 reported entries
after the same two observation gaps. The six registers equal at entry remain
exact at all aligned entries in both runs (49,128 value comparisons); entry-
relative `RSP` movement also matches 8,188 comparisons. Other registers and
flag bits are reported without general equivalence claims. Negative state
mutations reject, all 21 CTest suites pass, and the IDB inventory is unchanged.
See `VMP_NATIVE_RUNTIME_STATES.md` and its evidence JSON. Complete VM state,
memory effects, other inputs and ordinary function publication remain open.

Runtime-shadow entry replay checkpoint for rows 6a and V: a separate bounded
read-only API accepts a same-process register and entry-stack observation with
explicit stack-relative annotations. Two fresh IDA captures and two protected
QEMU/GDB runs match all 16 general-purpose registers at 4,094 aligned entries
per run after reversing the declared stack translation: 131,008 exact values.
The two known debugger gaps remain, raw RFLAGS bits differ, and the supplied
128-byte stack snapshot is not read in this prefix. Negative annotation and
register mutations reject; the measured IDB inventory is unchanged. See
`VMP_NATIVE_ENTRY_REPLAY.md` and its evidence JSON. The complete review remains
in progress.

Protected boundary-memory checkpoint for rows 6a and V: two fresh QEMU/GDB
processes step to the same Morok keygen stop PC and confirm the candidate's
16 final general-purpose registers, RIP and RFLAGS after stack translation.
The candidate's 68 writes occupy seven ranges and 142 distinct bytes. Applying
those final values to each process's independently captured entry data/stack
windows reproduces all 2,848 boundary bytes per run (5,696 byte comparisons
across both). The process entry data already differs from file-backed bytes;
emulator initial-memory identity and memory outside the captured windows
remain unverified. See `VMP_NATIVE_BOUNDARY_MEMORY.md` and its evidence JSON.

Observed-entry-memory replay checkpoint for rows 6a and V: a separate
read-only API overlays the protected process's data and translated stack
windows into the ephemeral image. Two fresh IDA captures and the protected
QEMU/GDB reports agree on 131,008 aligned GPR values and 5,696 boundary
window bytes. A one-bit entry-data mutation changes the first read and the
bounded path. Intermediate RFLAGS differ at 693 aligned entries per run;
outside-window memory and later execution remain unverified. The IDB inventory
is unchanged, and all 21 CTest suites pass. See `VMP_NATIVE_MEMORY_REPLAY.md`
and its evidence JSON. The complete review remains in progress.

Same-process defined-flag checkpoint for rows 6a and V: two additional
QEMU/GDB processes record entry memory, every reported instruction's scalar
registers and boundary memory together. Fresh IDA replays match all 16 GPRs
at 4,094 aligned entries per run. An explicit Intel-defined six-status-bit
mask yields 18,811 exact defined-bit comparisons per run, or 37,622 across
the pair. Raw RFLAGS still differ at 676 entries per run, all in undefined
bits. Mutation controls reject a changed defined bit, and the IDB inventory
is unchanged. See `VMP_NATIVE_DEFINED_FLAGS.md` and its evidence JSON.

Second protected input checkpoint for rows 0b, 6a and V: the fixed-seed
Morok keygen version-14.0 input has a different completed-process output from
version 14.1 while preserving exact clean/protected output equality within
each input. Two more protected QEMU/GDB processes and two fresh IDA replays
raise the bounded totals to 262,016 exact aligned GPR values, 75,244 exact
defined status bits and 11,392 exact boundary-window bytes across four runs.
The observed unpacked code, writable-data windows and 4,094-entry reported
path are identical across both inputs. Later input-dependent execution and
VM-region identity remain open. See `VMP_NATIVE_SECOND_INPUT.md` and its
evidence JSON.

Observed protected branch checkpoint for rows 6a and V: two longer QEMU/GDB
paths first differ after 21,979 reported instruction entries at the successor
of a shared `CMP; JNE`. A bounded read-only replay now accepts an explicit
runtime state at an executable packed-data tail and non-ABI stack alignment.
On two distinct inputs it matches 108 same-process GPR/RIP/RFLAGS values,
two stack reads and both branch successors. Stack-word mutation reverses
each replayed successor; invalid budgets and executable data patches reject.
The local two-instruction result does not establish whole-path replay or
logical VM-state identity. See `VMP_NATIVE_BRANCH_CHECKPOINT.md` and its
evidence JSON.

Protected branch continuation for rows 0b, 6a and V: two new same-process
QEMU/GDB captures seed bounded IDA replays after the input-dependent branch.
The 14.1 and 14.0 paths match 1,181 and 785 entered PCs and instruction
bytes respectively, 31,456 GPR values, 1,966 RIP values, 10,891
architecturally defined status bits, and 10,752 selected boundary data/stack
bytes. A narrower data overlay misses the live RNG state at `0x444b08` and
falsifies RAX at instruction 16, while the 4,096-byte overlay matches. Both
replays stop at the same cross-region CALL target `0x41d6c9`; they do not
establish its callee path or logical VM-state identity. See
`VMP_NATIVE_BRANCH_CONTINUATION.md` and its evidence JSON.

Ownerless native graph checkpoint: an explicit-root read-only inspector now
propagates register, flag and stack facts across existing decoded ownerless
branches and loops, with architectural successors, entry auditing and visible
frontiers. Across x64/i386, 6,140 native checks and 620 IDA assertions pass;
90 Qt assertions and all 21 CTest suites pass. A frozen protected development
measurement proves 0/5 bounded condition sites, with one graph rejected at the
64-node cap and zero microcode-lowering gain. Ordinary CFG publication, complete
predecessor discovery and broader review requirements remain incomplete. See
`VMP_OWNERLESS_DATAFLOW.md`.

Ownerless 128-node follow-up: the supplied VMP initializer changes from a
64-node limit abstention to a converged 75-node normal-completion region after
direct-jump decoding. Its two SETcc and one branch facts remain unresolved;
the read-only IDB inventory is unchanged. Exact 128/129-node synthetic controls
pass on x64/i386, with 3,582 native checks and 332 IDA assertions per
architecture; all 21 CTest suites pass. See `VMP_OWNERLESS_128.md`. The earlier
64-node checkpoint and its recorded hashes remain historical evidence. The
historical 97-node protected corpus root has not been rerun under the new bound
because its archived inputs are absent from this workspace.

Direction-flag transfer checkpoint: `CLD` and `STD` now retain CF, PF, AF, ZF,
SF and OF in the native abstract state. Matched prior-plugin probes reject one
owned and two ownerless facts on identical fixture binaries; the new plugin
proves all three on x64/i386. Native execution checks 3,070 owned cases and
4,094 ownerless cases per architecture, including a six-status-bit comparison
around both instructions. The supplied protected initializer still has three
unresolved records. See `VMP_DIRECTION_FLAGS.md`.

Bounded-runner follow-up: group signaling now checks the child's live process
group, and a denied or vanished group signal falls back to the direct child
PID before `wait4` accounting. Injected `PermissionError`, missing-group and
wrong-group controls pass; 21/21 CTest suites and three paired supplied-binary
runs pass. The direct-PID fallback does not prove descendant cleanup. See
`VMP_PROCESS_TERMINATION.md`.

Saved-flags checkpoint: a bounded stack word now carries individually known
architectural status bits across `PUSHF*` and `POPF*`; an ordinary literal
`PUSH` can also supply those bits. On matched x64/i386 fixtures, the prior
plugin misses three exact facts per architecture and the new plugin proves
all three. Each architecture passes 4,606 native and 67 IDA checks, including
overwritten and dynamic-word abstentions. All 21 CTest suites pass. The
supplied protected initializer still has three unresolved facts. See
`VMP_SAVED_FLAGS.md`.

Ownerless saved-flags follow-up: five explicit-root fixtures per architecture
prove three saved/literal flag facts and retain two overwritten/dynamic
abstentions. Both architectures pass 402 read-only IDA assertions and their
existing 4,094-check native oracle; see `VMP_SAVED_FLAGS_OWNERLESS.md`. One
concurrent VM-observation CTest assertion failed once, then passed in
isolation and in a complete 21/21 rerun; its intermittent cause is unknown.

Exact stack-word transfer checkpoint: a full-width `PUSH [SP]; RET` can now
derive its target from a preceding bounded stack definition in owned and
explicit-root ownerless analysis. Per architecture, 5,374 owned native checks,
74 owned IDA assertions, 4,094 existing ownerless native checks and 432
ownerless IDA assertions pass. Overwritten and conflicting-path words remain
unresolved; a source-byte patch revokes the owned edge and restoration
recomputes it. The supplied VMP initializer retains three unresolved facts;
see `VMP_STACK_WORD_TRANSFERS.md` and its evidence JSON.

Writable-memory transfer checkpoint: bounded x86-64/i386 state now retains
complete words from explicit full-width stores at exact mapped writable
addresses. Four target shapes per architecture gain owned edges and ownerless
facts; four initial/alias/conflict controls remain unresolved. Each architecture
passes 7,422 owned native checks, 108 owned IDA assertions, 4,094 existing
ownerless native checks and 512 ownerless IDA assertions. An owned store-byte
patch revokes its edge and restoration recomputes it. A matched prior plugin
misses all four exact ownerless targets on identical binary/probe pairs; the
supplied VMP initializer remains at three unresolved facts. See
`VMP_WRITABLE_MEMORY_TRANSFERS.md` and its evidence JSON.

Partial-width writable-memory follow-up: the bounded state now retains 128
individual bytes from exact local 8-/16-/32-/64-bit stores. Three new target
shapes per architecture gain owned edges and ownerless must-facts, while an
incomplete pointer and conflicting branch-defined byte remain unresolved.
Each architecture passes 8,702 owned native checks, 128 owned IDA assertions,
4,094 existing ownerless native checks and 562 ownerless IDA assertions.
Matched previous-plugin runs miss the three new targets; all 21 CTest suites
pass. The supplied VMP initializer retains three unresolved facts. See
`VMP_PARTIAL_WRITABLE_MEMORY.md` and its evidence JSON; the earlier full-word
checkpoint and its recorded hashes remain historical.

Stack alias invalidation follow-up: a direct global `PUSH memory; RET` after
i386 `PUSHA; POPA` now remains unresolved because the stack writes have no
proved disjoint address. A matched earlier plugin instead publishes a target
and user edge in the same i386 fixture; x86-64 outcomes are unchanged. Each
architecture passes 8,958 owned native checks, 132 owned IDA assertions,
4,094 existing ownerless native checks and 572 ownerless IDA assertions. The
final four-worker CTest run passes 21/21 after one initial 20-way failure of
an unrelated suite with unknown cause. See `VMP_STACK_ALIAS_INVALIDATION.md`
and its evidence JSON.

Writable exchange follow-up: exact mapped register/memory `XCHG` now exchanges
known byte slices in the bounded x86-64/i386 state. Three memory-source and one
register-source transfer shapes gain owned edges and ownerless must-facts;
an entry-supplied replacement pointer remains unresolved. Each architecture
passes 10,238 owned native checks, 150 owned IDA assertions, 4,094 existing
ownerless native checks and 622 ownerless IDA assertions. Matched previous-plugin
runs miss all four new targets; all 21 CTest suites pass. The supplied VMP
initializer remains at three unresolved facts. See `VMP_WRITABLE_EXCHANGE.md`
and its evidence JSON.

Writable load follow-up: an exact scalar `MOV register, memory` can now read
previously written local bytes from the bounded writable map. Full and byte
register-load targets, plus a formerly unresolved byte read-then-write memory
target, gain owned edges and ownerless facts on x64/i386. Initial writable
bytes and an intervening unknown-alias store remain unresolved. Each
architecture passes 11,262 owned native checks, 162 owned IDA assertions,
4,094 existing ownerless native checks and 662 ownerless IDA assertions.
Matched prior-plugin runs miss exactly three targets; all 21 CTest suites
pass. The supplied VMP initializer retains three unresolved facts. See
`VMP_WRITABLE_LOADS.md` and its evidence JSON.

Writable extension-load follow-up: exact locally written source bytes now feed
`MOVZX`, `MOVSX`, and long-mode `MOVSXD` register values. Byte and word
extension forms establish four new transfer targets on x64/i386. Negative byte
and word values establish two conditions per architecture; a negative dword
establishes an additional long-mode condition. Initial bytes and an
intervening unknown-alias write remain unresolved. Per architecture, 14,334
owned native checks, 192 owned IDA assertions, 4,094 existing ownerless native
checks and 782 ownerless IDA assertions pass. Matched prior-plugin runs miss
only the new facts; all 21
CTest suites pass. The supplied VMP initializer retains three unresolved
facts. See `VMP_WRITABLE_EXTENDED_LOADS.md` and its evidence JSON.

Guarded immediate-push checkpoint: payload/store effects, virtual-stack role
hypotheses and source-ordered taken stack checks now have conditional summaries.
Equivalence compares nonempty input domains and complete effects; observations
require every internal transfer witness. Across x64/i386, 168 synthetic native
cases and IDA captures pass 2,282 assertions and 84 independent full-path replays;
all 21 CTest suites pass. A matched protected case retains 80 dispatch-only
transitions and zero full guarded handlers, stopping at unsupported BSWAP16.
Relocation, complete logical state and protected full-handler recovery remain
incomplete. See `VMP_PUSH_HANDLERS.md`.

Native topology checkpoint: an actual IDA counterexample showed stale owned
comments and a branch edge after an external adjacent fallthrough or tail
removal, despite inspector rejection. Entry and ownership mutations now revoke
affected publications; revalidation shares the inspector's recognizer and checks
support coverage. Both architectures pass 106 production assertions and 5,116
native result checks; 169 ownership/get-PC regression assertions and all 20
CTest suites pass. See `VMP_NATIVE_TOPOLOGY.md`. Broader metadata/lifecycle and
protected-region requirements remain incomplete.

Explicit native-input checkpoint: `chernobog_vm_trace_input` supplies bounded
initialized objects through the existing ABI policy and captures final scalar
registers plus whole-object bytes. Of 640 x86/x64 paired captures, all 256
original/mutation cases return with matching result, selected memory including
guards, stack effects, and defined flags. The remaining 384 virtualization and
combined cases retain explicit native-region boundary stops. Independent decode
checks cover 30,596 entered instruction records; 4,509 production assertions and
19 CTest suites pass. See `VMP_NATIVE_INPUTS.md`. This advances input contracts
and behavior measurement for rows 0b, 6a, 6b, and V without completing their
broader requirements or establishing logical VM ownership.

Observed-native continuation checkpoint: `chernobog_vm_trace_walk` retains one
engine state while admitting bounded observed indirect/near-return destinations.
It extends 224 protected captures and passes 1,463 decoded transfer-effect checks;
117,757 entered instruction records pass independent byte/size/successor checks.
All 384 virtualization/combined cases remain incomplete at rejected semantics
or time budgets. A reproduced RDTSC counterexample prevents a false separate-run
register-repeatability claim. Near/far, budget, changed-code, inventory, and
publication controls pass; see `VMP_NATIVE_WALK.md`. Logical VM ownership and
complete handler/transition semantics remain required for rows 6a–6c.

Observed local-transition checkpoint: `chernobog_vm_trace_check` records bounded
scalar instruction-entry states and checks separately scoped VM role hypotheses
on actual native paths. Across 640 paired captures, 416 local visits receive
nonvacuous SMT corroboration and independent replay of 9,808 instruction visits.
Intermediate replay exposed a legacy i386 INC/DEC carry defect hidden by later
flag overwrites; a driver compatibility correction passes 56 red/green cases
and 56 sampling-independence checks. All 20 CTest suites and 41 production
controls pass. All 384 virtualization/combined executions remain incomplete at
rejected BSWAP16 semantics; full handler effects and logical VM state remain
unknown. See `VMP_NATIVE_OBSERVATIONS.md` for assumptions, quotas, per-variant
yield and evidence. This advances rows 6a–6c and V without completing them.

Native dataflow checkpoint: bounded owned-function analysis now joins register,
flag and stack facts across direct branches and iterates loops to a fixed point.
Both architectural Jcc successors are reconstructed from bytes; conflicting
predecessors and external entries retain uncertainty. Independent x64/i386
fixtures each recover five condition facts and one register PUSH/RET target,
with 5,116 native oracle checks and 50 production checks. Existing native and
microcode regressions and all 20 CTest suites pass. The 40-run protected matrix
still reports zero lowering events; broader region ownership and state recovery
remain required. See `VMP_NATIVE_DATAFLOW.md`.

Prefix-string checkpoint: a separate opt-in API compares intact event prefixes
ending at sentinel return or before an unexecuted native-region frontier. Mutation
seed 1 now retains both erased values across four captures, while every execution
remains incomplete at BSWAP16. Scoped protected recovery is 6/18; the existing
completed-run API remains 4/18. All 20 CTest suites, 829 production checks and
7,156 independent instruction-byte/size/successor checks pass. The Qt view retains
the incomplete-execution count and exact original witnesses. See
`VMP_PREFIX_STRINGS.md`. Timeout/fault prefixes, protected ctree publication and
broader review requirements remain incomplete.

Interleaved-read checkpoint: concurrent scoped stream endpoints retain alternating
reads from separate allocations or distinct buffers in one allocation, while
writes/calls/lifetime changes and ambiguous endpoint collisions remain barriers.
Portable image/frame/heap controls pass 384 checks. Native-region Qt and ordinary
ctree consumers retain exact original fragments and use-specific annotations;
487 production checks and all 20 CTest suites pass. See `VMP_INTERLEAVED_READS.md`.
Protected coverage remains 4/18; noncontiguous/write-interleaved algorithms and
broader protected/architecture coverage remain incomplete.

Repeated-visit verification checkpoint: quota tests now check every retained
semantic verdict and distinguish a ninth-visit counterexample despite unchanged
visit/attempt/query counts. Failure diagnostics retain solver results, rejection
reasons, budgets and fixture context. All 20 CTest suites pass, including 362
native-observation and 1,328 transition checks; see `VMP_VISIT_VERDICTS.md`.
The preceding lifecycle checkpoint's two full-suite failures remain unexplained;
this run does not retroactively establish their causes or complete the review.

Native-string lifecycle checkpoint: a saved-database/restart counterexample
reproduced equal numeric tickets validating different captured values. Freshness
requests now require a per-capture opaque lease, and the client also checks its
database identity. Capture/reopen/Qt, malformed/legacy requests, both rebase
modes, exact restoration and failed-recapture controls pass 67 checks; snapshot
and protected regressions add 265. See `VMP_STRING_LIFECYCLE.md` for the identity
assumption, historical counterexample, test outcomes and remaining lifecycle
limits. The full review remains incomplete.

Native use-snapshot checkpoint: the separate native-region projection now also
admits single scalar reads and explicitly bound modeled arguments, preserving
producer identity, argument/model metadata and original bytes. The Qt inspector
distinguishes machine reads from modeled snapshots without inventing data-event
sequences. A new native fixture passes independent positive/negative byte
oracles, 82 console/Qt checks, 183 protected regressions, 24 ordinary regressions
and all 20 CTest suites; see `VMP_USE_SNAPSHOTS.md`. Protected modeled-use coverage,
interleaved algorithms, wider architectures, protected ctree display and full
lifecycle/performance coverage remain incomplete.

Protected read-stream checkpoint: a separate four-run projection now recovers
both erased values from mutation seeds 0 and 12648430, retaining 16 protected
capture/lifetime witnesses. The original also recovers both values; seven
incomplete binaries publish none. An actual Qt view links values, captures and
read/data events under exact snapshot/profile/model freshness. All 239 production
checks and 20 CTest suites pass; see `VMP_REGION_STRINGS.md`. Protected ctree
annotations, interleaved/single-read/modeled-argument region strings, wider
architectures and the full lifecycle/performance matrix remain incomplete.

Modeled native-region checkpoint: an explicit temporal API now binds named ABI
models and retains allocation/use/release observations across owners. A checked
CALL followed by one JMP thunk preserves source and return provenance. Twelve
of 40 paired captures complete with 24 byte-value comparisons; 28 stop at rejected
BSWAP16, including mutation seed 1 after both lifetimes. All 377 production and
ordinary regression checks, 20 CTest suites and 7,156 independently decoded
instruction records pass. See `VMP_REGION_TEMPORAL.md`. Protected consensus/display,
wider architectures, caller objects and logical VM contracts remain incomplete
for rows 3a/3b, 6a/6b and V.

Protected string measurement checkpoint: nine deterministic x64 variants now
pass 30 native process runs against an unchanged byte comparator, with two
independent negative controls. Ten production runs recover 2/2 original literals
and 0/18 protected literals: all 36 protected executions stop at the entry jump
into ownerless code before allocation. See `VMP_PROTECTED_STRINGS.md`. This
measures the first execution bottleneck for rows 0b, 3a/3b and V; it does not
establish protected string recovery or complete those requirements.

Native read-string checkpoint: bounded contiguous scalar-read streams now retain
per-read source, event, object and lifetime witnesses. An independent native
fixture compares all consumed bytes and contains no plaintext literals. Both
erased strings receive exact ctree annotations, while a separate Qt stream table
retains eight witnesses despite generic timeline truncation. All 75 console/GUI/
modeled-regression checks and 20 CTest suites pass; see
`VMP_NATIVE_READ_STRINGS.md`. Protected fixtures, interleaved/noncontiguous read
algorithms, wider architectures and indirect-call display remain for rows 3a/3b.

Protected-corpus checkpoint: exact entry jumps into sectionless executable
segments now seed IDA decoding without changing permissions or forcing function
ownership. Twenty matched runs verify 18/18 protected entry destinations decoded,
with unchanged original inventories; 205 admission/budget controls and 38 native
evidence regression checks pass. See `VMP_DIRECT_JUMP_DECODE.md`. VM dispatch,
complete oracle-edge rates and the remaining requirements above stay incomplete.

VM-path checkpoint: two actual protected read/key-update/dispatch paths now have
bounded graph recognition and complete local normal-completion summaries across
ownerless blocks. All source instructions and spans are retained; modeled noise,
partial aliases, native oracle cases, boundary/freshness controls and GUI inspection
are checked in `VMP_VM_PATHS.md`. A subsequent push/near-return extension adds
one development-seed-one path, retaining target stack writes/reads and an explicit
CET-disabled contract. Independent native execution and actual RAX captures
validate the added local effects; see `VMP_VM_STACK_DISPATCH.md`. Reserved-seed
coverage, concrete VM state and protected execution-transition corroboration
remain incomplete.

ELF32 checkpoint: the independent paired runner executes all nine i386 variants
under QEMU, validates 16,800 behavior records, and records a matched 20-run IDA
inventory. Two local VM prefixes have complete models, including one reserved-seed
push/near-return path, without recognizer changes for this evaluation. Native
stack-transfer records remain unresolved candidates. See `VMP_ELF32_CORPUS.md`;
full protected-edge rates and dynamic VM recovery are still incomplete.

ELF32 get-PC execution checkpoint: a separate static i386 process verifies the
PUSH-next address, preserved defined flags, stack restoration, and six positive
materialization/transfer shapes. It exits 0 under the pinned QEMU image; a
target-result mutation exits 1. Re-running the unchanged IDA fixture with the
current plugin exposes one missing materialization annotation (15/16 assertions)
under both tested IDA versions. See `VMP_GET_PC32_EXECUTION.md`. At that
checkpoint, the annotation regression and other review requirements were open.

PUSH-next block-end repair: IDA marks the immediate PUSH-next entry as a block
end, and the adapter's generic block-end case previously hid its PUSH effect.
Opcode classification now retains the stack instruction. The unchanged ELF32
fixture passes 16/16 under IDA 9.3 and 9.4, the x64 get-PC probe passes 53/53,
and all 21 CTest suites pass. See `VMP_GET_PC32_BLOCK_END.md`. Other block-end
metadata patterns and the full review remain open.

ELF32 rejection execution checkpoint: a second i386 process drives register
and writable-memory PUSH/RET through two different target functions each,
checks both conditional-predecessor paths, and verifies a crafted RET-4 stack
continuation. The exact binary exits 0 under pinned QEMU; a result mutation
exits 1. Production and disabled-plugin IDA runs on that same binary each pass
11/11 assertions. Production retains unresolved candidates without unique
edges for the variable targets, while the matched disabled run has the same
edge sets. See `VMP_GET_PC32_REJECTIONS.md`. Width/far fault paths and the
broader protected-corpus requirements remain open.

Supplied-sample checkpoint: five local binaries are inventoried by exact hash,
format and byte length. The previously inspected `foo` original/protected
candidate pair has three matching no-argument macOS process observations,
each with exit 0, identical 11-byte stdout and empty stderr; scoped elapsed
seconds and peak resident bytes are retained in
`VMP_SUPPLIED_HELLO_EVIDENCE.json`. The static Linux samples lack valid
independent behavior oracles in the tested translators, and the arm64 Hikari
sample remains a separate control candidate. See `VMP_SUPPLIED_SAMPLES.md`.
Fresh IDA profiles on the protected `foo` input show 76 reachable initializer
code heads with direct jump decoding versus one entry code head plus an
unknown target without it, while the zero-filled original main remains
undecodable. The per-profile hashes and limits are in
`VMP_SUPPLIED_HELLO_IDA_EVIDENCE.json`.
Compiler/protector lineage, wider inputs and protected recovery rates remain
unknown.

Morok packed-entry control: the two supplied ELF files match the
user-identified Morok checkout by hash. Plausible source counterparts are
present but their source-to-binary lineage and effective settings remain
unknown. Four matched IDA 9.4 SP1 profiles inspect each entry and its direct
jump target. Enabled and disabled inventories agree exactly (47 and 35 heads
per ELF); the two inspected owners per ELF yield zero native and VM records,
while the solver API is unavailable. See `VMP_MOROK_ENTRY_CONTROL.md` and its
evidence JSON. This is a startup-path control, not a binary-wide specificity or application-recovery
estimate.

Hikari selected-entry control: the supplied arm64 Mach-O has disjoint
2,643-head `_main` and seven-head named-wrapper traversals. Fresh enabled and
disabled IDA databases have identical instruction and owner inventories, zero
native findings at those owners, and unavailable VM/solver APIs. No VMP
recovery denominator or binary-wide specificity estimate uses this control;
see `VMP_HIKARI_ENTRY_CONTROL.md`.

Disjoint heap-write checkpoint: the string aggregator now retains a read stream
across bounded writes to a separate heap allocation while same-allocation,
unknown and malformed writes remain barriers. A native fixture with an
independent result oracle changes from zero recovered strings in the prior
plugin to one four-run `second!` stream and one ctree use annotation; the shared
allocation control remains at zero. Portable controls, two existing console
regressions and all 21 CTest suites pass. See `VMP_HEAP_WRITE_STREAMS.md` and
`VMP_HEAP_WRITE_STREAMS_EVIDENCE.json`. VMP-emitted coverage remains unknown.

Same-object byte-span checkpoint: the next projector revision retains streams
across bounded writes wholly outside their completed observed bytes. On the
same binary, separate/shared allocations change from 1/0 to 2/2 use strings
and ctree annotations; a write overlapping `secret!` retains only `second!`.
Eight paired production profiles, 428 portable interleaved checks, the 23-check
no-write regression, four native process positives, two corrupted-value
negatives and all 21 CTest suites pass. The earlier disjoint-allocation result
above remains historical; see `VMP_SAME_OBJECT_WRITE_STREAMS.md` and its
evidence JSON. Protector-emitted coverage remains unknown.

Multisite heap-read checkpoint: the projector now combines exact reads from
two instruction sites in one allocation generation, with a common exact-site
ctree fallback when the anchor expression is absent. The same x86-64/arm64
binaries move from zero candidates in the archived prior plugin to one
`secret!` candidate in the modified plugin across four/six complete runs.
Both modified profiles show one transient annotation and pass 10/10 checks;
fixed- and variable-order probes and all 21 CTest suites pass. See
`VMP_MULTISITE_READ_STREAMS.md` and its evidence JSON. Protected-sample
coverage and spatially noncontiguous algorithms remain unknown.

Completed spatial-prefix checkpoint for rows 3a and 3b: a NUL-terminated
component followed by a real address gap now survives an incomplete higher
address read in the same allocation. The scan stops admitting components at
the first incomplete spatial span. On matched x86-64/arm64 native fixtures,
the prior plugin reports zero strings and the revised plugin reports both
`secret!` and `second!` with two transient use annotations. The exact
offset-30 `Z` read is visible in both bounded event views. First-incomplete,
middle-incomplete and duplicate-suffix controls bound admission; five prior
native-string probes and all 21 CTest suites pass. See
`VMP_COMPLETED_READ_PREFIX.md` and its evidence JSON. Protected-sample
coverage and proof of later string starts remain open.

Single-read corroboration checkpoint for rows 3a and 3b: direct executed
eight-byte reads previously supplied two visible heap strings from snapshots
alone. The general use-site projector now leaves executed reads to the native
projector, which requires matching memory events and complete data capture.
Matched x86-64/arm64 profiles retain two strings and two transient annotations
while adding 8/12 checked evidence rows; portable forged, missing and
unavailable-data controls abstain. Both prior multi-read profiles and all 21
CTest suites pass. See `VMP_SINGLE_READ_CORROBORATION.md` and its evidence JSON.
Protected-sample coverage and broader lifecycle verification remain open.

Modeled-call provenance checkpoint for rows 3a, 3b and 5: each modeled
argument string now requires the exact named model supplied to the worker, a
reported modeled run and the latest matching dynamic CALL transfer. The
bounded evidence view exposes model bindings, and callee-name changes revoke
strict queries and transient ctree display. On an identical native fixture,
probe and IDA binary, the archived plugin passes 25/27 checks and the revised
plugin passes 27/27; both x86-64 and arm64 executed-read regressions pass
10/10, and all 21 CTest suites pass. See `VMP_MODELED_USE_CONTRACT.md` and its
evidence JSON. Native callee semantics and protected-sample coverage remain
unknown.

Native-region modeled-use contract checkpoint for rows 3a, 3b, 5 and 6a: the
separate completed/prefix region projector now checks each binding's classified
name, the run's model-use flag and the latest observed CALL before each modeled
argument. Ambiguous transfer sequences abstain; completed captures cap edges
at 4,096 per run. Portable mutations and actual-backend edge removal reject
unbound uses. Fresh IDA completed and prefix inspections retain four scoped
observations across four runs and pass 38/38 and 43/43 checks; an interleaved
read-only regression passes 35/35, and all 21 CTest suites pass. See
`VMP_REGION_MODELED_USE_CONTRACT.md` and its evidence JSON. Protected modeled
calls and native callee equivalence remain unknown.

Writable-memory arithmetic checkpoint: exact locally established bytes now
feed modeled x86-64/i386 arithmetic, read-modify-write results and status
flags. Three new transfer targets and two conditions per architecture gain
owned proofs and explicit-root ownerless facts; six initial-byte and alias
controls remain unresolved. Per architecture, 17,150 owned native checks, 225
owned IDA assertions, 4,094 existing ownerless native checks and 892
ownerless IDA assertions pass. Matched prior/current runs isolate the five
new facts, all 21 CTest suites pass, and the selected supplied VMP initializer
still has three unresolved facts. See `VMP_WRITABLE_ALU.md` and its evidence
JSON. Other writable-memory forms and protected effectiveness remain open.

String-move state checkpoint for rows 1b and 2a: decoded plain and repeated `MOVS` preserve
CF, PF, AF, ZF, SF and OF and unaffected registers while invalidating pointer,
repeat-count, stack and memory facts. Per architecture, three new conditions
and two transfer targets are proved; `CMPSB`, a possible memory alias and
the consumed repeat count remain unresolved. The native
oracle's alias destination was corrected from a 4-byte C local to an 8-byte
object after an optimized build exposed counter corruption. Each architecture
passes 19,198 owned native checks, 248 owned IDA assertions, 4,094 existing
ownerless native checks and 972 ownerless IDA assertions. The selected supplied
VMP initializer remains at 75 nodes and three unresolved facts under matched
previous/current plugins. All 21 CTest suites pass. See `VMP_MOVS_FLAGS.md`
and its evidence JSON; broader string operations and protected effectiveness
remain open.

String-store/load state checkpoint for rows 1b and 2a: decoded `STOS` and
`LODS` retain six tracked status bits and unaffected state. Per architecture,
three additional conditions and two targets move from unresolved under the
previous installed plugin to proved under the new build on identical fixtures.
`SCASB` and a possible `STOSB` destination alias remain unresolved. Each
architecture passes 20,990 owned native checks, 269 owned IDA assertions,
4,094 ownerless native checks and 1,042 ownerless IDA assertions; 21 CTest
suites pass. The exact supplied VMP initializer report remains byte-identical
at 75 nodes, 77 edges and three unresolved facts. See
`VMP_STRING_IO_FLAGS.md` and its evidence JSON. Wider element-size process
controls, protected effectiveness and full review coverage remain open.

Native edge-benchmark checkpoint for row V: a frozen source-annotated oracle
identifies 28 fixed and six conditional edges across 31 selected transfer
sites; 15 additional concrete-driver-only sites are separately excluded. The
owned and ownerless x86-64/i386 analyses each recover 26/34 edges with zero
false edges at these sites and five unresolved eligible sites. Owned proof
targets agree with actual IDB user xrefs. The exact report, tool and binary
hashes, wrapper time and peak resident bytes, assumptions, and negative-score
controls are recorded in `VMP_NATIVE_EDGE_BENCHMARK.md` and its evidence JSON.
The archived protected corpus is unavailable for a new protected edge oracle;
full row V remains in progress.

REP MOVS completion-count checkpoint for rows 1b, 2a and V: after normal
completion with natural address size, the repeated move leaves RCX/ECX zero.
A matched prior/current plugin experiment on identical x86-64 and i386
fixture binaries moves one fixed target from unresolved to proved in both
owned and ownerless analyses. The native oracle now varies the count between
zero and one. The selected score rises from 26/34 to 27/34 correct edges with
zero false edges and four unresolved eligible sites per architecture and path;
all other 45 selected site outcomes are unchanged. See
`VMP_REP_MOVS_COUNT.md` and its evidence JSON. The protected benchmark and
broader review requirements remain open.

Exact stack-top store checkpoint for rows 1a, 1b and V: a full machine-word
`MOV` to natural-address-size `[SP]` replaces the tracked top word, whereas
partial and non-exact writes remain conservative. Matched previous/current
plugins on identical x86-64 and i386 binaries move one fixed transfer from
unresolved to proved in both owned and ownerless paths. Native execution,
byte-width mutation, restore, xref and read-only inventory controls pass.
The selected edge score rises from 27/34 to 28/34 with zero false edges and
three unresolved eligible sites per architecture and path. See
`VMP_STACK_TOP_STORES.md` and its evidence JSON. Protected-mode recovery and
the wider review remain open.

String-repeat completion-count checkpoint for rows 1b, 2a and V: normally
completed `REP STOS` and `REP LODS` with natural address size establish zero in
the full RCX/ECX count word. Two variable-count native fixtures move from
unresolved to proved under a matched prior/current plugin comparison on x86-64
and i386, owned and ownerless. All 46 previously selected site outcomes remain
unchanged. The expanded oracle score rises from 28/36 to 30/36, with zero
false edges and three unresolved eligible sites per architecture and path.
Each architecture passes 21,502 owned native checks, 278 owned IDA assertions,
4,094 ownerless native checks and 1,080 ownerless IDA assertions; all 21 CTest
suites pass. See `VMP_STRING_REPEAT_COUNT.md` and its evidence JSON. The
protected benchmark and full review remain open.

Local SCAS flag checkpoint for rows 2a and V: in long mode, ES and DS have
architectural zero bases, so a plain `SCAS` can compare the accumulator with
locally established writable bytes and retain exact subtraction flags. A
matched prior/current plugin comparison proves six byte/word/doubleword/
quadword conditions in owned and ownerless x86-64 analysis; the i386 versions
remain unresolved because a local DS write does not establish ES:[DI]. Initial
memory and zero-or-one-iteration repeat controls also remain unresolved. The
selected transfer-edge score stays at 30/36 with zero false edges. The x86-64
native driver passes 23,294 checks and the i386 driver 23,038; ownerless
drivers each pass 4,094 and reject their corrupted oracle. All 21 CTest suites
pass. See `VMP_SCAS_LOCAL_FLAGS.md` and its evidence JSON. Protected-mode
condition recovery and segment-aware i386 proofs remain open.

Local CMPS flag checkpoint for rows 2a and V: plain long-mode `CMPS` now
compares exact SI/DI addresses. Equal addresses prove comparison flags without
an initial-byte value; distinct addresses require locally established bytes.
Matched signed-plugin runs prove seven more x86-64 conditions in each owned and
ownerless path, with no i386 changes. Initial distinct bytes and repeat-count
ambiguity remain unresolved. Both native drivers pass 25,342 x86-64 and 24,830
i386 checks; ownerless drivers pass 4,094 per architecture and reject the
corrupted oracle. The selected transfer-edge score remains 30/36 with zero
false edges, and all 21 CTest suites pass. See `VMP_CMPS_LOCAL_FLAGS.md` and
its evidence JSON. The full rows remain in progress.

Local STOS memory checkpoint for rows 1b, 2a and V: plain long-mode `STOS`
with an exact mapped DI destination now invalidates only the written bytes and
records a known accumulator value. Three new x86-64 memory-source targets and
four reload conditions become proved in both owned and ownerless analysis;
i386, unknown destinations and repeat controls remain unresolved. With four
new fixed oracle sites, the matched x86-64 edge score rises from 30/40 to
33/40, zero false edges; i386 remains 30/40, zero false edges. The selected
supplied VMP initializer inspection remains byte-identical at 75 nodes, 77
edges and three unresolved facts. All 21 CTest suites pass. See
`VMP_STOS_LOCAL_MEMORY.md` and its evidence JSON. Wider protected coverage and
the full review remain in progress.

Local MOVS memory checkpoint for rows 1b, 2a and V: plain long-mode `MOVS`
with exact mapped SI and DI addresses now captures source bytes before
invalidating the exact destination range. Three new x86-64 memory-source
targets and four reload conditions become proved in both owned and ownerless
analysis; unknown source bytes retain disjoint facts. i386, unknown
destinations, initial source bytes and repeat controls remain unresolved.
With four new fixed oracle sites, the matched x86-64 edge score rises from
33/44 to 36/44, zero false edges; i386 remains 30/44, zero false edges. The
selected supplied VMP initializer remains byte-identical at 75 nodes, 77
edges and three unresolved facts. All 21 CTest suites pass. See
`VMP_MOVS_LOCAL_MEMORY.md` and its evidence JSON. The full review remains in
progress.

Exact REP MOVS local-memory checkpoint for rows 1b, 2a and V: a natural-width
`REP MOVS` with an exact initial zero count bypasses generic destination
invalidation on x86-64 and i386. An exact one count applies one local `MOVS`
copy on x86-64; i386 one-count copying remains unresolved because segment
bases are unknown. Matched previous/current plugins on identical binaries
change four x86-64 captures and two i386 zero-count captures in each analysis
path, with no other selected capture change. A 48-edge source oracle rises
from 38 to 40 correct x86-64 edges and from 30 to 31 correct i386 edges,
with zero false edges. Owned native checks total 33,278 and 31,998; both
ownerless corrupted-oracle controls reject. The selected supplied VMP
initializer remains byte-identical at 75 nodes, 77 edges and three unresolved
facts. All 21 CTest suites pass. See `VMP_REP_MOVS_LOCAL_MEMORY.md` and its
evidence JSON. Wider protected effectiveness and the full review remain in
progress.

Known-count repeated-comparison checkpoint for rows 1b, 2a and V: exact-zero
REPE/REPNE `SCAS` and `CMPS` preserve flags and indexes on both architectures;
exact-one iterations establish a zero count and apply one comparison. Long-mode
local bytes or equal addresses establish four one-count CF/ZF facts, while
i386 comparison flags remain unresolved across unknown DS/ES bases. Matched
previous/current plugins on identical fixtures change eight x86-64 and four
i386 captures per analysis path. The 50-edge oracle rises from 40 to 42
correct x86-64 edges and from 31 to 33 correct i386 edges, with zero false
edges. Both ownerless corrupted-oracle controls reject, and all 21 CTest
suites pass. The selected supplied VMP initializer remains byte-identical at
75 nodes, 77 edges and three unresolved facts. See `VMP_REP_COMPARE_LOCAL.md`
and its evidence JSON. Other widths and protected recovery remain open.

Local LODS load checkpoint for rows 1b, 2a and V: plain long-mode `LODS`
now loads locally established SI bytes into the exact accumulator slice,
preserving unaffected upper bits. Two new x86-64 register-source targets and
five conditions become proved in both owned and ownerless analysis; i386,
initial source bytes and repeat controls remain unresolved. Two new fixed
oracle sites raise the matched x86-64 score from 36/46 to 38/46 correct
edges with zero false edges; i386 remains 30/46. The selected supplied VMP
initializer remains byte-identical at 75 nodes, 77 edges and three unresolved
facts. All 21 CTest suites pass. See `VMP_LODS_LOCAL_LOADS.md` and its evidence
JSON. The full review remains in progress.

Packed-entry candidate checkpoint for rows 0b and 6a: the explicit-root,
read-only `chernobog_native_candidate_region` API conditionally decodes an
unlabeled executable data head without changing IDA's classification. Two
byte-identical fresh protected Morok keygen builds produce identical nine-node,
eleven-edge reports with one unresolved condition and zero proved protected
conditions. The existing-code VMP initializer report remains byte-identical;
x86-64/i386 ownerless regressions and all 21 CTest suites pass. See
`VMP_NATIVE_CANDIDATE_REGION.md` and its evidence JSON. Runtime unpacked bytes,
actual entered edges, ownership and VM semantics remain unmeasured.

Packed-entry Qt checkpoint for row 5: a separate candidate action opens the
existing linked graph view with conditional edge basis, visible unresolved
facts, and API-specific exact recomputation. Two protected keygen GUI runs
produce identical 12-check reports and screenshots without changing the
checked IDB inventory; the ordinary supplied VMP region passes five GUI
checks. The prior ownerless GUI probe fails the same three checks with both
the current and pre-change view in this isolated GUI environment. See
`VMP_NATIVE_CANDIDATE_GUI.md` and its evidence JSON. Menu dispatch and source
navigation, full lifecycle coverage and protected semantic recovery remain
unverified.

Protected hello Qt checkpoint for row 5: a separate shadow call-use action
shows nine planned heads, one conditional CALL edge, two stop frontiers and
the selected 12-byte argument with explicit synthetic provenance. Two fresh
IDA GUI runs with independently captured runtime windows each pass 15 checks;
their screenshots and reports are byte-identical. A byte change and a
during-query file change invalidate the display. The global inventory changes
during an idle Qt event pump before the form opens, then remains stable
through form display and action dispatch; the selected 40-byte region remains
unchanged. See `VMP_HELLO_CALL_USE_GUI.md` and its evidence JSON. Human menu
selection, prompt parsing, other use sites and full lifecycle remain open.

Synthetic packed-entry capture checkpoint for rows 6a and V: a separate
image-only native trace API accepts the explicit Morok data head without
creating an IDA function. Two byte-identical protected builds yield identical
4,096-entry synthetic prefixes over 543 distinct heads before an instruction
budget stop. Independent ELF64/Capstone verification finds zero byte, size or
linear-successor mismatches; the ordinary packed startup control retains its
existing function-trace scope. All 21 CTest suites pass. See
`VMP_NATIVE_CANDIDATE_TRACE.md` and its evidence JSON. The entry state is
synthetic; actual process reachability, completed unpacking, application
behavior and VM semantics remain unknown.

First implementation checkpoint: source changes, executable semantic checks,
and production IDA validation constitute progress. The complete objective is
still active. Validation commands and limits are in `tests/VMP_NATIVE.md`.

Undefined-result BSWAP checkpoint for rows 1b, 2a and V: exact unprefixed
`BSWAP r16` byte encodings now retain a static fallthrough and unaffected
flags while invalidating the entire destination register. Two native
discarded-result flag paths pass 4,606 process checks per architecture;
separate i386/x86-64 IDA controls prove two flag values and leave a
value-dependent predicate unresolved. The supplied VMP initializer retains
75 nodes, 77 edges and three unresolved facts under a fresh 8/8 IDA control.
All 21 CTest suites pass. See
`VMP_BSWAP16_ABSTRACT.md` and its evidence JSON. Concrete protected traces
still stop before BSWAP16; post-frontier VM effects remain unknown.

Status-into-AH checkpoint for row 2a: exact `LAHF`/`SAHF` transfers now retain
independent known bits in AH and SF/ZF/AF/PF/CF, including the constant AH
bits and OF preservation. Portable checks cover 4,096 partial profiles and
256 concrete AH values. Native x86-64/i386 processes pass 37,630/36,350
checks; owned IDA passes 453/386 and ownerless IDA passes 1,730/1,680.
Four new `SETcc` facts per path are proved and an input-dependent carry
remains unresolved; prefixed `LAHF`/`SAHF` remain frontiers. The supplied VMP
initializer remains 75 nodes, 77 edges
and three unresolved facts. All 21 CTest suites pass. See
`VMP_STATUS_AH_FLAGS.md` and its evidence JSON. Protected prevalence,
other status instructions and the full review remain open.

Protected hello return-tail checkpoint for rows 6a and V: an explicit,
read-only caller-state replay now admits an unnamed unloaded executable root
with 1–64 entered instructions and reports unverified checkpoint provenance.
Two fresh IDA runs seeded with synthetic post-call states derived from the
earlier LLVM/Apple `_main` captures each pass 13/13 admission, architectural
effect, byte-mutation and selected-IDB-inventory checks. Both enter three
restored tail instructions and reach the caller return address. A signed
disposable wrapper around the dyld-resolved original `printf` then captures two original and two
protected process return states; all four outputs and exit statuses match
their uninstrumented no-argument controls. The two protected captures seed
two more fresh IDA runs, each passing 11/11 raw-capture, entry-register,
architectural-effect and IDB-inventory checks. After full filesystem access
restored debugger launch, a corrected entry-stub-first capture observes the
noninterposed `printf` return and three tail instructions under both LLVM and
Apple LLDB with ASLR enabled. Two fresh installed-plugin IDA runs each pass
12/12 checks and 72/72 scoped scalar comparisons, including the post-RET state;
the two recorded stack reads and selected IDA inventory agree. Undefined XOR
AF is excluded, and the whole data trace remains incomplete at the external
caller frontier. Complete protected-path replay remains unknown.
See `VMP_HELLO_POSTCALL_CHECKPOINT.md` and its evidence JSON; the full review
remains in progress.

Accumulator-extension checkpoint for rows 1b and 2a: exact `CBW`, `CWDE`,
`CDQE`, `CWD`, `CDQ` and `CQO` now preserve the six status flags and unaffected
state while propagating independently known sign/source bits. Portable tests
cover 6,561 partial byte states and all 65,536 word values per mode. Native
x86-64/i386 oracles check 5,760/3,840 instruction cases across all 64 status
profiles, plus 512 static-control input groups each. Matched byte-identical
prior/new fixtures show eight/six additional condition values and one
stack-mediated target per owned and ownerless path; unknown signs and extra
prefixes abstain. New IDA probes pass 60/50 checks with opcode-patch freshness
controls. The supplied VMP initializer reports remain identical with zero
admitted extension heads and no measured gain. All 21 CTest suites pass.
The current emitter snapshot differs from the review's recorded source hash;
both identities and that limitation are explicit in
`VMP_ACCUMULATOR_EXTENSIONS.md` and its evidence JSON. Wider protected
effectiveness, lifecycle coverage and the full review remain in progress.


Rotate checkpoint for rows 1b and 2a: `ROL`, `ROR`, `RCL` and `RCR`
now transfer 8/16/32/64-bit values and independently known status flags in
32/64-bit execution modes. Unknown carry/count/operand cases preserve the
unaffected flags; exact local memory RMW, AH/CL aliases and long-mode upper
zero extension have production controls. Masked-zero counts retain all flags;
nonzero carry-ring cycles conservatively leave OF unknown. Portable tests
cover 104,976 partial-flag profiles. Executed oracles match 1,294,336 x86-64
and 1,232,896 i386 instruction cases, plus 512 static input groups per binary.
Matched prior/new IDA runs recover 20/19 selected values and one stack target
per owned and ownerless path; current probes pass 128/123 checks, including
opcode-patch freshness. All 21 CTest suites pass. The supplied VMP initializer
reports remain identical with zero rotate heads and no measured protected
gain. Native execution is translated, and the current emitter snapshot is
distinct from the review source. See `VMP_ROTATE_FLAGS.md` and its evidence
JSON. Wider protected effectiveness, the complete lifecycle matrix and the
full review remain in progress.

Multiplication checkpoint for rows 1b and 2a: unsigned full `MUL`, signed
full `IMUL`, two-operand `IMUL` and short/wide immediate forms now preserve
unaffected native state while transferring exact product halves and CF/OF.
Undefined SF/ZF/AF/PF remain unknown. Portable checks cover 131,072 byte
products, 1,350 wider pairs and 5,832 partial-flag profiles; a limb derivation
bounds the 64-bit arithmetic. Actual x86-64/i386 instructions match
769,088/697,088 oracle cases plus 512 static input groups per binary.
Matched prior/current production probes pass 240/195 current checks and
prove 40/31 selected values plus one stack target per owned and ownerless
path. Controls cover all encoding families at each width, immediate sign
extension, source/destination aliases, local memory, pushed stack words,
zero/one unknown-input identities, unsupported prefixes and mutation
freshness. The supplied 75-node VMP initializer contains one MUL, but its
three facts remain unresolved and its prior/current reports are identical.
All 21 CTest suites pass. See `VMP_MULTIPLY_FLAGS.md` and its evidence JSON;
translated execution, broader protected gain, the complete lifecycle matrix
and the full review retain their stated bounds.

Correlated-join checkpoint for row 1b: exact value queries now retry unknown
joins with at most eight alternative states. Overflow joins every state
conservatively; no path is discarded. Three independent register, local
memory and tracked-stack fixtures recover one named destination per owned
and ownerless path on x86-64 and i386, while differing destinations, nine-state
overflow and unestablished writable memory remain unresolved. The same
binaries pass 5,120 executed checks per plugin profile; current production
probes pass 49/49 checks per architecture, including predecessor mutation,
restoration, external-entry invalidation and read-only ownerless inventory.
Portable checks cover 65,536 concrete operand pairs and loop/budget controls.
Existing owned and ownerless corpus regressions and all 21 CTest suites pass.
The historical edge scorer rejects newer fixture pins; a current score from
it is unknown. See `VMP_CORRELATED_JOINS.md` and its evidence JSON. Conditional
target sets, broader protected effectiveness and the full review remain in
progress.

Destination-cover checkpoint for rows 1b and 5: existing native transfer
records now expose sorted destination sets, completeness, unknown inputs,
widening and current supporting bytes. The three historical dynamic stack,
byte-store and full-store fixtures each yield a complete two-member set on
x86-64/i386 and owned/ownerless paths; they remain unresolved scalar targets
and do not publish unique edges. Additional controls cover distinct local
addresses, incomplete sources, aliases, opaque calls, an infeasible member,
nine-state widening, literal mutation, external entries and tail ownership.
The UI shows containing sets and rejects changed snapshots. Same-binary
profiles pass 13,312 native checks each; current probes pass 297/297 checks
per architecture. Existing corpora and all 21 CTest suites pass. See
`VMP_TARGET_COVERS.md` and its evidence JSON. Feasible-member predicates,
current historical edge scores, broader protected gain and full review
completion remain unknown or in progress.

Universal-branch checkpoint for row 1b: a second fixed-point solve now excludes
Jcc successors only from universally decided converged alternative inputs.
Original entries and all original supporting code remain; orphaned refined
nodes are bottom, and provisional loop outcomes do not establish new facts.
Thirty-seven independent fixtures recover exact register/memory/stack targets
on x86-64/i386 and owned/ownerless paths: 148 additional target observations.
Seventeen dynamic controls remain unresolved. Matched profiles pass 41,984
native checks each; current production probes pass 1,056 checks per
architecture. Portable checks enumerate 746,496 condition unions and entry,
cycle, loop and budget controls. Predicate patches, inactive-arm external
entries and instruction-interior entries revoke current proofs; restoration
reestablishes them. Owned graph and prefix admission now reject interior
code entries. Existing corpus regressions and all 21 CTest suites pass.
The preceding `cv_infeasible` two-member set becomes a singleton exact target;
historical evidence remains unchanged. The supplied VMP initializer remains
75 nodes, 77 edges and three unresolved facts. See `VMP_BRANCH_FEASIBILITY.md`
and its evidence JSON. Conditional predicates, whole-program reachability,
broader protected gain and full review completion remain unknown or in progress.
