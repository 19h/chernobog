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
| 0b. Independent paired corpus; provenance, seeds, held-out seeds, native oracle | Nine variants per architecture cover x64 Mach-O and x86 ELF, with repeated deterministic generation, reserved seeds and 33,600 primary behavior records. ELF32 executes under independent QEMU translation; see `VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. The supplied packed hello-world pair now has three matched no-argument process observations (`VMP_SUPPLIED_SAMPLES.md`), separate from the generated matrix. Broader fixture shapes, source-build attestation, protected edge oracles and recovery metrics remain | In progress |
| 1a. Portable stack-transfer classification with widths, stack effects, dependencies | `classify_push_return`, 32/64-bit core controls, x64 and linked ELF32 IDA fixtures; matched ELF32 rejected-case baseline. A separate i386 ELF32 process checks get-PC/stack positive shapes and a negative result control under pinned QEMU (`VMP_GET_PC32_EXECUTION.md`). A second same-binary process/IDA control checks dynamic register/memory targets, alternate entry, and RET adjustment (`VMP_GET_PC32_REJECTIONS.md`). The IDA block-end regression is repaired (`VMP_GET_PC32_BLOCK_END.md`); wider paired, width/far, and exceptional execution controls remain | In progress |
| 1b. Exact register and memory target recovery; unknown candidates preserved | Bounded local replay, immutable-memory dependencies, and persisted ownership receipts implemented. Separate-process save/reopen, both tested rebase modes, Jcc undo/redo, and stack-pointer replacement controls pass; see `NATIVE_PROOF_OWNERSHIP.md`. Bounded owned-function joins and loop fixed points now support register targets (`VMP_NATIVE_DATAFLOW.md`). A same-binary i386 oracle reaches two register and two writable-memory targets while production IDA retains both as unresolved candidates (`VMP_GET_PC32_REJECTIONS.md`). Larger/ownerless regions, complete topology coverage, and legacy/plugin-absent metadata attribution remain | In progress |
| 1c. Push-based get-PC forms and call-as-jump summaries | Both source-emitted forms, stack replay, return-address provenance/effects, and owned native facts implemented (`VMP_GET_PC.md`). The 32-bit PUSH-next proof survives IDA's block-end metadata (`VMP_GET_PC32_BLOCK_END.md`). RET lowering preserves the POP; 1,792 scoped IR-effect comparisons and six entry/region guards pass (`VMP_MICROCODE.md`). Automatic region ownership, stale inferred noreturn repair, structural rollback, and the full lifecycle/corpus matrix remain | In progress |
| 2a. Per-flag abstract interpretation and complete condition evaluation | `x86_abstract.h`, production `x86_analysis.cpp`; exhaustive 8-bit arithmetic, defined shift flags, 729 partial flag profiles, width/alias controls. Owned-function direct CFG joins and loop fixed points are integrated (`VMP_NATIVE_DATAFLOW.md`); larger/ownerless graphs and protected effectiveness remain | In progress |
| 2b. Native CFG integration and SETcc/CMOV value/microcode consumers | Native Jcc edges and SETcc/CMOV value facts implemented. Persisted ownership, Jcc rebase/undo, and reopened value-fact invalidation controls pass. Consumers pass 12,288 independent x86/x64 effect comparisons and 192 read-fault checks (`VMP_CMOV_MEMORY.md`). Forty matched protected-corpus runs now measure zero lowering events: ten x64 condition sites are ownerless and three owned i386 sites remain unchanged (`VMP_CONDITION_CORPUS.md`). Protected region/state coverage, effectiveness and complete microcode lifecycle coverage remain | In progress |
| 3a. Bounded use-site snapshots, allocation generations, contexts, temporal ordering | Integrated bounded lifetime ledger, first-fit reuse, executed-read and modeled-argument snapshots. Erase/reuse, address changes, pre-write RMW, overlap, invalid free/use and cap controls pass. Contiguous-address streams preserve separate read-only interleavings under lifetime and memory-order checks (`VMP_INTERLEAVED_READS.md`). Wider architecture/protected corpus, noncontiguous and write-interleaved algorithms remain; see also `VMP_TEMPORAL_STRINGS.md` | In progress |
| 3b. Cross-run semantic-use consensus and ctree display | Address/generation-independent matching, strict corpus/duplicate/lifetime checks, current IDC API, and transient direct-call annotations implemented. Exact native pointer/index-expression annotations and a linked read-stream table now retain original source witnesses; console and actual Qt controls validate freshness and navigation (`VMP_NATIVE_READ_STRINGS.md`). Indirect-call display, wider lifecycle matrix and protected fixtures remain; see also `VMP_TEMPORAL_STRINGS.md` | In progress |
| 3c. Separate byte/word string transform recognition and encoding validation | Typed finite-index symbolic proof and independent UTF-8/UTF-16 validation; transient exact-shape/byte-checked ctree annotations. x64 Mach-O and x86 ELF each pass 51 production checks; byte-encrypted UTF-16 retains byte units. Source-routine identity is not inferred from an identical formula. Protected corpus, broader loop shapes, dynamic provenance, and full lifecycle matrix remain; see `VMP_ROTATING_STRINGS.md` | In progress |
| 4a. Representative microcode corpus and categorized canonicalization failures | Ten independent x64 native routines captured at four real SDK maturities with a matched disabled baseline. A late identity under zero-extension exposed a nested-recognition/order miss, now fixed. Width, stack-definition and full/partial-alias controls are categorized; source-emitted protected and wider architecture corpora remain. See `VMP_MBA_CANONICALIZATION.md` | In progress |
| 4b. Typed transformations and rejection controls in production | Actual microcode instance proofs gate catalog, chain and optional affine proposals before mutation. Typed counterexamples, unsupported effects, distinct frame owners and solver exhaustion reject. Native and independent captured-IR result/memory oracles pass; wider operations, flags/exception contracts and corpus remain. See `VMP_MBA_CANONICALIZATION.md` | In progress |
| 5. Linked CFG, lifetime timeline, proof detail with live provenance | Bounded JSON/Qt workspace links edges, lifetimes, run stops and native proofs. Actual scoped SMT checks now expose formulas, SAT assignments, UNSAT exclusions and UNKNOWN reasons; independent replay validates recorded counterexamples. Query navigation guards do not assert current IR applicability. Protected counterexamples, full quota/lifecycle coverage and performance measurements remain; see `VMP_EVIDENCE_VIEW.md`, `VMP_NATIVE_EVIDENCE_VIEW.md` and `VMP_SOLVER_EVIDENCE_VIEW.md` | In progress |
| 6a. Separate bounded VM-region and logical-state model | Separate `src/vm` descriptors and logical-state comparison; local recognition supports role permutations, both directions, clones, table/relative dispatch and stateful decoding. Boundary auditing distinguishes side entries and shared/foreign ownership (`VMP_REGION_BOUNDARIES.md`). A separate native-region capture API now executes bounded prefixes across existing owners with exact-byte admission and no ordinary function publication; 120 paired captures include 72 checked PUSH/CALL prefixes, and an independent decoder verifies 5,325 entered instruction records (`VMP_NATIVE_REGION_CAPTURE.md`). Virtual stack, VM context, complete memory identity, logical VM ownership and persistent lifecycle remain unresolved; see also `VMP_VM_REGIONS.md` and `VMP_VM_OBSERVATIONS.md` | In progress |
| 6b. Candidate recognition, visualization, and validated semantic summaries | Candidate inspection includes local normal-completion register/flag/memory/dispatch summaries. A symbolic array retains data aliasing and ordered stack writes; independent executed x64 oracle cases and x86/x64 IDA probes validate admitted scaffolds. Complete captured table/relative/boundary transitions now receive nonvacuous SMT checks, linked to their exact visit and query identities. Full-handler effects, VM input-state recovery, exceptions and admitted VM-region transitions remain; see `VMP_VM_SEMANTICS.md` and `VMP_VM_TRANSITIONS.md` | In progress |
| 6c. Proven normalized-summary reuse | Local modeled-effect references are shared only after UNSAT under a bijective register-role map; SAT, UNKNOWN and incompatible access/flag contracts prevent reuse. Production clone and distinct-syntax controls pass. Whole-handler summaries, cross-region ownership and persistent execution-cache reuse remain; see `VMP_VM_SEMANTICS.md` | In progress |
| V. Complete benchmark and completion audit | Paired x64 and x86 result/selected-memory/stack/defined-flag checks and scoped process elapsed time/peak bytes are recorded in `VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. The supplied hello-world pair adds exact process output/exit comparisons and scoped elapsed/peak measurements (`VMP_SUPPLIED_SAMPLES.md`). Recovery/error/abstention rates, literal accuracy, solver diagnostics, broader fixtures and full completion audit remain | In progress |

The review explicitly treats full bytecode lifting as a subsequent project;
this ledger retains the requested separate VM model, recognition, and validated
semantic summaries without claiming that they constitute full devirtualization.
Packing, licensing, anti-debugging, and .NET IL execution are excluded by the
review. Unsupported execution modes and unproved transformations retain explicit
abstentions; they cannot be counted as successful recovery.

Quality gates are applied to each completed change and again to the complete
objective. Neither baseline test success nor this ledger proves completion.

Ownerless native graph checkpoint: an explicit-root read-only inspector now
propagates register, flag and stack facts across existing decoded ownerless
branches and loops, with architectural successors, entry auditing and visible
frontiers. Across x64/i386, 6,140 native checks and 620 IDA assertions pass;
90 Qt assertions and all 21 CTest suites pass. A frozen protected development
measurement proves 0/5 bounded condition sites, with one graph rejected at the
64-node cap and zero microcode-lowering gain. Ordinary CFG publication, complete
predecessor discovery and broader review requirements remain incomplete. See
`VMP_OWNERLESS_DATAFLOW.md`.

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

First implementation checkpoint: source changes, executable semantic checks,
and production IDA validation constitute progress. The complete objective is
still active. Validation commands and limits are in `tests/VMP_NATIVE.md`.
