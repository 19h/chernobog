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
| 0b. Independent paired corpus; provenance, seeds, held-out seeds, native oracle | Nine variants per architecture now cover x64 Mach-O and x86 ELF, with repeated deterministic generation, reserved seeds and 33,600 primary behavior records. ELF32 executes under independent QEMU translation; see `VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. The packed hello-world remains separate. Broader fixture shapes, source-build attestation and recovery metrics remain | In progress |
| 1a. Portable stack-transfer classification with widths, stack effects, dependencies | `classify_push_return`, 32/64-bit core controls, x64 and linked ELF32 IDA fixtures; matched ELF32 rejected-case baseline. Dedicated 32-bit stack/get-PC execution controls and wider paired cases remain; see `VMP_GET_PC.md` | In progress |
| 1b. Exact register and memory target recovery; unknown candidates preserved | Bounded local replay, immutable-memory dependencies, and persisted ownership receipts implemented. Separate-process save/reopen, both tested rebase modes, Jcc undo/redo, and stack-pointer replacement controls pass; see `NATIVE_PROOF_OWNERSHIP.md`. Cross-block analysis, complete topology coverage, and legacy/plugin-absent metadata attribution remain | In progress |
| 1c. Push-based get-PC forms and call-as-jump summaries | Both source-emitted forms, stack replay, return-address provenance/effects, and owned native facts implemented (`VMP_GET_PC.md`). RET lowering now preserves the POP; 1,792 scoped IR-effect comparisons and six entry/region guards pass (`VMP_MICROCODE.md`). Automatic region ownership, stale inferred noreturn repair, structural rollback, and the full lifecycle/corpus matrix remain | In progress |
| 2a. Per-flag abstract interpretation and complete condition evaluation | `x86_abstract.h`, production `x86_analysis.cpp`; exhaustive 8-bit arithmetic, defined shift flags, 729 partial flag profiles, width/alias controls. Further corpus coverage remains | In progress |
| 2b. Native CFG integration and SETcc/CMOV value/microcode consumers | Native Jcc edges and SETcc/CMOV value facts implemented. Persisted ownership, Jcc rebase/undo, and reopened value-fact invalidation controls pass. Consumers pass 12,288 independent x86/x64 effect comparisons and 192 read-fault checks (`VMP_CMOV_MEMORY.md`). Forty matched protected-corpus runs now measure zero lowering events: ten x64 condition sites are ownerless and three owned i386 sites remain unchanged (`VMP_CONDITION_CORPUS.md`). Protected region/state coverage, effectiveness and complete microcode lifecycle coverage remain | In progress |
| 3a. Bounded use-site snapshots, allocation generations, contexts, temporal ordering | Integrated bounded lifetime ledger, first-fit reuse, executed-read and modeled-argument snapshots. Erase/reuse, address changes, pre-write RMW, overlap, invalid free/use and cap controls pass. Contiguous native read-stream aggregation now joins original reads under lifetime and memory-order checks (`VMP_NATIVE_READ_STRINGS.md`). Wider architecture/protected corpus and interleaved read algorithms remain; see also `VMP_TEMPORAL_STRINGS.md` | In progress |
| 3b. Cross-run semantic-use consensus and ctree display | Address/generation-independent matching, strict corpus/duplicate/lifetime checks, current IDC API, and transient direct-call annotations implemented. Exact native pointer/index-expression annotations and a linked read-stream table now retain original source witnesses; console and actual Qt controls validate freshness and navigation (`VMP_NATIVE_READ_STRINGS.md`). Indirect-call display, wider lifecycle matrix and protected fixtures remain; see also `VMP_TEMPORAL_STRINGS.md` | In progress |
| 3c. Separate byte/word string transform recognition and encoding validation | Typed finite-index symbolic proof and independent UTF-8/UTF-16 validation; transient exact-shape/byte-checked ctree annotations. x64 Mach-O and x86 ELF each pass 51 production checks; byte-encrypted UTF-16 retains byte units. Source-routine identity is not inferred from an identical formula. Protected corpus, broader loop shapes, dynamic provenance, and full lifecycle matrix remain; see `VMP_ROTATING_STRINGS.md` | In progress |
| 4a. Representative microcode corpus and categorized canonicalization failures | Ten independent x64 native routines captured at four real SDK maturities with a matched disabled baseline. A late identity under zero-extension exposed a nested-recognition/order miss, now fixed. Width, stack-definition and full/partial-alias controls are categorized; source-emitted protected and wider architecture corpora remain. See `VMP_MBA_CANONICALIZATION.md` | In progress |
| 4b. Typed transformations and rejection controls in production | Actual microcode instance proofs gate catalog, chain and optional affine proposals before mutation. Typed counterexamples, unsupported effects, distinct frame owners and solver exhaustion reject. Native and independent captured-IR result/memory oracles pass; wider operations, flags/exception contracts and corpus remain. See `VMP_MBA_CANONICALIZATION.md` | In progress |
| 5. Linked CFG, lifetime timeline, proof detail with live provenance | Bounded JSON/Qt workspace links edges, lifetimes, run stops and native proofs. Actual scoped SMT checks now expose formulas, SAT assignments, UNSAT exclusions and UNKNOWN reasons; independent replay validates recorded counterexamples. Query navigation guards do not assert current IR applicability. Protected counterexamples, full quota/lifecycle coverage and performance measurements remain; see `VMP_EVIDENCE_VIEW.md`, `VMP_NATIVE_EVIDENCE_VIEW.md` and `VMP_SOLVER_EVIDENCE_VIEW.md` | In progress |
| 6a. Separate bounded VM-region and logical-state model | Separate `src/vm` descriptors and logical-state comparison; local recognition supports role permutations, both directions, clones, table/relative dispatch and stateful decoding. Boundary auditing distinguishes side entries and shared/foreign ownership (`VMP_REGION_BOUNDARIES.md`). A separate native-region capture API now executes bounded prefixes across existing owners with exact-byte admission and no ordinary function publication; 120 paired captures include 72 checked PUSH/CALL prefixes, and an independent decoder verifies 5,325 entered instruction records (`VMP_NATIVE_REGION_CAPTURE.md`). Virtual stack, VM context, complete memory identity, logical VM ownership and persistent lifecycle remain unresolved; see also `VMP_VM_REGIONS.md` and `VMP_VM_OBSERVATIONS.md` | In progress |
| 6b. Candidate recognition, visualization, and validated semantic summaries | Candidate inspection includes local normal-completion register/flag/memory/dispatch summaries. A symbolic array retains data aliasing and ordered stack writes; independent executed x64 oracle cases and x86/x64 IDA probes validate admitted scaffolds. Complete captured table/relative/boundary transitions now receive nonvacuous SMT checks, linked to their exact visit and query identities. Full-handler effects, VM input-state recovery, exceptions and admitted VM-region transitions remain; see `VMP_VM_SEMANTICS.md` and `VMP_VM_TRANSITIONS.md` | In progress |
| 6c. Proven normalized-summary reuse | Local modeled-effect references are shared only after UNSAT under a bijective register-role map; SAT, UNKNOWN and incompatible access/flag contracts prevent reuse. Production clone and distinct-syntax controls pass. Whole-handler summaries, cross-region ownership and persistent execution-cache reuse remain; see `VMP_VM_SEMANTICS.md` | In progress |
| V. Complete benchmark and completion audit | Paired x64 and x86 result/selected-memory/stack/defined-flag checks and scoped process elapsed time/peak bytes are recorded in `VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. Recovery/error/abstention rates, literal accuracy, solver diagnostics, broader fixtures and full completion audit remain | In progress |

The review explicitly treats full bytecode lifting as a subsequent project;
this ledger retains the requested separate VM model, recognition, and validated
semantic summaries without claiming that they constitute full devirtualization.
Packing, licensing, anti-debugging, and .NET IL execution are excluded by the
review. Unsupported execution modes and unproved transformations retain explicit
abstentions; they cannot be counted as successful recovery.

Quality gates are applied to each completed change and again to the complete
objective. Neither baseline test success nor this ledger proves completion.

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

First implementation checkpoint: source changes, executable semantic checks,
and production IDA validation constitute progress. The complete objective is
still active. Validation commands and limits are in `tests/VMP_NATIVE.md`.
