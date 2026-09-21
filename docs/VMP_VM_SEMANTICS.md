# Local VM dispatch effects and proof-gated reuse

`src/vm/semantics.cpp` now summarizes the admitted local read/decode/dispatch
sequences. `chernobog_vm_summaries(ea)` explicitly builds bounded summaries and
shares a normalized reference only after a fresh UNSAT effect-mismatch query.
The VM workspace exposes the reference, candidate-to-role mapping, ordered
memory accesses, final flags, expressions, comparison result and source validity.
Ordinary navigation polling continues to use `chernobog_vm_regions(ea)` and
does not run the solver.

This extends `VMP_VM_REGIONS.md`. The checkpoint advances requirements 6b–6c
for isolated dispatch sequences. It does not summarize an entire VM handler,
recover a VM entry/context or admit cross-function execution. The full review
ledger remains incomplete. Exact source and execution provenance is recorded
in `VMP_VM_SEMANTICS_EVIDENCE.json`.

## Semantic contract

Inputs are the architecture's general-purpose registers and a symbolic
byte-addressed memory array. Register names are mapped bijectively to VIP,
decoded value, decoder key when present, dispatch base when present, SP and
the remaining preserved registers. Addresses and arithmetic use 32- or 64-bit
modular bitvectors. Memory is flat and little-endian. The instruction sequence
must remain unchanged while executing; every modeled data access succeeds.
Concurrent mutation, devices, nonzero segment bases, exceptions, traps and
execution of the target instruction are outside this normal-completion model.
In particular, code-overlapping writes that change later instructions do not
satisfy its unchanged-instruction-stream precondition.

The evaluator re-recognizes the complete support sequence before building a
summary; caller-supplied role claims are not trusted. It models byte/dword
loads, pointer advance, supported scalar decoder transforms, key feedback,
x64 sign extension and final table/register dispatch. Eight-bit writes retain
the rest of a GPR; x64 dword writes clear the upper half. The x64 dword key
idiom preserves the high key bits through the full push, low-dword read/modify/
write and full pop. SP is restored, but the written stack bytes remain effects.
The portable summarizer rejects unavailable x86-32 low-byte register forms.

Every read and write retains its order, width, address and value. A symbolic
array is updated byte by byte, so bytecode/stack aliasing and partial overlaps
are not replaced by independent memory symbols. The result includes all GPRs,
the final memory array and the computed next PC. It does not enumerate concrete
dispatch targets or imply that those targets belong to an admitted VM region.

Final CF/PF/AF/ZF/SF/OF values are modeled with explicit definedness. XOR leaves
AF undefined; arithmetic operations define the corresponding final flags.
The admitted grammar always ends with a pointer/base arithmetic operation or
key feedback that determines the observable final arithmetic flags. Rotations'
intermediate flag states are deliberately discarded because no admitted
instruction consumes them and the required later operation overwrites them.
This does not model flags at an intermediate fault or instruction boundary.
The evaluator rejects a result if the final required flag definitions are absent.

## Equivalence and actual reference reuse

For two summaries in one Z3 context, the comparison constructs:

```text
mismatch := different next PC OR different final memory
for each role-mapped GPR: mismatch |= different final value
for each architecturally defined output flag: mismatch |= different value
for each ordered data access: mismatch |= different address OR different value
check(mismatch)
```

Architecture, role availability, access count/kind/width and defined-flag
contracts must agree before this query is eligible. An incompatible contract
does not become an equality proof. UNSAT permits reference reuse under the
stated model; SAT reports a modeled effect counterexample; UNKNOWN or a solver
exception prevents reuse. The query has a 100 ms timeout and resource limit
200,000. Resource exhaustion is tested as an actual UNKNOWN result with a
nonempty diagnostic, not merely an arbitrary rejection.

`src/vm/summary_view.cpp` retains one expression reference and bindings from
each successfully proved equivalent candidate to that reference. This is
actual deduplication of the inspection's semantic representation. It is not
an execution cache or a bytecode-lifting transformation. No structural hash or
normalized-syntax equality can bypass the query. Distinct syntax can share a
reference when all modeled effects agree; equal-looking expressions with a
changed flag or memory-access contract cannot.

The production fixture contains four disconnected local candidates in an
explicitly declared test function: an original sequence, a register-renamed
clone, an extra `xor 0` transform and an altered decode constant. The first
three share one reference after two UNSAT checks. The last gets a separate
reference after SAT. The real query observer records these three checks with
phase `vm-local-summary` and exact originating source addresses. Array-bearing
formulas can exceed the earlier transcript serializer's supported sort budget;
an omitted transcript is not presented as a complete replayable formula.

## Bounds, cost and freshness

Explicit summary inspection handles at most 16 of the recognized candidates
and makes at most 32 comparison attempts. Contract-incompatible attempts can
return before any SMT check, so the API reports attempts separately from the
actual solver transcript. The 128-instruction recognition limit still applies.
Summary omissions include recognized candidates beyond the 64-candidate
inspection cap, within the scanned prefix; an exhausted instruction scan
cannot count its unseen suffix.

Each reference retains at most 32,768 bytes of key/value text. Individual
expressions retain at most 2,048 bytes and carry completeness markers; a
512-tree-occurrence/depth-64 serialization guard can omit them entirely.
Expression rendering materializes the accepted Z3 string before truncation;
these limits are not total temporary or process-memory bounds. Expression
omission does not truncate the internal semantic comparison. The UI reports
binding omissions and retains diagnostic omission counts in reference detail.

For L admitted instructions, the evaluator constructs O(L) symbolic DAG nodes
with fixed architectural widths and a constant bound on memory-access widths.
There are at most K=16 retained summaries and Q=32 comparison attempts. These
bounds limit construction and query count, not SMT complexity. Worst-case wall
time, temporary solver memory and GUI latency remain unmeasured. The 100 ms
timeout applies to each solver check, not decoding, expression construction,
serialization or total UI work.

Opening or explicitly reloading the workspace obtains the summary snapshot.
Polling only recomputes local candidate recognition. A reused summary displays
`sources_current` only when both its candidate and its reference still exactly
match recomputed rows in the same database/function. Invalidating the reference
therefore does not borrow freshness from an unchanged candidate. Navigation to
that candidate can remain available independently. Restored bytes can restore
the local source correspondence under the same semantic contract; no claim of
current concrete VM state follows. Full unload/reopen/multi-database lifecycle
coverage and semantic-model version migration remain outstanding.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| M1 | The re-recognized scalar instruction vocabulary implements the modeled normal-completion effects. Summary validity depends on this. | Execute independent x64 assembly and compare registers, final defined flags, SP, retained stack bytes and the reached target. Portable controls also cover both modes and the full transform vocabulary. Wider ISA/environment contracts remain outside scope. |
| M2 | Instructions remain unchanged and all data accesses succeed in flat little-endian memory. | Retain all reads/writes and test stack/bytecode aliasing. Do not use the summary for intermediate faults, self-modifying instruction streams, devices, concurrency or segment-base effects. Those conditions are not proved from a candidate. |
| M3 | The register-role correspondence is bijective and includes the unmodified frame. Reuse depends on this. | Prove renamed candidates, compare changed role contracts, re-derive forged role fields, reject unsupported effects, and compare every mapped GPR. |
| M4 | UNSAT is required for reuse; syntax is not proof. | Prove the extra-XOR-zero variant, retain a changed-decode SAT counterexample, inject flag/access-address mismatches and exercise actual resource-limited UNKNOWN. |
| M5 | Undefined flags cannot be borrowed from a stronger contract. | Compare definedness masks before solving; XOR AF is excluded only when both sides agree it is undefined. Captured native flags are checked only where the architecture defines the result. |
| M6 | Reused expressions depend on both retained source records. | Patch the reference while leaving the selected candidate intact; summary source validity must fail while candidate navigation remains available. Polling must leave solver transcripts unchanged. |
| M7 | Finite oracle cases validate exercised behavior, not exhaustive architectural or protected-corpus coverage. | Record the fixed corner inputs, deterministic PRNG seed, executable and capture hashes. x86 semantics have portable/IDA tests but no executed x86-32 oracle at this checkpoint. |

## Verification and reproduction

`tests/vm_semantics_tests.cpp` checks the symbolic engine and comparison logic.
It includes both modes, both directions, keyed/unkeyed forms, all scalar
transform operations, rotation count boundaries, retained stack effects, data
aliasing, flags, counterexamples, exact UNKNOWN rejection and quota behavior.
`tests/vmp_native/vm_semantics_oracle.c` plus its assembly companion execute
416 x64 cases: 160 corner cases and 256 seeded cases, covering keyed table and
relative dispatch in both directions. The PRNG initial state is
`0xd1b54a32d192ed03` and its update is explicit in the source.

The capture executes the actual indirect jump. It reads the written stack word
before flag capture can overwrite it. Harness setup/capture is outside the
summarized instruction interval. The symbolic check constrains the observed
data-read contents and compares the captured outputs; it does not claim a
complete native memory snapshot. This x86-64 executable ran on an arm64 macOS
host through its x86-64 compatibility path, not on physical x86 hardware. The
oracle is independent of Z3 and of Chernobog's evaluator.
The executable captures the active role registers and SP; the remaining GPR
frame is checked symbolically rather than exhaustively sampled by this oracle.
The executed decoder uses XOR, rotate-left and addition; other supported
transforms receive portable mathematical controls at this checkpoint.

Build the oracle with local SDK selection and run it to produce
`build/vm-semantics-native-final.txt`, then:

```sh
cmake --build build -j 2
ctest --test-dir build --output-on-failure
build/chernobog_vm_semantics_tests build/vm-semantics-native-final.txt
python3 -B tests/run_ida_smoke.py build/vmp-vm-regions \
  tests/ida_vm_regions_probe.py --ida "$IDA_TERMINAL" --plugin "$PLUGIN" \
  --output-dir build/vm-summary-terminal \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py"
```

The oracle compilation uses `-arch x86_64 -O2 -g0` and the macOS SDK. The
existing dispatcher fixtures now include the four-candidate reuse group;
their earlier manifest hashes remain historical. Use the ELF32 input for
x86 inspection and the GUI executable with `QT_QPA_PLATFORM=offscreen` for
real Qt checks. Rax stays disabled for these summary probes. Exact final check
counts, hashes and regression results are recorded in the checkpoint manifest.

Final validation passes 15/15 CTest targets, 4,220 portable semantic checks and
416 executed x64 oracle cases (18,158 assertions when the oracle checks are
included). The single CTest run reports 8.81 s, not a performance comparison.
Production IDA passes 72 x64 terminal, 72 x86 terminal and 83 x64 GUI checks,
plus 28 SMT, 47 native-proof and 31 lifetime GUI regression checks: 227 local
candidate/summary checks and 106 regressions. Each production reuse group
retains two references for four candidates after UNSAT, UNSAT and SAT results.

## Bounded expansion and quality gates

| Impact | Finding | Consequence |
|---|---|---|
| High | Zero net SP change can retain architecturally observable stack writes. | Compare ordered accesses and final memory, not only GPR/PC outputs. |
| High | One shared native address or equivalent decoded value does not define full local effects. | Include role-mapped frame, final flags, memory and transition result. |
| Medium | Different syntax can have identical normal-completion effects. | A proved reference can serve multiple candidates without relying on shape hashes. |
| Medium | A reference can become stale independently of its user. | Track both source rows and keep candidate navigation separate from summary validity. |

QG1: technical modeling without a normative premise. QG2: assumptions and
falsification probes are listed. QG3: bounded local effects/reuse are implemented;
full review and full-handler semantics are not claimed. QG4: bit widths, bytes,
milliseconds and finite case counts are explicit. QG5: memory/flag/exception,
execution, coverage and lifecycle limits remain explicit. QG6: production source,
independent oracle and real IDA artifacts are hashed. QG7: bounded adjacent
findings are listed. Protected-corpus recovery gains remain unknown.
