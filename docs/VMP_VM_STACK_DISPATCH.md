# VM dispatch through PUSH and near RET

Chernobog now recognizes a third protected read/decode/dispatch path in the
paired corpus: the 25-instruction `corpus_branch` prefix in `virtualization-1`.
The path updates a relative dispatch base, pushes it, and executes a near RET.
The previous path recognizer accepted only indirect JMP termination.

This implements another local-summary case from review requirements 6a–6c and
its evidence consumers. It does not complete the review or establish whole-VM
recovery. Source/artifact hashes and final measurements are in
[VMP_VM_STACK_DISPATCH_EVIDENCE.json](VMP_VM_STACK_DISPATCH_EVIDENCE.json).

The supplied tree's `core/intel.cc:16360–16370` explicitly emits `push operand;
ret` for selected non-immediate near jumps. Its read/key-feedback and relative
dispatch constructions are at lines 27795–27855. The observed binary supports
this particular mapping; exact source-to-protector-build equivalence remains
unknown, as recorded in [VMP_PAIRED_CORPUS.md](VMP_PAIRED_CORPUS.md).

## Implemented contract

Both 32-bit and 64-bit address modes admit native-width target pushes followed
by a zero-adjustment near return. The push operand can be the already-recognized
relative dispatch register or indexed table-memory operand. Recognition uses a
temporary jump-shaped projection for structural matching, then retains the full
original instruction sequence for symbolic evaluation. The dispatch address is
the RET address. Direct links and modeled flag operations may separate the push
and return, subject to the existing single-entry path rules and budgets.

For address width w bits, n = w/8 bytes, entry stack pointer S, and resolved
target T, the modeled suffix is:

```text
T := evaluate target operand using the state before the push
S := (S - n) mod 2^w
write n little-endian target bytes at S
next_pc := read n little-endian bytes at S
S := (S + n) mod 2^w
```

Final SP equals entry SP. The target bytes remain in memory at the decremented
stack address; table dispatch also retains its earlier target-memory read. All
existing modeled GPR and defined arithmetic-flag effects remain observable.
Symbolic arrays preserve data aliasing, including overlap with previous key
feedback. This representation has two more accesses than indirect JMP dispatch,
so the two forms cannot share a full-effect summary merely because their target
and final SP agree.

This follows the native-stack behavior described in Intel's
[RET instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).
The normal-completion model additionally assumes CET shadow stacks are disabled.
Enabled shadow stacks add a return-address comparison and separate stack effects;
see Intel's [shadow-stack description](https://edc.intel.com/content/www/us/en/design/ipla/software-development-platforms/client/platforms/alder-lake-desktop/12th-generation-intel-core-processors-datasheet-volume-1-of-2/005/shadow-stack/).
The assumption appears in both local-summary and captured-transition contracts.

Far returns, RET-immediate encodings (including immediate zero), mismatched
stack widths, unsupported prefixes, missing target pushes and alternate entries
reject. Instructions supplied after the terminal return also reject. There is
no instruction-byte rewrite, function merge, target execution authorization or
new VM-region ownership. Faults, device/concurrent memory, segment-base effects
and self-modified instruction streams remain outside the model.

The candidate JSON adds `transfer_kind`, distinguishing `push/near-return` from
`indirect jump`, while `dispatch_kind` still describes relative-register versus
indexed-table target calculation. The GUI retains both provenance and the
explicit contract. Existing syntax normalization now records return stack width;
semantic reuse still requires UNSAT under the full effect comparison.

The structural projection adds O(P) time and space for a path of P instructions.
The overall bounded recognizer remains O(P²) because it checks instruction-span
overlap. Existing traversal, path, candidate and solver budgets are unchanged.
This is not a bound on unconstrained SMT solving.

## Measured coverage and validation

The new protected candidate reads at `0x10007d6f5`, dispatches at `0x10003c909`,
and uses RBP as VIP, R9 as value, R8 as key and R11 as dispatch base. Its seven
ordered data accesses comprise the bytecode read; key push; 32-bit key-feedback
read/write; key pop; target push; return read. Every supporting instruction and
byte remains recorded, including native jumps to lower addresses.

Across the same 20 enabled/disabled corpus runs, candidate counts change from
two to three. `virtualization-0` retains two candidates; `virtualization-1` adds
one. The original, mutation variants, combined variants and reserved protector
seed retain zero. Inputs, IDA executable and analysis-option digests are matched
against the prior checkpoint. This is recognition of selected prefixes, not
whole-handler coverage or an oracle-edge/false-edge rate. The new sample is a
development seed; it does not establish held-out generalization.

Portable controls cover both address widths, both bytecode directions,
keyed/unkeyed and table/relative forms. An all-input SMT comparison establishes
the expected final registers/flags/target and exactly the additional target
stack bytes, with arbitrary data aliasing. Register-renamed and discontiguous
forms compare equivalent; direct-JMP and push/RET access contracts differ.
Width, immediate adjustment, absent push, far return, alternate entry and
post-return effects are rejected. Independent transition fixtures corrupt every
output GPR and defined flag, access provenance and target-stack consistency.

The independent assembly oracle executed 416 cases: four scenarios, each with
8 encoded-value corners × 5 key corners plus 64 seeded cases. Of these, 208 use
table-memory pushes and 208 use relative-register pushes with modeled noise.
The execution used x64 compatibility translation on the arm64 host. It captures
VIP/value/key/base/SP, defined flags, retained stack bytes and reached target;
it does not capture every preserved GPR or execution of the protected VM.

Actual RAX captures from the independent fixture corroborate 20 local
transitions per primary probe: 12 repeated table visits, four table dispatches
stopped at a function boundary, and four relative dispatches. Each uses SAT
input consistency followed by UNSAT output mismatch. The target push and return
read are recorded directly; the relative case retains seven accesses. The
boundary remains an execution stop after successful local corroboration.

The production matrix includes the real protected candidate in terminal and
GUI IDA, explicit x86/x64 positive and rejection fixtures, captured-transition
terminal/GUI tests, existing x86/x64 region regressions and the previous real
seed-zero paths. Both GUI screenshots were visually inspected. All 18 CTest
suites pass in 10.51 s, including 347 region, 4676 semantic, 89 observation and
1328 transition checks. The native-data checker performs 20,279 assertions
including its portable controls. Production IDA passes 395 checks: 67 protected
terminal, 71 protected GUI, 35 captured-transition terminal, 42 captured-transition
GUI, 72 x64-region, 72 x86-region and 36 seed-zero path checks. Exact artifact
hashes and per-process measurements are recorded in the evidence manifest;
elapsed time is an observation, not a latency or speedup claim.

Reproduce the independent native check:

```sh
xcrun clang -arch x86_64 -O2 -DCHERNOBOG_VM_PATH_ORACLE=1 \
  -DCHERNOBOG_VM_STACK_ORACLE=1 tests/vmp_native/vm_semantics_oracle.c \
  tests/vmp_native/vm_semantics_oracle.S -o build/vmp-stack-native
build/vmp-stack-native > build/vmp-stack-native.txt
build/chernobog_vm_semantics_tests build/vmp-stack-native.txt --path-stack
```

Run `tests/ida_vm_stack_dispatch_probe.py` against `virtualization-1` through
`tests/run_ida_smoke.py`, using the recorded corpus entries and companion module.
Compile `tests/vmp_native/vm_observations.S` with
`CHERNOBOG_VM_STACK_ORACLE=1` for the independent transition fixture, then run
`tests/ida_vm_transitions_probe.py` with RAX explicitly enabled and
`CHERNOBOG_VM_STACK_DISPATCH=1`. The default fixture/probe mode continues to test
indirect JMP. Full corpus inventory uses `tests/run_vmp_analysis.py`.

## Assumption register and bounded expansion

| ID | Assumption / dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | Current bytes, mode and single-entry path describe the local code. Recognition depends on this. | Patch RET to far RET, restore bytes, add/remove an incoming edge to RET, compare all source spans; unsupported prefixes and widths reject. |
| S2 | Flat little-endian normal completion, unchanged instruction bytes and disabled CET shadow stacks describe the modeled domain. Summary equivalence and transition corroboration depend on this. | Preserve ordered accesses and arbitrary data aliasing; native oracle checks retained target bytes; never infer exception or shadow-stack behavior from these tests. |
| S3 | Captured data accesses and registers correspond to the actual visit. Transition checks depend on this. | Require complete traces, SAT inputs, exact access sites/order/widths and all output GPRs/defined flags; inconsistent and consistently wrong target-stack data reject. |
| S4 | Protector artifacts correspond to the intended source family. Vendor-specific interpretation depends on this. | Record source/binary hashes and paired behavior; exact source-build attestation remains unknown. |
| S5 | Development-seed recognition is a limited capability result. | Preserve all zero-candidate profiles and the reserved-seed result; require separate oracle coverage before extrapolation. |

High impact: equal final SP and target do not imply equal memory effects.
High impact: a return's native stack and CET shadow stack are separate modeled
domains. Medium impact: treating the preceding PUSH as the dispatch site breaks
observed-transition provenance; the RET instruction owns the actual transfer.
Remaining work includes other interleaved operations, protected runtime state
and transitions, reserved-seed coverage, x86 protected execution and the broader
review ledger. Full bytecode lifting remains the review's subsequent project.

QG1: technical implementation. QG2: S1–S5 have falsification probes. QG3: this
dispatch extension is integrated across recognition, semantics, observations
and display; full-review completion remains unproven. QG4: width/byte equations,
modular arithmetic, counts and resource units are explicit. QG5: recognition,
local equivalence and observed execution remain separate claims. QG6: local
source/artifact hashes and primary architectural references are retained.
QG7: memory observability, shadow-stack scope and transfer provenance are bounded.
