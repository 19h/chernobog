# Bounded native-region capture

`chernobog_vm_trace(ea, seed)` now captures native execution across ownerless
code and existing IDA function boundaries in a separately identified region.
It executes admitted CALL/PUSH/RET instructions in the emulator, preserving
their actual modeled stack accesses. It does not merge functions, publish
ordinary function evidence, infer a VM identity, or prove a handler summary.

This advances the execution-scope limitation measured in
`VMP_REGION_BOUNDARIES.md`. The accepted paired matrix contains 120 captures:
72 virtualization/combined entry captures reach beyond the initial call and
pass independent stack-prefix checks. The other 48 captures stop on unresolved
input memory. Those failures are retained, not counted as recovered behavior.

## Production integration

- [native_region.hpp](../src/vm/native_region.hpp) and
  [native_region.cpp](../src/vm/native_region.cpp) define an immutable native
  instruction allowlist, independent of `FuncRange` ownership. Planning follows
  syntactic direct targets, conditional alternatives and possible call
  continuations. It does not enumerate indirect destinations or establish
  path feasibility. Existing foreign functions and shared native code can be
  included without altering their IDA owners.
- [emu_driver.cpp](../src/hybrid/emu_driver.cpp) exposes a distinct
  `emulate_region` entry point. Ordinary `emulate_from` retains its function
  boundary. Region entry requires the current image/generation identity,
  strict permissions and an empty event sink. Before each admitted instruction,
  its exact current emulator bytes and size must match the immutable plan.
  A changed instruction stops capture before it executes.
- [ida_native_trace.cpp](../src/vm/ida_native_trace.cpp) takes a fresh selected
  function/image snapshot and returns an ephemeral JSON capture. Instruction
  planning uses IDA's mode-aware native decoder, checking decoded bytes against
  the snapshot. Native register samples, ordered memory accesses, native edges,
  entered instruction records, final written bytes and explicit stop reasons
  are retained. IDB ownership is observational metadata.
- [evidence.cpp](../src/hybrid/evidence.cpp) rejects an entire attempted ordinary
  evidence publication if any input run has native-region scope. Region outcomes
  also cannot establish the driver's ordinary function-level conclusions.
  Known environment/callee summaries are disabled for these captures.

The capture has its own database identifier, monotonic capture number, region
label, image hash, generation field and seed. The region label and existing
image hashes are noncryptographic identifiers, not equivalence proofs. There
is no persistent region cache or freshness claim for a JSON response retained
after the database changes. This API does not publish into `TargetEvidence` or
the existing VM-role observation join.

`data_trace_complete` describes observed data accesses within the captured
native prefix. It does not establish a complete function, all paths, a complete
memory state, a virtual-stack identity, or a VM-context identity. An instruction
entry record is not proof that the instruction retired successfully; faults
and environment failures retain their separate outcomes.

## Decoder defect found during validation

The initial i386 capture exposed a disagreement between the linked stateless
RAX decoder and execution. For example, `4a 33 da` was reported as one 3-byte
instruction, while 32-bit execution advanced by 1 byte after DEC EDX; the next
instruction is XOR EBX,EDX. The stateless API's `oracle_options` selects its
x86-64 oracle regardless of the requested x86 mode
(`vendor/rax/capi/src/decode.rs`). The execution engine's legacy prefix decoder
correctly distinguishes INC/DEC from REX prefixes.

The first purportedly accepted i386 matrix is therefore **rejected as final
decode evidence**, despite its original harness pass. A subsequent independent
check finds 18 captured size disagreements and 18 unexpected linear successors
in those archived captures. The original harness checked byte identity but
did not independently check instruction partitioning; the strengthened probe
now checks linear progression as well.

Production native-region planning now supplies IDA's decoder, and runtime
capture uses that plan's instruction sizes and control-flow classes. The pure
planner requires a supplied mode-aware decoder for x86-32; it will not silently
fall back to the linked x86-64 oracle. A dedicated legacy INC/DEC execution
control covers this interface through the driver's hooks. The upstream RAX
stateless decoder itself is unchanged; its remaining 16/32-bit applicability
outside this new region path is a separate limitation.

Capstone 5.0.7 independently checks all **5,325 entered instruction records**
in the final matrix. Their bytes match the file-backed corpus inputs and their
sizes match the independent decode. There are zero size, byte or linear-successor
disagreements. The reproducible verifier is
[verify_vm_native_region_decode.py](../tests/verify_vm_native_region_decode.py).
Its red control against the rejected i386 matrix retains the exact 18 failures.

The native planner also stops before 16-bit BSWAP encodings. Intel specifies
their architectural result as undefined in the BSWAP entry of
[Software Developer's Manual, Volume 2A](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).
The local reference is `vendor/rax/docs/specifications/x86_64/bswap.txt`.
A deterministic emulator result is not treated as a portable hardware result.
The independent decoder identifies all 30 such final-matrix boundary instances.

## Accepted corpus measurements

Each architecture uses the original plus nine protected artifacts from
`VMP_PAIRED_CORPUS.md` and `VMP_ELF32_CORPUS.md`. Protection seeds remain 0, 1
and 12,648,430. Each of the two selected functions receives three deterministic
entry-state seeds with those same numeric values; entry seeds and protection
seeds are separate variables. No settings were changed using the reserved seed.

| Observation, summed per capture | x86-64 Mach-O | i386 ELF |
|---|---:|---:|
| IDA processes / native captures | 10 / 60 | 10 / 60 |
| Production checks | 560 | 560 |
| Entered instruction records | 3,354 | 1,971 |
| Retained memory accesses | 813 | 483 |
| Complete data prefixes | 36 | 36 |
| Independent PUSH/CALL prefix cases | 36 | 36 |
| Stops at an unenumerated indirect jump | 9 | 3 |
| Stops at an unenumerated RET destination | 15 | 15 |
| Stops before 16-bit BSWAP | 12 | 18 |
| Input/environment failures | 24 | 24 |
| Plan or data quotas reached | 0 | 0 |

The virtualization/combined prefixes contain 13–129 entered instructions in
x64 and 4–88 in i386. The largest plans contain 221 and 124 instructions
respectively. These are prefix observations, not whole-program coverage or
semantic recovery rates. None reaches the entry return sentinel in this matrix.

The original and mutation cases use the generic seeded ABI environment. Their
pointer argument does not identify the independent corpus harness's initialized
buffer, so they stop on unresolved memory. The independent paired executable
behavior oracle remains the earlier corpus evidence; these 48 failed captures
do not supersede it or demonstrate behavior preservation. Explicit initialized
input objects remain necessary for a complete native-region behavior benchmark.

For each matching entry prefix, the probe independently decodes its emitted
immediate and rel32 CALL displacement. With entry stack pointer S and native
pointer width W bytes, it requires:

```text
PUSH write: address = S - W; width = W;
            value = sign_extend_32(immediate) modulo 2^(8W)
CALL write: address = S - 2W; width = W; value = call_address + 5
callee entry: native SP = S - 2W
```

Here W is exactly 8 bytes in x64 and 4 bytes in i386. These checks retain the
actual write sites, values, widths and callee state. They establish this native
prefix contract, not that the pushed immediate is a recovered virtual PC or key.

Whole-image byte/mask, item/xref, segment-mode/permission and function/chunk
inventories remain identical before and after capture. The ordinary evidence
publication remains identical. The probe disables automatic analysis during
measurement after normal native analysis has settled. No IDB repairs, new code
items, function tails or persistent VM ownership are produced by capture.

## Controls, quotas and reproduction

The hybrid regression suite exercises both architectures' ownerless/direct-call
paths, sign extension, return-address values, native SP, balanced returns,
ordinary function-boundary preservation, separate publication rejection,
baseline restoration, stale image/generation rejection, permission/mode/loading
boundaries, indirect-call stops, runtime code changes, occupied sinks and zero
execution budgets. The fixture-only portable decoder does not claim general
x86-32 decoder coverage; the production and independent decoder matrix supplies
that scoped evidence for the captured instructions.

All **19 CTest suites pass** (`build/vmp-native-region-mode-ctest.log`, 11.02 s
for this execution). A separate disabled-backend IDA process passes two controls:
capture is unavailable and the ordinary publication remains unchanged. Together
the final production probes contain **1,122 checks**.

Planning admits at most 4,096 heads. The IDC capture requests at most 4,096
native instructions and a 250 ms backend timeout, snapshots at most 64 MiB,
and retains at most 4,096 records in each execution/data/state stream and
65,536 final written bytes. The lower-level region API clamps larger requests
to 65,536 instructions and 1,000 ms. These are backend timeout requests, not
hard real-time bounds on snapshotting or an individual emulator operation.
Caller-supplied zero run budgets reject before execution. Process probes have
a separate 180 s timeout.

For image bytes B, segments S, planned heads H and executed steps T, the core's
snapshot hashing, segment lookup and ordered instruction lookup are bounded
by O(B + H·(S + log H) + T·(S + log H)), excluding decoder/backend internals and
separately bounded data serialization. Space is O(B + H + T) with bounded native
register width and record quotas. The full inventory probe caps 1,048,576 item
heads, 2,097,152 xrefs, 4,096 functions and 64 MiB of mapped segment extent.

The final architecture matrices ran concurrently. Summed runner durations were
34.280675958 s and 53.078591417 s; peak reported resident sizes were 278,773,760
bytes and 177,061,888 bytes. These include startup, inventory and serialization
and establish no isolated tracing speedup or statistical performance estimate.

```sh
python3 -B tests/run_vmp_native_regions.py \
  --corpus-report build/vmp-corpus-release/corpus.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/native-region-reproduction-x64

python3 -B tests/run_vmp_native_regions.py \
  --corpus-report build/vmp-elf32-release/corpus.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/native-region-reproduction-x86

python3 -B tests/verify_vm_native_region_decode.py \
  --report build/native-region-reproduction-x86/native_regions_analysis.json \
  --corpus-report build/vmp-elf32-release/corpus.json \
  --output build/native-region-reproduction-x86/decode_verification.json
```

Accepted artifacts are `build/vmp-native-region-mode-x64` and
`build/vmp-native-region-mode-x86`. `VMP_NATIVE_REGION_CAPTURE_EVIDENCE.json`
records their hashes, source/plugin/IDA identities, decoder references,
disabled-backend evidence, and the rejected decoder experiment. The supplied
packed hello-world remains separate; no unpacking or protector-build attestation
is claimed.

## Assumptions and completion limits

| ID | Assumption / dependent claim | Stress test or falsification probe | Status |
|---|---|---|---|
| N1 | Archived corpus artifacts identify the measured protection/configuration family | Binary, corpus, plugin, IDA and source hashes must match before/after runs. Exact source-build attestation remains unknown | Retained |
| N2 | Mode-aware planned instruction boundaries agree with executed native progression | INC/DEC control, all linear successors, Capstone decode and file-byte checks. The initial stateless-RAX assumption failed on 18 records and was replaced | Revised and checked for captured records |
| N3 | RAX's modeled CPU, flat native memory and seeded stack/environment define these observations | Independent prefix arithmetic, indirect/changed-code/permission controls; 16-bit BSWAP stops. General hardware equivalence, CET-enabled behavior and complete handler effects remain unproved | Retained |
| N4 | A capture is observational and separate from function evidence | Complete bounded inventories and ordinary publication comparisons; mixed-scope builder rejection; stale plan and disabled-backend controls | Checked in stated scope |
| N5 | Hash labels identify snapshots but do not prove semantic equivalence or persistent freshness | Exact bytes gate each instruction; retained JSON is historical after a database change. No region reuse or state merging is authorized | Retained |

- **High impact:** typed input objects are required to progress beyond the 48
  input-memory failures and compare completed native behavior with the paired oracle.
- **High impact:** observed indirect/RET destinations and register/stack samples
  now provide concrete starting evidence for bounded VM-state/handler association.
  They do not prove unique targets or justify cross-run state merging.
- **High impact:** the upstream stateless x86 decoder still ignores 16/32-bit mode
  outside this new path. Other consumers need a separate applicability audit.
- **Medium impact:** undefined-width BSWAP requires either a justified target-CPU
  contract or a proof that its result cannot affect the modeled computation.

QG1 requires no normative content; QG2 is the reconciled assumption register.
QG3 covers this native-region implementation and its stated observations, while
the complete review remains open. QG4 is supported by explicit widths, units,
quotas and reproducible calculations. QG5 includes the rejected decoder result,
negative controls and separate failed-input outcomes. QG6 uses hashed source,
SDK, reference and capture evidence. QG7 is the bounded expansion above.
Logical VM context/virtual-stack recovery, complete memory identity, validated
handler transitions, persistent lifecycle and full behavioral recovery remain
incomplete in `VMP_IMPLEMENTATION.md`.
