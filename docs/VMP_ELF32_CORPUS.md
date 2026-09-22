# Paired ELF32 corpus and independent execution

The paired runner now covers i386 ELF in addition to x64 Mach-O. Nine ELF32
variants span mutation, virtualization and combined protection at three recorded
protector seeds. All 30 original/protected executions pass 16,800 independent
result, selected-memory, stack-delta and defined-flag comparisons. All nine
repeated protection runs produce identical bytes. Exact source, tool, image and
artifact identities are in [VMP_ELF32_CORPUS_EVIDENCE.json](VMP_ELF32_CORPUS_EVIDENCE.json).

This extends review requirements 0b and V and supplies real protected x86-32
inputs for the existing analysis. It does not complete the benchmark's recovery
metrics, broader string/CFG fixtures or source-build attestation.

## Execution and oracle

[pair32.S](../tests/vmp_corpus/pair32.S) implements the two independent arithmetic
functions using the i386 calling convention. A separate wrapper passes three
stack arguments, captures EFLAGS immediately after return, records the 32-bit
unsigned result, and measures SP relative to the expected post-call argument
position. Caller bookkeeping occurs after flag capture. The surrounding C
driver retains the same input sequence and adjacent memory sentinels as the
[x64 corpus](VMP_PAIRED_CORPUS.md).

The reference computes each result with Python integer masking. It derives the
six defined arithmetic flags from the final 32-bit ADD, verifies the changed
word and both surrounding sentinels, and requires zero stack delta. Records
must have the expected identity, inputs, cardinality and ordering; matching two
incorrect binaries does not satisfy the reference check.

Each input seed supplies 6³ = 216 corner tuples and 64 seeded tuples. Thus:

```text
records/run = (216 + 64) tuples × 2 functions = 560 records
runs = (1 original + 3 modes × 3 protector seeds) × 3 input seeds = 30
records = 560 × 30 = 16,800
```

The measured unique count is 816 function/input tuples per binary. Repeated
corner tuples across input seeds are not counted as independent unique inputs.
All 1680 original-binary records also equal the earlier x64 original records
byte for byte. Together, the two architecture corpora retain 33,600 primary
behavior records across 18 protected variants. These counts exclude discovery,
smoke, and repeated final-validation runs.

The i386 programs execute through `qemu-i386` in a Linux arm64 container. This
is an independent execution engine from Chernobog/RAX, not execution on physical
x86 hardware. QEMU's [user-space emulator documentation](https://www.qemu.org/docs/master/user/main.html)
describes this cross-architecture process model. The image is resolved once to
its immutable content ID; compiler, linker, emulator, runtime loader and libc
hashes and package versions are retained. The Dockerfile records the build
recipe, while the image ID identifies the environment actually used. Future
package updates can change a rebuilt image and must be recorded anew.

Only the supplied macOS protector and the existing test-only seed interposition
run on the host. The protector accepts ELF32 directly; `vmp/core/core.cc:547–548`
selects among PE, Mach-O and ELF loaders, and `core/elffile.cc` implements the ELF
format. No license data is read. Packing is requested off with the same project,
VM and procedure options as the x64 corpus; implicit license-dependent flags and
exact source-to-console build equivalence remain unknown.

## Runner and rejection boundaries

`--architecture i386` selects the ELF32 compiler/execution adapter and requires
an explicit prebuilt image. The existing x64 default remains supported; a fresh
Mach-O smoke pair passes after the change. Both formats use the same independent
behavior oracle, selected-entry transformation checks, seed attestation,
repeated-generation checks and final source/artifact integrity checks.

ELF admission verifies little-endian ELF32/i386 header and table bounds, one
initialized executable `.text` section, and its consistent executable PT_LOAD
file mapping. Wrong architecture, malformed names/tables, duplicate text,
non-file-backed data and inconsistent load mappings reject. Extended section
numbering and other ELF classes are outside this benchmark parser's scope.
The structures follow the [ELF header specification](https://gabi.xinuos.com/elf/02-eheader.html).
This is a fixture inventory parser, not a general ELF loader.

With file size B bytes, S section headers, P program headers and maximum scanned
section-name suffix L bytes, parsing costs O(B + S·(L + P)) time and O(B + S)
space. S and P are each capped at 4096. The file read and section-name data still
scale with input size; no constant-memory claim is made.

Each guest container has networking disabled, read-only source and root
filesystems, a bounded temporary filesystem, and a dedicated output mount.
Commands use the recorded image ID rather than resolving a mutable tag again.
Guest execution has a 10 s process limit and 2 MiB combined output limit.
The host launcher has its own timeout. A killed Docker client triggers removal
of only that invocation's uniquely named container; it is not treated as proof
that the guest stopped. All invocation containers had exited after validation.

Guest reports must match the executed binary, stdout and all three runtime
identities. Missing or changed runtime identities reject. Ten harness tests
cover these controls, container cleanup, field/identity corruption, process
limits and both file formats. All 18 configured CTest suites pass in 11.19 s.

## Measured analysis result

Twenty matched IDA runs inspect the ten ELF32 binaries with direct-entry
decoding disabled/enabled, while RAX execution stays disabled. The final corpus
rebuild produced the same ten binary hashes as the analysis input set; the
evidence manifest explicitly records that join. No plugin or recognizer source
was changed during this ELF32 evaluation.

| Artifact | Native candidate records | VM candidate prefixes |
|---|---:|---:|
| Original | 0 | 0 |
| Mutation, each of three seeds | 0 | 0 |
| Virtualization, seed 0 | 1 | 0 |
| Virtualization, seed 1 | 1 | 0 |
| Virtualization, reserved seed | 2 | 0 |
| Combined, seed 0 | 2 | 0 |
| Combined, seed 1 | 0 | 1 |
| Combined, reserved seed | 2 | 1 |

The native records are unresolved stack-transfer candidates, not proven target
edges. Both VM candidates obtain complete local normal-completion model
references in separate summary inspections. Seed one has a 20-instruction
indirect-JMP path with one data read. The reserved-seed candidate has a
17-instruction push/near-return path with three ordered accesses: bytecode read,
target push and return read. Its shadow-stack assumption remains explicit.
These are selected local prefixes, not complete handlers or protected runtime
transition corroboration. The reserved protector seed was evaluated without
tuning the recognizer to its result.

All enabled/disabled inventories are identical, with zero entry-decoder attempts
and no reported inventory truncation. The ELF loader already exposes these entry
paths. The earlier Mach-O sectionless-entry improvement therefore cannot be
generalized into an ELF recovery-rate gain. Inspection preserves the recorded
code/xref inventory in every run. Complete oracle-edge denominators, false-edge
rates, literal accuracy and whole-function coverage remain unknown.

## Resource observations and reproduction

Guest measurements use Linux `wait4` on the QEMU process. They include emulator
and guest process resources. Docker-client timing/memory is recorded separately
under `launcher` and is not substituted for guest measurements. Linux peak RSS
values are converted from KiB to bytes by multiplication by 1024; elapsed
nanoseconds convert to seconds by multiplication by 10⁻⁹.

| Runs | Wrapper elapsed range (s) | Peak resident byte range |
|---|---:|---:|
| Original, 3 | 0.022–0.025 | 18,620,416–18,808,832 |
| Mutation, 9 | 0.022–0.025 | 18,657,280–18,784,256 |
| Virtualization, 9 | 0.026–0.049 | 19,275,776–19,361,792 |
| Combined, 9 | 0.044–0.065 | 19,300,352–19,365,888 |

Displayed seconds are rounded to 0.001 s. The wrapper polls every 0.020 s and
includes launch/wait overhead and scheduler delays; these observations do not
establish sub-poll timing precision or physical-x86 performance. Raw measurements
are retained. No speedup claim is derived from this small corpus.

```sh
docker --context orbstack build -f tests/vmp_corpus/linux32.Dockerfile \
  -t chernobog-vmp-linux32:test tests/vmp_corpus
python3 -B tests/run_vmp_corpus.py \
  --protector '<protector-console>' --source-tree '<vmp-source-tree>' \
  --output-dir build/vmp-elf32-new --architecture i386 \
  --linux32-image chernobog-vmp-linux32:test --docker-context orbstack
```

Use an available Docker context and substitute the two local input references.
The output directory must be new. Run `tests/run_vmp_analysis.py` against the
resulting validated manifest; summary inspections use
`CHERNOBOG_CORPUS_VM_SUMMARIES=1` with `tests/ida_vmp_corpus_probe.py`.

## Assumption register and bounded expansion

| ID | Assumption / dependent conclusion | Stress test or falsification probe |
|---|---|---|
| E1 | The recorded protector artifacts belong to the intended source family. Source-specific interpretation depends on this. | Hash source/console/SDK, record settings and emitted bytes, attest seeds and repeat protection. Exact source-build equivalence remains unknown. |
| E2 | QEMU and the i386 capture wrapper represent the tested ISA/ABI behavior. Executed oracle conclusions depend on this. | Independent Python result/flags/memory oracle, sentinels, SP delta and x64 cross-check; physical-x86 execution remains a separate validation opportunity. |
| E3 | Each report belongs to the requested binary, input seed and runtime. | Verify complete ordered input/output records, binary/stdout/runtime hashes and unchanged artifacts; corrupt fields and omit identities to require rejection. |
| E4 | IDA metadata describes the current static prefixes. Candidate conclusions depend on this. | Match binary/plugin/probe hashes, preserve code/xrefs and report truncation; local models do not establish dynamic state or full handler semantics. |
| E5 | These arithmetic functions and seeds are a limited benchmark. | Keep reserved seeds, zero-candidate profiles and unresolved native records; add distinct CFG/string/alias cases before claiming broad recovery rates. |

High impact: the same protector's loader metadata differs across binary formats,
changing the analysis starting point. Medium impact: cross-architecture ABI
capture can invalidate a comparison even when arithmetic is unchanged; verify
the wrappers independently. Medium impact: client resource measurements do not
describe a guest process; retain their accounting scopes separately.

QG1: technical scope. QG2: E1–E5 register dependencies and falsification probes.
QG3: the x86-32 paired execution and analysis extension is covered; full review
completion remains unproven. QG4: exact counts, conversions, complexity and
timing limits are explicit. QG5: candidates, local models and runtime behavior
are separate claims. QG6: primary format/emulator references and exact local
artifact hashes are retained. QG7: loader-state, ABI and accounting risks are bounded.
