# Near RET imm16 stack-transfer metadata

This change admits a full-width `PUSH operand; RET imm16` pair as a bounded
stack-transfer fact in x86-32 and x86-64. A nonzero adjustment produces a
current, inspectable target proof when the operand value is established, but
the plugin publishes no jump reference for that pair. The input bytes and
IDA's native stack analysis remain unchanged. The previous zero-adjustment
edge path remains available.

## Architectural calculation and admission

The Intel instruction reference defines `C2 iw` as a near return with an
unsigned 16-bit stack-byte release after the return-address pop:
[Intel 64 and IA-32 SDM, Volume 2, RET](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf).
For initial stack pointer `S`, pushed word width `w = mode_bits / 8` bytes,
and encoded adjustment `u` bytes, the successful pair has:

1. `PUSH`: write `w` bytes at `[S-w, S)` and set `SP = S-w`.
2. Near `RET`: read the target at `S-w`; pop `w` bytes; release `u` bytes.
3. Final `SP = S+u`; net delta `+u` bytes; retained write offset `-w` bytes.

Thus the 64-bit fixture (`w=8`, `u=8`) has `+8` byte net delta and an
8-byte retained write at offset `-8`; the 32-bit fixture (`w=4`, `u=4`) has
`+4` byte net delta and a 4-byte retained write at offset `-4`. The classifier
rejects adjustments above `65,535` bytes. The IDA adapter requires an exact
three-byte `C2 iw` encoding and agreement between those bytes and IDA's
decoded immediate. Far returns, width mismatches and alternate entry into
the return remain rejected.

## Observed controls

The installed, signed plugin used for the first six fresh IDA 9.4 controls
in the table below had
SHA-256 `992a685a19cabb62e640585347f60f91b591c784e01f0c34cc633d00f11dad5e`.
`ctest --test-dir build --output-on-failure -j 20` passed 23/23 suites.
After commit `5049c460`, `make install -j 20` installed a signed plugin with
SHA-256 `053227360d8215069e676acbfff8935b249cb8fb87232e64765b966535c174e9`.
Five new isolated runs under `build/vmp-stack-ret-postcommit-*` and
`build/vmp-get-pc32-ret-postcommit-smoke` repeated the 64-bit, 32-bit,
native-evidence, lifecycle and ownerless probes successfully. The recorded
first six rows below identify the precommit artifacts rather than conflating
their hashes with the installed revision.
The separate x86-64 process-fixture IDA run used the signed plugin from commit
`0bde4c95`, SHA-256
`e0bbfa98c29a2f70208c44f1816c37360028123802a6dc8a33617b5c6671f146`.

| Control | Fresh run directory | Result |
| --- | --- | --- |
| x86-64 stack fixture, SHA-256 `0c0765b6d4c6baaebf0312cd11b8ba54080bdd05f5a23961f529b49ced8301a2` | `build/vmp-stack-ret-final-smoke` | 12/12 cases; `vt_adjust` reports exact target, `+8` byte delta and no jump edge |
| x86-32 ELF fixture, SHA-256 `9e2452212adb306096a7951de8923219f43be33ba4b6e5d70f2f20e89cdb33df` | `build/vmp-get-pc32-ret-final-smoke` | 16/16 checks; `gp32_extra` reports exact target and `+4` byte delta; no user jump reference |
| Native evidence inspection | `build/vmp-stack-ret-final-evidence-2` | 37/37 checks; `vt_adjust` is fresh, has target `0x100000410`, delta `8`, write offset `-8`, write width `8`, and `edge=false` |
| Live proof lifecycle | `build/vmp-stack-ret-final-lifecycle` | 20/20 checks; changing a plain `RET` to `RET 8` synchronously revokes the owned jump; restoration republishes the plain-return proof |
| Read-only ownerless region | `build/vmp-stack-ret-final-ownerless` | 6/6 checks; after removing the function owner, the bounded graph records the same target, `+8` byte delta, `-8` byte write offset and no database mutation during inspection |
| Matched executed ELF32, SHA-256 `dcb4f45c1a01e1d952b6717ebc4134af5f23e7714d33253143858a654c9520ea` | `build/vmp-get-pc32-rejections-ret-{enabled,baseline}` | 11/11 checks in each run; identical edge sets; only the enabled run annotates the adjusted transfer, with no user jump reference |
| Executed x86-64 Mach-O, SHA-256 `a50bf8f7a17d13502b1da651e0c97d96695a81f1318ea71c12d5a0b350c119c6` | `build/vmp-ret-adjust-runtime-ida` | Process exits 0; same-binary IDA probe passes 7/7 checks for the `+8` byte fact, retained 8-byte write, separate target owner and no plugin jump |

The 32-bit IDA database also contains an IDA-generated jump reference at
`gp32_extra`. Its `xref.user` flag is false. The test distinguishes that
reference from a plugin-owned user reference, so it does not attribute IDA's
edge to this change. The 64-bit adjusted case has no jump reference at all.
The standalone 64-bit executable runs only the three unadjusted positive
transfers. The separate ELF32 fixture exercises `push target; ret $4` with a
continuation and stack marker. The exact binary above exits 0 under the pinned
QEMU i386 image; its result-mutated control exits 1. This repeats the process
oracle documented in [VMP_GET_PC32_REJECTIONS.md](VMP_GET_PC32_REJECTIONS.md)
and binds the current static metadata run to that input hash. No full
instruction-state capture of the adjusted pair is asserted.

The subsequent x86-64 process fixture
`tests/vmp_native/ret_adjust_runtime.S` has SHA-256
`f2facb7fce82f8d6a2e23fd932f15238e74d02426d666ac48a96a1b71e1e662c`.
Its matching IDA probe `tests/ida_ret_adjust_runtime_probe.py` has SHA-256
`36306e0cca8bd245607996a4ff650dff1936358cad61703f133fe87d1b8d4faf`.
For stack pointer `S` before its marker setup, it places a marker at `S-8`,
continuation at `S-16`, CALL return at `S-24`, and pushed target at `S-32`.
`RET 8` transfers to the target with `SP=S-16`; the target's `RET` reaches
the continuation with `SP=S-8`, and consuming the marker restores `SP=S`.
The continuation checks the marker, target result, final pointer, retained
target word at `S-32`, and RFLAGS captured before the pair and at the target.
The tested process exits 0. Changing only the target's result from 7 to 8
produces a distinct binary with SHA-256
`2755b065c784d5a4e197e21186b2b4153f00ff4ac57e33f42ed078c87c101ad3`
that exits 1. These are exact process statuses and source-encoded assertions,
not separately captured intermediate register states. The macOS arm64 host
runs this x86-64 Mach-O through its installed x86 translation environment;
physical x86-64 execution has not been measured here.
Two rebuilds at the documented `build/vmp-ret-adjust-runtime` destination
produced the same SHA-256. Linking the same source under a different output
name changed its whole-file bytes at the Mach-O UUID. Omitting `LC_UUID`
made two differently named outputs identical, but the current macOS loader
refused to execute them. Reproduction therefore uses the exact output names
in the commands below; code-byte equivalence does not imply equal whole-file
hashes after renaming a linker output.
Exact source, positive and negative image, runner, IDA, plugin and raw-report
hashes are in
[VMP_RET_IMM16_X64_RUNTIME_EVIDENCE.json](VMP_RET_IMM16_X64_RUNTIME_EVIDENCE.json).

Rebuild the fixtures and rerun the probes with a current installed plugin:

```sh
xcrun clang -arch x86_64 -g0 -Wl,-no_pie tests/vmp_native/stack.S -o build/vmp-stack-ret-adjust
clang -target i386-unknown-linux-gnu -c tests/vmp_native/get_pc32.S -o build/vmp-get-pc32.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32.o -o build/vmp-get-pc32
python3 -B tests/run_ida_smoke.py build/vmp-stack-ret-adjust tests/ida_stack_transfer_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN"
python3 -B tests/run_ida_smoke.py build/vmp-get-pc32 tests/ida_get_pc32_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64
python3 -B tests/run_ida_smoke.py build/vmp-stack-ret-adjust tests/ida_native_evidence_probe.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --set CHERNOBOG_NATIVE_FIXTURE=stack
python3 -B tests/run_ida_smoke.py build/vmp-stack-ret-adjust tests/ida_native_proof_lifecycle_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN"
python3 -B tests/run_ida_smoke.py build/vmp-stack-ret-adjust tests/ida_ret_adjust_ownerless_probe.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN"
xcrun clang -arch x86_64 -g0 -Wl,-no_pie tests/vmp_native/ret_adjust_runtime.S -o build/vmp-ret-adjust-runtime
xcrun clang -arch x86_64 -g0 -Wl,-no_pie -DRET_ADJUST_NEGATIVE tests/vmp_native/ret_adjust_runtime.S -o build/vmp-ret-adjust-runtime-negative
build/vmp-ret-adjust-runtime
# The negative process returns status 1.
build/vmp-ret-adjust-runtime-negative
python3 -B tests/run_ida_smoke.py build/vmp-ret-adjust-runtime tests/ida_ret_adjust_runtime_probe.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN"
```

## Assumption register and bounded risks

| ID | Assumption and dependent result | Falsification probe |
| --- | --- | --- |
| A1 | The successful near return uses the modeled 32-bit or 64-bit stack width. The delta and write-offset calculation depends on it. | Execute the pair under an independently verified 16-bit stack-address configuration; if accepted with a different stack pointer behavior, narrow the admission gate. |
| A2 | The exact target is valid only while the bounded reaching definition, source bytes and entry topology remain current. The target proof depends on these. | Patch a definition, return byte or inbound reference and inspect publication freshness and target. The lifecycle probe covers return-byte transitions. |
| A3 | `xref.user` identifies plugin-owned published jumps in these IDA runs. The no-plugin-edge claim depends on this distinction. | Compare all outgoing reference flags with native ownership receipts in a fresh database, including a case where IDA independently creates an automatic edge. |
| A4 | The successful instruction path reaches the return pop. Static metadata does not prove runtime reachability under exceptional stack, privilege or control-flow-enforcement state. | Capture an independent instruction state at the pair and compare target, stack bytes and final pointer with the static summary. The matched ELF32 process oracle checks final behavior and stack markers, but does not capture every instruction boundary. |
| A5 | The macOS arm64 host's x86-64 translation correctly executes this fixture's normal path. The new x86-64 process result depends on it. | Repeat on physical x86-64 hardware or an independent translation engine; capture the same continuation state. The result-mutated control detects an ignored target return value but does not establish ISA-wide translator fidelity. |

High impact: treating `RET imm16` as a zero-delta ordinary jump can misstate
the target function's stack state and merge functions; the nonzero path records
metadata without such a plugin edge. Medium impact: a precise adjustment
extends candidate coverage for obfuscated native control flow. Low impact:
prefixed immediate-return encodings remain outside this exact-byte admission.

QG1: technical scope only. QG2: A1–A5 state dependencies and falsification
probes. QG3: classifier, IDA adapter, ownerless record, owned proof, static
inspection, lifecycle and negative boundaries are covered. QG4: widths,
offsets and deltas use bytes consistently. QG5: plugin and IDA references,
static and process evidence, and exact target versus jump publication are
separate claims. QG6: Intel's instruction reference and the named fixture,
runner and installed-plugin hashes identify the evidence. QG7: segment,
runtime and prefixed-encoding limits are explicit above.
