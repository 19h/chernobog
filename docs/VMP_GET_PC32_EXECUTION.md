# ELF32 get-PC execution control

Review item 1a requested an executed 32-bit stack/get-PC control. The linked
analysis fixture remains `tests/vmp_native/get_pc32.S`; its bytes and historical
evidence are unchanged. `tests/vmp_native/get_pc32_exec.S` is a separate Linux
i386 process that checks the same positive instruction shapes against executed
behavior. It exits with status 0 only after all checks pass, and status 1 on a
failed check.

The control checks a PUSH-next/POP materialized continuation, a 32-bit stack
round trip, and preservation of CF/PF/AF/ZF/SF/OF (EFLAGS mask `0x08d5`). The
address oracle checks its own stack round trip. The entry point checks the
result and exact initial ESP after six additional calls: immediate
materialization, literal address, register PUSH/RET,
read-only-memory PUSH/RET, CALL/POP/PUSH/RET, and CALL/POP/JMP. The target
routine returns `7`; the literal routine instead returns the address of that
target. The exit syscall uses i386 `int 0x80` with EAX = 1 and EBX = 0 or 1.
Thus the status is an independently observed Linux process result, not an IDA
annotation. Deliberately rejected width, far-return, and adjusted-return cases
in the analysis fixture are not executed by this control.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| E1 | QEMU's i386 user-mode translation implements the tested instructions and Linux exit ABI. All process conclusions depend on this. | Pinned image ID and QEMU hash below; repeat on physical i386 or a second independent ISA engine to test translator dependence. Physical execution is **unknown**. |
| E2 | The executable's status path is reached and distinguishes success from a wrong target result. | Rebuild with `GP32_NEGATIVE_CONTROL`, changing the target result from 7 to 8. The same checks then produce status 1. |
| E3 | The control's positive shapes correspond to those in the linked IDA fixture. | Compare decoded instruction bytes and operands for each shape. This separate build does not assert equal addresses or whole-binary identity. |
| E4 | A Linux process result and IDA metadata measure separate properties. | Run the unchanged IDA fixture under the current plugin; report its 15/16 result below instead of counting execution as proof of annotation. |

## Reproduction and observed results

```sh
clang -target i386-unknown-linux-gnu -c tests/vmp_native/get_pc32_exec.S -o build/vmp-get-pc32-exec.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32-exec.o -o build/vmp-get-pc32-exec
clang -target i386-unknown-linux-gnu -DGP32_NEGATIVE_CONTROL -c tests/vmp_native/get_pc32_exec.S -o build/vmp-get-pc32-negative.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32-negative.o -o build/vmp-get-pc32-negative
docker --context orbstack run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src="$PWD/build",dst=/output,readonly \
  sha256:7b1781979ac73774803cdcd1ce8797d345cbae204731e0e684c1d74e89bef654 \
  /usr/bin/qemu-i386 /output/vmp-get-pc32-exec
# Repeat the Docker command with vmp-get-pc32-negative; expect status 1.
```

| Artifact or check | Observation |
|---|---|
| Source SHA-256 | `dfa166c2b0435d40b794a835eca2eb92aaffdd41c07df07c896478dee81eb4c5` |
| Positive ELF32 SHA-256, process status | `fee9d3dc723279ed35742ffa3ef6b148e3e304267f2ee960a763a19e1f64067d`, 0 |
| Negative ELF32 SHA-256, process status | `9c25732fc4b325d890d5093cc6f45f5de90bfe43079db123b3a1c87753e6e073`, 1 |
| Container image ID | `sha256:7b1781979ac73774803cdcd1ce8797d345cbae204731e0e684c1d74e89bef654` |
| `/usr/bin/qemu-i386` SHA-256 | `25939c0dba72ea1b8124b583c00d7c9b9afa6b4cb38a182f5808f2ca31b3b566` |
| Analysis fixture SHA-256 | `7b9d8fa8f6cd20f079257228c0e1275c599f7cf80843d039ac009af50af67646` |

The current installed plugin has SHA-256
`09e865b5066c2cf10da3103cf0e78a0006baa4ccdb6e9fbdbbf7047e8e0aaa78`.
Re-running `tests/ida_get_pc32_smoke.py` on the unchanged analysis fixture
produced 15/16 passing assertions under both the recorded IDA 9.3 executable
(SHA-256 `2cf9bab3f967af98a8eda93349598ac3d4a0a26c63671684f0aa73535033f12a`)
and IDA 9.4 executable (SHA-256
`387d681d6fb4f4c1c485a60025cae3f0affa6f5ea1efce3b1809639cb1aaeb28`).
The missing assertion is the PUSH-next materialization comment; the other
target, rejection, call-context, and database checks pass. The earlier 16/16
result in `VMP_GET_PC.md` belongs to its historical plugin hash and is not a
claim for the current artifact. At this checkpoint, root cause and repair of
this annotation regression were open.

Subsequent work identified and repaired this regression; see
[VMP_GET_PC32_BLOCK_END.md](VMP_GET_PC32_BLOCK_END.md). The observations and
hashes above remain the pre-repair execution and IDA measurements.
Separate [executed rejection controls](VMP_GET_PC32_REJECTIONS.md) now test
dynamic register and writable-memory targets, alternate entry, and RET
adjustment on the same binary inspected by IDA.

## Bounds and quality gates

The control performs a fixed sequence of seven calls and constant-size state
checks. Its own instruction count and storage are O(1); QEMU startup, loader,
and translation costs are excluded. ESP deltas are compared in bytes, and the
six defined arithmetic flag bits are selected by the exact EFLAGS mask above.
No timing or recovery-rate conclusion follows from a process exit status.

High impact: a current plugin can regress an annotation while the same native
instruction executes correctly. Medium impact: translator agreement on these
fixtures does not prove every i386 instruction. Low impact: the two fixtures
have different link layouts, so only their instruction shapes are comparable.

QG1: technical analysis only. QG2: E1–E4 include falsification probes. QG3:
the bounded execution gap is covered; global review item 1a remains in progress.
QG4: widths, stack bytes, flag mask and exit statuses are explicit. QG5: the
current IDA failure is identified separately from the execution pass. QG6:
source, binaries, translator and IDA executables have recorded hashes. QG7:
adjacent annotation and translator limitations are bounded above.
