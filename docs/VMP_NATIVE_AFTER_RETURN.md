# Source-derived caller continuation after the protected Morok syscall

This checkpoint extends `VMP_NATIVE_POST_SYSCALL.md` for review rows 0b, 6a
and V. The prior archive contains two QEMU/GDB states observed at the return
from the owned callee to `0x41b885`. The distinct version-14.1 and
version-14.0 inputs use the same fixed-seed protected keygen binary (SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`).
The user-supplied keygen is a different artifact.

Two fresh isolated IDA 9.4 SP1 processes admit `0x41b885` as a loaded
x86-64 code head owned by the existing function at `0x41b855`. The read-only
observed-head API seeds each query from its own preceding process registers,
4,096 data bytes and 1,280 stack bytes. Its 256-byte caller shadow is read
from the IDB and independently checked against the file-backed ELF bytes;
the process did **not** supply a post-return code shadow. Each query plans
43 heads, enters the same 18 instructions, and stops at the return from
`0x41b8cf`. The derived targets differ: `0x430584` and `0x43068f`. The
three preceding POPs consume 24 bytes, and each target equals the 8-byte
little-endian word at the observed entry RSP plus 24 bytes.

An independent bounded x86 transfer model decodes every planned head from
the ELF with Capstone and checks the exact entered path. The observed
`[RBX+0x28]` word is nonzero, `[RBX+8]` equals `[RBX+0x10]`, and EBP is
zero, determining the three local conditional successors. `PXOR` zeroes
XMM0; the subsequent `MOV` and two `MOVUPS` operations write 40 zero bytes
within the observed data window, changing nine previously nonzero bytes per
input. The model checks all 16 GPRs before each entered instruction
(18 × 16 × 2 = **576** comparisons), all 16 final GPRs for both inputs
(**32** comparisons), both return targets, the three final write ranges and
the five architecturally defined final status bits CF/PF/ZF/SF/OF. AF is
excluded after XOR. Five independent mutations of a branch input, return
word, head byte, final register and final write are rejected. The two
database inventories are unchanged; interior-byte, wrong/missing observed
PC and missing-budget requests are rejected. The instruction contracts are
specified in the [Intel 64 and IA-32 instruction set reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

A second, independently executed control embeds the exact 75 ELF bytes from
`0x41b885` through the `RET` in a Mach-O x86-64 harness. LIEF confirms that
the compiled symbol contains those exact bytes; the harness also compares
all 75 mapped instruction bytes with the independently extracted ELF slice
before entry. A changed-byte input exits with a distinct rejection status.
Two Rosetta processes run the slice with the 64-byte observed `[RBX, RBX+64)`
data subsection and the observed third stack word. Both exit zero. Each checks
75 live code bytes against the ELF (**150** byte comparisons total) and agrees
with the candidate on five selected GPRs per input (**10** register
comparisons), five defined final status bits per input (**10** bit
comparisons), the 64 output data bytes per input (**128** byte comparisons),
and a restored harness stack pointer.
The executed slice and its four mutation controls are checked by
`tests/verify_native_after_return_execution.py`; source, artifact and
result hashes are in `VMP_NATIVE_AFTER_RETURN_EXECUTION_EVIDENCE.json`.
The generated Mach-O UUID changes across builds, so the compiled executable
hash is run-specific; the verifier instead compares its embedded slice to
the hash-pinned ELF every run.

This remains a **source-derived prediction from an observed pre-caller
state**, corroborated by separate-process execution of the byte slice.
There is no QEMU/GDB instruction or memory trace after `0x41b885` in the
archived protected-process evidence. The harness has a new data allocation
and synthetic stack, and it cannot establish the original process's code
bytes, mapped-page permissions, faults or execution after the return target.
The report's `data_changed_bytes` field counts differences between the
process overlay and IDB image; the independently checked nine-byte count
compares modeled before/after process data windows.

`VMP_NATIVE_AFTER_RETURN_CAPTURE.json.gz.b64` contains the two exact IDA
reports, run manifests and IDB caller shadows. It is base64-encoded gzip;
the uncompressed JSON has no personal absolute paths. The preceding
`VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz` supplies the exact binary, inputs
and observed pre-caller states. The independent verifier reconstructs both
captures in a temporary directory, replays the transfer model and mutations,
and checks the source, Capstone, archive and report hashes recorded in
`VMP_NATIVE_AFTER_RETURN_EVIDENCE.json`:

```sh
python3 -B tests/verify_native_after_return_archive.py \
  --archive docs/VMP_NATIVE_AFTER_RETURN_CAPTURE.json.gz.b64 \
  --prior docs/VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz \
  --evidence docs/VMP_NATIVE_AFTER_RETURN_EVIDENCE.json
python3 -B tests/verify_native_after_return_execution.py \
  --archive docs/VMP_NATIVE_AFTER_RETURN_CAPTURE.json.gz.b64 \
  --prior docs/VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz \
  --evidence docs/VMP_NATIVE_AFTER_RETURN_EXECUTION_EVIDENCE.json \
  --output build/native-after-return-execution-recheck.json
```

For binary size `B`, planned heads `H=43` per input, entered instructions
`I=18` per input, `R=16` GPRs and observed data/stack bytes `W=5,376`
per input, replay verification is `O(B + H + IR + W)` time and
`O(B + H + W)` retained space per input, excluding decoder/library and
archive decompression internals. The five mutation replays multiply the
first case by a fixed factor. Counts use bytes, bits and instruction entries
as labeled; no throughput or general recovery rate follows from two runs.
The executable control additionally compares 75 live code bytes and 64 output
data bytes per input; compilation and process startup dominate its fixed-size
test and are outside the replay complexity bound.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The prior hash-pinned QEMU/GDB boundary state is the state before the first caller instruction. Every source-derived state comparison depends on that timing. | Re-run the protected process, capture the first post-return entry, and compare all GPRs, RIP, RFLAGS and selected memory with the archived boundary. |
| R2 | The file-backed 256-byte caller window matches executable process memory at this point. The decoded path prediction depends on this. | Read live bytes at every entered address in a fresh process. The current archive establishes only IDB-to-ELF equality for this window. |
| R3 | The selected data and stack pages remain mapped and writable through normal completion of these 18 instructions. The protected-process final state/write prediction depends on the absence of a fault or concurrent modification. | The separate Rosetta control checks normal-completion effects on a fresh allocation; capture the complete post-return QEMU/GDB instruction and memory trace to test the original process. |
| R4 | Scratch-stack translation retains the process pointer relation within the declared ±32,768-byte annotation window. The 576 GPR comparisons depend on it. | Mutate an annotated stack pointer and require a mismatch; compare a fresh process trace with unmodified raw registers. |
| R5 | The IDB inventory fields detect persistent changes relevant to this read-only query. The no-mutation finding is limited to those fields. | Compare segment bytes, items, references, functions and names before/after and across save/reopen; inspect additional netnodes separately. |

| Impact | Result or remaining risk |
|---|---|
| High | The cross-function protected path can be continued to distinct source-derived return targets from two observed entry states. |
| High | A protected-process trace after the callee return is still required to establish a same-process execution match. |
| Medium | The 18-entry model and separate executable control exercise SSE zeroing, data writes and three stack POPs under the selected input windows. |
| Low | Current queries publish no ordinary function evidence or VM identity. |

QG1: technical claims only. QG2: R1–R5 have falsification probes. QG3:
both inputs, 18-entry paths, 43-head plans, register/write/return checks,
an exact-byte executable control, negative controls and read-only inventory
are covered. QG4: byte, bit, instruction and complexity units are explicit.
QG5: separate-process execution and a source-derived path are kept distinct
from an observed protected-process continuation. QG6: local primary
binary/process/IDA and executable-control artifacts and the Intel instruction
reference are linked by hashes or direct citation. QG7: code-memory identity,
faults, later paths and VM semantics remain bounded unknowns. The full review
remains in progress.
