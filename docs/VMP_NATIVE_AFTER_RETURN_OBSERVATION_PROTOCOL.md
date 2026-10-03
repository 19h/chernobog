# Protected Morok caller continuation: observation protocol

This protocol tests the source-derived continuation in
`VMP_NATIVE_AFTER_RETURN.md` against the same protected process after its
owned callee returns to `0x41b885`. It addresses review rows 0b, 6a and V.
The fixed-seed test binary is identified by SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`;
it is distinct from the user-supplied keygen. The two input files are
`tests/vmp_native/morok_keygen_v14_1.stdin` and
`tests/vmp_native/morok_keygen_v14_0.stdin`.

## Procedure and admission criteria

From the repository root, with OrbStack running:

```sh
python3 -B tests/run_morok_after_return.py
```

The runner first verifies and expands the committed post-syscall and caller
archives into an ignored output directory. It checks the original binary,
input, report and source hashes before starting one protected process per
input under QEMU/GDB. The three
existing GDB scripts capture the packed branch, owned call and post-syscall
continuation. `tests/morok_qemu_after_return.py` then takes up to 64 live
caller instruction entries, stopping when control leaves
`[0x41b885, 0x41b8d0)`. It retains all 16 general-purpose registers, RIP,
RFLAGS, 16 code bytes and 32 stack bytes at each entry, plus a 64-byte data
window when RBX remains within the selected data page. It also captures the
75-byte caller code slice and the complete 4,096-byte data and 1,280-byte
stack windows before and after the caller path. The stack window keeps the
preceding report's base: the caller RSP is 112 bytes above that report's
helper-entry RSP. Its base must not be recomputed from caller RSP.

`tests/verify_native_after_return_observed.py` first revalidates the archived
IDA/source-derived case. It then requires a fresh process report with the
same binary and input hashes, a hash chain covering all four GDB scripts,
exact branch-to-owned, owned-to-post-syscall and post-syscall-to-caller
receipts, and the QEMU/GDB executable identities recorded at the branch.
The runner checks that `chernobog-linux-ci:latest` resolves to image ID
`sha256:b27cd74d026e02bdcdd8bac7c97447fe0d598174f76e252f106239aeb9722cfa`
before and after each input, as recorded in
`VMP_NATIVE_MEMORY_REPLAY_EVIDENCE.json`, and launches by that local image ID.
[Docker documents image-ID references for `run`](https://docs.docker.com/reference/cli/docker/image/ls/).
It invokes the same `/usr/bin` tool
paths that the branch capture hashes. The verifier also checks branch-to-owned
registers and data and the
owned-to-helper register boundary. It compares the live helper and
post-syscall paths with their archived entry addresses and checks all 23
live 16-byte pre-caller code windows against the ELF. It compares the live
caller code slice and every entered instruction's 16 code bytes against the ELF,
the exact 18-entry path, 16 GPRs at each entry and at the final boundary,
ZF at the three branch entries, five defined final status bits, selected
live stack/data windows, all 4,096 final data bytes, all 1,280 final stack
bytes, and the two input-dependent return targets. An observation that
differs from the archived state in irrelevant data or stack cells can still
pass; all compared state must match the replay. If a relevant state differs,
the verifier rejects it and the new reports remain available for an IDA
replay seeded from that fresh state.

The bounded capture permits at most 64 caller steps; the verifier admits
exactly 18. For each input the expected comparison counts are 18 instruction
entries, 304 GPR values, three branch ZF bits, 288 live instruction bytes,
576 sampled stack bytes, 4,096 final data bytes, 1,280 final stack bytes and
five final status bits. A 64-byte live data sample is compared at each entry
where RBX equals its entry value; the report records the actual count. The
75-byte code-slice check is separate from the 288 instruction-byte checks.
The pre-caller code comparison covers another `23 × 16 = 368` bytes per input.
All byte counts are exact; elapsed time and memory use are not inferred.

For binary size `B` bytes, expanded archive payload size `A` bytes, at most `I=64`
captured instruction entries, `R=18` register fields, per-entry code/data/stack
caps `C=16`, `D=64` and `S=32` bytes, and one data-plus-stack window
`W=4,096+1,280=5,376` bytes, capture and comparison retain
`O(A+B+I(R+C+D+S)+W)` space and perform
`O(A+B+I(R+C+D+S)+W)` local processing per input, excluding the cost of
guest instruction execution, ELF decoding and GDB/IDA startup. The archived
source-derived replay adds its separately documented 43-head plan. These
bounds do not estimate elapsed seconds or a recovery rate.

## Current evidence boundary

The synthetic format test passes for both inputs and rejects 18 altered
fields: capture source, source chain, three process receipts, QEMU, GDB and
container identities, stack origin, first PC, first GPR, branch ZF, first code, first
stack, first data, return target, defined final flag and final data. A separate
changed pre-caller code byte is rejected after its observation receipt is
updated. The test accepts deliberate changes in unused data and stack cells
of a synthetic fresh report. These tests construct their putative observation
from the archived IDA result. They do **not** show that the protected process
executed the predicted path. At the last check, `orb status` reported
`Stopped`, so there is no new same-process trace or verification result.

The live GDB step, QEMU memory reads and subsequent targets remain
**unknown** until the runner produces and the verifier accepts raw reports
for both inputs. A failure is a result to investigate, not permission to
replace the raw trace with the source-derived prediction.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| O1 | The fresh process reaches the same owned return boundary. The new path comparison depends on this. | Require the post-syscall report and live GDB registers to agree at `0x41b885`; a mismatch stops capture. |
| O2 | The four hash-identified GDB scripts are the scripts mounted in the runner. Capture attribution depends on this. | Compare each script's SHA-256 in the live report with the repository source; mutate one hash and require rejection. |
| O3 | The archived IDA replay applies to relevant fresh caller inputs. The cross-run state comparison depends on this. | Compare every entered GPR and branch ZF, code, data and stack effects; if a relevant input differs, rerun IDA from the fresh report. |
| O4 | The selected stack and data windows contain all effects of these 18 instructions. The final-window claim depends on this. | Inspect the decoded 18 instructions and collect a wider live trace if an address falls outside either window. The current verifier makes no claim about memory outside them. |
| O5 | GDB `stepi` reports the guest architectural state at each instruction entry. The protected-process claim depends on this. | Compare independent execution or another guest trace mechanism for the same input; the synthetic checker alone cannot test this. |
| O6 | The local container image ID identifies the tool environment used by the fresh capture. Toolchain attribution depends on this. | Inspect the tag before and after each run, launch by the pinned local image ID, compare the reported ID and executable hashes, and reject any mismatch. |

| Impact | Adjacent result or risk |
|---|---|
| High | A differing live branch, fault or return target would falsify the source-derived continuation for that input. |
| High | A passing live trace would establish a same-process match for these two inputs and this binary hash, not general VMP or Morok coverage. |
| Medium | Stack address randomization can change irrelevant captured cells; exact archived/fresh window equality would reject a valid local match. |
| Low | Source hashes authenticate the inspected files, not the runtime behavior of QEMU/GDB. |

QG1: technical claims only. QG2: O1–O6 include falsification probes.
QG3: the capture and checker cover both input paths and the bounded state
components stated above; protected-process completion is pending. QG4:
instruction, register, bit and byte counts are explicit. QG5: synthetic
checks are not presented as live evidence. QG6: the SHA-256 identity and
repository-local raw report paths supply the provenance to be checked after
capture; no live report is presently claimed. QG7: memory outside the
selected windows, faults, later execution and other protector builds remain
unknown.
