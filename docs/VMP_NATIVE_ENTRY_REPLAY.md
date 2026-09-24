# Morok packed-prefix entry-state replay

This checkpoint extends `VMP_NATIVE_RUNTIME_STATES.md` with a caller-supplied
entry-state replay. It uses the same two byte-identical fixed-seed Morok keygen
protected ELF64 builds, 35-byte valid stdin and 65,536-byte mapped unpacked
entry dump. The supplied `samples/int_woma_keygen-linux-x86_64-static` is a
different binary: SHA-256 `7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9`.
It matches the binary in the user-identified Morok checkout by hash. That
checkout also contains `programs/int_woma_keygen.c` and a static `max` TOML
configuration with virtualization enabled at 50% probability. The precise
source/configuration/seed lineage of the supplied binary remains unknown.

`chernobog_vm_trace_candidate_shadow_replay(data_head_ea, seed, entry_json)`
accepts a strict JSON object with exactly `shadow_file`, `observed_sp`,
`gprs` (16 hex strings in RAX order), `rflags`, `stack_above` (hex bytes),
`stack_relative_gprs` (register indexes) and `stack_relative_words` (byte
offsets into the stack snapshot). The shadow is at most 65,536 bytes; the
stack snapshot is 8–512 bytes; the register and word offset lists are bounded
at 16 and 64 entries. The API accepts only an x86-64 executable data-head
candidate and invokes the existing 4,096-instruction state sampler. It does
not mutate the database or publish ordinary function evidence.

The driver validates every explicitly marked stack-relative value against a
±32,768-byte window around the observed `RSP`, and rejects unmarked values in
that window. It places the replay stack in its isolated 1 MiB scratch region,
preserving the observed `RSP mod 4,096`, then translates only the marked
registers and 8-byte stack words by their signed displacement from the
observed `RSP`. Other registers and words retain their literal values. The
response reports the observed and translated entry stack addresses, snapshot
size and register mask. This mapping is a declared test input, not a claim
that the emulator maps the protected process's physical stack.

Two new QEMU/GDB 16.3 reports capture the 16 general-purpose registers, RIP,
EFLAGS, 16-byte instruction window and 128 entry stack bytes in the **same**
protected process. The two process stacks have different addresses but the
same page offset `0xbe8`. Each fresh IDA 9.4 SP1 replay retains 16,335 planned
heads and samples 4,096 entered instructions before the instruction budget;
the plan remains truncated. The old shadow reports' head, execution and edge
arrays match the replay reports. The IDB inventory before and after each
query is unchanged: SHA-256
`aced12a072b293db11c869da5bc803a7fed070a05cce39f6119a84d8d09c2118`.

The independent verifier checks all 16,335 head bytes and decode sizes against
the ELF/dump with Capstone 5.0.7. It aligns 4,094 debugger-reported entries
per run to candidate instruction states. The two prior debugger observation
gaps at `0x40d63f` and `0x40c1a2` remain; the verifier checks their bounded
linear-successor evidence. After reversing the declared stack translation,
all 16 general-purpose registers agree at all 4,094 aligned entries in each
run: `2 × 4,094 × 16 = 131,008` exact 64-bit value comparisons. A one-bit
mutation of one independent `RAX` value makes the verifier reject the result.
The portable test also checks that translated stack bytes and registers affect
executed instructions and that missing pointer annotations are rejected.

RFLAGS is reported separately. All six selected status bits match together at
3,418 of 4,094 aligned entries per run; CF matches 4,094, PF 3,708, AF 4,057,
ZF 4,090, SF 3,655 and OF 4,059. These are raw bit counts, without a
defined-flag equivalence claim. No instruction in this prefix reads the
supplied 128-byte stack snapshot above entry `RSP`; its real-process content
has not been validated as a causal input to this prefix. The first 4,096
instruction states do not establish complete plan coverage, other inputs,
memory equivalence or VM-state identity.

## Reproduction and cost

The two raw same-process reports are
`build/morok-runtime-probe/packed-entry-state-{first,second}-4096.json`,
captured by `tests/morok_qemu_packed_entry_state.py` using the bounded
container command pattern in `VMP_NATIVE_RUNTIME_STATES.md`. The GDB step
loops took 829,124,815 ns and 859,946,861 ns respectively, excluding
container startup. Run `tests/ida_native_shadow_replay_probe.py` with
`tests/run_ida_smoke.py` on each protected binary, setting
`CHERNOBOG_SHADOW_FILE`, `CHERNOBOG_SHADOW_SHA256` and
`CHERNOBOG_ENTRY_STATE_FILE` to its matching dump and same-process report.
The fresh report paths are
`build/ida-shadow-replay-final-{first,second}/shadow_replay.json`.

Run `tests/verify_native_shadow_replay.py` with the two binaries, two dumps,
valid stdin, the preceding shadow IDA and QEMU reports, and the four new
IDA/QEMU reports using its named CLI arguments. The resulting report is
`build/morok-runtime-probe/shadow-replay-final-verification.json`. Exact SHA-256
provenance and counts are retained in `VMP_NATIVE_ENTRY_REPLAY_EVIDENCE.json`.
For `B` input bytes, `P` ELF load segments, `H ≤ 16,384` planned heads,
`I ≤ 4,096` entered instructions and 18 sampled scalar registers, verifier
time is `O(B + P·H + 18·I)` and retained space is `O(B + H + 18·I)`;
the fixed two-run factor is omitted. The stack translation itself is
`O(S + 16)` time and `O(S)` additional space for `S ≤ 512` stack bytes.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| E1 | The hashed fixed-seed pair, stdin and dumps identify the protected path. All replay comparisons depend on this identity. | Rehash all files; rebuild with the recorded fixture procedure and reject any changed binary, input or dump. The supplied keygen binary is separate. |
| E2 | GDB's register and stack reads describe the state before its reported instruction. The 131,008 comparisons depend on this timing. | Repeat with an independent instruction tracer or physical x86-64 debugger at the same PC/byte tuples. |
| E3 | The two omitted debugger entries are observation gaps with the recorded linear successors. Alignment depends on this bounded model. | Obtain direct retirement evidence at both sites; a changed predecessor byte, successor or next PC rejects alignment. |
| E4 | Explicitly marked near-`RSP` values represent stack pointers, and preserving `RSP mod 4,096` is sufficient for this finite path. Translated GPR equality depends on this mapping. | Omit one pointer annotation, change the page offset, or extend the trace until a stack address escapes the ±32,768-byte window; reject or reclassify any mismatch. |
| E5 | The IDB inventory covers relevant persistent changes. The read-only result depends on that coverage. | Save/reopen and inspect additional netnodes if another database difference is observed. |
| E6 | The checked-in Morok source and TOML are plausible counterparts of the supplied files. Only the stated candidate-settings description depends on this. | Reproduce a byte-identical supplied ELF from the source, config, toolchain and seed; until then lineage is unknown. |

- **High impact:** all sampled general-purpose registers now have independent
  finite-path agreement under an explicit entry-state mapping.
- **Medium impact:** per-process stack address variation is isolated in a
  checkable translation, and input annotation omissions fail closed.
- **Low impact:** raw status flags differ, entry stack bytes are not read in
  this prefix, and VM-state recovery remains unestablished.

QG1: technical scope. QG2: E1–E6 specify falsification probes. QG3: API,
portable test, two IDA runs, two same-process QEMU runs and independent
verification are covered; the complete review remains in progress. QG4:
all bounds, counts, byte units and complexity are explicit. QG5: GPR
agreement is conditional on translation; flags and unused stack bytes are
reported separately. QG6: source and raw-report hashes are in the evidence
JSON. QG7: broader inputs, flags, memory and VM semantics have bounded scope.
