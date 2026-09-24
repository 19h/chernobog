# Morok protected prefix under a second valid input

This checkpoint extends `VMP_NATIVE_DEFINED_FLAGS.md` from the fresh,
source-controlled Morok keygen pair to its valid version-14.0 input. The
second input is 26 bytes, selects menu option 2 and differs from the 35-byte
version-14.1 input. The paired process control records two clean and four
protected completed runs per input. Within each input, exit status, stdout and
stderr agree across the six observations; the two inputs produce different
stdout hashes. The supplied keygen sample has a different binary hash and is
outside this paired comparison.

Two new QEMU/GDB processes capture the version-14.0 path from protected entry
`0x430000` to the 4,096-instruction boundary at `0x40c89b`. Two fresh IDA
processes replay each process's own entry registers, 1,696 writable-data
bytes and 1,152 stack bytes against the 65,536-byte observed unpacked code.
All four current and prior version-14.1 replays use the same installed plugin
interface; `tests/verify_native_shadow_second_input.py` reruns the independent
defined-flag and boundary verifier on each report.

| Measure | Four protected process/replay pairs |
|---|---:|
| Aligned GDB instruction entries | 4 × 4,094 = 16,376 |
| Exact aligned x86-64 GPR values | 16,376 × 16 = 262,016 |
| Exact architecturally defined status bits | 4 × 18,811 = 75,244 |
| Exact boundary scalar registers | 4 × 18 = 72 |
| Exact captured boundary data/stack bytes | 4 × 2,848 = 11,392 |

The two inputs have different SHA-256 and completed-process stdout hashes.
Across all four protected debugger runs, the observed unpacked code, entry
and boundary writable-data windows, and 4,094 reported PC/16-byte instruction
windows are identical. The prefix therefore remains input-invariant within
the recorded windows. The observed stack bytes vary with process placement;
each replay translates explicitly annotated near-RSP pointers and compares
against its own process. The two previously bounded GDB instruction-entry
omissions are the same at `0x40d63f` and `0x40c1a2`. There are 901 differing
architecturally undefined status bits per run; these are excluded from the
defined-bit totals.

The extra input establishes a second process-output oracle and confirms the
same protected prefix under two user-visible paths. It does **not** add an
input-dependent branch within that prefix, identify a VM region, or validate
memory outside the captured windows. Both native plans remain truncated.

## Reproduction

The source-controlled pair and earlier version-14.1 reports are described in
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md` and `VMP_NATIVE_DEFINED_FLAGS.md`. Create
the second exact input in ignored build storage:

```sh
printf '2\n1234-56789-01234\n800001\n' \
  > build/morok-runtime-probe/valid-v14-0.stdin
```

Run `tests/morok_qemu_packed_entry_memory_states.py` twice as described in
`VMP_NATIVE_DEFINED_FLAGS.md`, setting
`CHERNOBOG_PACKED_ENTRY_MEMORY_STATES_OUTPUT` to distinct version-14.0 report
paths and `CHERNOBOG_PACKED_STDIN` to the new input. Run
`tests/ida_native_shadow_replay_memory_probe.py` through `tests/run_ida_smoke.py`
with `--enable-rax` once per protected binary, setting
`CHERNOBOG_BOUNDARY_FILE` to its matching QEMU report and
`CHERNOBOG_SHADOW_FILE` to its matching unpacked dump. The accepted reports
are named in `VMP_NATIVE_SECOND_INPUT_EVIDENCE.json`.

Run the cross-input verifier with the original and second-input reports:

```sh
python3 -B tests/verify_native_shadow_second_input.py \
  --pair-report build/morok-keygen-evidence-final/report.json \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --shadow build/morok-runtime-probe/packed-first.bin \
  --second-shadow build/morok-runtime-probe/packed-second.bin \
  --first-input build/morok-runtime-probe/valid.stdin \
  --second-input build/morok-runtime-probe/valid-v14-0.stdin \
  --first-ida build/ida-shadow-memory-states-first/shadow_memory_replay.json \
  --second-ida build/ida-shadow-memory-states-second/shadow_memory_replay.json \
  --first-runtime build/morok-runtime-probe/packed-entry-memory-states-first.json \
  --second-runtime build/morok-runtime-probe/packed-entry-memory-states-second.json \
  --other-first-ida build/ida-shadow-memory-v14-0-rax-first/shadow_memory_replay.json \
  --other-second-ida build/ida-shadow-memory-v14-0-rax-second/shadow_memory_replay.json \
  --other-first-runtime build/morok-runtime-probe/packed-entry-memory-states-v14-0-first.json \
  --other-second-runtime build/morok-runtime-probe/packed-entry-memory-states-v14-0-second.json \
  --output build/morok-runtime-probe/second-input-verification.json
```

For total report bytes `B`, input cases `C = 2`, protected runs per case
`P = 2`, instruction entries `I = 4,094`, GPRs `R = 16` and retained window
bytes `W = 2,848`, the cross-input verifier uses
`O(B + C × P × (I × R + W))` time and space. This is a verifier bound,
excluding QEMU, IDA and plugin resources. The new IDA processes took
4,950,994,334 ns and 4,972,296,375 ns wall time including startup.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | The two fixed-seed protected ELF files and both input files match the paired build report. Process-output and cross-input comparisons depend on these hashes. | Rehash each artifact; substitute one input hash for the other and require rejection. |
| S2 | Each QEMU/GDB register and memory report samples one process before each stated instruction. The 16,376-entry and 11,392-byte counts depend on that timing. | Repeat on physical x86-64 or a second instruction tracer; reject changed PC/byte tuples or boundary windows. |
| S3 | Explicit near-RSP annotations cover translated stack pointers within the captured stack interval. GPR and stack comparisons depend on this mapping. | Remove an annotation and require the replay API to reject it; widen the sampled stack interval. |
| S4 | The existing Intel-defined flag masks apply to every decoded instruction in this prefix. The 75,244-bit count depends on them. | Reject any unclassified instruction/count and flip a defined bit; preserve the recorded undefined-bit disagreements. |
| S5 | The captured prefix precedes the input-dependent output difference. The invariance statement is limited to the observed prefix and windows. | Increase the instruction budget and capture a later divergence, or exhibit a differing state inside this prefix. |

- **High impact:** two distinct valid user inputs now have separately checked
  protected process-output and same-process replay evidence.
- **Medium impact:** matching code, data and path across inputs localizes this
  prefix as invariant within the recorded windows.
- **High impact risk:** the later divergent behavior remains outside the
  4,096-instruction replay budget; full protected recovery cannot be scored
  from this prefix.

QG1: technical scope. QG2: S1–S5 state dependencies and falsification probes.
QG3: both inputs, four protected captures, process outputs, register/flag and
boundary comparisons are covered; the full review is in progress. QG4: counts,
units and complexity are explicit. QG5: prefix invariance is separated from
whole-process output divergence. QG6: local source, artifact, runner and raw
report hashes are recorded in `VMP_NATIVE_SECOND_INPUT_EVIDENCE.json`; the
flag rules and Intel primary source are in `VMP_NATIVE_DEFINED_FLAGS.md`.
QG7: later branches, outside-window memory and logical VM identity remain
bounded unknowns.
