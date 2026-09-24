# Protected Morok branch from an observed runtime checkpoint

This checkpoint follows `VMP_NATIVE_SECOND_INPUT.md` beyond its common
4,096-instruction prefix. It uses the fresh fixed-seed Morok keygen ELF64
fixture, not the distinct supplied keygen executable. Two completed process
inputs select version 14.1 and version 14.0 and produce different stdout.
The source-controlled clean and protected builds agree within each input.

Two bounded QEMU/GDB paths of 32,768 **reported** instruction entries share
their first 21,979 PC/16-byte tuples. Their first different tuple follows the
same `CMP` at `0x430315` and `JNE` at `0x43031a`: the version-14.1 path enters
`0x430320`, and the version-14.0 path enters `0x43042b`. The first 4,094 tuples
of each long path match the earlier same-input, same-binary 4,096-instruction
boundary report, including its two bounded debugger observation gaps. Reported
GDB entries are not equated to retired instruction counts.

Fresh same-process QEMU stops at `0x430315` record the unpacked 65,536-byte
code hash, 16 GPRs, RFLAGS, 1,696 writable-data bytes, and 1,152 stack bytes.
The 32-bit word at `[RSP+12]` is `1` on the 14.1 path and `2` on the 14.0
path. QEMU steps the `CMP` and `JNE`: RFLAGS after `CMP` is `0x246` versus
`0x202`, and the two successors match the long-path difference. Capstone
5.0.7 independently decodes the recorded bytes as
`CMP dword ptr [RSP+0xc], 1; JNE 0x43042b`.

The read-only
`chernobog_vm_trace_candidate_shadow_replay_memory(root, seed, request)`
accepts a caller-observed checkpoint at the tail of a packed data item when
the root lies in an executable image segment, has no function or user name,
and the request supplies a bounded executable shadow, exact entry registers,
translated stack windows, writable-data window, and explicit `max_insns`
from 1 to 4,096. The previous data-head replay still defaults to 4,096
instructions. A checkpoint may have non-ABI RSP alignment; the isolated
scratch stack preserves its observed page offset. The API labels the tail
checkpoint and instruction budget, and publishes no ordinary function
evidence or VM identity. Caller provenance remains an external obligation.

Both IDA replays start at `0x430315` from their own QEMU state and execute
exactly two instructions. Each reads its observed 32-bit stack word and stops
at the same successor as QEMU. At the states before `CMP`, before `JNE`, and
after `JNE`, all 16 normalized GPRs, RIP and RFLAGS agree: per input,
`3 × (16 + 2) = 54` exact scalar values, or 108 across both inputs. The
observed stack read agrees in each case. A one-word input-stack mutation in
each disposable IDA process reverses its successor. Missing, zero or oversized
instruction budgets and a data overlay targeting executable bytes are
rejected. An independent verifier rejects altered runtime successor, stack
word and replayed branch flags. Both measured IDA inventories are unchanged.

This is a local native transition from an independently observed state.
The 21,979-entry common path is **not** replayed end to end by this
checkpoint. It does not identify a virtual-machine context, prove a logical
VM transition, establish memory identity outside the recorded windows, or
attribute the supplied keygen executable to this fresh build.

## Reproduction and bounds

The QEMU/GDB scripts are `tests/morok_qemu_packed_long_path.py` and
`tests/morok_qemu_packed_branch.py`. Run each for the two exact inputs from
`VMP_NATIVE_SECOND_INPUT.md` in the container and GDB setup recorded by
`VMP_MOROK_UNPACKED_ENTRY.md`. Set
`CHERNOBOG_PACKED_LONG_PATH_BUDGET=32768`; give every run its own
`CHERNOBOG_PACKED_LONG_PATH_OUTPUT` or `CHERNOBOG_PACKED_BRANCH_OUTPUT`.
Both scripts also require `CHERNOBOG_PACKED_BINARY` and
`CHERNOBOG_PACKED_STDIN`. The accepted paths and stop reports are hash-pinned
in `VMP_NATIVE_BRANCH_CHECKPOINT_EVIDENCE.json`.

Use the suffix of the observed unpacked code beginning at offset `0x315` as
`CHERNOBOG_BRANCH_SHADOW_FILE`. Run
`tests/ida_native_branch_replay_probe.py` through `tests/run_ida_smoke.py`
with `--enable-rax`, once for each QEMU branch report. Set
`CHERNOBOG_BRANCH_FILE` and `CHERNOBOG_BRANCH_SHADOW_SHA256` explicitly.
The Python probe constructs the register and stack-relative annotations and
requests `max_insns: 2`. The accepted IDA reports are named in the evidence
JSON. Verify the pair with:

```sh
python3 -B tests/verify_native_shadow_branch.py \
  --pair-report build/morok-keygen-evidence-final/report.json \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --full-shadow build/morok-runtime-probe/packed-first.bin \
  --suffix-shadow build/morok-runtime-probe/packed-branch-suffix.bin \
  --first-input build/morok-runtime-probe/valid.stdin \
  --second-input build/morok-runtime-probe/valid-v14-0.stdin \
  --first-long build/morok-runtime-probe/packed-long-v14-1-32768.json \
  --second-long build/morok-runtime-probe/packed-long-v14-0-32768.json \
  --first-prefix build/morok-runtime-probe/packed-entry-memory-states-first.json \
  --second-prefix build/morok-runtime-probe/packed-entry-memory-states-v14-0-first.json \
  --first-runtime build/morok-runtime-probe/packed-branch-v14-1.json \
  --second-runtime build/morok-runtime-probe/packed-branch-v14-0.json \
  --first-ida build/ida-branch-replay-final-v14-1/branch_replay.json \
  --second-ida build/ida-branch-replay-final-v14-0/branch_replay.json \
  --output build/morok-runtime-probe/branch-final-verification.json
```

For `C = 2` inputs, `L = 32,768` reported entries per long path,
`H ≤ 16,384` planned heads, `W = 2,848` captured memory bytes and `R = 18`
scalar registers, the verifier uses `O(B + C × (L + H + W + 3R))` time and
space, where `B` is the total parsed report size. This excludes QEMU, IDA,
Capstone and RAX internal resources. Each GDB long-path step loop took
6,629,471,798 ns and 6,100,615,975 ns respectively, excluding container
startup. The two IDA processes took 4,668,981,625 ns and 4,670,170,750 ns
including startup, not pure replay time. Source, artifact, runner and report
hashes are in the evidence JSON.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| B1 | The fixed-seed protected ELF, two stdin files and unpacked dump identify the same fresh paired fixture. All cross-run conclusions depend on these hashes. | Rehash them; require the long, branch and paired process reports to agree. A supplied-sample hash mismatch excludes it. |
| B2 | QEMU/GDB captures state before the indicated instruction and the two observed single steps follow `CMP` then `JNE`. The 108 scalar comparisons depend on this timing. | Capture at the same PCs with an independent x86-64 tracer; changed bytes or register states invalidate the comparison. |
| B3 | Each explicitly marked near-RSP word is a stack pointer to translate; unmarked words remain literal. The GPR and stack-read comparisons depend on this classification. | Omit an annotation and require rejection; widen the stack observation and inspect near-RSP values. |
| B4 | The 32,768-entry GDB reports use comparable observation semantics. The 21,979-entry common-prefix result depends on this. | Repeat both long runs; compare their first 4,094 entries to the earlier register reports and both reports at the branch breakpoint. |
| B5 | The caller's `0x430315` checkpoint is an instruction boundary in the protected process. Local replay applicability depends on it. | Require exact QEMU RIP and 16-byte instruction window and matching independent Capstone decode; shift the recorded RIP to falsify attribution. |

- **High impact:** the plugin now admits a bounded, read-only protected data-tail
  checkpoint and reproduces an actual input-dependent branch on both paths.
- **Medium impact:** explicit instruction budgets and checkpoint labeling make
  the local replay and its finite coverage inspectable.
- **High impact risk:** caller-supplied snapshots and unobserved memory outside
  the 2,848-byte window prevent whole-path or VM-state equivalence claims.

QG1: technical scope. QG2: B1–B5 specify dependencies and falsification
probes. QG3: both protected outcomes, source bytes, stack reads, three scalar
states, mutation controls and IDB preservation are checked; the full review
remains in progress. QG4: instruction, byte and scalar counts and elapsed
times have explicit units. QG5: GDB reported entries, local replay and
completed process outputs remain distinct. QG6: local primary binaries,
source, reports and tool identities are hash-pinned; the instruction
definedness reference is the Intel manual linked in
`VMP_NATIVE_DEFINED_FLAGS.md`. QG7: full-path execution, wider memory,
VM-region identity and supplied-sample lineage are bounded unknowns.
