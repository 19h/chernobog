# Observed Morok call target: owned native checkpoint

This extends [the protected branch continuation](VMP_NATIVE_BRANCH_CONTINUATION.md)
for review rows 0b, 6a and V. The measured binary is the reproducible
fixed-seed Morok keygen (`f479ae1a…`), distinct from the supplied keygen
sample (`7d1971b1…`). IDA 9.4 SP1 identifies the entered target
`0x41d6c9` as a loaded x86-64 code head and exact function start; the call
source `0x41b882` belongs to another function. That distinction is checked
in a disposable database before replay.

The new read-only `chernobog_vm_trace_owned_shadow_replay_memory` entry
accepts an observed checkpoint only at an existing loaded x86-64 function
start. It requires the caller's bounded executable-byte shadow, 16 GPRs,
RFLAGS, translated stack windows, writable-data window and an explicit
1–4,096 instruction budget. A wrong root or omitted budget is rejected. The
shadow and data overlays affect the ephemeral program image; no IDB
retyping, function evidence or VM identity is published.

Two new QEMU/GDB runs reach that target from the distinct version-14.1 and
version-14.0 branch paths. Each run records the exact callee entry and live
256-byte code shadow, 4,096 writable-data bytes, and 1,024 stack bytes below
plus 256 above RSP. The bounded IDA replay plans and enters the first 26
callee instructions for each input. It stops before `0x41d78d` (`SYSCALL`),
which the native planner does not admit. GDB records the state immediately
before that instruction and then observes two further entries up to
`0x41d364`; those latter entries are outside this replay claim.

The independent verifier compares every planned head with Capstone 5.0.7,
file bytes and live instruction bytes. After explicit scratch-stack
translation, all **832/832 GPR values**, **52/52 RIP values**, **52/52 raw
RFLAGS values** and **312/312 defined status-flag bits** match across the two
26-instruction prefixes. The final 16 GPRs, RIP and RFLAGS agree at the
frontier. Applying the plugin's final writes to each entry snapshot
reproduces all **4,096 data plus 1,280 stack bytes** at that frontier:
**10,752/10,752 selected bytes** across both inputs. The observed stack
window changes in 22 bytes per input; the plugin reports 88 final-written
bytes and translates one stack pointer word. Mutating an observed register,
a final write or a planned head makes verification fail. The checked IDA
segment/item/reference/function/name inventory is unchanged.

The source, tool, binary, input, report and plugin hashes are recorded in
[the evidence manifest](VMP_NATIVE_OWNED_CALL_CHECKPOINT_EVIDENCE.json).
The complete captured reports remain in `build/morok-runtime-probe` and the
isolated IDA run directories. For reproduction, use the container procedure
in the branch continuation document with
`tests/morok_qemu_owned_call_checkpoint.py` as the GDB source, setting
`CHERNOBOG_PACKED_BRANCH_CONTINUATION_OUTPUT`,
`CHERNOBOG_OWNED_CHECKPOINT_OUTPUT` and `CHERNOBOG_OWNED_SHADOW_OUTPUT` to
distinct files for each input. Then run `tests/run_ida_smoke.py` with
`tests/ida_native_owned_call_probe.py`, setting
`CHERNOBOG_OWNED_CHECKPOINT_FILE` and `CHERNOBOG_OWNED_SHADOW_FILE` to those
files. Finally run `tests/verify_native_owned_call_checkpoint.py` with both
input, branch, runtime, shadow and IDA reports and the protected binary.

For total parsed report bytes `B`, planned heads `H=26` per input, entered
instructions `I=52` across both inputs, `R=18` compared scalar fields and
selected boundary bytes `W=10,752`, verification costs `O(B + H + IR + W)`
time and `O(B + H + W)` retained space, excluding library internals.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| O1 | The hash-pinned binary and two stdin files identify these paths. All replay comparisons depend on that identity. | Rehash inputs and rebuild the fixed-seed pair; reject altered hashes or changed clean/protected output comparisons. |
| O2 | GDB captures state before each reported instruction. GPR, RIP and flag counts depend on that timing. | Repeat on physical x86-64 or a second tracer; compare entered addresses, bytes and selected registers. |
| O3 | The live 256-byte shadow and selected memory windows cover these finite prefixes. Head and memory equality depend on that coverage. | Compare every entered byte to process memory; expand the data and stack windows for later instructions and reject any observed read beyond them. |
| O4 | The declared stack-relative fields identify process-stack pointers in these snapshots. The translated-value comparisons depend on those annotations. | Perturb one annotation and require register or boundary-memory disagreement; inspect aliases outside the selected windows. |
| O5 | The checked IDA inventory covers relevant persistent state. The read-only conclusion is limited to its fields. | Save and reopen disposable databases; compare additional analysis records and netnodes. |

- **High impact:** a protected cross-function CALL target now admits a
  measured native prefix from a live checkpoint.
- **Medium impact:** the identical 26-instruction prefix for both inputs
  provides a control for input-dependent state at the same target.
- **High impact risk:** the `SYSCALL` frontier, later callee behavior, memory
  outside the selected windows and logical VM state remain unknown.

QG1: technical claims only. QG2: O1–O5 include falsification probes. QG3:
the finite owned prefix, both inputs, boundary state, negative controls and
IDB inventory are covered. QG4: counts, byte units and complexity are
explicit. QG5: instructions after the syscall frontier are excluded. QG6:
local primary binaries, process reports, source and tool identities are
hash-pinned. QG7: later paths and VM semantics are bounded unknowns.
