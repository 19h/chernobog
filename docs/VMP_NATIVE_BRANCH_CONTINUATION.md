# Morok protected branch continuation to an owned-call boundary

This checkpoint extends `VMP_NATIVE_BRANCH_CHECKPOINT.md` for review rows
0b, 6a and V. It uses the fresh source-controlled fixed-seed Morok keygen
pair, not the distinct user-supplied keygen binary. The two protected builds
are byte-identical. Version-14.1 and version-14.0 stdin inputs produce
different completed-process outputs and take different successors of the
observed `CMP; JNE` at `0x430315` and `0x43031a`.

Two new QEMU/GDB processes stop at `0x430315` after unpacking. Each
records all 16 x86-64 GPRs, RIP, RFLAGS, a 65,536-byte code hash, 4,096
writable-data bytes, 1,024 stack bytes below and 256 above RSP, then
single-steps to `0x41d6c9`. The 14.1 path reports 1,181 instruction entries;
the 14.0 path reports 785. Every PC and 16-byte instruction window equals
the corresponding slice of the earlier independent 32,768-entry QEMU path.
The two paths first differ at the branch successor after 21,979 common
reported entries. This comparison does not treat reported GDB entries as a
universal count of retired instructions.

The existing read-only
`chernobog_vm_trace_candidate_shadow_replay_memory` API was seeded from each
new process's own compare state. Each fresh IDA 9.4 SP1 query uses the same
unpacked code suffix and a 4,096-instruction budget. It plans 10,174 heads
and enters the exact 1,181 or 785 addresses and instruction bytes, stopping
at `native-region-boundary`: CALL `0x41b882` targets `0x41d6c9`. Capstone
5.0.7 independently decodes all planned heads against the binary and
runtime shadow. After reversing only the declared scratch-stack translation,
all **31,456 GPR values** and 1,966 RIP values match the process observations
at the entered instructions. The final 16 GPRs, RIP and RFLAGS also match
for each input. No ordinary function evidence or VM identity is published.

An instruction-specific six-status-bit definedness mask admits 6,599 bits
on the 14.1 path and 4,292 on the 14.0 path: **10,891/10,891 defined bits**
match. Raw RFLAGS differ at 32 entries on each path; their 79 differing
status-bit instances are architecturally undefined at those entries. The
verifier requires the relevant condition flags to be defined before each
entered Jcc or CMOV. It rejects an unclassified instruction effect.

The plugin's final writes reproduce all **4,096 data and 1,280 stack bytes**
at the process boundary on each input: 10,752 exact selected boundary bytes
total. The 14.1 replay retains 179 final-written bytes; the 14.0 replay
retains 156. The verifier checks the entire before/after windows, not only
these written bytes. A deliberately truncated 1,696-byte data overlay
omits the live RNG word at `0x444b08`: the replay reads zero instead of
`0x6553f0ff`, and RAX at entered instruction 16 becomes zero instead of
`0xd87380906cbaddd3`. This causal negative control distinguishes an
incomplete memory snapshot from correct replay. Independent in-memory
mutations of a process register, final write and decoded head are rejected.
The checked IDA segment/item/reference/function/name inventory is unchanged
before and after both replay queries.

The boundary is a cross-region CALL target. The plugin does not enter that
target in this candidate query. This result is a validated finite native
continuation from an observed input-dependent branch, not a complete keygen
path, external-call model, VM-region proof or logical VM-state recovery.

## Reproduction and bounds

The inputs, protected binaries, unpacked dump and long QEMU paths are pinned
by `VMP_NATIVE_BRANCH_CHECKPOINT_EVIDENCE.json`. For each input, run the new
GDB script with the same isolated container setup used there. One invocation
is shown; repeat with `valid-v14-0.stdin`, a distinct output filename and a
distinct GDB log for the second input:

```sh
docker --context orbstack run --rm --platform linux/arm64 \
  --memory 2g --pids-limit 128 \
  --mount type=bind,src="$PWD/build/morok-keygen-evidence-final/protected-first",dst=/artifacts,readonly \
  --mount type=bind,src="$PWD/tests",dst=/probe,readonly \
  --mount type=bind,src="$PWD/build/morok-runtime-probe",dst=/out \
  --env CHERNOBOG_PACKED_BRANCH_CONTINUATION_OUTPUT=/out/packed-branch-continuation-v14-1-pinned.json \
  --env CHERNOBOG_PACKED_BINARY=/artifacts/int_woma_keygen-linux-x86_64-static \
  --env CHERNOBOG_PACKED_STDIN=/out/valid.stdin \
  --entrypoint sh chernobog-linux-ci:latest -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gdb-multiarch >/dev/null && (qemu-x86_64 -g 1234 /artifacts/int_woma_keygen-linux-x86_64-static </out/valid.stdin &) && sleep 1 && timeout 120s gdb-multiarch -q -nx -batch -ex "source /probe/morok_qemu_packed_branch_continuation.py" /artifacts/int_woma_keygen-linux-x86_64-static >/out/gdb-packed-branch-continuation-v14-1-pinned.log 2>&1'
```

Set `IDA_CONSOLE` to the IDA text executable and `CHERNOBOG_PLUGIN` to the
installed plugin. Use fresh output directories:

```sh
for variant in v14-1 v14-0; do
  python3 -B tests/run_ida_smoke.py \
    build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
    tests/ida_native_branch_continuation_probe.py \
    --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
    --output-dir "build/ida-branch-continuation-$variant-pinned" \
    --set "CHERNOBOG_BRANCH_SHADOW_FILE=$PWD/build/morok-runtime-probe/packed-branch-suffix.bin" \
    --set "CHERNOBOG_BRANCH_FILE=$PWD/build/morok-runtime-probe/packed-branch-continuation-$variant-pinned.json" \
    --set CHERNOBOG_BRANCH_CONTINUATION_BUDGET=4096
done
python3 -B tests/verify_native_branch_continuation.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --full-shadow build/morok-runtime-probe/packed-first.bin \
  --suffix build/morok-runtime-probe/packed-branch-suffix.bin \
  --first-input build/morok-runtime-probe/valid.stdin \
  --second-input build/morok-runtime-probe/valid-v14-0.stdin \
  --first-long build/morok-runtime-probe/packed-long-v14-1-32768.json \
  --second-long build/morok-runtime-probe/packed-long-v14-0-32768.json \
  --first-runtime build/morok-runtime-probe/packed-branch-continuation-v14-1-pinned.json \
  --second-runtime build/morok-runtime-probe/packed-branch-continuation-v14-0-pinned.json \
  --first-ida build/ida-branch-continuation-v14-1-pinned/branch_continuation.json \
  --second-ida build/ida-branch-continuation-v14-0-pinned/branch_continuation.json \
  --output build/morok-runtime-probe/branch-continuation-verification-pinned.json
```

For total parsed report bytes `B`, planned heads `H=10,174` per input,
entered instructions `I=1,966` across both inputs, `R=18` scalar fields and
selected boundary bytes `W=10,752`, the verifier uses
`O(B + H + IR + W)` time and retained space, excluding IDA, QEMU, Capstone
internals and JSON library allocation details. The two GDB step loops took
275,305,841 ns and 196,921,360 ns; the two IDA processes took
5,224,917,167 ns and 5,212,800,625 ns including startup. No throughput or
general recovery rate is inferred. Exact source, tool, binary, input, report
and verifier hashes are in `VMP_NATIVE_BRANCH_CONTINUATION_EVIDENCE.json`.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | The hash-pinned fresh protected pair and two stdin files identify the measured paths. All cross-input conclusions depend on these artifacts, not on the distinct supplied keygen. | Rehash and rebuild the pair; reject changed binary or input hashes. Repeat completed clean/protected output comparisons. |
| C2 | QEMU/GDB captures state before each reported instruction. The 31,456 GPR and 10,891 defined-bit comparisons depend on that timing. | Reproduce on physical x86-64 or a second tracer; compare every PC/byte tuple and selected registers. The separate long QEMU runs already agree on PC/byte paths. |
| C3 | The 65,536-byte code shadow represents entered protected code on this path. Graph and byte comparisons depend on that window. | Compare every planned head to the shadow or file and every entered instruction to the live 16-byte read; reject a changed byte or decode. |
| C4 | The 4,096-byte data and 1,280-byte stack snapshots cover memory relevant to this finite replay. GPR and boundary-memory equality depends on their contents and explicit stack translation. | Truncate the data at 1,696 bytes: the RNG read and RAX must disagree. Observe additional memory and aliases past the boundary before extending the claim. |
| C5 | The instruction-specific flag mask describes defined six-status-bit effects for this exact mnemonic set. The defined-bit count depends on it. | Compare each classified operation with the Intel x86-64 instruction contract; require failure on an unclassified effect or a mutated defined bit. Undefined-bit differences remain excluded. |
| C6 | The checked IDA inventory detects relevant persistent changes. The read-only conclusion is limited to its fields. | Save/reopen disposable databases and compare additional netnodes and analysis state. |

- **High impact:** both input-dependent protected branches now have validated
  native continuations of 1,181 and 785 instruction entries with exact GPR,
  defined-flag and selected-memory agreement.
- **Medium impact:** the RNG state outside the prior memory window explains
  the first scalar mismatch and supplies a same-query negative control.
- **High impact risk:** the cross-region CALL at `0x41d6c9`, unobserved memory
  outside selected windows and absent logical VM state prevent a complete-path
  or devirtualization claim.

QG1: technical claims only. QG2: C1–C6 have falsification probes. QG3:
both protected inputs, live registers, full entered bytes, planned heads,
defined flags, boundary memory, negative controls and IDB inventory are
covered; the complete review remains in progress. QG4: exact counts, byte
units, time units and complexity are explicit. QG5: the cross-region stop is
not counted as a recovered callee path. QG6: local primary binaries, code,
tool executables and reports are hash-pinned. QG7: other inputs, later paths,
memory outside the windows and VM semantics remain bounded unknowns.
