# Morok packed-prefix instruction states against QEMU/GDB

This checkpoint extends `VMP_NATIVE_RUNTIME_SHADOW.md`. It uses the same two
byte-identical fresh, fixed-time Morok keygen protected ELFs, the same exact
35-byte valid-v14.1 stdin, and the same 65,536-byte unpacked entry dumps.
It does not use the different supplied keygen sample. The protected binary,
input and unpacked dump SHA-256 values are respectively
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`,
`e19b1a7e7df224c8d242640e0a7b491ef593b37f9cdc49e597f813412502614f`
and `5fd0de1c7f61df57706d918f19af3f956a520e6484e156809bead053307d845d`.

`chernobog_vm_trace_candidate_shadow_states(data_head_ea, seed,
local_file_path)` uses the earlier ephemeral x86-64 shadow snapshot and native
plan, but retains the 16 general-purpose registers, RIP and RFLAGS before
every admitted instruction. The driver uses its existing 4,096-instruction
sample cap and a 1,000 ms engine timeout. It neither extends the plan nor
publishes ordinary function evidence or VM identity. The original shadow API
and ordinary function capture contracts remain separate.

Two fresh IDA 9.4 SP1 runs return byte-identical 4,405,121-byte reports. Each
retains 16,335 planned heads and exactly 4,096 entered instructions plus
4,096 corresponding instruction-entry register states. Another 390 states
mark region entry, transfers or predicate inputs: 4,486 state records total.
The full state-capture flag is true for the executed prefix. Its planned-head,
execution and edge arrays equal the preceding shadow reports exactly. Both
queries preserve the measured IDB inventory (SHA-256
`aced12a072b293db11c869da5bc803a7fed070a05cce39f6119a84d8d09c2118`,
38,006 heads, 40,917 references); all 16,335 planned head bytes and decode
sizes agree with the dump or ELF mapping under independent Capstone 5.0.7.
The plan still reports `plan_truncated=true` and stops execution at the
instruction budget before `0x40c89b`.

Two independent QEMU 10.0.13/GDB 16.3 protected-process runs capture all 16
general-purpose registers, RIP, EFLAGS and a 16-byte instruction window at
each of 4,096 debugger-reported entries. Their PC/byte windows exactly match
the earlier QEMU prefix reports. Alignment again identifies the two bounded
GDB entry gaps at `0x40d63f` and `0x40c1a2`, using their bytes in the preceding
window and their linear successors. Thus 4,094 reported entries align with
4,096 candidate entries; the two omitted candidate entries have no
independently observed register snapshot. The next debugger PC at the aligned
boundary is `0x40c89b` in both runs.

At the entry, the candidate and real process agree on `RAX`, `R8`, `R9`,
`R10`, `R14` and `R15`. Every one of those six registers then agrees at every
one of the 4,094 aligned entries in both processes: 49,128 exact comparisons.
This is nonvacuous for `RAX`, which takes 485 distinct candidate values and
changes 959 times between adjacent aligned observations. `R8` takes 143
distinct values and `R9` takes 151. The candidate and real `RSP` addresses
differ, but the unsigned 64-bit byte offset from each run's own entry `RSP` agrees
at all 4,094 aligned entries in both runs (8,188 comparisons). A one-bit
mutation to a real `RAX` observation or `RSP` offset causes the verifier to
reject its corresponding invariant.

The other registers are reported without an equivalence claim. For example,
`RBX`, `R11` and `R12` start differently and retain constant entry-relative
differences throughout this prefix. `RCX`, `RDX`, `RSI` and `RDI` have partial
exact agreement; `RBP` has none, and `R13` carries a process-dependent address.
The six selected status bits jointly match in 3,406 of 4,094 aligned entries.
Individual bit counts and each register's exact/relative counts are retained
in the verifier report. These raw bit comparisons do not prove architectural
flag effects, since the entry states differ and some instructions have
undefined flag results. The two QEMU runs also differ in stack addresses.
This checkpoint proves only the specified finite observations and invariants,
not full-state equivalence, function recovery, logical VM state, or behavior
on other inputs.

## Reproduction and bounds

Build the plugin and retain the paired binaries and dumps described in
`VMP_NATIVE_RUNTIME_SHADOW.md`. Run the new IDA probe on each protected file
in a fresh output directory. The first invocation is:

```sh
python3 -B tests/run_ida_smoke.py \
  build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  tests/ida_native_shadow_state_probe.py \
  --ida '/Applications/IDA Professional 9.4-sp1.app/Contents/MacOS/idat' \
  --plugin "$(realpath ../ida-sdk/src/bin/plugins/chernobog.dylib)" \
  --output-dir build/ida-shadow-states-first --enable-rax \
  --set "CHERNOBOG_SHADOW_FILE=$PWD/build/morok-runtime-probe/packed-first.bin" \
  --set CHERNOBOG_SHADOW_SHA256=5fd0de1c7f61df57706d918f19af3f956a520e6484e156809bead053307d845d
```

Repeat with the second protected binary and dump in a fresh
`build/ida-shadow-states-second` directory. Capture the first process register
prefix under the same container limits as the preceding packed-entry probe:

```sh
docker --context orbstack run --rm --platform linux/arm64 \
  --memory 2g --pids-limit 128 \
  --mount type=bind,src="$PWD/build/morok-keygen-evidence-final/protected-first",dst=/artifacts,readonly \
  --mount type=bind,src="$PWD/tests",dst=/probe,readonly \
  --mount type=bind,src="$PWD/build/morok-runtime-probe",dst=/out \
  --env CHERNOBOG_PACKED_REGISTER_OUTPUT=/out/packed-registers-first-4096.json \
  --env CHERNOBOG_PACKED_REGISTER_LIMIT=4096 \
  --env CHERNOBOG_PACKED_BINARY=/artifacts/int_woma_keygen-linux-x86_64-static \
  --env CHERNOBOG_PACKED_STDIN=/out/valid.stdin \
  --entrypoint sh chernobog-linux-ci:latest -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gdb-multiarch >/dev/null && (qemu-x86_64 -g 1234 /artifacts/int_woma_keygen-linux-x86_64-static </out/valid.stdin &) && sleep 1 && timeout 120s gdb-multiarch -q -nx -batch -ex "source /probe/morok_qemu_packed_registers.py" /artifacts/int_woma_keygen-linux-x86_64-static >/out/gdb-packed-registers-first-4096.log 2>&1'
```

Repeat with the second protected binary and unique second report/log names.
Verify the binary pair, stdin, dump pair and old/new IDA/QEMU reports:

```sh
python3 -B tests/verify_native_shadow_states.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --input build/morok-runtime-probe/valid.stdin \
  --shadow build/morok-runtime-probe/packed-first.bin \
  --second-shadow build/morok-runtime-probe/packed-second.bin \
  --old-first-ida build/ida-shadow-16384-first/shadow_trace.json \
  --old-second-ida build/ida-shadow-16384-second/shadow_trace.json \
  --first-ida build/ida-shadow-states-first/shadow_states.json \
  --second-ida build/ida-shadow-states-second/shadow_states.json \
  --old-first-runtime build/morok-runtime-probe/packed-prefix-first-4096.json \
  --old-second-runtime build/morok-runtime-probe/packed-prefix-second-4096.json \
  --first-runtime build/morok-runtime-probe/packed-registers-first-4096.json \
  --second-runtime build/morok-runtime-probe/packed-registers-second-4096.json \
  --output build/morok-runtime-probe/shadow-state-verification.json
```

The verifier hashes each input, rechecks all reported head bytes and decodes,
verifies sampled sequence identity, aligns both debugger paths, compares every
mapped register state and executes the two in-memory mutation controls.

For `B` bytes of binary/dump/report input, `P` ELF load segments, `H ≤ 16,384`
planned heads, `I ≤ 4,096` entered instructions and 18 sampled registers,
verification takes `O(B + P·H + 18·I)` time and `O(B + H + 18·I)` retained
space. The one-time IDA and QEMU process costs are outside this bound. GDB
reports 809,504,165 ns and 870,081,990 ns for its respective 4,096-step
loops; those intervals exclude container setup and are not performance
benchmarks. Counts and byte comparisons are exact, with no rounding.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The hashed fixed-time pair, input and mapped dumps identify one protected path. Cross-run results depend on that identity. | Rehash and rebuild with the recorded seed/config; reject any changed binary, input, dump or prior report. The supplied keygen ELF is separate. |
| R2 | GDB register reads occur before the corresponding reported instruction. Register comparisons depend on this timing. | Repeat with another instruction tracer or physical x86-64 debugger and compare the same PC/byte/register tuples. |
| R3 | Two verified linear gaps are debugger observation gaps. The 4,094-entry alignment depends on this model. | Obtain direct retirement evidence for the two omitted instructions; a different next PC, bytes or successor rejects alignment. |
| R4 | Entry-equal registers and entry-relative `RSP` form the stated finite comparison contract. The 49,128 and 8,188 counts depend on this selection. | Supply matched full entry registers and stack memory, vary the input and require a fresh comparison; in-memory one-bit mutations must be rejected. |
| R5 | The full IDB inventory captures relevant persistent state. The read-only claim depends on its coverage. | Save/reopen and compare additional netnodes or database state if a discrepancy appears. |

- **High impact:** every admitted instruction now has a bounded scalar-state
  record, and dynamic result values receive independent protected-process
  corroboration on this valid path.
- **Medium impact:** entry-relative stack movement matches despite differing
  process stack addresses.
- **Low impact:** full register, flag, memory, exception and VM-state
  equivalence remain unknown; the plan and execution are truncated.

QG1: technical scope. QG2: R1–R5 include falsification probes. QG3: source
API, two IDA captures, two QEMU captures, all sampled entries and negative
controls are covered; broader review requirements remain incomplete. QG4:
byte, instruction and register bounds and exact arithmetic are stated. QG5:
entry-equal and entry-relative comparisons are separate from mismatched
registers and raw flag counts. QG6: primary source, binary, dump, plugin and
raw-report hashes are linked in the evidence JSON. QG7: other inputs and
full VM-state recovery remain bounded unknowns.
