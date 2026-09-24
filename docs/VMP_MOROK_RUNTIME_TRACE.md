# Real process prefix for the packed Morok keygen pair

The source-controlled fixed-time Morok keygen pair in
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md` has two byte-identical protected ELF64
executables, SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
This experiment runs each executable as a Linux x86-64 process under QEMU's
user-mode translator and GDB remote stub. It stops at the application callback
`0x418440`, then single-steps 4,096 instructions. The process uses empty stdin.
The prior synthetic IDA candidate capture is the comparison target, not an
input to QEMU.

Both processes start at ELF entry `0x40021b` and reach the callback breakpoint.
At the callback, `RDI = 1`; `RSI` and `RDX` point into the actual process stack.
Those live register and stack values differ from the synthetic candidate seed.
Nevertheless, each of the 4,096 entered program counters matches the earlier
candidate capture at the same sequence index. Both processes stop at the
instruction limit with next PC `0x419896`, also matching the candidate stop PC.
The 16-byte window read at every entry agrees between the two processes; the
bytes of each entered instruction agree with both the candidate capture and
the ELF file mapping. Across 2 × 4,096 = 8,192 entries, the verifier finds
zero address, runtime-byte or image-byte mismatches.
Disposable reports with a changed first-entry address and a changed first
instruction byte are both rejected by the same verifier.

At both ELF entry and callback, the mapped 4,096-byte region starting at
`0x418440` has SHA-256
`87a0e7992dfef9ace66f2443ccb7c3b712ef619f2f3a337df24913e0c67bbe42`.
The mapped 65,536-byte region starting at `0x430000` has SHA-256
`bf85bf0f311c33ee8137644a8c513c3aa1582f0e225dd03a19b663cc270bd385`.
Both match their respective ELF file ranges. These checks show no change in
those ranges before the callback; they do not locate all future unpacked code
or establish VM semantics. Instruction stepping records entered addresses and
memory windows, not an independent proof of all intermediate architectural
effects. The prefix is one empty-input path on QEMU, not every application
path or physical x86-64 execution.

The arm64 Linux container image is
`sha256:b27cd74d026e02bdcdd8bac7c97447fe0d598174f76e252f106239aeb9722cfa`.
It ran Debian 13, QEMU x86-64 10.0.13 and GDB Multiarch 16.3. Each container
had a 2 GiB memory and 128-process limit; GDB had a 120 s timeout. Exact
registers, stack bytes, per-entry addresses/bytes and comparisons are retained
in ignored `build/morok-runtime-probe/`. Their hashes and the source hashes are
in `VMP_MOROK_RUNTIME_TRACE_EVIDENCE.json`.

Reproduce each trace with that local image or a compatible arm64 Debian image
containing QEMU user mode and GDB Multiarch. For the first protected build:

```sh
docker --context orbstack run --rm --platform linux/arm64 \
  --memory 2g --pids-limit 128 \
  --mount type=bind,src="$PWD/build/morok-keygen-evidence-final/protected-first",dst=/artifacts,readonly \
  --mount type=bind,src="$PWD/tests",dst=/probe,readonly \
  --mount type=bind,src="$PWD/build/morok-runtime-probe",dst=/out \
  --env CHERNOBOG_RUNTIME_TRACE_LIMIT=4096 \
  --env CHERNOBOG_RUNTIME_TRACE_OUTPUT=/out/trace-first-4096.json \
  --entrypoint sh chernobog-linux-ci:latest -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gdb-multiarch >/dev/null && (qemu-x86_64 -g 1234 /artifacts/int_woma_keygen-linux-x86_64-static </dev/null &) && sleep 1 && timeout 120s gdb-multiarch -q -nx -batch -ex "source /probe/morok_qemu_runtime_trace.py" /artifacts/int_woma_keygen-linux-x86_64-static >/out/gdb-first.log 2>&1'
```

Repeat with `protected-second`, `trace-second-4096.json` and
`gdb-second.log`, then run:

```sh
python3 -B tests/verify_morok_qemu_runtime_trace.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --candidate build/keygen-candidate-trace-control-first/candidate_trace.json \
  --first-runtime build/morok-runtime-probe/trace-first-4096.json \
  --second-runtime build/morok-runtime-probe/trace-second-4096.json \
  --output build/morok-runtime-probe/verification.json
```

For `I` entries, `P` ELF load headers and a fixed 16-byte entry window, the
GDB probe takes O(I) remote steps and O(I) retained trace space, excluding
guest/QEMU/GDB internal cost. The verifier takes O(I·P) mapping work and O(I)
retained sequence space. Here `I = 4,096` per run and `P = 3` load headers.
No latency or throughput inference is made from the container wall time.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The two hashed executables are the fresh fixed-time Morok pair. Cross-build comparison depends on this identity. | Rehash both outputs and rerun their paired process oracle; changed bytes invalidate the comparison. |
| R2 | QEMU/GDB single-step reports each entered x86-64 PC in execution order. The real-process prefix claim depends on this engine behavior. | Repeat on physical x86-64 with a second trace mechanism and compare the ordered prefix. |
| R3 | Breakpoint `0x418440` selects the application callback on the empty-input process path. The callback-state claim depends on this path. | Verify the startup callback argument and repeat with valid stdin and a later breakpoint. |
| R4 | The selected mapped ranges and first 4,096 entries bound the comparison. No later unpacking or general path claim follows. | Extend the trace budget, inspect all mapped writable/executable ranges and compare later code bytes. |
| R5 | The candidate's recorded instruction bytes and ELF file mapping are exact for entered addresses. The zero-byte-mismatch result depends on them. | Change one trace address or byte in a disposable report; require the verifier to reject it. |

- **High impact:** the synthetic candidate's complete 4,096-entry address and
  instruction-byte prefix now has a matching real-process observation on two
  protected executions.
- **Medium impact:** live callback registers and stack distinguish the observed
  process state from the synthetic seed, while the prefix remains identical.
- **Low impact:** the inspected packed range is unchanged before the callback;
  later unpacking, alternate inputs and physical-x86 agreement remain unknown.

QG1: technical scope. QG2: R1–R5 include falsification probes. QG3: both
protected builds, startup/callback states, full bounded prefixes and file-byte
comparisons are covered; the full VMP review remains open. QG4: byte ranges,
entry counts, limits and complexity are explicit. QG5: QEMU observation,
synthetic execution and ISA-wide claims are distinct. QG6: primary local ELF,
GDB/QEMU reports, source, image and exact hashes are linked. QG7: impact and
unobserved later paths are bounded.

Subsequent valid-input comparison: `VMP_MOROK_UNPACKED_ENTRY.md` records the
first execution of the packed section at `0x430000`. Its mapped bytes still
match the file at the callback but differ at packed entry. This later path
does not change the empty-input prefix measured here.
