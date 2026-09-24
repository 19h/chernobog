# Mapped packed-code transition on the Morok keygen valid path

This checkpoint uses the fresh fixed-time Morok keygen pair in
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md`, with protected ELF64 SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
The 35-byte stdin fixture selects version 14.1 and supplies a valid MathID,
serial and expiry. It is identical to that paired control's `valid_v14_1`
case. Each protected executable runs as an x86-64 Linux process under QEMU
user mode with the GDB remote stub. The probe samples memory at ELF entry
`0x40021b`, application callback `0x418440` and first execution of the
packed-section entry `0x430000`.

The 65,536-byte mapped region `[0x430000, 0x440000)` has SHA-256
`bf85bf0f311c33ee8137644a8c513c3aa1582f0e225dd03a19b663cc270bd385`
at both ELF entry and callback, matching its ELF file bytes. At the first
`0x430000` execution breakpoint, that same mapped range has SHA-256
`5fd0de1c7f61df57706d918f19af3f956a520e6484e156809bead053307d845d`.
Exactly 65,274 of 65,536 byte positions differ from the file mapping. The
two independently stopped protected processes yield byte-identical mapped
dumps. The first file bytes are `76 e5 40 7d 53 ae ac e2`; at execution they
are `55 41 57 41 56 41 55 41`, and GDB decodes the latter as four register
pushes at the section entry. The 4,096-byte callback region retains its file
hash at all three sampled points. The observations locate a change between
sampled states; they do not establish the instruction that made each write or
that every changed byte represents executable code.
Changing one byte at offset 100 in a disposable dump makes the verifier's
dump-hash check fail.

Separate bounded QEMU runs with this input complete for the clean executable
and both protected builds. All three exit 0 and produce identical 255-byte
stdout, SHA-256
`2ff6c69467f441be9b4db70e72dc935503171785b53d1d60f54ed290db965855`,
with empty stderr. The output contains `Password:`. These whole-process
results are separate from the debugger runs, which stop at packed entry.
QEMU's execution-block log for one completed protected run also contains
entry `0x430000`; translation blocks are not instruction counts.

The arm64 Linux container image is
`sha256:b27cd74d026e02bdcdd8bac7c97447fe0d598174f76e252f106239aeb9722cfa`.
It ran Debian 13, QEMU x86-64 10.0.13 and GDB Multiarch 16.3. Containers
had a 2 GiB memory and 128-process limit. GDB was limited to 120 s, and
whole-process runs to 15 s. Exact reports and 65,536-byte dumps are retained
under ignored `build/morok-runtime-probe/`; identifying source, artifact,
container and report hashes are in `VMP_MOROK_UNPACKED_ENTRY_EVIDENCE.json`.
Stack addresses in raw GDB reports can vary across repetitions; the dump and
byte comparisons are the stable oracle.

Reproduce with the paired build artifacts present. Create the exact input:

```sh
printf '1\n1234-56789-01234\n800001\n20270101\n' \
  > build/morok-runtime-probe/valid.stdin
```

The GDB/QEMU command for the first protected build is:

```sh
docker --context orbstack run --rm --platform linux/arm64 \
  --memory 2g --pids-limit 128 \
  --mount type=bind,src="$PWD/build/morok-keygen-evidence-final/protected-first",dst=/artifacts,readonly \
  --mount type=bind,src="$PWD/tests",dst=/probe,readonly \
  --mount type=bind,src="$PWD/build/morok-runtime-probe",dst=/out \
  --env CHERNOBOG_PACKED_TRACE_OUTPUT=/out/packed-first.json \
  --env CHERNOBOG_PACKED_DUMP_OUTPUT=/out/packed-first.bin \
  --env CHERNOBOG_PACKED_BINARY=/artifacts/int_woma_keygen-linux-x86_64-static \
  --env CHERNOBOG_PACKED_STDIN=/out/valid.stdin \
  --entrypoint sh chernobog-linux-ci:latest -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gdb-multiarch >/dev/null && (qemu-x86_64 -g 1234 /artifacts/int_woma_keygen-linux-x86_64-static </out/valid.stdin &) && sleep 1 && timeout 120s gdb-multiarch -q -nx -batch -ex "source /probe/morok_qemu_packed_entry.py" /artifacts/int_woma_keygen-linux-x86_64-static >/out/gdb-packed-first.log 2>&1'
```

Repeat with `protected-second`, `packed-second.json` and
`packed-second.bin`. Run the clean and each protected binary to completion
under the same QEMU version with the valid input, retaining stdout and
stderr, then verify all files:

```sh
python3 -B tests/verify_morok_packed_entry.py \
  --original build/morok-keygen-evidence-final/original/keygen-original \
  --first-binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --input build/morok-runtime-probe/valid.stdin \
  --first-report build/morok-runtime-probe/packed-first.json \
  --second-report build/morok-runtime-probe/packed-second.json \
  --first-dump build/morok-runtime-probe/packed-first.bin \
  --second-dump build/morok-runtime-probe/packed-second.bin \
  --original-stdout build/morok-runtime-probe/qemu-original-valid.stdout \
  --protected-stdout build/morok-runtime-probe/qemu-valid.stdout \
  --second-protected-stdout build/morok-runtime-probe/qemu-second-valid.stdout \
  --original-stderr build/morok-runtime-probe/qemu-original-valid.stderr \
  --protected-stderr build/morok-runtime-probe/qemu-valid.stderr \
  --second-protected-stderr build/morok-runtime-probe/qemu-second-valid.stderr \
  --output build/morok-runtime-probe/packed-verification.json
```

For `B = 65,536` mapped bytes and `P = 3` load headers, each probe retains
O(B) dump/report space and reads O(B) bytes at each of three stops. The
verifier uses O(B·P) worst-case ELF mapping and O(B) byte comparisons and
working space, apart from executable reads and QEMU/GDB internal state.
Counts and hashes are exact, with no rounding.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| U1 | The hashed executables and input represent the fresh fixed-time keygen pair. Process and dump comparisons depend on this identity. | Rehash both protected files, clean file and exact stdin; rebuild under the recorded seed and compare whole-process behavior. |
| U2 | QEMU/GDB reads mapped bytes before the selected instruction executes. The observed transition depends on that breakpoint behavior. | Repeat on physical x86-64 or a second debugger and compare the full mapped dump at first execution. |
| U3 | `0x430000` is entered on this valid path. The entry claim depends on the breakpoint and separate execution-block log. | Require the recorded RIP and first instruction bytes; repeat with another valid input and an execution tracer. |
| U4 | The original executable is the exact output oracle for this fixed input and engine. The behavior equality claim depends on it. | Recheck status/stdout/stderr bytewise, vary input and fixed epoch, and compare on physical x86-64. |
| U5 | The two runtime dumps are complete over the stated 65,536-byte range. The changed-byte count depends on complete reads and the ELF mapping. | Require exact dump length, hashes and all-position comparison; perturb one dump byte and require a mismatch. |

- **High impact:** actual packed-code bytes and the transition between observed
  file-state and execution-state are now available for protected analysis.
- **Medium impact:** two independent protected builds yield identical mapped
  bytes while their valid-input process outputs match the clean executable.
- **Low impact:** later writes, other entry addresses, VM interpretation and
  physical-x86 behavior remain unknown.

QG1: technical scope. QG2: U1–U5 include falsification probes. QG3: both
protected dumps, three process outputs, mapped file and callback controls are
checked; full VMP review remains open. QG4: addresses, byte counts, bounds
and complexity are explicit. QG5: sampled memory states, debugger stops and
completed process observations are distinct. QG6: primary local ELF, QEMU,
GDB and hash-linked raw reports support the claims. QG7: impact and untested
paths are bounded.
