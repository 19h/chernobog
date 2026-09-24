# Bounded Morok runtime-shadow candidate trace

The user identifies Morok as their own obfuscator. This is user-supplied
authorship information. The measured executables are the fresh fixed-time
source-controlled pair in `VMP_MOROK_KEYGEN_PAIRED_CONTROL.md`, not the distinct
supplied keygen sample. Their protected ELF64 files are byte-identical,
SHA-256 `f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
The exact 35-byte valid-v14.1 stdin has SHA-256
`e19b1a7e7df224c8d242640e0a7b491ef593b37f9cdc49e597f813412502614f`.
Both protected processes reach packed entry `0x430000`. At its first execution,
their 65,536-byte mapped dumps are identical, SHA-256
`5fd0de1c7f61df57706d918f19af3f956a520e6484e156809bead053307d845d`,
and differ from the ELF file mapping in 65,274 byte positions. Entry, callback
and completed-process controls are in `VMP_MOROK_UNPACKED_ENTRY.md`.

`chernobog_vm_trace_candidate_shadow(root_ea, seed, local_file_path)`
reads a caller-supplied file of 1–65,536 bytes and overlays an ephemeral image
snapshot beginning at the selected root. The measured Morok run used one
loaded x86-64 executable segment and decoded its bytes with RAX. The current
API also admits an explicitly selected unloaded, code-referenced root and
contiguous readable, nonwritable segments; that separate VMP fixture is in
`VMP_HELLO_RUNTIME_SHADOW.md`. This explicit API plans at most 16,384 native
heads; ordinary native plans retain their 4,096-head
default. The response records shadow length, changed and newly loaded byte
counts, segment count and FNV-1a fingerprint with a synthetic-entry contract.
It creates no IDA function or
ordinary function evidence and does not prove runtime provenance or VM identity
by itself. The independently hashed GDB dumps supply the runtime link here.

Two fresh IDA processes returned byte-identical candidate reports. Each planned
16,335 distinct heads, retained 184 frontiers and reported
`plan_truncated=true`; this is not a complete CFG. From the synthetic
packed-entry state, each executed 4,096 instructions, stopped at the
instruction budget before PC `0x40c89b`, and recorded 198 nonfallthrough
transitions, 390 state records and 320 data-access records. Nine entered heads
had no IDA function owner and 904 were foreign to the entry owner.
`region_code_changed=false` applies only to this prefix and snapshot. The full
IDB inventory was unchanged before and after each query: SHA-256
`aced12a072b293db11c869da5bc803a7fed070a05cce39f6119a84d8d09c2118`,
38,006 heads and 40,917 references. Missing-file, oversized-file, data-tail
and existing-code-head controls were rejected.

Independent Capstone 5.0.7 checks compare all 16,335 reported head bytes and
decodes per run against the runtime dump or ELF mapping. They also compare
every entered candidate instruction and linear successor; all mismatch counts
are zero. Two QEMU 10.0.13/GDB 16.3 runs under the same input report 4,096
instruction-entry PC/16-byte windows each. Their PC/byte sequences agree
exactly. All reported runtime instruction bytes decode and agree with the
mapped shadow or ELF bytes. The first 1,620 candidate and GDB addresses agree
without alignment adjustment.

At two points, GDB's single-step records omit a linear instruction entry:
`0x40d63f` and `0x40c1a2`, each a three-byte `MOV RCX,RSP` after `PAUSE`.
For each, the preceding 16-byte window contains the omitted instruction and
the next reported PC equals its linear successor. This establishes a bounded
observation gap; it does not independently prove retirement of the omitted
instruction. Accounting for these two gaps aligns all 4,096 candidate entries
with 4,094 GDB entries; GDB next reports the candidate stop PC `0x40c89b`.
The runtime record has 200 apparent nonfallthrough transitions through that
boundary. Exactly two arise from the gaps. The remaining 198 match the
candidate's 198 recorded edge occurrences as a source/target multiset, with
zero missing or extra occurrences. Both protected processes give this result.
This is a finite valid-input prefix oracle, not unbounded CFG or VM recovery.

The verifier rejects an in-memory one-byte shadow mutation through its digest
and head-byte checks. Changing one candidate edge target in memory produces
one missing and one extra edge, so the edge comparison rejects it. These
controls do not write to the source artifacts or IDB.

## Reproduction and bounds

Generate the fixed-time pair and the two packed-entry dumps as described in
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md` and `VMP_MOROK_UNPACKED_ENTRY.md`. Build
the plugin. Use a fresh IDA output directory per run. The first invocation is:

```sh
python3 -B tests/run_ida_smoke.py \
  build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  tests/ida_native_shadow_trace_probe.py \
  --ida '/Applications/IDA Professional 9.4-sp1.app/Contents/MacOS/idat' \
  --plugin "$(realpath ../ida-sdk/src/bin/plugins/chernobog.dylib)" \
  --output-dir build/ida-shadow-16384-first --enable-rax \
  --set "CHERNOBOG_SHADOW_FILE=$PWD/build/morok-runtime-probe/packed-first.bin" \
  --set CHERNOBOG_SHADOW_SHA256=5fd0de1c7f61df57706d918f19af3f956a520e6484e156809bead053307d845d \
  --set "CHERNOBOG_OVERSIZED_FILE=$PWD/build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static"
```

Repeat with `protected-second`, `packed-second.bin` and a fresh
`build/ida-shadow-16384-second` directory. QEMU/GDB capture uses the same
container as `VMP_MOROK_UNPACKED_ENTRY.md`. The first invocation is:

```sh
docker --context orbstack run --rm --platform linux/arm64 \
  --memory 2g --pids-limit 128 \
  --mount type=bind,src="$PWD/build/morok-keygen-evidence-final/protected-first",dst=/artifacts,readonly \
  --mount type=bind,src="$PWD/tests",dst=/probe,readonly \
  --mount type=bind,src="$PWD/build/morok-runtime-probe",dst=/out \
  --env CHERNOBOG_PACKED_PREFIX_OUTPUT=/out/packed-prefix-first-4096.json \
  --env CHERNOBOG_PACKED_PREFIX_LIMIT=4096 \
  --env CHERNOBOG_PACKED_BINARY=/artifacts/int_woma_keygen-linux-x86_64-static \
  --env CHERNOBOG_PACKED_STDIN=/out/valid.stdin \
  --entrypoint sh chernobog-linux-ci:latest -c \
  'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gdb-multiarch >/dev/null && (qemu-x86_64 -g 1234 /artifacts/int_woma_keygen-linux-x86_64-static </out/valid.stdin &) && sleep 1 && timeout 120s gdb-multiarch -q -nx -batch -ex "source /probe/morok_qemu_packed_prefix.py" /artifacts/int_woma_keygen-linux-x86_64-static >/out/gdb-packed-prefix-first-4096.log 2>&1'
```

Repeat with the second protected build and distinct `second` report/log names.
Then run:

```sh
python3 -B tests/verify_native_shadow_trace.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --input build/morok-runtime-probe/valid.stdin \
  --shadow build/morok-runtime-probe/packed-first.bin \
  --second-shadow build/morok-runtime-probe/packed-second.bin \
  --first-ida build/ida-shadow-16384-first/shadow_trace.json \
  --second-ida build/ida-shadow-16384-second/shadow_trace.json \
  --first-runtime build/morok-runtime-probe/packed-prefix-first-4096.json \
  --second-runtime build/morok-runtime-probe/packed-prefix-second-4096.json \
  --output build/morok-runtime-probe/shadow-verification-16384.json
```

For `B ≤ 65,536` overlaid bytes, `H ≤ 16,384` planned heads and `I ≤ 4,096`
entered instructions, the verifier takes `O(P·(B + H + I))` time for `P` ELF
load segments and `O(B + H + I)` working space, excluding decoder and debugger
internals. Planning and execution have separate bounds. Counts, hashes and
byte comparisons are exact, with no rounding.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | The hashed fresh pair, input and dumps identify one Morok build path. Cross-run conclusions depend on this identity. | Rehash and rebuild with the recorded source, config and seed. The different supplied keygen sample is excluded. |
| S2 | The GDB read at first packed execution represents mapped bytes for the following prefix. The shadow link depends on this timing. | Capture the boundary with another tracer or physical x86-64 debugger; compare the full dump and instruction windows. |
| S3 | QEMU/GDB entry records describe this bounded path except the two identified gaps. The 198-edge comparison depends on this alignment. | Use an independent instruction tracer; require retirement evidence for the omitted instructions or revise alignment and counts. |
| S4 | The synthetic entry state and one overlay suffice for this prefix. Byte/path conclusions depend on that state and coverage. | Vary registers and mapped memory; trace later writes and spans, rejecting mismatched visits. |
| S5 | The IDB inventory covers relevant persistent state. The no-mutation claim depends on its coverage. | Save/reopen and compare additional netnodes and IDA state if discrepancies appear. |

- **High impact:** actual unpacked bytes support a 4,096-instruction protected
  path and 198 independently compared transition occurrences.
- **Medium impact:** the overlay makes file-state and execution-state decoding
  comparable while preserving the measured IDB inventory.
- **Low impact:** planning remains truncated; later writes, other inputs,
  physical x86-64 behavior and VM-state semantics are unknown.

QG1: technical scope. QG2: S1–S5 include falsification probes. QG3: API
contract, two IDA runs, two QEMU runs, negative controls and finite edge
comparison are covered; the wider review remains incomplete. QG4: byte,
instruction and head bounds plus complexity are explicit. QG5: synthetic
entry, debugger gaps, runtime bytes and complete CFG claims are separate.
QG6: exact hashes link primary binaries, dumps, source, reports, plugin and
tool versions in the evidence JSON. QG7: additional paths and semantic work
are bounded above.
