# Fixed-time Morok keygen static-analysis boundary

The source-controlled clean and packed keygen pair in
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md` has an exact five-case process oracle.
This checkpoint measures what a fresh IDA 9.4 SP1 database and the installed
Chernobog revision `74f8a0418536` identify at the corresponding startup and
application entry sites. No IDB item was created or retyped for measurement;
RAX execution was disabled.

The clean ELF entry is `0x40019b`. Its startup code loads `0x4002c0` at
`0x4001c5` as an immediate register value before its startup transfer. IDA
classifies `0x4002c0` as code and as the start of one function. The bounded
probe traversed 844 heads in that owner without reaching its 4,096-head cap.
The packed ELF entry is `0x40021b`. Its startup code loads `0x418440` at
`0x400245` in the corresponding position. The bytes at `0x418440` decode as
`PUSH RAX; CALL 0x4185f0; ...; JMP 0x430000` on the normal guarded route.
`0x430000` is the start of the 65,536-byte executable
`.v1ki223lk5mbtl` section. These file-byte observations locate the packed
application trampoline; they do not establish its runtime unpacked contents.

| Input and selected site | Heads, enabled / disabled | First IDA item | Owners | Native / VM / solver API at selected site |
|---|---:|---|---:|---|
| Clean `main`, `0x4002c0` | 844 / not measured | code, `sub_4002C0` | 1 | zero native records in enabled run |
| Packed application trampoline, `0x418440` | 1 / 1 | data, `qword_418440` | 0 | unavailable / unavailable / unavailable |
| Packed ELF startup, `0x40021b` | 47 / 47 | code, `start` | 2 | zero native and VM records; solver unavailable |

The packed enabled and disabled profiles use identical binary, plugin, IDA,
probe and selected addresses. Their instruction/owner inventories match
exactly at both selected sites; neither traversal was truncated, and read-only
inspection preserved code and xrefs. Both profiles report zero direct-jump
decode attempts and zero new targets. The packed application address is loaded
and decodable for one instruction but remains an IDA **data** item, with no
code xrefs or function owner. The native and VM evidence APIs therefore report
unavailable for that address. Empty records there are not a negative recovery
result. The clean/packed difference is an observed static-analysis boundary,
not an attribution of its cause to Chernobog or IDA alone.

`VMP_MOROK_KEYGEN_IDA_BOUNDARY_EVIDENCE.json` identifies the ignored raw
`run.json` and `corpus_inspection.json` files for the clean enabled, packed
enabled and packed disabled processes. It also records the executable, runner,
probe, IDA and plugin hashes. Reproduce the packed enabled profile and repeat
with `--set CHERNOBOG_DISABLE=1` in a new output directory:

```sh
python3 -B tests/run_ida_smoke.py \
  build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  tests/ida_vmp_corpus_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/morok-keygen-main-ida-reproduction \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set 'CHERNOBOG_CORPUS_ENTRIES={"corpus_transform":"0x418440","corpus_branch":"0x40021b"}'
```

The probe traverses at most 4,096 code heads per selected address and inspects
at most 64 function owners. With `H` visited heads and `X` outgoing xrefs,
traversal is `O(H + X)` time and `O(H + X)` retained space before owner API
work. Counts are exact integers; no SI physical quantity is inferred. The
bounded process runner records elapsed time separately in its raw manifests.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| B1 | The two fresh binaries represent the same source and fixed-time process contract. The clean/packed comparison depends on the paired-build hashes. | Rebuild from the recorded source, shim, config and tool hashes; rerun the five-case oracle. |
| B2 | The startup immediate values identify the application entry trampolines in these two files. The selected-site comparison depends on the observed startup bytes. | Independently disassemble both ELF entries and follow their startup transfers; trace runtime entry on a validated x86-64 engine. No general CRT rule is asserted. |
| B3 | A fresh IDA database under each profile reflects the selected static classification. The enabled/disabled comparison depends on matching environment and preserved read-only inventory. | Compare exact runner input/plugin/IDA/probe hashes, first-item flags, head arrays and owners; repeat with a second IDA version to test stability. |
| B4 | The packed application's file-backed executable section contains a runtime target, but its decrypted executed bytes are unknown. Any application-recovery claim depends on future capture. | Capture entry and post-unpack bytes in a validated runtime, map entered addresses to file and memory, then supply an independent edge oracle. |

**High impact:** the source-controlled packed application entry is classified
as data, so owner-based native/VM evidence cannot yet measure its recovery.
**Medium impact:** enabled and disabled profiles agree at this exact boundary;
the measured difference from the clean case precedes any supported recovery
rate. **Low impact:** the startup and section addresses provide precise targets
for a future runtime and decode experiment without asserting decrypted bytes.

QG1: technical scope. QG2: B1–B4 include falsification probes. QG3: the
selected-site comparison is complete; full application recovery remains open.
QG4: head and owner limits and complexity are explicit. QG5: one decodable
data item is distinguished from an IDA code head, and unavailable APIs are not
counted as negative findings. QG6: exact local binaries, probe, runner, IDA,
plugin and raw reports are hash-linked. QG7: runtime unpacking, causation and
complete protected-edge recovery remain bounded unknowns.
