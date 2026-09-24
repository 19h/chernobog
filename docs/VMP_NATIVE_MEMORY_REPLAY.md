# Morok native replay from observed entry memory

This checkpoint supplies the native candidate at `0x430000` with the
protected process's own entry data and stack bytes. It extends
`VMP_NATIVE_ENTRY_REPLAY.md` and `VMP_NATIVE_BOUNDARY_MEMORY.md` on the same
fixed-seed Morok keygen valid-input path. The two protected ELF64 files and
their 65,536-byte unpacked executable dumps are byte-identical across runs.
The supplied keygen sample remains a distinct artifact.

The separate read-only IDC API
`chernobog_vm_trace_candidate_shadow_replay_memory(root, seed, request)`
accepts the existing executable shadow, 16 entry GPRs, RFLAGS and 128 bytes
at and above entry RSP. It adds 1,024 bytes below entry RSP and a bounded
caller-observed writable data window. The request marks every 8-byte stack
word and GPR within ±32,768 bytes of observed RSP; the emulator translates
only those marked fields to its isolated scratch stack. The data overlay is
limited to at most 4,096 bytes in contiguous, readable, writable,
nonexecutable x86-64 image segments. It marks previously unloaded BSS bytes
as loaded in the ephemeral image. No IDA database bytes, items, names,
functions or cross-references are published by this API.

For this fixture, the data window is `[0x444000, 0x4446a0)` and the stack
window is `[entry RSP−1,024, entry RSP+128)`. Their lengths are
`1,696 + 1,024 + 128 = 2,848` bytes per run. Of the 1,696 observed data
bytes, 128 lie beyond the ELF's file-backed extent. The replay marks those
128 bytes loaded; 736 image bytes differ from the IDA snapshot before the
overlay. The replayed RSP and observed RSP both have page offset `0xc18`.
The request explicitly translates three GPRs, 11 words below RSP and seven
words at or above RSP. Missing a required word annotation, omitting the data
field or targeting executable bytes is rejected.

Both fresh IDA captures execute 4,096 candidate instructions and stop before
`0x40c89b` at the instruction budget. Each aligns with 4,094 QEMU/GDB
reported instruction entries after the same two bounded debugger gaps at
`0x40d63f` and `0x40c1a2`. After reversing the explicit stack translation,
all 16 GPRs match at all aligned entries: `4,094 × 16 = 65,504` exact values
per run, `131,008` across two runs. RIP matches by the aligned path. Full
intermediate RFLAGS match at `3,401/4,094` entries per run; the other 693
entries remain mismatched. The comparison does not infer full architectural
state equivalence from the GPR result.

At the boundary, all 16 GPRs, RIP and RFLAGS match: 18 exact scalar values
per run. Applying the candidate's seven final write ranges to the *same
protected process's* observed entry windows reproduces all 2,848 observed
boundary bytes per run, or 5,696 byte comparisons across the pair. These
same-process boundary observations are independent of the earlier QEMU/GDB
intermediate-register processes. The entry data buffers are identical across
the two boundary runs. A one-bit mutation at entry data offset `0x684`
changes the first read at `0x444684` from zero to one and the bounded stop
from `0x40c89b` to `0x40d636` in both IDA runs. One-bit final-write and
boundary-register mutations also invalidate their comparisons. The full
database inventory digest is unchanged after the normal and mutation probes.

This establishes a bounded replay from the recorded entry windows, an exact
GPR path at the aligned entries and an exact captured boundary projection.
Intermediate RFLAGS at 693 entries, intermediate memory outside the recorded
windows, later execution and other inputs remain unverified. The native plan
is truncated. No logical VM state identity or ordinary function evidence is
asserted.

## Reproduction and cost

The two raw QEMU/GDB boundary files and earlier 4,096-entry register files
are recorded in `VMP_NATIVE_BOUNDARY_MEMORY.md` and
`VMP_NATIVE_ENTRY_REPLAY.md`. Run
`tests/ida_native_shadow_replay_memory_probe.py` with `tests/run_ida_smoke.py`
once per protected binary, setting `CHERNOBOG_SHADOW_FILE`,
`CHERNOBOG_SHADOW_SHA256` and `CHERNOBOG_BOUNDARY_FILE` to the matching
first or second artifacts. The accepted IDA reports are
`build/ida-shadow-memory-replay-commit-{first,second}/shadow_memory_replay.json`.
The independent verification command is:

```sh
python3 -B tests/verify_native_shadow_memory_replay.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --input build/morok-runtime-probe/valid.stdin \
  --shadow build/morok-runtime-probe/packed-first.bin \
  --second-shadow build/morok-runtime-probe/packed-second.bin \
  --first-ida build/ida-shadow-memory-replay-commit-first/shadow_memory_replay.json \
  --second-ida build/ida-shadow-memory-replay-commit-second/shadow_memory_replay.json \
  --first-runtime build/morok-runtime-probe/packed-entry-state-first-4096.json \
  --second-runtime build/morok-runtime-probe/packed-entry-state-second-4096.json \
  --first-boundary build/morok-runtime-probe/packed-boundary-memory-final-first.json \
  --second-boundary build/morok-runtime-probe/packed-boundary-memory-final-second.json \
  --output build/morok-runtime-probe/shadow-memory-replay-commit-verification.json
```

For binary/report bytes `B`, planned heads `H ≤ 16,384`, aligned entries
`I = 4,094`, scalar registers `R = 16`, retained memory events `D = 320`,
captured window bytes `W = 2,848` and image segments `S`, verification uses
`O(B + H + I × R + D + W)` time and space. The bounded data overlay uses
`O(W × S)` worst-case lookup time and `O(W)` additional bytes. The two IDA
processes each took approximately 5.09 s wall time in the isolated runner;
this includes IDA startup and is not an emulation throughput measurement.
All source, artifact and runner hashes are in
`VMP_NATIVE_MEMORY_REPLAY_EVIDENCE.json`.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The hashed binary, stdin, executable shadow and QEMU entry observations identify the same protected valid-input path. All cross-tool comparisons depend on this pairing. | Rehash every artifact; compare QEMU entry PC, executable bytes and input hash; reject mismatched pairs. |
| R2 | The QEMU/GDB entry and boundary reads occur before the stated instruction at each stop. The 18 boundary scalar and 2,848 window comparisons per run depend on this timing. | Repeat with an independent tracer or direct x86-64 debugger and compare snapshots at the same PCs. |
| R3 | Values within ±32,768 bytes of observed entry RSP that are explicitly marked as 8-byte words are stack addresses. The normalized GPR and stack comparisons depend on this classification. | Omit one annotation and require rejection; mutate a nonpointer value into the relative range and require classification review. |
| R4 | The two debugger entry omissions are the previously bounded linear successors. The 4,094-entry alignment depends on this model. | Directly observe both retirements; a predecessor byte or successor mismatch invalidates alignment. |
| R5 | The captured data and stack windows include the memory relevant to the claimed boundary projection. The 5,696-byte result is limited to those windows. | Capture a wider window, add a different input, or compare all QEMU writes; any outside-window effect narrows the result. |
| R6 | A sampled entry data byte reaches a real emulator read. The mutation control depends on its address and initial zero. | Flip bit zero at `0x444684`; require the read to become one and the bounded path to change. |

- **High impact:** the emulator now starts this bounded protected prefix with
  the observed 1,696 data bytes and 1,152 stack bytes after declared pointer
  translation, including 128 data bytes that were unbacked in the IDA
  snapshot.
- **Medium impact:** 131,008 aligned intermediate GPR values and 5,696
  boundary window bytes match across the two protected runs.
- **High impact risk:** 693 intermediate RFLAGS mismatches per run constrain
  any larger architectural-state-equivalence claim.
- **Low impact:** the unchanged IDB inventory covers only the measured item,
  reference, segment, name, function and byte state; other IDA internals are
  outside that digest.

QG1: technical scope. QG2: R1–R6 state dependencies and falsification probes.
QG3: entry overlay, path, GPR, boundary, mutation and database checks are
covered; the complete review remains in progress. QG4: address intervals,
byte counts, instruction limits and complexity are explicit. QG5: RFLAGS
mismatches and debugger gaps are reported separately from exact comparisons.
QG6: local source, binary, tool and raw-report hashes are in the evidence
JSON. QG7: other inputs, outside-window memory, later execution and logical
VM identity remain bounded unknowns.
