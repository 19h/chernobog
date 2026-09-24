# Morok protected boundary memory comparison

This checkpoint extends `VMP_NATIVE_ENTRY_REPLAY.md` with an independent
protected-process memory observation at the 4,096-instruction candidate stop
PC `0x40c89b`. It uses the same two byte-identical, fixed-seed Morok keygen
ELF64 builds, 35-byte valid stdin and 65,536-byte packed-entry dump. The
supplied keygen ELF remains a separate binary.

`tests/morok_qemu_packed_boundary_memory.py` stops the protected QEMU process
at `0x430000`, records its registers and two memory windows, then takes at
most 4,096 GDB `stepi` requests until the first `0x40c89b` entry. It records
every reported PC and 16-byte instruction window before a step, then reads
the same memory windows and all scalar registers at the boundary. The data
window is `[0x444000, 0x4446a0)`, 1,696 bytes. The stack window is
`[entry RSP−1,024, entry RSP+128)`, 1,152 bytes. The two disjoint windows
contain `1,696 + 1,152 = 2,848` bytes per process.

Both fresh protected processes report exactly 4,094 instruction entries
before `0x40c89b`. Every PC and 16-byte window agrees with its earlier
same-binary GDB register trace. The two bounded debugger observation gaps
remain at `0x40d63f` and `0x40c1a2`; the candidate's prior alignment and
linear-successor checks still cover them. All 16 boundary general-purpose
registers, RIP and RFLAGS match the candidate's final register record after
translating stack-relative addresses: 18 exact scalar values per run, 36
across the pair. Unlike the earlier replay capture, these processes start
with `RSP mod 4,096 = 0xc18`, while the candidate uses `0xbe8`. The
boundary result is an observed finite-path comparison across that page-offset
change; intermediate scalar states were not re-sampled in these processes.

The candidate records 68 write events. Their byte-address union equals the
142 addresses in seven disjoint `final_writes` ranges. Three 8-byte stack
words hold addresses within the candidate's ±32,768-byte stack-relative
window; the verifier translates only those words. It copies the *independent
protected process's own entry bytes* into two buffers, applies the candidate's
final write values at their observed addresses, and compares the resulting
2,848 bytes with the protected process's boundary memory. All bytes match in
each run: `2 × 2,848 = 5,696` exact byte comparisons. In each process, 50
data bytes and 41 stack bytes actually change between its entry and boundary
snapshots. A one-bit final-write mutation, removal of a write range, and a
one-bit boundary `RAX` mutation, and removal of stack-pointer translation
each make the verifier reject the result.

The process's data at entry already differs from the ELF file mapping:
608 of the 1,568 file-backed bytes in the captured data window differ, and
15 of the remaining 128 bytes beyond the file-backed extent are nonzero.
Thus the 5,696-byte result proves **boundary reconstruction using observed
entry memory plus candidate writes**. It does not establish that Chernobog's
emulation began with identical data memory, that every intermediate read
observed the same value, or that memory outside the two windows agrees.
The native plan remains truncated and stops at the instruction budget;
logical VM state and ordinary function evidence are separate contracts.

## Reproduction and cost

Capture each protected process under the pinned container/image and
QEMU/GDB versions in `VMP_NATIVE_ENTRY_REPLAY.md`, using
`tests/morok_qemu_packed_boundary_memory.py` as the GDB script and
`CHERNOBOG_PACKED_BOUNDARY_MEMORY_OUTPUT` as its unique output path.
The accepted raw reports are
`build/morok-runtime-probe/packed-boundary-memory-final-{first,second}.json`.
The independent comparison runs as follows:

```sh
python3 -B tests/verify_native_shadow_boundary_memory.py \
  --binary build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  --second-binary build/morok-keygen-evidence-final/protected-second/int_woma_keygen-linux-x86_64-static \
  --input build/morok-runtime-probe/valid.stdin \
  --shadow build/morok-runtime-probe/packed-first.bin \
  --second-shadow build/morok-runtime-probe/packed-second.bin \
  --old-first-ida build/ida-shadow-16384-first/shadow_trace.json \
  --old-second-ida build/ida-shadow-16384-second/shadow_trace.json \
  --first-ida build/ida-shadow-replay-final-first/shadow_replay.json \
  --second-ida build/ida-shadow-replay-final-second/shadow_replay.json \
  --first-runtime build/morok-runtime-probe/packed-entry-state-first-4096.json \
  --second-runtime build/morok-runtime-probe/packed-entry-state-second-4096.json \
  --first-boundary build/morok-runtime-probe/packed-boundary-memory-final-first.json \
  --second-boundary build/morok-runtime-probe/packed-boundary-memory-final-second.json \
  --output build/morok-runtime-probe/boundary-memory-final-verification.json
```

For input bytes `B`, planned heads `H ≤ 16,384`, reported steps
`I = 4,096`, retained data events `D = 320` and captured window bytes
`W = 2,848` per run, the verifier's hashing, path alignment, write-coverage
and projection work is `O(B + H + I + D + W)` time and space. This excludes
the protected process and debugger. The two GDB step loops' nanosecond
durations and all source, tool and raw-report SHA-256 values are in
`VMP_NATIVE_BOUNDARY_MEMORY_EVIDENCE.json`; these timings exclude container
setup and are not plugin-performance measurements.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| M1 | The hashed pair, stdin and entry dump identify one protected path. All cross-run comparisons depend on this identity. | Rehash the artifacts and reject any changed binary, input or dump; keep the supplied keygen ELF distinct. |
| M2 | GDB's memory/register reads occur at the stated pre-instruction entry and boundary stops. The 36 scalar and 5,696 byte comparisons depend on this timing. | Repeat with an independent tracer or physical x86-64 debugger; perturb the stop PC and require path rejection. |
| M3 | The two omitted debugger entries are the earlier bounded observation gaps. The 4,094-step alignment depends on that model. | Directly observe retirement at both sites; a different predecessor byte or successor invalidates the alignment. |
| M4 | Only values within ±32,768 bytes of the candidate entry `RSP` and explicitly represented as 8-byte words are translated as stack pointers. The three normalized word comparisons depend on this mapping. | Disable translation and require a byte mismatch; extend the path beyond the window and reclassify if needed. |
| M5 | The seven candidate final ranges cover all 68 retained writes in the two windows. Full-window reconstruction depends on this finite coverage. | Require equality of write-event and final-range byte-address unions; remove one range or mutate one byte and require rejection. |
| M6 | The observed entry windows are a valid baseline for the *same* protected process's boundary windows. The 5,696 byte claim depends on this pairing. | Cross-pair entry and boundary windows from different processes or capture another path/input; any mismatch rejects the paired result. |

- **High impact:** the candidate's finite protected prefix now has an
  independently checked 2,848-byte boundary projection per run.
- **Medium impact:** a different process stack page offset still yields exact
  final scalar and translated stack-word agreement on the same PC path.
- **Low impact:** initial data differs from the file mapping and emulator
  initial-memory equivalence remains unverified; other memory and VM state are
  outside these windows.

QG1: technical scope. QG2: M1–M6 include falsification probes. QG3: two
fresh QEMU captures, exact path/byte alignment, register and window checks,
coverage and mutation controls are present; the complete review remains in
progress. QG4: address intervals, byte totals, step limits and complexity
are explicit. QG5: the observed initial-memory difference and page-offset
change are separated from the finite boundary agreement. QG6: local source,
binary, tool and report hashes are recorded in the evidence JSON. QG7:
other inputs, outside-window memory and VM identity remain bounded unknowns.
