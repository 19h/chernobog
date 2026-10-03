# BSF/BSR native replay through garbage instructions

## Transfer and scope

The non-virtualizing garbage inventory in `docs/ATHENA_MAPPING.md` includes
`bsf` and `bsr`. Previously these instructions reached the unsupported
instruction fallback and erased the native abstract state. `State::step` now
captures the source before writing the destination, scans for the first set
bit in the specified direction, defines ZF from the source, and forgets the
other five tracked status flags. A known nonzero source with unknown earlier
bits establishes ZF=0 without inventing an exact bit index. A zero or
possibly zero source leaves the entire destination unknown: a 32-bit
zero-extension fact is admitted only when nonzero completion is guaranteed.
Exact replay-local memory bytes can supply the source; the operation does not
write memory.

Intel's [BSF and BSR definitions](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf),
Volume 2A, pages 3-124–3-128, define the destination as undefined for a
zero source, define ZF, leave CF/OF/SF/AF/PF undefined and reject `LOCK`.
The transfer covers 16-, 32-, and 64-bit operands in 32- and 64-bit x86
modes. Unsupported prefixes and 16-bit execution mode retain the whole-state
fallback. Whether an instance executes in a supplied protected binary is
unknown.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| BS1 | IDA 9.4 decodes the register destination, register or memory source, widths and prefixes as inspected. Production transfer depends on this mapping. | `tests/ida_bit_scan_probe.py` records the decoder form for 18 fixture functions, including 16-, 32-, 64-bit, memory and locked forms. |
| BS2 | A zero source has undefined destination but ZF=1. Destination abstention and zero-flag proof depend on this distinction. | `bs_zero_flag` proves ZF; `bs_zero_destination` yields no destination-derived proof. The portable test erases the result on zero. |
| BS3 | A nonzero bit may fix ZF without fixing the scan index when earlier bits are unknown. Partial-source proof depends on this invariant. | A preceding `BTS` fixes one bit in an otherwise unknown source; `bs_partial_nonzero` proves ZF=0, while unit controls with unknown earlier bits leave the index unknown. |
| BS4 | Local memory source bytes originate from prior modeled writes. Memory-index proofs depend on this scope. | `bs_forward_memory` and `bs_reverse_memory` write before reading; `bs_preserve_disjoint_memory` checks an unrelated slot after an unknown register source. |
| BS5 | A nonzero 32-bit result clears the upper register half in long mode; a possibly zero result does not justify this fact. The zero-extension proof depends on nonzero admission. | `bs_zero_extend` proves the entire 64-bit register; zero and unknown source controls abstain on the destination. |
| BS6 | Locked BSF/BSR encodings have no normal completion. Prefix handling depends on this instruction definition. | Locked register and memory fixtures decode with `LOCK` and yield no proof. |

## Evidence

An independent x86-64 executable compared 3,168 `BSF`/`BSR` cases across
16-, 32-, and 64-bit widths and two initial flag patterns. Every nonzero
destination and defined ZF result matched native instruction execution.
Zero-source tests compared ZF and deliberately made no claim about the
undefined destination. Portable tests cover partial known-bit sources and
both scan directions.

On the same 18-function Mach-O fixture, the prior plugin published zero
fresh native `SETcc` proofs. The current plugin published 13 exact
one-valued proofs and abstained for five zero-destination, unknown-source
or invalid-prefix controls. Both isolated IDA runs used matching input,
probe and IDA hashes and reported unchanged artifacts. Source, executable,
plugin, report and runner SHA-256 values, plus each expected case result,
are retained in `VMP_BIT_SCAN_GARBAGE_EVIDENCE.json`. The raw reports reside
in ignored `build/bit-scan-ida-baseline-1` and
`build/bit-scan-ida-current-1`; the handoff repeats the current production
probe.

## Bounded impact and cost

| Impact | Observation |
| --- | --- |
| High | The previous fallback erased unrelated register and local memory facts; a bit scan now preserves both through an unknown source. |
| Medium | Exact register and memory sources produce an index and ZF; a known set bit can produce ZF even when the index is unresolved. |
| Low | Zero-source destinations, unresolved indices, unsupported prefixes and unmodeled memory remain abstentions. Protected-binary occurrence and recovery gain are unknown. |

The pure scan visits at most `W` bits for operand width `W ∈ {16, 32, 64}`:
`O(W)` time and `O(1)` extra space. Exact local memory reads cost `O(W/8)`
byte lookups, bounded by 8 B. No memory write or general solver query is
introduced.

Quality gates: QG1 no normative content; QG2 BS1–BS6 and probes; QG3 two
directions, three widths, aliases, memory, flags, partial values, prefixes
and zero/unknown controls; QG4 widths and byte bounds checked; QG5 zero
destination and upper-half ambiguity explicit; QG6 Intel primary source,
native x86 execution and matched IDA artifacts; QG7 bounded impact and
remaining scope above.
