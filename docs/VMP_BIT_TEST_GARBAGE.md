# BT-family native replay through garbage instructions

## Transfer and scope

The garbage inventory in `docs/ATHENA_MAPPING.md` includes `bt`, `btc`,
`btr`, and `bts`. Previously these instructions reached the unsupported
instruction fallback and erased all native abstract state. `State::step` now
computes carry from the selected old bit, preserves ZF, and forgets the four
undefined status flags. `BTC`, `BTR`, and `BTS` also update the selected bit.
Register bit indices wrap modulo the operand width. For memory, a register
index is signed and selects a containing operand word; an immediate index
selects a bit in the given operand word. The model checks the whole addressed
word for readability and changes only its selected byte. An unresolved
modifying address invalidates the local memory map. Any memory modification
also invalidates the separate stack suffix.

These rules follow Intel's [BT-family instruction definitions and bit-string
addressing rule](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf),
Volume 2A, pages 3-11–3-12 and 3-130–3-137. The transfer covers 16-, 32-, and
64-bit operands in 32- and 64-bit x86 modes. `LOCK` is admitted for memory
`BTC`/`BTR`/`BTS`; locked `BT` and locked register forms have no normal
completion. Unsupported prefixes and 16-bit execution mode retain the
whole-state fallback. Whether any supplied protected binary executes one of
these instructions is unknown.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| BT1 | IDA 9.4 exposes the base as `Op1`, bit index as `Op2`, and `LOCK` in `auxpref`. Production transfer depends on this mapping. | `tests/ida_bit_test_probe.py` records decoded opcodes, operand types and widths, and prefixes for 19 fixture functions. |
| BT2 | A register index wraps within the register, while a signed memory register index selects a possibly preceding word. Register and memory results depend on this split. | 12,288 native register cases, 6,218 native memory cases, and the positive/negative memory-index IDA fixtures. |
| BT3 | Prior modeled writes supply replay-local memory bytes. Exact memory proofs depend on this domain. | The fixture writes each slot before use, probes a disjoint slot, and checks unknown-index abstention. |
| BT4 | `BT` leaves ZF unchanged and only CF is defined after a bit operation. Flag proofs depend on this definition. | Native x86 flag comparisons and `bt_register_zero_preserved`; the oracle compares every claimed flag. |
| BT5 | A locked memory bit change is represented as one completed local instruction. The locked-memory proof depends on this bounded execution model. | `btc_locked_memory` proves the resulting byte; locked `BT` register and memory forms yield no proof. Concurrent histories are outside this local state model. |
| BT6 | An unknown register index may still yield an invariant fact; a nonuniform selected bit does not determine CF. | `bt_register_unknown_uniform` proves CF=0, while `bt_unknown_offset` and `bts_unknown_memory_offset` abstain. |

## Evidence

An x86-64 executable compared 12,288 register cases and 6,218 memory
cases against executed `BT`, `BTC`, `BTR`, and `BTS` instructions. Register
results and every claimed flag matched. Memory results, CF and preserved ZF
matched for signed offsets −129 through 129 bits at all three widths. Two raw
high-immediate cases confirmed selection in the base operand word. A separate
portable test checks signed containing-word displacement and immediate
index handling.

On an identical Mach-O fixture, an earlier plugin published zero fresh native
`SETcc` proofs across 19 decoded functions. The current plugin published 15
exact one-valued proofs and abstained for two unknown-index cases and two
invalid locked `BT` forms. Both isolated IDA runs used the same input,
probe, and IDA hashes and reported unchanged artifacts. Source, executable,
plugin, report, and runner SHA-256 values, plus each expected case result,
are retained in `VMP_BIT_TEST_GARBAGE_EVIDENCE.json`. The raw reports reside
in ignored `build/bit-test-ida-baseline-2` and `build/bit-test-ida-current-4`;
the handoff repeats the current production probe.

## Bounded impact and cost

| Impact | Observation |
| --- | --- |
| High | The earlier fallback erased unrelated native facts; a bit operation can now preserve a disjoint local memory slot. |
| Medium | Register and memory forms, signed word addressing, aliasing, carry, preserved ZF and valid locked memory can produce exact predicates. |
| Low | Unknown memory indices still erase modeled memory on a modifying operation. Protected-binary occurrence and recovery gain are unknown. |

For a known bit index, the pure transfer is `O(1)` time and space. For an
unknown register index it joins at most `W` bit positions, where `W` is 16,
32, or 64, using `O(W)` time and `O(1)` extra space. For `M` tracked local
bytes and `K` erased entries, exact memory invalidation costs
`O(log M + K)`; unknown-address invalidation can erase all `M` entries.

Quality gates: QG1 no normative content; QG2 BT1–BT6 and probes; QG3 four
opcodes, register/memory, aliases, flags, prefixes and unknown operands; QG4
operand and byte widths checked; QG5 signed indices and invalid `LOCK` forms
covered; QG6 Intel primary source, x86 execution and matched IDA artifacts;
QG7 bounded impact and remaining scope above.
