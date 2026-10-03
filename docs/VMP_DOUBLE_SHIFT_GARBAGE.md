# SHLD/SHRD native replay through garbage instructions

## Scope and result

The garbage-insertion inventory in `docs/ATHENA_MAPPING.md` includes `SHLD` and `SHRD`.
Previously, both reached the unsupported-instruction fallback in `State::step`, which erased
all register, memory, and flag facts. The new transfer models 16-, 32-, and 64-bit operand
forms in 32- or 64-bit x86 modes, for register and memory destinations. It retains facts
unaffected by the instruction. It does not establish that either instruction occurs in a
specific protected Morok or VMP path; that observation is unknown.

The transfer follows Intel's [SHLD and SHRD instruction definitions](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf),
Volume 2B, pages 4-611 through 4-616. The count is masked to 5 bits, or 6 bits for a
64-bit operand. A masked zero leaves destination and six status flags unchanged. A count
greater than a 16-bit operand's width makes its destination and status flags unknown.
For a positive defined count, the transfer derives known destination bits and `CF`,
`SF`, `ZF`, and `PF` independently; it derives `OF` only for count one and forgets `AF`.

An unknown count makes the destination and status flags unknown. For a 32-bit register
destination in 64-bit mode, the transfer joins the possible unchanged upper half with
the zero-extended written upper half. A memory destination invalidates only its exact
local byte range when its address is known. Unsupported operand forms and prefix
combinations retain the existing whole-state fallback. A `LOCK` prefix has no normal
completion under the cited instruction definitions.

## Assumption register and falsification probes

| ID | Assumption | Dependent result | Falsification probe |
| --- | --- | --- | --- |
| DS1 | IDA 9.4 exposes destination, source, and count as `Op1`, `Op2`, and `Op3`. | Operand transfer. | `tests/ida_double_shift_probe.py` records one decoded instruction and all three operand types for each of 15 fixture functions. |
| DS2 | A local memory value is known only after a write within the replay. | Memory destination result and disjoint preservation. | `ds_memory` writes before shifting; `ds_preserve_disjoint_memory` shifts one slot with unknown count and proves the other slot. |
| DS3 | x86-64 execution gives the architectural result and defined status flags for the selected cases. | Native oracle comparison. | Compile `tests/x86_abstract_tests.cpp` for x86-64 and execute its 127,008 double-shift cases with two incoming flag patterns. |
| DS4 | The count may be zero when `CL` is unknown. | Upper-register join and no invented predicate. | `ds_unknown_count_upper` must publish no `SETcc` value. |

## Verification

- `clang-format --dry-run --Werror` passed for the three C++ files.
- The portable abstract test executable passed on arm64.
- The x86-64 executable passed 127,008 native `SHLD`/`SHRD` cases across widths 16, 32, and 64 bits, both directions, masked counts 0 through 255, and two initial flag patterns. Counts beyond a 16-bit operand width were excluded from equality checks because the instruction result is undefined.
- The IDA 9.4 probe passed 15 decoded fixture functions: 12 exact `SETcc` proofs and three deliberate abstentions. The isolated smoke runner reported unchanged binary, script, plugin, and IDA artifacts.

The fixture binary SHA-256 was
`a37fb7a2cbea4f44e72a38794648f6e4c5a872027e3f1d22689dcfeda24a95c3`.
The tested plugin SHA-256 was
`b07488540f467f592196cd247d73c5c7528707e0bd06ee420ffa64868e97680f`.
These identify the local pre-commit check; the post-install check is performed by
`build/finish-double-shift.sh` in the regular Terminal handoff.

## Bounded impact

| Impact | Observation |
| --- | --- |
| High | An unsupported `SHLD`/`SHRD` previously erased unrelated facts in a replay. The unknown-count fixtures now retain a separate register and a separate local memory slot. |
| Medium | A locally stored memory destination can now produce an exact subsequent `SETcc` value. |
| Low | 16-bit execution mode remains outside this transfer. It retains the existing abstention. |

Time and space for the pure 64-bit transfer are `O(1)`. A tracked memory write touches
at most 8 B and uses the existing ordered map; invalidation is `O(log M + K)` for `M`
tracked bytes and `K` erased entries.

Quality gates: QG1 no normative content; QG2 DS1–DS4; QG3 instruction forms and
bounded exclusions above; QG4 bit widths, count masks, and 8 B maximum local write;
QG5 zero, unknown, and oversized count controls; QG6 Intel primary source plus native
execution and IDA decoder; QG7 impact table.
