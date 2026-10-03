# RDTSC native replay through garbage instructions

## Transfer and scope

The non-virtualizing garbage inventory in `docs/ATHENA_MAPPING.md` includes
`rdtsc`. Previously it reached the unsupported-instruction fallback and
erased the native abstract state. `State::step` now admits only the exact
two-byte `0F 31` encoding in 32- or 64-bit mode. It marks the low 32 bits
of EAX and EDX unknown, clears their high halves in long mode, and preserves
status flags, direction, unrelated registers, stack suffix and replay-local
memory. It never guesses counter values. Prefixed and unsupported-mode forms
retain the whole-state fallback.

Intel's [RDTSC instruction definition](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf),
Volume 2B, pages 4-545–4-546, specifies EDX:EAX output, cleared upper RAX/RDX
halves on Intel 64 processors, unchanged flags, possible #GP under CR4.TSD,
and #UD under `LOCK`. This local transfer describes normal completion only.
Execution of `RDTSC` in a supplied protected binary is unknown.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| TS1 | IDA 9.4 decodes the unprefixed `0F 31` as operand-free `NN_rdtsc` and exposes a locked form distinctly. Admission depends on exact decoding. | `tests/ida_rdtsc_probe.py` records opcode, size and prefix for nine fixture functions; locked length 3 abstains. |
| TS2 | The counter value is unconstrained by local replay. Negative result controls depend on this treatment. | Comparisons of EAX and EDX against zero yield no proof after `RDTSC`. |
| TS3 | RDTSC preserves status flags and unrelated state on normal completion. Four positive proofs depend on this rule. | Native x86 execution compares all six status bits under two prior flag patterns; IDA proves CF, ZF, one unrelated register and one disjoint local memory slot. |
| TS4 | Long-mode EAX/EDX writes clear the upper halves of RAX/RDX. Two additional proofs depend on this rule. | Native x86 tests inspect both high halves; IDA uses `BT` at bit 32 for each output while the low halves remain unknown. |
| TS5 | The analyzed path completes normally. Preserved-state conclusions depend on this scope. | Intel's CR4.TSD exception is recorded; no claim is made for a faulting instruction, other privilege configuration or counter timing. |

## Evidence

An x86-64 executable ran `RDTSC` under two initial status-flag patterns.
Both runs retained all six status flags and cleared the upper halves of
RAX/RDX. The fixture does not compare counter values across runs.

On an identical nine-function Mach-O fixture, the prior plugin published
zero fresh native `SETcc` proofs. The current plugin published six exact
one-valued proofs and abstained on unknown EAX/EDX values and a locked form.
Both isolated IDA runs used matching input, probe and IDA hashes and reported
unchanged artifacts. Source, executable, plugin, report and runner SHA-256
values and expected results are retained in
`VMP_RDTSC_GARBAGE_EVIDENCE.json`. The raw reports reside in ignored
`build/rdtsc-ida-baseline-1` and `build/rdtsc-ida-current-2` directories;
the handoff repeats the current production probe.

The original fixture checked zero extension by shifting the partly known
register right by 32 bits; that path abstained because the existing single
shift transfer discards partial known-bit information. The final fixture
checks bit 32 directly with the already validated `BT` transfer. This
distinguishes the RDTSC result from the separate partial-shift gap.

## Bounded impact and cost

| Impact | Observation |
| --- | --- |
| High | The earlier fallback erased unrelated register, flag and local memory facts; those facts now survive the exact RDTSC encoding. |
| Medium | The high halves of both output registers provide exact zero facts without constraining counter values. |
| Low | Faulting, prefixed and unsupported-mode forms abstain. Protected-binary occurrence and recovery gain are unknown. |

The transfer performs two bounded register writes and no memory reads,
memory writes or solver queries: `O(1)` time and space.

Quality gates: QG1 no normative content; QG2 TS1–TS5 and probes; QG3
flags, outputs, unrelated state, prefix and unknown-counter controls; QG4
32-bit halves and two-byte encoding checked; QG5 exceptions and the
partial-shift gap explicit; QG6 Intel primary source, native x86 execution
and matched IDA artifacts; QG7 bounded impact and remaining scope above.
