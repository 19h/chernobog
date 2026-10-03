# Partial-register SHL, SHR and SAR replay

## Transfer and admission

The RDTSC fixture exposed a separate native-analysis gap: the low 32 bits of
RAX/RDX are unknown while the high 32 bits are known zero. A 64-bit right
shift by 32 must therefore produce an exact zero, but the previous
whole-register shift transfer discarded the known high bits. The new
`partial_shift` transfer moves individual known bits through SHL, SHR and SAR
for an exact masked count. It records zero bits shifted in by SHL/SHR and
copies a known sign bit for SAR. It derives CF, OF, SF, ZF and PF only when
their defining bits are known; AF remains unknown for a nonzero count.
Masked-zero counts preserve all input and flag facts. The IDA state uses the
partial transfer for a register destination and an exact immediate or CL
count. An unknown count retains the prior conservative whole-result behavior.
LOCK-prefixed shifts clear the analysis state because their normal successor
does not exist.

Intel's [SAL/SAR/SHL/SHR instruction definition](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)
specifies 5-bit count masking for 8/16/32-bit operands, 6-bit masking for
64-bit operands, zero-count flag preservation, undefined AF for nonzero
counts, CF undefined for SHL/SHR counts at or beyond operand width, and #UD
for LOCK. The transfer covers normal completion in 32- and 64-bit execution
modes. Protected-binary occurrence and a recovery-rate gain are unknown.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| PS1 | Intel's documented shift result and status-flag rules apply to the admitted x86 execution modes. Every derived bit depends on these rules. | Compare 148,104 matching 8-bit concrete inputs and initial flag profiles with native x86 execution; test counts 0, 1, width, over-width and masked zero. |
| PS2 | The IDA operand is an exact immediate or the low CL byte when the partial transfer runs. Live proof counts depend on this admission. | The IDA probe records every decoded instruction and compares identical input bytes and decoding under prior/current plugins. An unknown CL count produces no proof. |
| PS3 | RDTSC clears the upper halves of RAX/RDX while leaving their low halves unknown. Six new fixture proofs depend on this partial input. | Right-shift both outputs, shift a known zero in from the left, and propagate known zero/one sign bits through SHR/SAR. Comparisons involving remaining unknown low bits abstain. |
| PS4 | Only defined flags are used as facts. Derived condition proofs depend on this restriction. | Native x86 flag comparisons check each claimed bit; over-width logical-shift CF and unknown source CF remain unknown. |
| PS5 | A LOCK-prefixed shift has no normally completing successor. The invalid-prefix negative depends on this rule. | Decode the five-byte locked SHR in IDA and require no SETcc proof after it. |

## Evidence and bounds

Portable concretization checks cover 14,400 completions at 8, 16, 32 and
64 bits. Native x86 checks cover 148,104 matching 8-bit inputs with two
initial flag profiles. Both counts are exact integer enumerations. The full
23-suite CTest run passes.

Two isolated IDA 9.4 runs analyze the same 11-function Mach-O binary and
probe with unchanged artifacts. The prior plugin produces one existing
masked-zero-count proof; the new plugin produces that proof and six additional
one-valued SETcc proofs. Four controls for unknown low bits, count, carry and
LOCK prefix remain without a proof. Source, executable, plugin, report and
runner hashes and the raw-pair verifier are in
`VMP_PARTIAL_SHIFT_EVIDENCE.json`; ignored raw reports are in
`build/partial-shift-ida-baseline-1` and `build/partial-shift-ida-current-2`.
This is a bounded native transfer result, not protected-corpus effectiveness.

The transfer touches one 64-bit word and six tracked status flags, using
`O(1)` time and space. Higher-impact opportunities are known-bit movement
through additional arithmetic operators and actual protected predicate
coverage; both remain unmeasured. A lower-impact risk is the lack of a
normally completing state after invalid prefixes; the locked control
abstains.

Quality gates: QG1 no normative content; QG2 PS1–PS5 and probes; QG3 three
shift operations, count classes, flags, production proof and negative cases;
QG4 bit widths, masks and exact case counts checked; QG5 undefined flags,
unknown operands/counts and invalid prefix explicit; QG6 Intel primary source,
native x86 execution and source-pinned paired IDA artifacts; QG7 bounded
impact, cost and remaining scope above.
