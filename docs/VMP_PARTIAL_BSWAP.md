# Partial-register BSWAP replay

## Transfer and scope

The bounded native state previously reversed a 32- or 64-bit BSWAP operand
only when every source bit was known. Unknown bits in a different byte erased
known bits that the instruction merely permutes. `byte_swap` now moves the
known and value masks byte by byte. The production replay reads the register
before writing its result, preserves all status flags and applies x86-64
zero extension to a 32-bit destination. It clears the stack suffix if the
destination aliases SP. The existing 16-bit undefined-result path remains
separate. LOCK-prefixed BSWAP has no normal successor state; the replay now
rejects it instead of carrying prior flags into a later condition proof.

Intel's [BSWAP instruction definition](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf)
specifies the byte permutation, unchanged flags, undefined 16-bit result,
32-bit default size in 64-bit mode, and #UD with LOCK. The change models
normal completion of 32- and 64-bit register forms in 32- or 64-bit execution
modes. It does not infer a VM decoder key, handler identity or protected
recovery gain.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| PB1 | Intel's BSWAP byte and flag rules hold for admitted forms. Every output-bit fact depends on them. | An independent bit-position oracle checks 48 partial patterns; 320 concrete completions compare results, flags and 32-bit zero extension with native x86 execution. A 16-bit request returns no value fact. |
| PB2 | A decoded operand is one exact 32- or 64-bit register and the current state contains independent known bits. Production proofs depend on this mapping. | Both IDA probes record instruction types, prefix and size under prior/current plugins on byte-identical binaries. Unknown source bits remain unresolved. |
| PB3 | The x86-64 fixture's RDTSC high zeros, BT/BTS facts and immediate AND facts are valid inputs to BSWAP. Three new long-mode condition proofs depend on their composition. | The matched eight-function IDA pair changes three cases from zero to one exact SETcc proof; two prior positive controls and two unknown-value controls remain unchanged. |
| PB4 | i386 32-bit BSWAP uses the same low-word byte permutation with independent input values. Two new i386 proofs depend on this mode mapping. | The matched four-function ELF pair changes two cases from unresolved to exact; an existing flag proof and unknown-value control remain unchanged. Native 32-bit BSWAP is also exercised in the x86-64 execution oracle. |
| PB5 | LOCK-prefixed BSWAP faults before the following SETcc. Rejection of a prior invalid proof depends on this rule. | An exact locked x86-64 fixture loses its prior SETcc proof. IDA did not admit the corresponding i386 locked bytes as a function; no i386 plugin proof claim is made for that encoding. |

## Evidence and bounds

The source-pinned certificate `VMP_PARTIAL_BSWAP_EVIDENCE.json` identifies the
source, executable, plugin, IDA, probe, report and runner SHA-256 values. The
raw x86-64 reports are in ignored `build/partial-bswap-ida-baseline-1` and
`build/partial-bswap-ida-current-1`; the i386 pair is in
`build/partial-bswap32-ida-baseline-3` and
`build/partial-bswap32-ida-current-3`. Each pair uses identical decoded
instructions and inputs. The x86-64 prior/current proof totals are three and
five, respectively: three new valid one-valued proofs, two preserved valid
proofs and one rejected locked-form proof. The i386 totals are one and three:
two new valid proofs, one preserved flag proof and one unresolved input
control. The full 23-suite CTest run passes.

The transfer visits four or eight bytes and uses constant-sized registers:
`O(1)` time and space for the architectural width limit. A high-potential
extension is to retain this known-bit information through VM decoder
arithmetic and a recovered logical-state contract; its protected effect is
unknown. The measured local proof gain is medium impact for the bounded
fixtures. The invalid-prefix correction is a low-frequency but direct
normal-completion soundness repair. i386 invalid-prefix function admission,
runtime exceptions and broader protected paths remain outside these pairs.

Quality gates: QG1 technical content only; QG2 PB1–PB5 and probes; QG3
32/64-bit results, flags, zero extension, i386/x86-64 production paths,
unknown inputs and invalid prefix; QG4 widths, finite counts and complexity
checked; QG5 undefined 16-bit result, abnormal completion and i386 decoder
limit explicit; QG6 Intel primary source, native x86 execution and paired
source-pinned IDA evidence; QG7 bounded adjacent opportunity and risk above.
