# XADD native replay through garbage instructions

## Transfer and scope

The garbage inventory in `docs/ATHENA_MAPPING.md` includes `xadd`. Previously,
`NN_xadd` reached the unsupported-instruction fallback and erased all native
abstract state. `State::step` now captures both operands and the destination
address before either write, adds the old values with the existing typed
addition transfer, writes the old destination to the source register, and
writes the sum to the destination. All six tracked status flags follow the
addition. Register slices retain unaffected bits; 32-bit writes in 64-bit
mode zero-extend. An exact local memory address invalidates only the written
byte range. An unresolved address invalidates the local memory map, and any
memory destination invalidates the separate stack suffix.

This matches Intel's [XADD instruction definition](https://cdrdv2-public.intel.com/789589/334569-sdm-vol-2d.pdf),
Volume 2D, page 6-23. The transfer covers 8-, 16-, 32-, and 64-bit operands
in 32- and 64-bit x86 modes. `LOCK` is admitted for a memory destination;
the register-destination `LOCK` encoding has no normal completion. Unsupported
prefixes and 16-bit execution mode retain the whole-state fallback. No claim
is made that an `XADD` instance has been entered in a particular supplied
protected binary; that occurrence is unknown.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| XA1 | IDA 9.4 exposes the destination and source as `Op1` and `Op2`, including register aliases and `LOCK`. The production transfer depends on this mapping. | `tests/ida_xadd_probe.py` records both decoded operand types and prefix flags for each of 18 exact fixture functions. |
| XA2 | Replay-local writable bytes arise only from prior modeled writes. The memory destination and disjoint-memory proofs depend on this scope. | `xa_memory` writes before `XADD`; `xa_preserve_disjoint_memory` leaves a separate slot provable after an unknown destination value. |
| XA3 | Each instruction reads its old operands before either write. Source/destination alias and address calculations depend on this ordering. | Same-register and `AH`/`AL` fixtures, a memory address held in the source register, and an independent x86-64 execution control. |
| XA4 | The local replay represents one normal-completion thread. The `LOCK` memory transfer depends on this bounded execution model. | `xa_locked_memory` proves the local result; `xa_locked_register` yields no proof. Concurrency histories are outside this local state model. |
| XA5 | An unknown operand does not determine an arbitrary sum. Predicate publication depends on this restraint. | `xa_unknown_destination` abstains, while known old destination values still reach the source register in two unknown-source fixtures. |

## Evidence

An x86-64 executable compared 131,456 `XADD` cases with independent instruction
execution: all 65,536 pairs of 8-bit values under two incoming flag patterns,
plus eight corner values per operand for each of 16-, 32-, and 64-bit widths.
Destination sum, exchanged source and all six defined status flags matched.
A separate same-register instruction confirmed the final sum.

On the same Mach-O fixture (SHA-256
`c01d014348768cd38d9ec48cb49f74736b92d2bd1c077d755f639fa2edbf5895`),
the prior plugin (SHA-256
`b07488540f467f592196cd247d73c5c7528707e0bd06ee420ffa64868e97680f`)
published zero `SETcc` proofs across 18 decoded functions. The new plugin
(SHA-256
`1f99b7beb4a5edc8487eae5b7d55191472fe634257acb52bd8dd8cd33d3d8832`)
published 16 exact one-valued proofs and abstained at the unknown destination
and illegal locked-register controls. The isolated runs used identical input,
probe, and IDA hashes, and both reported unchanged artifacts. The respective
raw IDA report SHA-256 values are
`46602b0678daf56a552be5e3cc9a5680cdf2d165bf026d37b4604c37e93a3548`
and `f932c0d127bd26fefe7ac6af5df65fa49f9e9521ccb5b0395fa718924c53b65d`.
The source, binary, tool, plugin, report and per-case hashes and results are
retained in `VMP_XADD_GARBAGE_EVIDENCE.json`. The full reports reside in ignored
`build/xadd-ida-baseline-1` and `build/xadd-ida-current-2` directories; the
handoff reruns the current proof.

The rebuilt plugin also passed the 15-case `SHLD`/`SHRD` regression, and all
23 CTest suites passed. `clang-format --dry-run --Werror` passed for the
changed C++ files; Black check mode passed for the IDA probe.

## Bounded impact and cost

| Impact | Observation |
| --- | --- |
| High | The previous fallback erased unrelated register and local memory facts. Current unknown-input fixtures prove one unrelated register and one disjoint local memory slot. |
| Medium | Two-write results, status flags, register aliases, memory destinations and valid locked memory now provide exact local predicates. |
| Low | 16-bit execution mode and unsupported prefixes remain abstentions. Protected-binary frequency and recovery gain are unknown. |

The two-input arithmetic transfer is `O(1)` time and space. For `M` tracked
local bytes and `K` erased entries, an exact memory invalidation is
`O(log M + K)`; at most 8 B are stored. Unknown-address invalidation can
erase all `M` entries.

Quality gates: QG1 no normative content; QG2 XA1–XA5 and probes; QG3
register/memory, alias, flag, prefix, and unknown-input forms; QG4 exact
widths and byte bounds; QG5 explicit alias, invalid-prefix, and unknown
controls; QG6 Intel primary source, native x86 execution, and matched IDA
artifacts; QG7 impact and remaining scope above.
