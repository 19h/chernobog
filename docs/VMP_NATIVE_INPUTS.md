# Explicit input objects for native-region observations

This checkpoint adds `chernobog_vm_trace_input(ea, seed, input_json)` to the
separate native-region capture API. Specified pointer arguments now refer to
initialized scratch objects. The paired original and mutation routines complete
under these inputs; virtualization and combined protection still stop at
explicit native-region boundaries. This is input-specific execution evidence,
not a universal summary or a logical VM ownership decision.

Primary implementation: `src/hybrid/emu_input.hpp`,
`src/hybrid/emu_driver.cpp`, `src/vm/ida_native_trace.cpp`, and
`src/plugin/idc_api.cpp`. Primary fixture/oracle sources:
`tests/vmp_corpus/pair.S`, `tests/vmp_corpus/pair32.S`,
`tests/vmp_corpus/pair.c`, and `tests/run_vmp_corpus.py`.
SHA-256 provenance and accepted artifact identities are recorded in
`VMP_NATIVE_INPUTS_EVIDENCE.json`. Earlier checkpoints retain their historical
source/build identities; this change does not retroactively update them.

## Input and observation contract

The JSON request has exactly two fields. Scalar arguments are unsigned
hexadecimal strings, avoiding JSON floating-point conversion and signed IDC
integer ambiguity. An object replaces a zero placeholder in the positional
argument array. Its pointer is the allocated object address plus `offset`:

```json
{"args":["0x1","0x2","0x0"],"objects":[{"argument":2,"offset":4,"bytes":"a5a5a5a5000000005a5a5a5a"}]}
```

The existing ABI policy places arguments in x64 SysV/Windows registers or
i386 stack slots. Production coverage here is x64 SysV and i386 cdecl; explicit
object coverage on Windows is unknown. Values exceeding 32 bits are rejected
on i386 through the IDC input API. Existing C++ scalar-input behavior is
unchanged. No pointer arguments are inferred from disassembly or seed values.

Requests are limited to 140,000 bytes, nesting depth 8, 32 positional arguments,
16 objects, 4,096 bytes per object, and 65,536 initialized bytes in total.
Object data must be nonempty, even-length hexadecimal. The offset must identify
a byte inside the object. Duplicate object arguments, conflicting scalar
values, unknown/duplicate keys, malformed data, and unsupported types reject.
The C++ object path also rejects custom register/argument overrides, positional
offsets, and separate stack argument vectors, preventing competing ABI writes.

Objects occupy disjoint, 16-byte-aligned intervals in the existing scratch
mapping, beyond reserved entry artifacts and below the upper stack area.
Baseline restoration precedes initialization on every run. The region path
disables allocator/callee summaries, so these objects do not share a modeled
allocator. Ordinary function execution rejects object-bearing inputs and
ordinary function evidence continues to reject native-region observations.

The output adds `explicit_input`, `input_arguments`, `input_objects`,
`final_registers`, `final_registers_complete`, `sp_valid`, and `sp_delta`.
Each object records its argument index, interior offset, allocated address,
initial bytes, final bytes, and readback availability. Snapshots include bytes
that the executed program did not write. Original argument placeholders remain
visible in `input_arguments`; resolved pointers are observable in the entry
state and object address/offset records.

Final registers describe the stopped engine, including incomplete captures.
`final_registers_complete` means all requested scalar registers were readable;
it does not imply return, hardware equivalence, or execution beyond a boundary.
Likewise `data_trace_complete` describes the retained executed prefix.
Return, boundary, changed-code, and other stop indicators remain separate.

The initialized objects are byte ranges within mapped scratch memory, not
individually protected allocations. Reads/writes outside an object's extent
may still access mapped scratch memory. Guard-byte equality checks selected
memory effects; it does not establish absence of every out-of-range access or
exception equivalence. Pointer aliases between different supplied objects,
custom alignment, read-only objects, and arbitrary memory graphs are unsupported.

For request length L, A arguments, O objects, B initialized bytes, and R sampled
registers, added work is O(L + A + O log O + B + R) time and O(L + A + B + R)
space, excluding preexisting image snapshots, region planning, execution, and
trace storage. The fixed limits above bound the additional input/state material;
they do not bound total IDA process memory to 65,536 bytes.

## Accepted measurements

The matrix uses ten existing binaries per architecture: original, three
mutation, three virtualization, and three combined variants. Protection seeds
are 0, 1, and 12,648,430. Each of two functions receives eight recorded corner
triples and eight xorshift triples initialized with `0xc0ffee`. The supplied
values are x, y, and the middle word of a 12-byte buffer. The entry-state seed
is the case index 0–15. These 16 cases are a bounded subset, not exhaustive
coverage or an expansion of the earlier 33,600 independently executed records.

| Measurement | x64 Mach-O | i386 ELF |
|---|---:|---:|
| Captures | 320 | 320 |
| Returned, result/memory/stack/defined-flags oracle matched | 128 | 128 |
| Incomplete native-region boundary captures | 192 | 192 |
| Production assertions | 2,248 | 2,258 |
| Entered instruction records independently checked | 18,980 | 11,616 |
| Recorded memory accesses | 4,720 | 3,168 |
| Complete retained data prefixes | 320 | 320 |
| Indirect-jump boundary captures | 48 | 16 |
| Return-destination boundary captures | 80 | 80 |
| Rejected 16-bit BSWAP frontier captures | 64 | 96 |
| Sum of runner elapsed time / s | 46.877825002 | 53.813680125 |
| Maximum measured runner resident memory / bytes | 473,759,744 | 181,829,632 |

The architecture matrices ran concurrently. Elapsed values are sums of
per-process runner measurements, not combined wall time or performance gains.
Resident-memory figures include the runner/IDA measurement scope, not isolated
input-buffer overhead. Source-to-supplied-protector build attestation remains
unknown, as in the paired-corpus reports.

For all 256 completed captures, the independent integer oracle computes the
32-bit rotated/XOR/ADD result and ADD-defined CF/PF/AF/ZF/SF/OF mask `0x8d5`.
The result register and all 12 selected bytes, including both guards, match.
The production probe and outer runner both check the oracle. The outer runner
uses the same `expected` function previously checked against independently
executed paired binaries. Those earlier executions used Rosetta for x64 and
QEMU for i386; no physical x86 execution claim is added here.

Stack measurements use different observation points: the capture starts at
callee entry and stops after RET. Thus, with pointer width W = mode_bits / 8
bytes, `sp_delta = W`; subtracting W yields the paired wrapper's caller-relative
delta of 0 bytes. These are exact integer differences, with no rounding.

Capstone 5.0.7 independently verifies all 30,596 entered instruction sizes,
file-backed bytes, and recorded linear successors: zero mismatches. The 384
incomplete captures are not counted as behavior recovery. The BSWAP stop policy
and primary architectural reference remain documented in
`VMP_NATIVE_REGION_CAPTURE.md`.

Twenty process inventories preserve segment bytes/loaded masks, native item
flags and sizes, xrefs, function flags/chunks, and ordinary evidence publication.
The disabled-backend probe passes three checks across both capture APIs and
publication preservation. Total production assertions: 4,506 + 3 = 4,509.
All 19 CTest suites pass in 11.07 s, including 28 added portable assertions for
32/64-bit object initialization, ADD result/flags, guards, repeat isolation,
ordinary-scope rejection, and malformed/over-limit object contracts.

Accepted roots are `build/vmp-native-input-matrix-x64`,
`build/vmp-native-input-matrix-x86`, and `build/vmp-native-input-disabled`.
The first x64 smoke run is preliminary, excluded from the totals above.
Reproduction uses `tests/run_vmp_native_inputs.py` with the existing paired
corpus, IDA, plugin, and a fresh output directory; independent decoding uses
`tests/verify_vm_native_region_decode.py --capture-artifact vm_native_inputs.json`.
The build and CTest logs are `build/vmp-native-input-build.log` and
`build/vmp-native-input-ctest.log`.

## Assumptions, falsification, and bounded scope

| ID | Assumption / dependent result | Falsification probe and limit |
|---|---|---|
| I1 | The paired function signatures identify argument 2 as an interior pointer; all completed comparisons depend on this explicit contract | Fixture assembly/C wrapper inspection, x86 stack and x64 register execution, guard and result checks. Unknown arbitrary-function signatures are not inferred |
| I2 | Each run starts from the recorded input rather than prior writes | Same-driver repeated portable captures and 16 production input cases; compare full initial/final snapshots |
| I3 | Recorded native instruction boundaries match execution mode | Independent Capstone/file-byte and successor checks across all 640 captures; previous decoder counterexample remains in the earlier checkpoint |
| I4 | ADD's selected flags and caller-relative stack normalization are the intended observables | Independent integer oracle, paired native/QEMU oracle history, exact W-byte RET normalization; arbitrary exception behavior remains unknown |
| I5 | Observations do not alter ordinary function conclusions or database topology | Object-bearing ordinary execution rejection, separate publication veto, 20 before/after inventories, disabled-backend control |

High impact: explicit pointer initialization removes the prior generic-input
failure for original/mutation routines and yields complete observable checks.
This does not resolve virtualized control-flow boundaries. High impact:
unwritten guard bytes require whole-object readback; a final-write list alone
cannot certify them. Medium impact: parser, argument, and object limits prevent
caller-supplied input size from bypassing execution trace limits. Medium impact:
full image snapshots dominate some process memory measurements; incremental
capture reuse would need separate freshness and isolation validation. That
optimization is not implemented or claimed here.

QG1: technical behavior only. QG2: I1–I5 and probes above. QG3: explicit-input
checkpoint implemented through the production API, not completion of every
review requirement. QG4: exact fixed-width arithmetic, byte/bit distinction,
stack normalization, and process measurement scope stated. QG5: incomplete
captures, mapped-scratch bounds, partial stopped state, and unsupported input
forms remain explicit. QG6: local primary source and artifact hashes recorded;
no protector source-build identity inferred. QG7: bounded adjacent opportunities
and limitations stated. Complete VM semantics, arbitrary input recovery, and
the remaining `VMP_IMPLEMENTATION.md` requirements remain incomplete.
