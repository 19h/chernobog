# Typed MBA rewrites preserving explicit memory reads

The i386 `combined-12648430` protected `corpus_transform` body previously
rejected an existing De Morgan replacement because its operands contain
explicit `m_ldx` instructions. The instantiated verifier now accepts that
replacement after checking its value and read effects. No algebraic rule is
added. This checkpoint addresses review rows 4a, 4b and V; the complete review
remains in progress.

## Contract and implementation

For each explicit read, record
`T_i = (binary_branch, source_EA, result_bits, selector, offset)` in traversal
order. Translation assigns each occurrence a separate symbolic bitvector
`read_i`, including two reads with identical addresses. Original and proposed
expressions must have equal read counts and equal `T_i` records. Selector and
offset equality uses Z3 AST equality in one typed operand namespace. Register
identities retain operand kind, byte width, SDK value number and register
number. Stack/local identities additionally retain frame ownership and offset.

After this effect check, the existing verifier proves finite-width value
equality for all independent `read_i` values, through simplification or an
UNSAT result for inequality. DISPROVED, UNSUPPORTED and UNKNOWN continue to
reject proposals. No equality between separate read results, reaching
definitions or values across writes is inferred. SDK `valnum=0` means unknown;
the verifier does not equate distinct storage coordinates merely because they
share that number. Unequal value numbers distinguish otherwise equal register
coordinates.

Loads require a 2-byte selector, a 4- or 8-byte offset and an existing supported
1-, 2-, 4- or 8-byte result. Load and address properties must be zero. Addresses
contain only supported typed pure values; nested reads and implicit global,
stack or local memory are rejected. Expressions combining explicit loads with
implicit memory operands are rejected. Nested instructions must have anonymous
destinations, excluding additional register or memory writes. Existing barrier,
floating, undefined, persistent and unsupported-opcode checks remain active.

Binary branch strings retain left/right placement through binary operations;
unary wrappers do not add a branch component. This admits De Morgan while
rejecting read commutation and reassociation that change those paths. Each
load retains its source EA, selector, offset and width. The existing
`apply_match` caller restores the root destination and EA; the verifier does
not translate stores or calls. The observed store is therefore checked as
unchanged surrounding context by the independent capture auditor.

The captured 32-bit store value changes from

```text
(~load32(ds, edi + 4)) & (~load32(ds, edi))
```

to

```text
~(load32(ds, edi + 4) | load32(ds, edi))
```

Both reads retain their original source EAs, DS value number 3, EDI value
number 5, widths and binary branches. Store EA `0x80c8328`, its selector,
address and every other captured statement remain unchanged. These are
effective addresses in the recorded i386 fixture, not portable addresses.

## Verification and bounded conclusions

| Gate | Observed result |
|---|---|
| CTest | 21/21 suites |
| Registered catalog identities | 108/108 verified; deliberate invalid identity rejected |
| Typed instance controls | 190 initial results: 25 VERIFIED, 18 DISPROVED, 146 UNSUPPORTED, 1 UNKNOWN |
| Diagnostic quota/reset | 32 retained keys, 39 unrecorded observations; reset and subsequent rejection pass |
| Prior/current protected matrix | 40/40 processes per artifact; 80 total, with 40 actual native-enabled processes and 40 global-disable controls |
| Native ownership and SDK outcomes | All 152 native rows and 456 stages retain outcomes; 454 stages captured |
| Full structured capture comparison | Exactly one changed store value; unchanged CFGs, native bytes and all other statements |
| Independent integer/effect audit | 139,552 normal comparisons, six modeled fault prefixes, ten corrupted proposals rejected |

Portable SDK-layout controls cover result widths 8, 16, 32 and 64 bits with
32- and 64-bit addresses. They accept effect-preserving De Morgan with distinct
or aliased addresses, and reject dropped, duplicated, reordered or altered
reads, differing value numbers, barriers, implicit memory and nested destination
writes. Aliased read XOR versus subtraction is DISPROVED, demonstrating that
separate observations are independent. The resource-limit UNKNOWN control
continues to reject.

The independent captured-IR interpreter evaluates both left-first and
right-first operand schedules. It compares result, ordered read attempts and
the subsequent store attempt for all 256-by-256 byte-valued pairs in the
32-bit container, 12-by-12 corner pairs and 4,096 deterministic random pairs:
`2 * (256^2 + 12^2 + 4096) = 139552` comparisons. These are not exhaustive
32-bit enumeration. Faults at the first read, second read and store are modeled
under both schedules: `2 * 3 = 6` comparisons. The event prefix and fault source
must match; neither expression produces a result on the modeled fault path.

The preceding artifact records four typed verifications and two unsupported
attempts across the complete matrix. The candidate preserves those four
verifications and adds one, with no unsupported attempts in this population.
The new rewrite removes a subsequent structural match, so the two old rejected
attempts become one accepted replacement. Structural match counts are not
rewrite counts. The maximum observed process duration is 30.184 s for the
candidate and 27.992 s for the preceding artifact, each below the 120 s cap;
no general performance claim follows from these observations.

The capture includes gooMBA alongside Hex-Rays and Chernobog. The independent
audit establishes the captured value/read/store contract and modeled fault
prefixes. Whole-function equivalence, native flags, hardware exception delivery,
complete protected ownership and logical VM equivalence remain unknown. The
matrix retains 18 ownerless x86-64 body entries, one i386 target inside another
owner and one SDK stage refusal per profile. No owner is forced to obtain a
capture. Existing native behavior records are revalidated by the runner;
this checkpoint adds no new native behavior run for rewritten microcode.

Raw report pins, source and SDK identities, per-process measurements and the
complete before/after store capture are preserved in
[VMP_MBA_LOAD_EFFECTS_EVIDENCE.json](VMP_MBA_LOAD_EFFECTS_EVIDENCE.json).
The preceding installed artifact is hash-pinned and associated with revision
`90e165ec`; a reproducible compiled-source attestation is unknown. Its runner
source snapshot records the worktree inspected at capture time, not the source
compiled into that historical module. Historical evidence remains unchanged.

## Assumption register and scope expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| L1 | SDK typed operands and explicit `m_ldx` selector/offset semantics match SDK 9.40. Translation and the effect record depend on this contract. | Hash-pin primary `hexrays.hpp`; exercise all eight width/address combinations and fresh IDA captures. Other SDKs remain unknown. |
| L2 | Supported arithmetic and unary operations add no memory effects. Read conservation depends on this bounded opcode set. | Reject calls, stores, barriers, nonzero load/address properties, implicit memory and nested explicit destinations. Alter captured nested destinations in the independent audit. |
| L3 | Retaining binary read branches preserves order under either operand schedule. Modeled effect/fault equivalence depends on this execution model. | Compare both schedules; reject swapped, duplicated and dropped reads; inject faults at both reads and the store. Hardware fault semantics remain unknown. |
| L4 | Register coordinates, widths, frame owners and SDK value numbers distinguish local values sufficiently for this program-point proof. Typed equivalence depends on those identities. | Change a register value number without changing its coordinate; cancellation is DISPROVED. Alter a captured address value number; reject the proposal. No cross-program-point substitution is performed. |
| L5 | Hash-pinned artifacts and identical harness/tool components identify the paired captures. The observed protected gain depends on this attribution. | Recheck current sources and non-source artifacts; require equal owners, bytes, outcomes, CFGs and every other statement. Reject ten corrupted proposals. Compiled-source reproducibility remains unknown. |

Let `N` be visited instruction/operand nodes across both translations,
`H` the nesting depth and `L` the explicit read count. Admission bounds
`N <= 512`, `H <= 64`, `L <= N`. Translation and branch construction take
`O(N H)` time and temporary space, excluding hash-table worst cases, Z3 AST
management and SDK operations. Read-record comparison takes `O(L H)` plus Z3
AST equality costs. Symbolic solver cost is separate; its existing default
timeout is 250 ms with no default resource quota. UNKNOWN rejects. No persistent
cache or new lifecycle state is introduced. Time conversion is
`t_s = t_ns / 10^9`, rounded here to 0.001 s.

**High impact:** an actual protected memory-expression miss now passes the
typed verifier. **Medium impact:** retaining value numbers prevents equality
between distinct reaching values at the same register coordinate. **Low
impact:** broader address properties, implicit-memory mixtures, other SDKs and
hardware fault contracts remain bounded expansion opportunities.

QG1: technical scope. QG2: L1–L5 enumerate assumptions and falsification probes.
QG3: admission, rejection, production capture and independent effects are
covered; the full review remains in progress. QG4: byte/bit widths, counts,
time conversion and algorithm bounds are explicit. QG5: aliasing, operand
order, hidden writes, unknown solver results and incomplete SDK outcomes have
controls or stated limits. QG6: local primary SDK contracts and measured source,
module and capture identities are pinned. QG7: additional opportunities and
remaining contracts have bounded impact labels.
