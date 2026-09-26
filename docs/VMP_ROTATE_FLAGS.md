# Rotate values and independent status flags

Review rows 1b and 2a require exact native effects with independent flag
knowledge. The prior plugin discarded its abstract state at `ROL`, `ROR`,
`RCL` and `RCR`. All four forms now have portable transfers and production
register/local-memory consumers in 32-bit and 64-bit execution modes [R1–R3].
The current VMP emitter snapshot contains these forms; its source hash differs
from the original review snapshot, and both identities remain recorded [R6].

## Production contract [R1–R3]

Let `w` be the destination width in bits, `c` the count masked to five bits
(or six bits for a 64-bit destination), and `s` the effective rotation count.

| Form | Effective count | Destination and CF |
|---|---|---|
| ROL/ROR | `s = c mod w` | Rotate the destination; for nonzero `c`, CF receives the result's least/most significant bit |
| RCL/RCR, 8/16 bits | `s = c mod (w + 1)` | Rotate the destination and CF as one 9/17-bit ring |
| RCL/RCR, 32/64 bits | `s = c` | Rotate the destination and CF as one 33/65-bit ring |

All four preserve SF/ZF/AF/PF, including unknown operands or counts. Masked
count zero preserves the destination and all six tracked flags. OF is derived
only for masked count one. Other nonzero counts leave OF unknown. A nonzero
plain full cycle still derives CF from the unchanged result. A complete carry
ring cycle retains the destination and incoming CF.

These normal-completion effects follow Intel SDM revision 090, Volume 2B,
`RCL/RCR/ROL/ROR`, pages 4-533–4-537. The prose concerning a zero-bit carry
rotate and the pseudocode's nonzero-count OF rule admit different readings for
a nonzero masked count that reduces to zero steps. This transfer deliberately
forgets OF in that case. Neither an observed unchanged OF nor a full-ring
cycle is used to prove OF. The
[Intel SDM](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)
artifact is hash-bound in the evidence manifest.

A known destination with unknown incoming CF can still establish outgoing CF
for a positive carry rotation. One-bit RCL also establishes OF from the two
highest source bits; one-bit RCR needs the incoming CF to establish OF. The
destination remains unknown when the carry input affects its value. With
unknown count, an all-zero/all-one word remains exact under plain rotates;
carry rotates additionally require matching known CF. Otherwise CF/OF and
the destination remain unknown while the other four flags survive.

Production snapshots both operands before writing, preserving CL/destination
aliasing. Byte/word writes preserve unaffected register slices; long-mode
32-bit writes clear the upper half. Exact mapped writable bytes established
by local stores supply memory read-modify-write operands. Initial writable
image contents do not establish such facts. Unknown addresses or results
invalidate the affected memory knowledge [R3, R5].

LOCK-prefixed rotates reset owned state and stop ownerless replay at
`unsupported_locked_rotate`, or at an earlier invalid instruction span.
Intel specifies an invalid-opcode exception for LOCK. This checkpoint covers
normal completion, not memory faults or exceptional execution [R1, R2].

```text
cache destination, count and incoming CF
if count is unknown:
    preserve SF/ZF/AF/PF; retain only the admitted constant-ring invariants
else:
    mask count; return unchanged flags/value if masked count is zero
    reduce to effective count; handle carry-ring cycles
    derive CF from source/result bits independently of destination knowledge
    derive OF only if masked count is one and its inputs are known
    compute destination only if every required input is known
write destination slice or locally established memory
```

The fixed-word transfer takes O(1) time and O(1) additional space. The independent
test oracle rotates a Boolean bit array in O(CW) time and O(W) space, where
C ≤ 63 steps and W ≤ 65 bits. Existing graph/state limits are unchanged.

## Measured controls [R1–R5]

Portable controls cover all `3^6 = 729` partial status-flag profiles over four
operations, four widths and nine counts:
`729 · 4 · 4 · 9 = 104,976` profiles. Compatible incoming CF completions
are joined using a separate explicit bit-vector oracle. Unknown operand/count,
zero-count and constant-zero invariants have additional controls.

The literal instruction oracle in `tests/vmp_native/rotate_asm.c` executes
the ISA operations; the comparator in `rotate.cpp` calls the production
portable helper. Per architecture, the byte matrix covers
`4 · 256 · 256 · 4 = 1,048,576` operation/value/count/CF-OF cases.
Fifteen values, sixteen counts and all 64 complete status profiles add
`4 · 4 · 15 · 16 · 64 = 245,760` x86-64 cases and
`4 · 3 · 15 · 16 · 64 = 184,320` i386 cases.
The resulting totals are 1,294,336 and 1,232,896 instruction cases, or
2,527,232 across the pair. Each binary also executes 512 static-control input
groups. Every claimed known flag and the full destination register match;
undefined OF is excluded by the transfer's known mask. This finite matrix
does not exhaust 16/32/64-bit values.

Both binaries run through translation on this arm64 host: the x86-64 process
uses macOS translation, and i386 uses the recorded QEMU container. The added
`rotate.Dockerfile` extends the existing Linux32 image with the C++ cross
compiler; image, compiler, static C++ library and runtime hashes are recorded.
A later rebuild against mutable package repositories need not reproduce that
image identity [R4].

Fresh IDA 9.4 SP1 comparisons use byte-identical binaries and archived prior/new
plugins. Both profiles execute the same newly compiled portable comparator;
only IDA's loaded plugin changes. Baseline IDA probes pass 103 x86-64 and
99 i386 checks with none of the selected values or native-proof targets
recovered. Current probes pass 128 and 123 checks.

| Architecture | Prior selected values per path | Current selected values per path | Current stack target per path |
|---|---:|---:|---:|
| x86-64 | 0 | 20 | 1 |
| i386 | 0 | 19 | 1 |

Each path means owned-function analysis and separate ownerless inspection.
Controls include all four locally stored memory RMW forms, unknown carry,
unknown operand/count with preserved ZF, masked-zero count, plain and carry
cycles, AH and CL aliases, constant-zero variable count, and long-mode upper
zero extension. Unknown initial memory, undefined OF, one-bit RCR OF without
known carry and full carry-cycle OF remain unresolved. The stack target
survives a rotate of another register. Ownerless calls preserve the checked
item/byte/owner/comment/reference inventory and do not publish facts.

An owned ROR-to-ROL byte patch immediately revokes the old publication, proves
the different zero value after analysis, and recomputes the one value after
restoration. The complete save/reopen/rebase/undo matrix for these added forms
remains unknown [R5].

Matched prior/current inspection of `samples/foo_x86_vmp` passes 8/8 checks
per profile. Reports are identical: 75 initializer nodes, 77 edges and three
unresolved facts. None of those heads encodes a rotate. The selected IDB
inventory remains unchanged. This supplied region establishes no measured
protected recovery gain [R6]. All 21 configured CTest suites pass.

## Reproduction

With the existing Linux32 base image available:

```sh
docker --context orbstack build -f tests/vmp_corpus/rotate.Dockerfile \
  -t chernobog-vmp-rotate32:test .
python3 -B tests/run_rotate.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-rotate32:test \
  --output-dir build/rotate-reproduction
ctest --test-dir build -R '^chernobog\.x86_abstract$' --output-on-failure
```

Use `--baseline` with the archived prior plugin for the previous IDA behavior.
Source, report, binary, tool and plugin identities are recorded in
`VMP_ROTATE_FLAGS_EVIDENCE.json`. Earlier evidence manifests remain unchanged.

## Assumption register and bounded expansion

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| R1 | Intel normal-completion semantics apply in the admitted 32/64-bit modes. All transferred facts depend on this. | Compare actual results and defined flags across the byte matrix and all 64 corner status profiles; repeat on physical x86. Exclude LOCK and faults from admitted execution cases. |
| R2 | IDA decode, loaded bytes and execution mode agree. Production admission depends on this identity. | Inspect mode/width and exact bytes; LOCK must yield no exact fact and an explicit frontier or invalid-span rejection. Other execution modes remain unsupported. |
| R3 | Known/value masks and complete local operands describe the abstract state. Partial-flag and alias conclusions depend on this. | Join compatible CF completions over all 729 flag profiles; exercise unknown inputs/counts, AH/CL aliases, zero extension, masked-zero and ring-cycle distinctions. |
| R4 | Hash-bound tools and translated runs describe the measured scope. Native counts and matched comparisons depend on this. | Rehash sources, binaries, plugins, IDA, image, cross compiler, static library and reports; reject changed identities. A physical-machine result or rebuilt image is a separate observation. |
| R5 | Local memory provenance and current publication dependencies remain valid. Memory/freshness/read-only conclusions depend on this. | Establish each RMW operand by a local store; initial writable memory must remain unresolved. Patch, query immediately, reanalyze and restore; compare ownerless inventories. Extend separate persistence/rebase/undo controls before claiming the full lifecycle. |
| R6 | The current emitter forms can occur in future protected fixtures. Expected VMP benefit depends on this. | Retain both distinct source hashes, generate source-controlled paired fixtures and inspect emitted heads. The supplied 75-node initializer has zero rotate heads; wider protected gain is unknown. |

**High impact:** four native operations now retain independently useful
register, memory and flag facts. **Medium impact:** unknown incoming carry can
still leave CF and selected RCL OF exact. **Medium impact risk:** translated
oracles, mutable package inputs and a distinct emitter snapshot bound
generalization. **Low impact:** conservative full-cycle OF abstention trades
potential precision for an explicit contract. Wider protected effectiveness
and the full review remain in progress.

QG1: technical claims only. QG2: R1–R6 register assumptions and falsification
probes. QG3: all four forms, admitted widths/modes, native comparison, memory,
aliases, flags, owned/ownerless facts and freshness controls are covered at
the stated scope. QG4: integer counts, bit units and time/space bounds are
reproducible. QG5: zero-count/full-cycle distinctions, unknown carry, undefined
OF, exceptional execution and translation retain explicit bounds. QG6:
Intel SDM, actual local emitter hashes and recorded primary process/IDA
artifacts establish provenance. QG7: protected effectiveness and remaining
architecture/lifecycle coverage are explicit unknowns.
