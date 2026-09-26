# Full and truncated integer multiplication

Review rows 1b and 2a require exact native register effects and independently
known flags. The prior plugin discarded its entire abstract state at `MUL`
and `IMUL`. Production now handles unsigned full products, signed full
products, signed two-operand products and signed immediate products in 32-bit
and 64-bit execution modes [M1–M3].

## Architectural and production contract [M1–M3]

| Encoding family | Widths in bits | Written result |
|---|---|---|
| MUL, `F6 /4`, `F7 /4` | 8/16/32/64 | AL × source into AX, or accumulator × source into DX:AX / EDX:EAX / RDX:RAX |
| Full IMUL, `F6 /5`, `F7 /5` | 8/16/32/64 | Same written slices, with signed operands |
| Two-operand IMUL, `0F AF` | 16/32/64 | Truncated product into the explicit destination |
| Immediate IMUL, `6B`, `69` | 16/32/64 | Truncated source × sign-extended immediate into the explicit destination |

Unsigned CF/OF indicate a nonzero high half. Signed CF/OF indicate that the
full product differs from the sign extension of its low half. SF/ZF/AF/PF are
undefined for every form, including a zero product. These normal-completion
contracts follow Intel SDM revision 090, Volume 2A, `IMUL`, pages 3-451–3-454,
and Volume 2B, `MUL`, pages 4-141–4-142. Immediate operands are sign-extended;
a 64-bit `69` form has a 32-bit encoded immediate. The
[Intel SDM](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)
artifact is hash-bound in the evidence manifest.

The adapter checks instruction kind, mode, width, opcode family, operand
shape and loaded bytes. It accepts an optional `66` followed by an optional
long-mode REX prefix. LOCK, address-size and segment-prefix controls abstain;
other prefix sequences remain unsupported. The ownerless frontier is
`unsupported_multiply_encoding`, or an earlier invalid instruction span.
Memory faults and exceptional execution are outside this normal-completion
contract [M1, M2].

IDA 9.4 exposes the implicit accumulator as Op1 and the encoded full-product
source as Op2. The probe records these actual operand fields. Production
caches both inputs before either implicit write, including AH, accumulator
and high-register aliases. Byte products write AL and AH while retaining
the remaining accumulator bits. Word products retain unaffected register
slices; long-mode 32-bit writes clear the upper accumulator and high-register
halves. Explicit products write only their destination. Unaffected registers,
locally established memory and stack words survive [M3, M5].

Exact local writable bytes and a previously pushed full stack word can supply
memory sources. Initial writable image bytes do not establish those facts.
An unknown source multiplied by zero still yields exact zero halves and
cleared CF/OF. Multiplication by one also clears CF/OF; the unsigned high half
is known zero. Other unknown products leave both halves and all six status
bits unknown. These are facts on normal completion; source reads remain part
of the instruction's effects [M1, M3, M5].

## Arithmetic derivation [M3]

For width w, let m = 2^w − 1. The helper uses unsigned host arithmetic and
represents the 2w-bit result as two w-bit halves. At w ≤ 32, the unsigned
product fits in a 64-bit host value.

For w = 64, take B = 2^32 and write a = a0 + B·a1 and b = b0 + B·b1,
with every digit in [0, B − 1]. Define pij = ai·bj. Then:

```text
a·b = p00 + B·(p01 + p10) + B²·p11
t = floor(p00/B) + (p01 mod B) + (p10 mod B)
low  = a·b mod B²
high = p11 + floor(p01/B) + floor(p10/B) + floor(t/B)
```

Each pij is below B², and t < 3B fits in a 64-bit host value. The nonnegative
high sum is at most B² − 2, because (B² − 1)² is the maximum unsigned
product. The low host multiplication wraps modulo B², as required.

For signed operands let εa and εb be their sign bits. Their signed values
are a − εa·2^w and b − εb·2^w. Expanding the product modulo 2^(2w)
leaves the low half unchanged and gives:

```text
signed_high = unsigned_high − εa·b − εb·a mod 2^w
signed_overflow = signed_high != (low_sign ? m : 0)
unsigned_overflow = unsigned_high != 0
```

This avoids signed host overflow and compiler-specific 128-bit integers.
The fixed-word arithmetic is O(1) time and O(1) additional space. Prefix
inspection is O(L) for L ≤ 15 bytes. The independent Boolean-vector oracle
uses shifted magnitude additions and whole-vector two's-complement negation:
O(w²) time and O(w) space, bounded here by w ≤ 64 bits.

## Measured controls [M1–M5]

Portable comparisons exhaust `2 · 256 · 256 = 131,072` signed/unsigned byte
pairs against that independent bit-serial oracle. Fifteen recorded values
add `2 · 3 · 15² = 1,350` pairs over 16/32/64-bit widths.
All `3^6 = 729` partial flag profiles across four widths and two signedness
choices add `729 · 4 · 2 = 5,832` comparisons, with zero, one and unknown
product controls. Invalid width abstains. Wider values are not exhausted.

The literal assembly oracle executes the actual five encoding families:
full MUL, full IMUL, two-operand IMUL, and short/wide immediate IMUL.
Per architecture, byte pairs under four CF/OF profiles give
`2 · 256² · 4 = 524,288` cases. Fifteen values per input under all 64
complete status profiles add:

- x86-64: `(2 + 3 · 5) · 15² · 64 = 244,800` cases;
- i386: `(2 + 2 · 5) · 15² · 64 = 172,800` cases.

Totals are 769,088 and 697,088 instruction cases, or 1,466,176 across the
pair. Each binary also executes 512 static-control input groups. The
comparator checks the full accumulator and high register, initial status
bits and every claimed defined output flag. Undefined flags are excluded.
For immediate forms the operand comes from the fixed encoded immediate,
rather than the second runtime input. Both plugin profiles compile the
same current portable comparator; the IDA plugin alone changes [M4].

Fresh IDA 9.4 SP1 runs use byte-identical binaries and archived plugins:

| Architecture | Prior checks | Current checks | Prior/current selected values per path | Current stack targets per path |
|---|---:|---:|---:|---:|
| x86-64 | 193 | 240 | 0 / 40 | 1 |
| i386 | 157 | 195 | 0 / 31 | 1 |

Both owned-function and ownerless paths have those value/target counts.
The matrix covers every admitted encoding family at each available width,
short/wide immediate sign extension, upper-slice preservation, high/source
aliases, extended registers, local memory for each product form, retained
source memory, exact stack-word sources and unknown zero/one inputs.
Undefined ZF/SF/PF, unknown nontrivial products and initial writable-memory
sources remain unresolved. Unsupported prefixes produce no exact result.
Ownerless calls preserve the checked item/byte/owner/comment/reference
inventory, converge within the configured bounds and do not publish facts.

Changing `MUL CL` to `IMUL CL` immediately revokes the old publication;
reanalyzing changes the selected carry value from one to zero. Restoring the
byte recomputes one. Complete persistence/rebase/undo coverage for these
additional forms remains unknown [M5].

Execution is translated on this arm64 host: macOS runs the x86-64 process,
and the pinned Linux32 C++ image runs i386 through QEMU. Physical x86 execution
is unmeasured. Image, cross compiler, static C++ library, runtime, host
compiler, sources and reports are hash-bound [M4]. All 21 configured CTest
suites pass; the recorded total is 6.97 s for one run, not a latency estimate.

## Protected control and reproduction [M6]

The supplied `samples/foo_x86_vmp` initializer contains `MUL EDX` at
`0x1001e80f7`, bytes `f7 e2`. Matched prior/current inspection passes
8/8 checks per profile, with identical reports: 75 nodes, 77 edges and three
unresolved facts. This region shows no measured recovery gain despite the
newly supported instruction. The current emitter's VM-handler builder
selects MUL/IMUL at logical `core/intel.cc:29433`; its source hash differs
from the original review snapshot. Neither snapshot identity nor complete
VM-handler recovery is inferred.

With the existing C++ Linux32 image available:

```sh
python3 -B tests/run_multiply.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-rotate32:test \
  --output-dir build/multiply-reproduction
ctest --test-dir build -R '^chernobog\.x86_abstract$' --output-on-failure
```

The reused image recipe is `tests/vmp_corpus/rotate.Dockerfile`. Use
`--baseline` with the archived prior plugin to check previous IDA behavior.
Identities and bounds are in `VMP_MULTIPLY_FLAGS_EVIDENCE.json`; historical
manifests remain unchanged.

## Assumption register and bounded expansion

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| M1 | Intel normal-completion multiplication and defined-flag semantics apply in the admitted modes. All transferred facts depend on this. | Compare actual register results and defined flags across both architecture matrices; repeat on physical x86. Keep faults and LOCK outside admitted execution. |
| M2 | Loaded bytes, IDA operand fields and execution mode agree. Production admission depends on this identity. | Record actual implicit/source operands and immediate bytes for each family/width; test both immediate sizes and LOCK/address/segment prefixes. Changed SDK/decoder settings require separate observations. |
| M3 | Known/value masks and unsigned modular arithmetic represent the admitted values. Product/flag conclusions depend on this. | Check the algebraic bounds, exhaust signed/unsigned byte pairs, compare an independent bit-serial wider oracle and sweep all partial flag profiles plus zero/one/unknown cases. |
| M4 | Hash-bound translated tools and process artifacts describe the measured scope. Counts and matched comparisons depend on this. | Rehash binaries, sources, plugins, IDA, compiler, image, library and reports; reject changed identities. The same current comparator in both profiles must not be described as an old-helper comparison. |
| M5 | Local memory/stack provenance and current publication dependencies remain valid. Memory/freshness/read-only conclusions depend on this. | Compare stored and initial memory, cached aliases and pushed-word sources; patch/query/reanalyze/restore and compare ownerless inventories. Extend persistence/rebase/undo before claiming the full lifecycle. |
| M6 | The actual protected head and current emitter are relevant to broader target coverage. Expected protected/VM benefit depends on this. | Pin the supplied binary and both distinct emitter hashes, inspect emitted heads and compare protected regions. Current reports are identical; broader protected gain and complete VM ownership remain unknown. |

**High impact:** full and truncated products retain unaffected state and
independently exact CF/OF. **Medium impact:** zero/one identities can establish
facts with an unknown source. **Medium impact risk:** undefined flags, translated
execution and decoder operand conventions bound inference. **Low impact:**
other prefix sequences remain explicit abstentions. Wider protected gain,
the complete lifecycle matrix and the full review remain in progress.

QG1: technical claims only. QG2: M1–M6 include falsification probes. QG3: all
five encoding families, admitted widths/modes, register/memory/stack effects,
defined/undefined flags, unknown operands, owned/ownerless analysis and
freshness are covered at the stated scope. QG4: bit widths, exact finite
counts, modular calculations and complexity bounds are reproducible.
QG5: decoder conventions, sign extension, aliases, undefined flags,
normal/exceptional completion, translation and source-revision differences
retain explicit bounds. QG6: Intel SDM and hash-bound local primary code,
process and IDA artifacts establish provenance. QG7: adjacent opportunities
and remaining protected, architecture and lifecycle coverage are explicit.
