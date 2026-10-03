# Read-only facts for exact near-indirect jump registers

## Transfer and scope

The bounded ownerless region query previously stopped at `JMP r/m` with an
`unsupported_control` frontier and no target record. It now labels a decoded
near-indirect jump as an `indirect_target` frontier and reports a separate
`indirect-jump-target` fact. Only an exact natural-width register encoding can
produce a scalar target. The gate accepts `FF E0..E7` in 32- or 64-bit mode
and `40/41 FF E0..E7` in 64-bit mode when the decoded register matches the
opcode and `REX.B` extension. Other encodings, widths and memory operands
remain unresolved. The query does not follow the target or publish an IDA
jump edge. Intel's [JMP definition](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
identifies `FF /4` as a near absolute indirect jump and the 64-bit form as
using the register or memory offset.

The new record is conditional on entry at the selected ownerless root and
normal execution through the represented graph. Its support lists admitted
instruction EAs. A direct entry at the jump has unknown incoming registers
and cannot inherit a predecessor's target fact.

## Paired observations

The source-pinned `VMP_INDIRECT_JUMP_REGION_EVIDENCE.json` binds its historical
source and three same-binary IDA pairs. The x86-64 fixture executes five calls:
one locally defined target returning 7, two caller-supplied targets returning
7 and 8, and two targets loaded after writes to one writable pointer, again
returning 7 and 8. It exits zero only when all results agree. The IDA query
reports one exact `0x100000420` fact for the local `LEA`/`JMP r10` path and
unresolved facts for the caller-supplied register and writable-memory paths.
Starting a separate region at the same known jump yields an unresolved fact.
The prior plugin reported no indirect-jump records. Every current region is
unpublished and stops at the jump frontier.

An ELF32/i386 fixture has the same three transfer cases with exact `FF E7`
register jumps. Paired IDA runs prove its locally loaded target `0x40118e`,
leave its caller-supplied and writable-memory cases unresolved, and reject
the direct-entry proof. The binary assembles and links as a static ELF32.
Its process result is **unknown**: the local QEMU service is unavailable, so
this pair establishes static analysis behavior without an executed i386
oracle. The x86-64 execution claim remains confined to the Mach-O fixture.

The exact supplied `samples/foo_x86_vmp` initializer remains a 75-node,
77-edge ownerless region. Its `41 FF E2` (`JMP r10`) at `0x10024801a` gains
one **unresolved** target record; three existing condition records remain
unresolved. The prior/current checked inventory is identical. `r10` is not
established from the selected entry: the represented path reads it before its
first write. No protected target or recovery gain is claimed.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| IJ1 | The exact `FF /4` register encoding and decoded operand refer to the same natural-width GPR. The exact target fact depends on this identity. | The production gate checks instruction length, opcode, ModR/M, mode, width and register mapping. IDA records the exact `41ffe2` and `ffe7` sites. A mismatched or prefixed form must abstain. |
| IJ2 | The local `LEA` establishes `r10` before the jump along the selected root path. The fixture proof depends on that path. | Paired IDA reports agree on source bytes and ownership; entering at the jump itself loses the proof. The native process reaches the 7-valued target. |
| IJ3 | A caller register or writable pointer can vary between invocations. Unique-target abstention depends on this. | The same binary executes both 7- and 8-valued targets for each dynamic source; production reports both unresolved and never imports the pointer's initial image value as a constant. |
| IJ4 | The supplied VMP initializer's root and bytes match the pinned protected input. The four-record result depends on this identity. | Rehash input, probe, plugin and IDA artifacts; require identical checked IDB inventories and 75/77 graph counts. The indirect record must remain unresolved. |
| IJ5 | The ELF32 fixture has the intended 32-bit register encoding. The i386 static proof depends on IDA's decode and source bytes. | Require exact `ffe7` at all three sites, a 32-bit region, matched prior/current input and probe hashes, and rejection on direct entry. Execute its five-call process under an independently pinned i386 runner before claiming runtime equivalence. |

## Bounds and quality gates

The exact-encoding gate inspects at most three instruction bytes and one
register slice: `O(1)` time and auxiliary space at fixed architectural
width. The region retains the existing 128-node, 128-round and 256-incoming-
reference limits. The executed x86-64 fixture performs five fixed transfers; its result
checks are exact integers, with no rounding. The current IDA query adds one
constant-sized record per admitted near-indirect jump.

| Impact | Bounded result or risk |
| --- | --- |
| High | Treating one observed writable-memory or caller-supplied target as unique would create a false static edge; the dynamic controls remain unresolved. |
| Medium | One locally established register target becomes inspectable without changing ordinary CFG publication. |
| Low | The protected sample gains an explicit abstention record and no target proof. |

QG1: technical claims only. QG2: IJ1–IJ5 and probes above. QG3: exact
register, two dynamic-source controls, direct-entry control, both static
architectures and one protected
region are covered; the full review remains in progress. QG4: widths, counts
and constant work are explicit. QG5: unresolved inputs, ownership and
nonpublication remain separate. QG6: Intel primary instruction definition,
scoped x86-64 native execution and source-pinned paired IDA artifacts. QG7: bounded gain
and false-edge risk are explicit.

The later `VMP_INDIRECT_JUMP_REXW.md` extends the exact long-mode gate to
`REX.W` and ignored `REX.R/X` bits with a separate source-pinned paired
certificate. The original certificate remains unchanged as historical
evidence; current-plugin semantic controls still cover its fixture and
protected abstention.
