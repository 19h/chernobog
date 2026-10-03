# REX-prefixed near-indirect register jump facts

## Architectural gate

The ownerless native-region query now accepts one exact long-mode REX byte
`40..4F` followed by `FF E0..E7` for a register-form `JMP r/m64`. It checks
that IDA decoded a natural-width register whose index equals ModR/M.r/m plus
`REX.B`. ModR/M.reg is the `/4` opcode extension; `REX.R` does not select a
register there, and `REX.X` has no SIB field in this form. `REX.W` does not
change the near-jump target width in 64-bit mode. The separate unprefixed
32/64-bit form remains admitted. Other lengths and prefixes remain unresolved.
Intel's [instruction reference](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)
defines `FF /4` as `JMP r/m64` in long mode and the REX-field encoding.

The result is a read-only target record, conditional on entry at the selected
ownerless root. It does not follow the target or publish an IDA edge. The
existing bounded state still requires an exact register definition on every
represented input; a caller-supplied register remains unresolved.

## Paired and executed evidence

`VMP_INDIRECT_JUMP_REXW_EVIDENCE.json` pins its historical source, fixture, probe, IDA,
plugins, and two raw reports. The native x86-64 Mach-O fixture executes five
calls and exits zero: locally defined `48 FF E0` reaches a 7-valued target,
`49 FF E0` reaches an 8-valued target, and `4F FF E0` reaches the 7-valued
target. A caller-supplied `48 FF E7` reaches both targets on separate calls.
The prior plugin left all four region target records unresolved. The current
plugin proves the three local targets and leaves the dynamic case unresolved.
All four direct-entry queries remain unresolved. Both runs pass 19 probe
checks, use the same binary and IDA build, preserve identical node/edge and
database inventories, and report no published target edge.

The earlier `VMP_INDIRECT_JUMP_REGION_EVIDENCE.json` remains a historical
certificate for the pre-REX.W source snapshot. The later
`VMP_INDIRECT_JUMP_MEMORY_EVIDENCE.json` pins the current combined source.
Current-plugin controls rerun this fixture and the supplied VMP region using
their semantic checks. This
extension does not establish a target for the supplied `JMP r10`, whose input
register remains unknown from the selected root.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| RW1 | The exact three bytes and decoded natural-width GPR identify the same near transfer. The three target facts depend on this. | Require the four recorded bytes, long mode, ModR/M `/4` register form, and decoded GPR agreement; reject any differing length or width. |
| RW2 | The local LEA is the reaching definition on the selected root path. The three scalar facts depend on this. | Start at each jump site instead; every target becomes unresolved. Require identical prior/current graph and inventory. |
| RW3 | Caller-supplied RDI can vary between calls. Unique-target abstention depends on this. | The same native binary invokes the dynamic jump with 7- and 8-valued targets; both IDA reports leave it unresolved. |
| RW4 | REX.R and REX.X do not alter the register-form `/4` operand. The `4F` result depends on this. | Execute `4F FF E0` natively, require IDA to decode R8 and match its exact bytes, and require the same 7-valued target as `49 FF E0` with a 7-valued definition. |

## Bounds and quality gates

The gate reads three bytes and one decoded register slice: `O(1)` time and
auxiliary space. The region keeps its 128-node, 128-round, and 256-incoming-
reference limits. Five process calls and five exact integer result checks
have no rounding error.

| Impact | Bounded result or risk |
| --- | --- |
| High | Treating one caller-supplied target as unique would invent a static fact; both native outcomes are observed and IDA abstains. |
| Medium | Three common REX-prefixed register forms gain exact read-only target facts. |
| Low | The supplied protected `JMP r10` remains unresolved; no protected recovery gain is claimed. |

QG1: technical claims only. QG2: RW1–RW4 and falsification probes above.
QG3: `REX.W`, `REX.B`, ignored `REX.R/X`, dynamic input, and direct-entry
controls are covered for the stated three-byte long-mode scope. QG4: widths,
counts, and constant work are explicit. QG5: proof and publication remain
separate. QG6: Intel instruction reference, executed x86-64 fixture, and
source-pinned paired IDA artifacts. QG7: bounded gain and false-fact risk are
explicit. Other encodings and full review implementation remain in progress.
