# Read-only target facts for exact stack-memory jumps

## Scope and transfer

The ownerless native-region inspector now recognizes direct near-indirect
`JMP [SP]` (`FF 24 24`) in 32- and 64-bit mode and the four-byte long-mode
`REX.W JMP [RSP]` (`48 FF 24 24`) within a byte-exact gate. The wider code
gate permits other REX bytes only when `REX.B` and `REX.X` are clear and IDA
decodes a natural-width stack-top operand with no segment or address-size
override. Intel's [instruction reference](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)
defines `FF /4` as the near absolute indirect jump; the SIB byte `24`
selects a scale-one, no-index stack-pointer base in the unextended form.

The fact is conditional on entry at the selected root and normal completion
of the represented prefix. Only a word written by that local replay can be
read from its abstract stack top. No initial stack bytes or absolute stack
address are presumed. Unknown, aliased or unsupported writes invalidate the
retained stack word. The query stops at the indirect jump, never follows it,
and never publishes an IDA edge.

## Paired evidence and process oracle

`VMP_INDIRECT_JUMP_STACK_EVIDENCE.json` pins its historical source, fixtures, probe, IDA,
plugins and four raw report/run pairs. In an x86-64 Mach-O fixture, a local
`LEA`/`PUSH`/`JMP [RSP]` and the REX.W variant each prove the same 7-valued
target. A caller-supplied register pushed before the jump remains unresolved;
the same process invokes it with 7- and 8-valued targets. All four calls
return the expected integer and the process exits zero. The prior plugin
left all three jump records unresolved. Current and prior runs each pass 15
probe checks with identical binaries, graph nodes/edges and database
inventories; all three direct-entry queries stay unresolved.

An ELF32/i386 fixture has a locally pushed immediate target and a pushed
caller register. Paired IDA runs each pass eight checks on the same binary.
The current plugin proves the local `0x401160` target; the prior plugin and
the dynamic case remain unresolved. Both direct-entry queries stay
unresolved. Its process result is **unknown** because an i386 execution
runner is unavailable in this environment. The binary assembles and links as
a static ELF32, which does not establish runtime equivalence.

The prior `VMP_INDIRECT_JUMP_REXW_EVIDENCE.json` and
`VMP_INDIRECT_JUMP_REGION_EVIDENCE.json` remain historical certificates for
their source snapshots. The later `VMP_INDIRECT_JUMP_MEMORY_EVIDENCE.json`
pins the current combined source. Current-plugin semantic controls are rerun for their
fixtures and supplied VMP abstention. The supplied `JMP r10` remains an
unknown-register frontier; this stack-memory feature makes no protected
target claim.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| SJ1 | Exact `FF /4` and SIB bytes plus IDA's natural-width `[SP]` decode identify the same memory read. All target facts depend on this. | Require exact site bytes, mode, operand size, no segment/address override, and stack-pointer/no-index decode. The current run records both unprefixed widths and `48 FF 24 24`. |
| SJ2 | The local PUSH is the last write to the abstract stack top. The local scalar fact depends on this. | Start the region at the jump itself; every direct-entry target is unresolved. The gate reads only a locally retained word, and other memory writes clear or replace that word. |
| SJ3 | A caller-provided pushed target can vary. Abstention depends on this. | The x86-64 process invokes both 7- and 8-valued destinations in one binary; both architectures report the dynamic target unresolved. |
| SJ4 | Prior/current IDA observations compare the same fixture and database topology. The measured delta depends on this. | Match binary, probe, IDA and environment hashes; require identical checked inventories, nodes and edges, with no published target edge. |
| SJ5 | The ELF32 binary has the intended i386 jump and target bytes. The static i386 proof depends on this. | Require `FF 24 24`, 32-bit IDA decode and matched paired run hashes. Execute under a pinned independent i386 runner before asserting its process result. |

## Bounds and quality gates

The encoding gate inspects at most four bytes and one decoded memory operand:
`O(1)` time and auxiliary space. The existing region caps are 128 nodes,
128 rounds and 256 incoming references per node. Four x86-64 calls and four
exact integer comparisons have no rounding error.

| Impact | Bounded result or risk |
| --- | --- |
| High | Treating a caller's stack word as a unique target would invent a fact; the dynamic process control has two outcomes and both IDA paths abstain. |
| Medium | A locally pushed word yields two x86-64 and one i386 inspectable target facts without ordinary CFG publication. |
| Low | The supplied protected register jump is unaffected and remains unresolved. |

QG1: technical claims only. QG2: SJ1–SJ5 and probes above. QG3: exact
stack-memory encodings, local/dynamic inputs, direct entry, both static
architectures and the x86-64 process oracle are covered within the stated
scope. QG4: widths, limits and exact counts are explicit. QG5: unknown
initial memory and publication remain separate. QG6: Intel instruction
reference and source-pinned matched raw reports. QG7: bounded gain and
false-fact risk are explicit. Full review implementation remains in progress.
