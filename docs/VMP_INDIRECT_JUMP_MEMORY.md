# Read-only target facts for exact direct-memory jumps

## Transfer and admission

The ownerless native-region inspector now handles the exact six-byte
`FF 25 disp32` near-indirect jump when IDA decodes a natural-width memory
operand at a mapped writable word. In 64-bit mode ModR/M `00:101` addresses
`RIP + sign_extend(disp32)`; in 32-bit mode it addresses `disp32`. The byte
gate reconstructs that address and requires it to equal IDA's decoded
operand address. Intel's [instruction reference and addressing table](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)
define `FF /4` and this mode-dependent ModR/M interpretation.

Only bytes written by the selected local replay can establish the pointer
value. Initial image contents of the writable word are not imported. An
incomplete write, unknown value or invalidating alias leaves the target
unresolved. The query stops at the jump and publishes no IDA edge. Other
memory encodings and prefixes remain outside this exact gate.

## Paired observations

`VMP_INDIRECT_JUMP_MEMORY_EVIDENCE.json` pins the source, two fixtures, probe,
IDA, plugins and four raw report/run pairs. The x86-64 Mach-O process calls a
locally written pointer jump once and a caller-written pointer jump twice,
with target results 7, 7 and 8. All three comparisons pass and the process
exits zero. The prior plugin leaves both target facts unresolved. The current
plugin proves only the local 7-valued target (`0x1000003f0`). Both runs pass
10 IDA probe checks with identical binary, graph and database inventories.
The caller-dependent target and both direct-entry queries remain unresolved,
even though the binary contains an initial pointer value.

The ELF32/i386 fixture has the same locally written and caller-written
pointer forms. Two paired static IDA runs each pass eight checks; the current
plugin proves the local target (`0x401180`) and leaves the caller and
direct-entry targets unresolved. Its process result is **unknown** because
no i386 execution runner is available in this environment. The ELF32 binary
assembles and links, which establishes its bytes but not runtime behavior.

The earlier `VMP_INDIRECT_JUMP_STACK_EVIDENCE.json` and other jump
certificates remain historical source snapshots. Current-plugin semantic
controls rerun their fixture and supplied VMP abstention checks. The
supplied `JMP r10` still has an unknown input register and gains no target
fact from this memory form.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| MI1 | `FF 25 disp32` and the decoded operand identify one mode-correct address. Both local target facts depend on this. | The verifier reconstructs signed RIP-relative x64 and absolute i386 addresses from exact bytes, then requires equality with the decoded address and pointer symbol. |
| MI2 | A complete local write establishes the last value of the mapped writable pointer. The scalar facts depend on this. | Paired IDA proves only the local write path; direct entry at the jump leaves the image-initialized word unknown. Unknown or aliased writes invalidate retained bytes. |
| MI3 | A caller-written pointer may vary across calls. Unique-target abstention depends on this. | One x64 binary executes two values, 7 and 8, through the dynamic jump; both architectures leave that static fact unresolved. |
| MI4 | The paired runs compare the same fixture and database topology. The measured delta depends on this. | Hash binary, probe, IDA, plugin and run reports; require identical IDB inventories, nodes and edges, with no published direct-jump edge. |
| MI5 | The ELF32 fixture has the intended i386 bytes. Its static analysis conclusion depends on this. | Require exact `FF 25`, 32-bit decoded address and matched report hashes. Execute under a pinned i386 runner before claiming a process oracle. |

## Bounds and quality gates

The gate reads six bytes and performs constant-width address arithmetic:
`O(1)` time and auxiliary space. The existing region caps are 128 nodes,
128 rounds and 256 incoming references per node. Three x64 calls and three
exact integer comparisons have no rounding error.

| Impact | Bounded result or risk |
| --- | --- |
| High | Using the writable image's initial pointer or one observed caller value as a unique target would invent a fact; both controls remain unresolved. |
| Medium | One locally written direct-memory target becomes inspectable per architecture without CFG publication. |
| Low | The supplied protected register jump remains unresolved. |

QG1: technical claims only. QG2: MI1–MI5 and probes above. QG3: exact
mode-dependent encoding, local/dynamic inputs, direct entry, both static
architectures and the x64 process oracle are covered for this gate. QG4:
widths, limits and exact counts are explicit. QG5: initial writable image
content and published edges remain distinct from local proof. QG6: Intel
primary instruction reference and source-pinned paired raw reports. QG7:
bounded gain and false-target risk are explicit. Full review implementation
remains in progress.
