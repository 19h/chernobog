# PUSH-next classification after IDA block-end analysis

The unchanged ELF32 get-PC fixture regressed from its historical 16/16 IDA
result to 15/16 under the current plugin. Its entry PUSH-next instruction
retained exact bytes and an immediate equal to its continuation, but lost the
stack-address-materialization comment. Both tested IDA versions marked that
instruction as a basic-block end. A read-only native evidence query showed the
later PUSH/RET target still current while the entry materialization proof was
absent. Reanalysis and an explicit queue of the entry did not restore it.

The adapter's `translate_instruction` checked IDA's generic block-end marker
before decoding `NN_push`. The marker caused a 32-bit PUSH to become an abstract
conditional branch. During the diagnostic run, classification of the same PUSH
changed from admitted to rejected as IDA analysis progressed. The corrected
order excludes `NN_push` from that generic branch case, allowing its decoded
stack effect to be represented. Other actual branch instructions retain the
generic case. This repairs the classification on the observed fixture without
asserting that every IDA block-end pattern is understood.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| B1 | A decoded 32-bit PUSH remains a stack instruction when IDA marks it as a block end. The classification fix depends on this. | Exact `68 55 11 40 00` fixture bytes, immediate equal to the next EA, and `block_end=true` are recorded by the IDA probe. The normal-execution 32-bit PUSH effect is also checked by `VMP_GET_PC32_EXECUTION.md`. |
| B2 | The old missing comment is caused by classifying the PUSH as a branch, not by a changed target or different fixture. | Same binary SHA-256 and probe: old plugin 15/16 under both IDA versions; corrected plugin 16/16 under both. Read-only evidence retained the downstream target and showed no materialization record before the fix. |
| B3 | The correction does not corrupt the recognized x64 sequence or other portable behavior. | x64 IDA get-PC probe and all 21 CTest suites pass with the corrected plugin. This is bounded regression evidence, not a whole-program equivalence proof. |

## Validation

| Check | Result |
|---|---|
| Corrected `get_pc_ida.cpp` SHA-256 | `5f3a2cd8d48a71020fd5ad8aa3fe88b1042c5298e91a99aaa888383ded192c45` |
| Unchanged ELF32 analysis binary SHA-256 | `9e2452212adb306096a7951de8923219f43be33ba4b6e5d70f2f20e89cdb33df` |
| Failing installed plugin SHA-256 | `4e5f3520c35f8af46ead7e74727a89117a53c411b837802b1b8729d3538314ed`; 15/16 under IDA 9.3 |
| Corrected test plugin SHA-256 | `a356eefedbec73fcb39973ece2a448c5244a91c242f3c407ea8b94bfa48e5ff4` |
| IDA 9.3, corrected plugin | 16/16 pass; entry PUSH `block_end=true` |
| IDA 9.4, corrected plugin | 16/16 pass; entry PUSH `block_end=true` |
| x64 IDA get-PC probe, corrected plugin | 53/53 pass; fixture and process hashes retained in `build/get-pc64-block-end-fixed` |
| CTest | 21/21 pass, 11.06 s reported wall time with `-j 20` |
| Formatting | `clang-format --dry-run --Werror src/ida_analysis/get_pc_ida.cpp` and `git diff --check` pass |

The two IDA runs use the source fixture and exact plugin artifact recorded in
`build/get-pc32-block-end-fixed-93` and `build/get-pc32-block-end-fixed-94`.
Their `run.json`, IDA logs, and `get_pc32.json` reports contain process identity,
per-assertion outcomes, and the decoded entry metadata. The x64 report is in
`build/get-pc64-block-end-fixed`. These build artifacts are local and are not
treated as immutable historical evidence. The earlier failed reports are in
`build/get-pc32-preserved-analysis` and
`build/get-pc32-historical-ida-current-plugin`.

## Bounds and quality gates

`translate_instruction` handles one decoded instruction in O(1) time and
space, excluding SDK decoding and downstream proof work. The correction changes
one branch in that translation, without changing instruction bytes, stack
widths or the native proof quota. The checked PUSH width is 32 bits and its
stack write is 4 bytes.

High impact: IDA's structural block marker can override architectural
classification if checked before the opcode. Medium impact: an initially valid
proof can disappear after autoanalysis changes metadata while leaving bytes
unchanged. Low impact: the same bug could affect other opcodes marked as block
ends; their coverage remains **unknown** and requires opcode-specific probes.

QG1: technical scope only. QG2: B1–B3 include falsification probes. QG3: the
observed PUSH-next regression is repaired; the complete review remains open.
QG4: bit/byte widths, exact pass counts and elapsed time are explicit. QG5:
the old and corrected plugin results are attributed to different hashes. QG6:
source, fixture, plugin, IDA process and reports provide direct provenance.
QG7: adjacent marker-order risks are bounded above.
