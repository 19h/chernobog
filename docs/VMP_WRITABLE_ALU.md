# Local writable-memory arithmetic and flags

Review rows 1b and 2a require exact native target and condition proofs. The
x86-64/i386 abstract state now reads a modeled arithmetic instruction's memory
operand only when its effective address is exact, the full operand lies in one
mapped readable/writable segment, and every source byte was established by
the bounded local replay. It captures operands before write invalidation,
applies the existing width-aware arithmetic/flag transfer, and retains an
exact memory result after invalidation. An unknown result does not repopulate
the memory map. The state still forgets initial image bytes and clears retained
bytes after a write with an unresolved alias.

This routes decoded `ADD`, `ADC`, `SUB`, `SBB`, `CMP`, `INC`, `DEC`, `NEG`,
`AND`, `OR`, `XOR`, `TEST`, `NOT`, and modeled shifts through the existing
transfer. The new process fixtures directly exercise full-word `ADD`, byte
`XOR`, memory-source `ADD`, memory-source `CMP`, and zero-flag production by
memory-destination `ADD`; the other routed forms have existing arithmetic
unit controls but no distinct writable-memory process fixture here. All
claims concern normal completion in the existing flat, unchanged-code model.

## Executed and IDA controls

Eleven new assembly functions run for 256 input values on each architecture.
Their internal operands are constant across those calls; the input sweep does
not constitute 256 distinct arithmetic operands. The process results and
production facts are:

| Fixture shape | Native result | Current IDA fact on both modes |
|---|---:|---|
| Store target − 1, `ADD 1, [slot]`, `PUSH [slot]; RET` | 7 | Exact memory-definition target and owned edge |
| Store target with low byte XORed, `XOR 0x5a, byte [slot]`, `PUSH [slot]; RET` | 7 | Exact memory-definition target and owned edge |
| Store target, `ADD [slot], register`, `PUSH register; RET` | 7 | Exact register-definition target and owned edge |
| Store target, `CMP register, [slot]`, `SETE` | 1 | Proved true condition |
| Store `0xffffffff`, `ADD 1, dword [slot]`, `SETE` | 1 | Proved true zero-flag condition |
| Initial image pointer used by register `ADD`, or initial image pointer subjected to `ADD 0` in memory | 7 | Unresolved target; no owned edge |
| Unknown-address intervening write before register `ADD` or memory `ADD` | 7 | Unresolved target; no owned edge |
| Initial image pointer used by `CMP`, or initial image `0xffffffff` subjected to memory `ADD` | 1 | Unresolved condition |

The complete owned harness passes **17,150 native process checks and 225 IDA
assertions per architecture**. The ownerless harness passes its **4,094
existing native checks and 892 read-only IDA assertions per architecture**;
its native oracle does not execute the eleven new functions, and its
deliberately corrupted oracle is rejected. Four focused ownerless runs form
two same-binary prior/current comparisons, with 37 assertions per run; the previous
plugin has all five new positive facts unresolved, whereas the current plugin
proves them. The corresponding owned comparisons pass 221 baseline and 225
current assertions per architecture. The five facts comprise three transfer
targets and two conditions; all six new abstention shapes remain unresolved.
Input, probe and IDA hashes match in each comparison. The expectation-only
`CHERNOBOG_ALU_BASELINE=1` setting makes the recorded environment digests
differ; scan-depth settings are the same. All 21 CTest suites pass.

The selected supplied `samples/foo_x86_vmp` initializer still completes at
75 nodes with three unresolved facts, and its read-only IDB inventory is
unchanged. No gain is measured on that static root. Exact source, binary,
plugin, IDA and raw-report SHA-256 values appear in
`VMP_WRITABLE_ALU_EVIDENCE.json`. Reproduce with fresh output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-alu-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-alu-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| AL1 | A decoded arithmetic operation consumes the pre-write operand and produces the modeled width-specific result and flags on normal completion. All five positive facts depend on this. | Execute full-width add, partial-byte XOR, memory-source add/compare and memory-destination add/SETE on both architectures. Compare process results with exact IDA facts. |
| AL2 | Only exact locally established mapped writable bytes enter a memory-source proof. The three target and two condition facts depend on this. | Require each local-store positive; use initial image pointer and initial `0xffffffff` controls with valid native results that remain statically unresolved. |
| AL3 | An unknown-address write may alias the retained word. The two alias abstentions depend on this. | Write through an entry-supplied pointer to a disjoint runtime object and require the subsequent register and memory ADD targets to remain unresolved. |
| AL4 | Prior/current differences arise from plugin bytes under the same binary and probe. Feature attribution depends on this. | Compare binary/probe/IDA hashes and all eleven fact outcomes for x86-64 and i386, owned and ownerless. The expectation flag is the only intentional environment change. |
| AL5 | The supplied protected initializer is one selected static root. The unchanged protected observation has that scope. | Rehash the protected input, require 75 nodes and three unresolved records, and compare full before/after IDB inventories. Runtime-entered bytes remain unmeasured. |

For operand width W ∈ {1, 2, 4, 8} bytes and at most B = 128 retained
bytes, the new pre-read and result-store work takes O(W log(B + 1)) time and
O(1) additional space, excluding IDA queries and state copies. The existing
graph bound remains O(K(N + E)(16 + S + B log B)) time and
O(N(16 + S + B) + E) space, with at most N = 64 owned or 128 ownerless
nodes, K = 128 rounds, S = 64 stack words and 256 incoming references per
node. Widths and addresses use bytes here; 8 bits = 1 byte. The native check
count is the exact integer sum 17,150 = 65 × 256 + 2 × 255, with no rounding.

- **High impact:** three locally derived transfer targets per architecture
  acquire exact native proofs and owned edges.
- **Medium impact:** two additional conditions per architecture acquire exact
  zero-flag facts.
- **Low impact:** initial image values and unknown aliases remain unresolved;
  the selected protected initializer remains unchanged.

QG1: no normative premise. QG2: AL1–AL5 have falsification probes. QG3:
both memory operand positions, partial-width update, flags, initial-byte and
alias controls, owned publication, ownerless inspection and matched attribution
are covered; the complete review remains open. QG4: widths, bounds and counts
are explicit. QG5: the result is retained only after exact pre-read and normal
modeled transfer; unknown memory remains unknown. QG6: hash-matched source,
executed process oracles, IDA captures and CTest reports are primary provenance
for the implementation claims. QG7: static-root, operation coverage and model
limits are explicit.
