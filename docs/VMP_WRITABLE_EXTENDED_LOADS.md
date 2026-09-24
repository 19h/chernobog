# Local writable-memory extension loads

Review rows 1b and 2a require exact source values before admitting native
transfer targets or flag facts. The bounded x86-64/i386 must-analysis now reads
locally established writable bytes for decoded scalar `MOVZX` and `MOVSX`
register loads. In long mode it also handles `MOVSXD` from a locally written
32-bit source into a 64-bit register. Admission requires an exact mapped
readable/writable address, an architectural source width smaller than the
destination width, a recognized non-SP destination slice, and every source
byte in the local map. The existing register write handles 32-bit destination
upper-half zeroing. The existing extension code masks the source and applies
zero or sign extension; none of these instructions changes flags. This follows
Intel's [instruction set reference](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf)
for `MOVZX`, `MOVSX` and `MOVSXD` under normal completion.

Initial writable image bytes remain unknown, even when they contain a pointer
or a fixed negative integer in the file. A possibly aliased write removes
retained bytes before the subsequent load. Segment overrides, 16-bit address
modes, unmodeled memory, faults, concurrent writes and device memory remain
outside this local proof. The analyzer does not rewrite the load or assert a
universal runtime value from the observed process inputs.
The executed fixtures exercise byte and word sources extended to 32-bit
registers and a dword source extended to 64 bits. Other decoded destination
widths use the same bounded transfer but have no separate process control in
this changeset.

## Executed and production controls

Twelve new source-emitted functions execute for 256 inputs on x86-64 and i386.
The two `MOVSXD` functions use full-width `MOV` controls on i386 because
`MOVSXD r64, r/m32` is a long-mode operation. Every native call reaches its
expected result. The production inspections distinguish these cases:

| Source and consumer | Native result | Current IDA fact |
|---|---:|---|
| Local pointer byte through `MOVZX`, reconstruct pointer, `PUSH register; RET` | 7 | Exact register-definition target on both modes |
| Local pointer byte through `MOVSX`, mask reconstructed byte, `PUSH register; RET` | 7 | Exact register-definition target on both modes |
| Local pointer word through `MOVZX`, reconstruct pointer, `PUSH register; RET` | 7 | Exact register-definition target on both modes |
| Local pointer word through `MOVSX`, mask reconstructed word, `PUSH register; RET` | 7 | Exact register-definition target on both modes |
| Local `0x80` byte through `MOVSX`, compare with −128, `SETE` | 1 | True condition on both modes |
| Local `0x8000` word through `MOVSX`, compare with −32768, `SETE` | 1 | True condition on both modes |
| Local `0x80000000` dword through `MOVSXD`, compare with −2147483648, `SETE` | 1 | True condition on x86-64; existing full-width `MOV` control on i386 |
| Initial image pointer byte through `MOVZX`, or a local byte after an unknown-alias write | 7 | Unresolved transfer candidate; no owned edge |
| Initial image `0x80` byte or `0x8000` word through `MOVSX`, or initial `0x80000000` dword through `MOVSXD` | 1 | Unresolved condition |

The complete owned harness passes **14,334 native checks and 192 IDA
assertions per architecture**. The ownerless harness passes its **4,094
existing native checks and 782 read-only IDA assertions per architecture**;
its native oracle does not execute the new functions and its deliberately
corrupted oracle is rejected. Four prior/current IDA comparisons have equal
fixture, probe, IDA and Chernobog-environment hashes, and unequal plugin
hashes. The previous plugin has eleven owned and seven ownerless assertion
errors on x86-64; ten owned and six ownerless errors on i386. All are the expected
new target or condition facts. The current plugin has zero probe errors. All
21 CTest suites pass.

The exact supplied `samples/foo_x86_vmp` initializer still converges at 75
nodes and 77 edges with two unresolved SETcc facts and one unresolved branch
fact. Its before/after IDB inventory is identical. This selected static root
shows no measured gain. Source, fixture, tool, plugin and report hashes are in
`VMP_WRITABLE_EXTENDED_LOADS_EVIDENCE.json`. Reproduce with fresh output
directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/extended-loads-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/extended-loads-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| XL1 | The decoded extension instruction uses its source width and sign rule under normal completion. All four transfer targets and the new flag facts depend on this. | Execute byte and word `MOVZX`/`MOVSX`, signed `0x80` and `0x8000` sources, and long-mode `MOVSXD` with source dword `0x80000000`; compare native and IDA results on both architectures where applicable. |
| XL2 | A local store establishes only the bytes it writes at an exact mapped writable address. All new proofs depend on this. | Require the positive local-store cases; require initial image bytes containing the same native values to remain unresolved. |
| XL3 | An unknown write can alias a retained byte. The alias abstention depends on this. | Write through an entry-supplied disjoint pointer during execution, then require static `MOVZX` and its transfer target to remain unresolved. |
| XL4 | Prior/current differences are attributable to plugin bytes. Feature attribution depends on this. | Compare fixture, probe, IDA and environment SHA-256 in four pairs; require only the expected fact failures on the prior plugin. |
| XL5 | The supplied initializer is one static root. Its unchanged result has this scope. | Rehash the sample, check 75 nodes, 77 edges, three unresolved records, and equal before/after IDB inventories. Runtime-entered code remains unmeasured. |

For W loaded bytes, W ∈ {1, 2, 4}, and B ≤ 128 retained writable bytes,
lookup costs O(W log(B + 1)) time and O(1) additional space, excluding IDA
queries and copied graph states. The existing graph bound remains
O(K(N + E)(16 + S + B log B)) time and O(N(16 + S + B) + E) space, with at most
N = 64 owned or 128 ownerless nodes, K = 128 rounds, S = 64 stack words, and
256 incoming references per node. Widths are bits; addresses and offsets are
bytes; 8 bits = 1 byte. Native check counts are exact integer sums:
14,334 = 54 × 256 + 2 × 255, with zero rounding error.

- **High impact:** extension loads of locally established bytes supply four
  additional exact native transfer targets per architecture.
- **Medium impact:** negative signed-source values supply byte and word
  condition facts on both architectures and a distinct `MOVSXD` fact in long mode.
- **Low impact:** the selected protected static root remains unchanged; initial
  bytes and dynamic heap identity remain unresolved.

QG1: no normative premise. QG2: XL1–XL5 include falsification probes. QG3:
the stated source/destination widths, signed values, target consumers, negative
controls, owned publication, ownerless inspection and matched attribution are
covered; other width combinations and the full review remain open. QG4:
widths, counts and bounds are explicit. QG5: local, initial and possibly
aliased bytes remain distinct.
QG6: Intel's primary instruction reference and hash-matched independent
process oracles support the claims. QG7: the selected-root and execution-model
limits are explicit.
