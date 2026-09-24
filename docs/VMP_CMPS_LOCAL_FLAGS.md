# Exact local CMPS comparison flags

Review row 2a requires status flags to reflect the executed comparison. Intel's
[CMPS instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
specifies the subtraction order as DS:[SI] minus ES:[DI] and advances both
index registers after the comparison. Its
[long-mode segment rule](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf)
sets DS and ES bases to zero. The native abstract step now compares two exact,
readable long-mode addresses for plain `CMPS`. It proves all six modeled status
bits when the addresses are identical, even if the initial element is unknown:
the two operands read the same element at that instruction. For different
addresses, it requires every byte of both elements to have been established by
local writes. The decoded operands must be the matching-width implicit SI and
DI phrases, with natural address size and no segment override. The transfer
then invalidates SI and DI because their advances depend on DF. It retains the
count, stack and local memory on plain `CMPS`.

The i386 transfer abstains: a local DS write does not establish ES:[DI], and
equal offsets need not denote equal linear addresses. For distinct addresses,
an unknown element or address leaves the comparison flags unknown; unsupported
operand shapes, address-size overrides, segment prefixes and repeat prefixes
do as well. Repeated `CMPS` can
execute zero iterations, so it additionally invalidates the count and does
not infer final flags. These are normal-completion facts under the existing
flat, unchanged-code model; faults, concurrent writes and device memory are
outside the modeled state.

The independent assembly fixture executes byte equal-address CF-false and
ZF-true comparisons, locally written distinct-byte CF-true and CF-false
comparisons, word CF-true, doubleword ZF-true and x86-64 quadword ZF-true
comparisons. The CF cases test the source-minus-destination operand order.
Two negative controls retain unknown analysis outcomes: distinct initialized
bytes without local writes, and `REPE CMPSB` with input-dependent count zero
or one. The native process verifies the expected concrete result for every
input from 0 through 255 on both architectures.

| Architecture | Prior/current proved CMPS conditions per path | Owned native checks | Prior/current owned IDA assertions | Ownerless native checks | Ownerless IDA assertions |
|---|---:|---:|---:|---:|---:|
| x86-64 | 0 / 7 | 25,342 | 305 / 319 | 4,094 | 1,230 |
| i386 | 0 / 0 | 24,830 | 291 / 291 | 4,094 | 1,210 |

The owned native totals are `97 × 256 + 2 × 255 = 25,342` on x86-64 and
`95 × 256 + 2 × 255 = 24,830` on i386; counts are dimensionless, exact
integers. Every ownerless runner also rejects its deliberately corrupted
oracle. Prior/current runs share source, probes, executable binaries and IDA
bytes. The signed production plugin and expectation-only
`CHERNOBOG_CMPS_BASELINE=1` setting differ. Comparison of every captured SETcc
outcome finds exactly the seven x86-64
changes above in each path and zero i386 changes. The fixed 36-edge transfer
oracle remains 30 correct, zero false and three unresolved eligible sites on
both architectures and paths. All 21 CTest suites pass. These native fixtures
do not establish a protected-binary flag-recovery rate.

Reproduce with fresh output directories and hash-matched tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/cmps-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/cmps-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/cmps-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/cmps-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/cmps-score-reproduction
```

The prior controls add `--cmps-baseline` to both runners and use the prior
signed plugin. `VMP_CMPS_LOCAL_FLAGS_EVIDENCE.json` records source, tool,
binary and report SHA-256 values. A memory read inspects W/8 bytes for W in
{8, 16, 32, 64} bits. Each byte lookup in the at-most-128-entry ordered map
costs O(log B), so a distinct-address comparison takes O((W/8) log B) time and
O(1) additional space for B retained bytes. Exact-address equality avoids
those local-byte lookups. IDA segment lookup and CFG iteration lie outside
this bound. One byte is eight bits.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | Long-mode DS and ES have zero bases; decoded SI/DI phrases carry the actual operand width. All seven x86-64 proofs depend on these architectural facts. | Inspect IDA operands on x86-64 and i386; execute byte, word, doubleword and quadword comparisons; require i386 abstention. |
| C2 | Equal exact addresses yield the same value at one plain comparison in the modeled normal, nonconcurrent memory state. The two equal-address proofs depend on this. | Run equal-address CF/ZF fixtures; introduce an address-size or segment override and require abstention. A device or concurrent writer requires a richer model. |
| C3 | Distinct-address values are known only after local writes, and comparison order is source minus destination. Five distinct-address proofs depend on this. | Reverse the byte values and require CF to flip; remove a local write and require an unresolved condition. |
| C4 | A repeat may execute zero times and initial distinct bytes are unknown. The two negative outcomes depend on these barriers. | Execute counts zero and one with different native CF results; retain unknown status. Require the initial-byte fixture to remain unresolved. |
| C5 | The matched plugin comparison isolates the CMPS transfer, and the native oracle has fixed source and probe contracts. Attribution and edge-score claims depend on this. | Compare source, probe, binary and IDA hashes, all captured SETcc outcomes, both paths and the pinned 36-edge scorer. |

- **High impact:** seven long-mode CMPS condition facts are available in both
  owned and ownerless analysis.
- **Medium impact:** i386 segment ambiguity and repeat zero iterations prevent
  corresponding proofs.
- **Low impact:** the 36-edge score is unchanged; protected-sample condition
  recovery remains unknown.

QG1: technical scope. QG2: C1–C5 include falsification probes. QG3: both
paths, architectures, four widths, operand order and negative controls are
covered; the full review remains in progress. QG4: widths, complexity and
count arithmetic are explicit. QG5: segment, repeat and initial-memory cases
remain unresolved. QG6: Intel manuals and hash-linked process/IDA evidence
support the bounded claims. QG7: concurrency, device memory and protected
effectiveness are bounded above.
