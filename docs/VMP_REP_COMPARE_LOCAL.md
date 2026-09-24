# Known-count REPE/REPNE SCAS and CMPS

Review rows 1b, 2a and V require repeated comparisons to preserve flags and
count when their effects are exact. Intel's
[REP/REPE/REPNE specification](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
starts a `SCAS` or `CMPS` iteration only when the address-size count is
nonzero. REPE and REPNE check ZF after an iteration. An initial zero count
therefore performs no comparison, index advance or flag update. An initial
one count executes exactly one comparison and finishes with count zero,
irrespective of the resulting ZF. The plain [SCAS](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)
and [CMPS](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
subtraction orders remain those already modeled.

The abstract step admits either repeat prefix only for a decoded `SCAS` or
`CMPS` with matching implicit operands, a supported element width, natural
address size and no segment prefix. It reads the full RCX/ECX count before
generic operand-write invalidation. At exact zero, the step returns without
changing retained flags, registers, memory or stack. At exact one, it
establishes count zero and applies one plain comparison. In x86-64, exact
locally written bytes or a same-address `CMPS` establish subtraction flags.
In i386, the one-iteration count is known, but comparison flags remain
unknown because a DS-relative local definition does not establish ES:[DI].
Unknown or larger counts keep the prior conservative state.

Ten independent `SCASB`/`CMPSB` fixtures exercise REPE and REPNE: two
zero-count flag-preservation cases, four one-count CF/ZF cases spanning both
prefixes and both instruction families, and two one-count targets based on
the final count. Two count-two fixtures terminate after their first unequal
REPE `SCAS` or equal REPNE `CMPS` comparison and remain unresolved, as do the
preexisting input-dependent zero-or-one controls. Each native driver evaluates
256 inputs; a deliberately corrupted
ownerless oracle is rejected on each architecture. Prior/current runs use
identical source, probes, fixture binaries and IDA executable. Only the
plugin differs; the prior probes set expectation-only
`--rep-compare-local-baseline`.

| Architecture and path | Changed captures | Prior/current correct oracle edges | False edges | Prior/current unresolved eligible sites |
|---|---:|---:|---:|---:|
| x86-64 owned | 8 | 40/50 → 42/50 | 0 | 7 → 5 |
| x86-64 ownerless | 8 | 40/50 → 42/50 | 0 | 7 → 5 |
| i386 owned | 4 | 31/50 → 33/50 | 0 | 16 → 14 |
| i386 ownerless | 4 | 31/50 → 33/50 | 0 | 16 → 14 |

Both paths gain two count-derived target edges. The x86-64 paths additionally
gain six condition facts; i386 gains the two zero-count preservation facts
but abstains on four one-count comparisons. Owned native checks are
`138 × 256 + 2 × 255 = 35,838` on x86-64 and
`133 × 256 + 2 × 255 = 34,558` on i386. Owned IDA assertions move
428 → 440 and 369 → 373. Ownerless assertions are 1,640 and 1,590;
the ownerless native oracle executes 4,094 checks per architecture.
All 21 CTest suites pass. The 50 oracle edges count distinct targets;
unresolved eligible sites count sites, so those columns do not sum.

The exact supplied `samples/foo_x86_vmp` selected initializer has
byte-identical prior/current inspection JSON: 75 nodes, 77 edges and three
unresolved facts. This checkpoint establishes no protected recovery gain.
Other protected roots, runtime-entered bytes and binary-wide recovery are
unmeasured.

Reproduce with fresh directories and hash-matched tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/rep-compare-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/rep-compare-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/rep-compare-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/rep-compare-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/rep-compare-score-reproduction
```

Run the two runners again using the prior signed plugin and
`--rep-compare-local-baseline`, then score and compare both pairs with
`tests/verify_rep_compare_local.py`. That verifier also checks the two
protected inspections. The evidence JSON pins exact source, tool, binary and
report SHA-256 values. Wrapper elapsed nanoseconds and peak resident bytes
include process launch; they do not establish a plugin speed change.

For one abstract step with B ≤ 128 retained bytes and element width
W ∈ {8, 16, 32, 64} bits, exact-zero handling takes O(1) time and extra
space after decode. An exact-one x86-64 comparison reads at most 2W/8 bytes
from an ordered map in O((W/8) log B) time and O(1) extra space. These
fixtures exercise W = 8 bits. IDA address-range queries, CFG iteration and
process startup are outside the step bound.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | REPE/REPNE test the count before the first comparison and ZF only afterward. Zero-count preservation and one-count completion depend on this. | Execute zero and one for each prefix and instruction family; vary the one-count comparison between equal and unequal values. A count-two early-stop control must remain unresolved. |
| C2 | IDA's decoded implicit operands, count width and prefix flags identify the supported string operation. All new proofs depend on this decode contract. | Inspect both architectures; introduce address-size/segment overrides or unsupported operands and require abstention. |
| C3 | x86-64 DS/ES bases are zero and local bytes or an identical address represent the value read by one comparison. Four one-count condition gains depend on this. | Compare locally written unequal bytes and equal-address bytes; require i386 one-count flag abstention. Test other element widths before extending fixture coverage. |
| C4 | A normally completed one-count operation cannot fault or observe concurrent/device-memory changes inside the modeled transfer. Count and flag results depend on this. | Inject unmapped addresses or external writes and require a separate exceptional or concurrent model before admitting those executions. |
| C5 | Source-annotated native results and matched source, binary and IDA identities isolate the plugin change. The 50-edge score depends on this. | Pin source/probe/report hashes, reject the corrupted ownerless oracle, compare every selected capture and test target/score mutations. |
| C6 | The selected protected root represents only one static region. Its unchanged result depends on that input and inventory. | Compare byte-identical reports and IDB inventories; inspect other roots and runtime-entered code before estimating protected effectiveness. |

- **High impact:** two count-derived targets are newly proved on each
  architecture in both paths; six x86-64 and two i386 condition facts also
  become available.
- **Medium impact:** i386 one-count comparison flags and variable counts
  remain unresolved under explicit segment and loop ambiguity.
- **Low impact:** the selected protected root is unchanged; wider
  effectiveness is unknown.

QG1: technical scope. QG2: C1–C6 state dependent results and falsification
probes. QG3: both prefixes, both instruction families, both architectures,
owned/ownerless analyses, native oracle, negative controls and one protected
root are covered. QG4: widths, counts, units and complexity are explicit.
QG5: count, segment and exceptional-memory limits are explicit. QG6: Intel's
primary instruction references and hash-linked process/IDA reports support
the bounded claims. QG7: other widths, abnormal execution and broader
protected recovery remain bounded unknowns; the full review is in progress.
