# Exact zero- and one-count REP MOVS local memory

Review rows 1b, 2a and V require target and condition proofs to retain exact
local memory effects. Intel's [REP/MOVS specification](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
executes the string operation while the address-size count is nonzero and
decrements that count after each iteration. A zero initial count therefore
performs no source read, destination write or SI/DI adjustment. An initial
count of one performs one MOVS and finishes with count zero. In long mode,
[DS and ES bases are zero](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf).

The native abstract step admits a decoded `REP MOVS` only with matching-width
implicit SI/DI operands, a natural address size, no segment prefix and no
`REPNE`. It reads the full RCX/ECX count before the generic operand-write
invalidation. For exact zero it skips that invalidation and retains locally
known memory, stack, SI, DI and the six modeled status flags. For exact one in
x86-64 it snapshots the source before writing, invalidates only the exact
mapped destination range, stores the known element if available, and applies
the existing one-element MOVS register/count effects. The result has count
zero. Unknown or larger counts retain all-memory invalidation. i386 count one
remains unresolved because DS and ES bases are not established by this state.
An unknown x86-64 destination also remains unresolved.

Four independent `REP MOVSB` fixtures exercise an aliasing zero-count target,
a disjoint one-count target, an initialized destination preserved at zero
count (`0x33`), and a one-count copy/reload of locally written `0x5a`. Both
architectures execute all four natively. The prior plugin and the current
plugin analyze identical fixture, probe and IDA bytes. The prior probes use an
expectation-only `--rep-movs-local-baseline` switch. Every captured target and
SETcc record was compared, including the variable-count negative control.

| Architecture and path | Changed captures | Prior/current correct fixed or conditional oracle edges | False edges | Prior/current unresolved eligible sites |
|---|---:|---:|---:|---:|
| x86-64 owned | 4 | 38/48 → 40/48 | 0 | 7 → 5 |
| x86-64 ownerless | 4 | 38/48 → 40/48 | 0 | 7 → 5 |
| i386 owned | 2 zero-count only | 30/48 → 31/48 | 0 | 15 → 14 |
| i386 ownerless | 2 zero-count only | 30/48 → 31/48 | 0 | 15 → 14 |

Each x86-64 path gains one zero-count target, one one-count target and two
condition facts. Each i386 path gains the zero-count target and condition;
both one-count captures remain unresolved. The 48 edges are distinct oracle
target edges, whereas unresolved counts count eligible sites, so these columns
do not sum. Owned native process checks are `128 × 256 + 2 × 255 = 33,278` on
x86-64 and `123 × 256 + 2 × 255 = 31,998` on i386. Owned IDA assertions are
410 → 414 and 353 → 355, respectively. Ownerless assertions are 1,540 and
1,490, with 4,094 native checks per architecture; both deliberately corrupted
ownerless oracles exit with status 1. All 21 CTest suites pass.

The exact supplied `samples/foo_x86_vmp` selected initializer has
byte-identical prior/current inspection JSON: 75 nodes, 77 edges and three
unresolved facts. This local checkpoint does not demonstrate a protected
recovery gain. Other protected roots, runtime-entered bytes and binary-wide
recovery remain unmeasured.

Reproduce with fresh output directories and the hash-matched IDA, compiler
and symbol tool recorded in the evidence JSON:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/rep-movs-local-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/rep-movs-local-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/rep-movs-local-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/rep-movs-local-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/rep-movs-local-score-reproduction
```

Run the two runners again with the prior signed plugin and
`--rep-movs-local-baseline`, then score and compare the two pairs with
`tests/verify_rep_movs_local.py`. The evidence JSON pins source, plugin,
executable, binary and report SHA-256 values. Wrapper elapsed time in
nanoseconds and peak resident bytes are in the raw reports; they include
process launch and do not establish a plugin speed difference.

For one abstract instruction with at most S retained stack words, B retained
bytes and an element of W bits, the zero-count state transfer is O(1) time and
space after decoded-instruction lookup. A resolved one-count transfer is
O(S + (W/8) log B) time and O(1) additional space for an ordered byte map;
unknown destinations can clear O(B) bytes. Here B ≤ 128, W ∈ {8, 16, 32,
64} bits, and the fixture exercises W = 8 bits. CFG iteration, IDA range
queries and process startup are outside this step bound.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | Intel's count-zero REP loop performs no string memory or index operation on normal completion. Both architectures' zero-count gains depend on this. | Execute zero-count MOVSB with destination aliasing a known target and with distinct initialized source/destination bytes; compare target and reload. |
| R2 | IDA's matched implicit operands and natural address size denote the full RCX/ECX count. All new proofs depend on this decode contract. | Inspect decoded operands, use an address-size override or segment prefix, and require abstention outside the admitted shape. |
| R3 | Long-mode DS/ES bases are zero and a one-count MOVS reads before it writes. The x86-64 one-count gains depend on this. | Copy locally written source to exact destination, reload and compare; retain i386 one-count abstention. Overlapping one-count cases remain to be tested. |
| R4 | Locally established addresses and bytes describe unchanged, ordinary mapped memory until the operation completes. Exact destination preservation depends on this. | Replace DI with an unknown pointer and require all-memory invalidation; test faults, concurrent changes and device memory before extending the claim. |
| R5 | The process oracle and source-annotated target sites describe the selected normal paths. Scores depend on this. | Run 256 input values plus rejection paths, reject the corrupted ownerless oracle, pin source/probe hashes and compare every capture. |
| R6 | Same source, probe, fixture and IDA bytes isolate the plugin change. Attribution depends on this. | Verify raw and scored report hashes and reject mismatched identities in `verify_rep_movs_local.py`. |
| R7 | The supplied initializer inspection covers one selected static root. Its unchanged result depends on that scope. | Compare JSON bytes and inventories; inspect additional roots and runtime-entered code for a wider claim. |

- **High impact:** two x86-64 target edges and one i386 target edge move from
  unresolved to proved in both analysis paths, with zero false edges in the
  48-edge selected oracle.
- **Medium impact:** zero-count propagation retains local memory even when DI
  aliases a known target. i386 one-count and variable-count cases abstain.
- **Low impact:** the selected protected root is unchanged. Broader protected
  effectiveness is unknown.

QG1: technical scope. QG2: R1–R7 specify falsification probes. QG3: owned,
ownerless, x86-64, i386, negative controls, source oracle and selected
protected control are covered. QG4: element width, bounds, counts and units
are explicit. QG5: segment, alias, count and source-order limits are explicit.
QG6: Intel specifications and hash-linked process/IDA reports support the
bounded claims. QG7: other widths, abnormal memory and wider protected scope
remain bounded above; the full review remains in progress.
