# Natural-address-size REP STOS and REP LODS completion counts

Review rows 1b, 2a and V call for exact x86 state effects and a measured native
edge oracle. On normal completion, `REP STOS` and `REP LODS` with natural address
size leave the selected RCX/ECX count at zero. Intel's
[REP instruction reference](https://cdrdv2-public.intel.com/868141/253667-089-sdm-vol-2b.pdf)
lists both instructions and defines repetition through count zero. The shared
transfer now applies the existing `REP MOVS` count rule to these two decoded
instructions. It first discards the incoming count fact, then establishes the
full zero word only for the F3 `REP` prefix with natural address size. Plain
forms retain the count. `REPNE` and non-natural address sizes stay unknown.
`STOS` continues to invalidate retained stack and writable-memory facts,
including the zero-iteration case; `LODS` continues to preserve those memory
facts while invalidating its accumulator and source pointer. The six modeled
status flags are preserved.

Two assembly fixtures compute an unknown-to-static-analysis count as
`input & 1`, execute `REP STOSB` or `REP LODSB`, add the post-count to a fixed
target address, and transfer with `PUSH; RET`. For each architecture, 256 native
inputs exercise both zero and one iterations. The x86-64 and i386 owned
drivers each pass `82 × 256 + 2 × 255 = 21,502` native checks and 278 IDA
assertions. The ownerless drivers each pass 4,094 native checks, reject a
corrupted oracle, and pass 1,080 IDA assertions. The two paths use the same
binary per architecture in matched prior/current runs. All 21 CTest suites
pass.

The prior signed plugin is the installed plugin from the exact stack-top store
checkpoint. The current signed plugin differs in this state transfer. Both
runs use equal fixture, probe, binary, IDA and `llvm-nm` bytes. The
expectation-only `CHERNOBOG_STRING_COUNT_BASELINE=1` flag distinguishes prior
probe assertions. The scorer checks the source-annotated targets against
independently resolved binary symbols and requires owned proof targets to
equal published IDB user code xrefs. Ownerless inventories remain unchanged.

| Architecture and path | Prior correct / oracle edges | Current correct / oracle edges | Current false edges | Current unresolved eligible sites |
|---|---:|---:|---:|---:|
| x86-64 owned | 28/36 | 30/36 | 0 | 3/33 |
| x86-64 ownerless | 28/36 | 30/36 | 0 | 3/33 |
| i386 owned | 28/36 | 30/36 | 0 | 3/33 |
| i386 ownerless | 28/36 | 30/36 | 0 | 3/33 |

The current fraction is `30/36 = 5/6 = 83.3%` to three significant figures.
The selected oracle has 30 fixed-target sites and three conditional sites with
two input-dependent target edges each. The three conditional sites remain
unresolved. Fifteen additional concrete-driver-only sites remain excluded and
unresolved. All 46 previously selected site outcomes are unchanged; only the
two new repeat-count sites change from unresolved to proved. This native
fixture fraction is not a protected-binary recovery estimate.

Reproduce with fresh output directories and hash-matched local tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/string-count-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/string-count-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/string-count-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/string-count-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/string-count-score-reproduction
```

The prior runs used `--string-count-baseline` on both runners with the prior
signed plugin. `VMP_STRING_REPEAT_COUNT_EVIDENCE.json` pins the exact source,
tool, binary and report SHA-256 values and the wrapper resource observations.
Elapsed nanoseconds and peak resident bytes describe the outer `wait4`
launcher, including IDA startup; they do not isolate plugin latency or memory.

For S at most 64 retained stack words and B at most 128 retained writable
bytes, the `STOS` transfer costs O(S + B) time and O(1) additional space for
alias invalidation. `LODS` and the shared count update cost O(1) time and
space. These bounds exclude CFG iteration and IDA startup. Counts and edges
are dimensionless; time is in nanoseconds and resident size is in bytes.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | F3 `REP STOS` and `REP LODS` with natural address size reach count zero on normal completion. Both new target proofs depend on this. | Compare Intel's count rule; execute zero- and one-iteration native cases on x86-64 and i386. Add width, address-size-override, F2 and exceptional-path controls before extending the transfer. |
| C2 | The fixed assembly target labels define the 36-edge selected oracle. The 30/36 score depends on this. | Rehash source and probes, resolve labels with `llvm-nm`, reject missing or duplicate records, compare owned user xrefs with proofs, and require ownerless inventory equality. |
| C3 | Prior/current inputs and analysis tools are matched; the state transfer accounts for the two new outcomes. Attribution depends on this. | Compare binary, source, probe and IDA hashes and all 48 site classifications across both plugins. Require only the two named sites to change. |
| C4 | Outer `wait4` accounting includes launcher and IDA startup. The recorded resource scope depends on this. | Instrument the plugin separately before estimating plugin-specific time or memory. |

- **High impact:** normal-completion count zero proves two additional native
  transfer targets even when the incoming count is unknown.
- **Medium impact:** a future count-sensitive conditional target model could
  use path predicates; the current single-target proof leaves three sites
  unresolved.
- **Low impact:** `REPNE`, address-size overrides, faults and protected-binary
  effectiveness remain outside this experiment.

QG1: technical scope. QG2: C1–C4 have falsification probes. QG3: the two
transfers, both architectures, analysis paths and benchmark change are covered;
the full review remains incomplete. QG4: edge arithmetic, units and complexity
are explicit. QG5: conditional targets and unadmitted prefix/address forms
remain unresolved. QG6: Intel's primary manual and hash-linked native and IDA
reports support the bounded claims. QG7: adjacent opportunities and limits
are labeled above.
