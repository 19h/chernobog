# Exact local long-mode LODS loads

Review rows 1b, 2a and V require source-defined accumulator values through
native string loads. Intel's
[LODS instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2a-manual.pdf)
specifies an element read from DS:[SI] into AL, AX, EAX or RAX, followed by
an SI advance; it does not modify status flags. Intel's
[long-mode segment rule](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf)
sets the DS base to zero. For a plain long-mode `LODS` with matching-width
implicit accumulator and SI operands, the abstract step reads an exact mapped
source from locally established bytes and writes the accumulator slice. An
unknown source clears the loaded slice: a byte load retains known AH and other
upper bits, while a doubleword load also zero-extends EAX into RAX. SI becomes
unknown because DF is outside this state. The count, six modeled status bits,
stack and retained memory remain unchanged.

Repeated loads and unsupported operand shapes retain the earlier
whole-accumulator invalidation. Address-size overrides and segment prefixes
cannot contribute a known source because the exact-address resolver rejects
them. The i386 path also retains whole-accumulator invalidation; a general
segment-aware address model is outside this transfer. Initial writable image
bytes do not establish local source values. These are normal-completion facts
under flat, unchanged, nonconcurrent memory; faults, device memory and
external writes are outside the transfer.

The independent native driver stores a target pointer at the SI address and
loads it with full-width `LODS`. A second target case writes and reloads only
the pointer's low byte, testing retained upper accumulator bits. Byte, word,
doubleword and long-mode quadword loads feed comparison conditions. A separate
condition checks that an unknown source byte still preserves a known AH.
Initialized source bytes without a local write remain unresolved, as does a
zero-or-one-count `REP LODSB` condition.

| Architecture | Prior/current proved target sites | Prior/current proved conditions | Owned native checks | Prior/current owned IDA assertions | Ownerless native checks | Ownerless IDA assertions |
|---|---:|---:|---:|---:|---:|---:|
| x86-64 | 0 / 2 | 0 / 5 | 32,254 | 390 / 400 | 4,094 | 1,500 |
| i386 | 0 / 0 | 0 / 0 | 30,974 | 343 / 343 | 4,094 | 1,450 |

The owned totals are `124 × 256 + 2 × 255 = 32,254` on x86-64 and
`119 × 256 + 2 × 255 = 30,974` on i386, exact dimensionless counts. Both
ownerless drivers reject a deliberately corrupted oracle. Matched runs share
source, probe, executable and IDA hashes; the signed plugin and the
expectation-only `CHERNOBOG_LODS_LOCAL_BASELINE=1` setting differ. Comparison
of every captured transfer and SETcc outcome finds exactly seven x86-64
changes in each analysis path and zero i386 changes. Two new fixed sites raise
the edge denominator from 44 to 46. The x86-64 score changes from 36/46 to
38/46 correct edges, with zero false edges; i386 stays at 30/46, zero false.
All 21 CTest suites pass.

The exact supplied `samples/foo_x86_vmp` initializer has byte-identical
prior/current protected inspection JSON. Its selected ownerless root has
75 nodes, 77 edges and three unresolved facts. Other protected roots,
runtime-entered bytes and binary-wide recovery remain unmeasured here.

Reproduce with fresh directories and hash-matched tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/lods-local-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/lods-local-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/lods-local-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/lods-local-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/lods-local-score-reproduction
```

The prior controls add `--lods-local-baseline` to both runners and use the
prior signed plugin. The evidence JSON records exact source, tool, binary,
report and protected-sample SHA-256 values. For B at most 128 retained bytes
and element width W in {8, 16, 32, 64} bits, an exact load costs
O((W/8) log B) time and O(1) additional space. An unresolved address avoids
local-byte lookup; an unknown element at a known address may still require
up to W/8 byte lookups. IDA segment lookup and CFG iteration are outside
these step bounds. One byte is eight bits.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| L1 | In long mode DS has zero base, and IDA decodes Op1 as the accumulator and Op2 as matching-width SI memory. All source-value gains depend on this. | Inspect actual IDA operands on both architectures; execute byte, word, doubleword and quadword loads; require i386 abstention. |
| L2 | A local write to the exact SI address supplies the next plain load's bytes. Four width conditions and the full target depend on this. | Write each value immediately before `LODS`, then compare the loaded slice or return through it; require an initial-byte control with no local write to remain unresolved. |
| L3 | A byte load changes AL but retains AH and upper bits. The partial target and unknown-source AH condition depend on this. | Store and reload only the target's low byte, then return through RAX; separately load an initially unknown byte and compare the pre-established AH. |
| L4 | A repeat may execute zero or multiple loads, and the i386 address model does not establish all segment bases. Abstentions depend on this. | Sweep counts zero and one, require unresolved repeat outcome, and require no new i386 target or condition. |
| L5 | Prior/current source, probe, binary and IDA identities match while signed plugin bytes differ. Attribution of seven gains and the 46-edge score depends on this. | Compare recorded hashes, every captured outcome, owned user edges, ownerless inventories and pinned scorer output. |
| L6 | The selected protected root is one bounded static region. Its unchanged observation depends on its exact input hash. | Require identical prior/current report bytes and inventories; test other roots and runtime-unpacked code before a wider claim. |

- **High impact:** two additional exact x86-64 native targets and five
  condition facts are available in both analysis paths.
- **Medium impact:** partial-register retention proves a condition even when
  the loaded source byte is unknown; repeated and i386 cases still abstain.
- **Low impact:** the selected protected root is unchanged; protected-wide
  effectiveness is unknown.

QG1: technical scope. QG2: L1–L6 include falsification probes. QG3: both
architectures, four widths, owned publication, ownerless inspection, native
results, negative controls, matched attribution and one protected root are
covered; the full review remains in progress. QG4: widths, counts and bounds
are explicit. QG5: partial registers, source uncertainty, segments and repeat
ambiguity are covered. QG6: Intel manuals and hash-linked process/IDA reports
support the bounded claims. QG7: exceptional memory and wider protected scope
are bounded above.
