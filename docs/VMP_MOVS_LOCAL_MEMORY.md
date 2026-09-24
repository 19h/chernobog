# Exact local long-mode MOVS copies

Review rows 1b, 2a and V require exact local memory effects where the source
and destination are established. Intel's
[MOVS instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
specifies a read from DS:[SI] followed by a write to ES:[DI], with no status
flag change. Intel's
[long-mode segment rule](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf)
sets DS and ES bases to zero. For a plain long-mode `MOVS`, the abstract step
now accepts matching-width implicit SI and DI phrases at the natural address
size. It resolves an exact writable destination, captures any fully known
source element before invalidating destination bytes, and stores that value.
When the source value is unknown, only the exact destination range loses its
known bytes. Other local bytes remain. The abstract stack is cleared because
the destination may alias a stack word. SI and DI become unknown; modeled
status flags and the count remain unchanged.

An unknown destination, segment prefix, address-size override, repeated copy
or i386 execution retains all-memory invalidation. The i386 DS and ES bases
need not match. A repeated copy may touch multiple elements or none. Initial
writable image bytes are not treated as local definitions. The state assumes
normal completion in flat, unchanged, nonconcurrent memory; faults, device
memory and external writes are outside this transfer.

The native driver executes three fixed target cases: a locally written source
byte copied to a disjoint destination, an unknown source byte copied to a
disjoint destination, and a full pointer-width self-copy. A zero-or-one-count
`REP MOVSB` control reaches the target natively but remains unresolved in IDA.
Local byte, overlapping word, doubleword and long-mode quadword copy/reload
conditions return true. A copy from an initialized source with no local write
returns true natively and remains unresolved in IDA.

| Architecture | Prior/current proved target sites | Prior/current proved reload conditions | Owned native checks | Prior/current owned IDA assertions | Ownerless native checks | Ownerless IDA assertions |
|---|---:|---:|---:|---:|---:|---:|
| x86-64 | 0 / 3 | 0 / 4 | 29,950 | 369 / 377 | 4,094 | 1,410 |
| i386 | 0 / 0 | 0 / 0 | 28,926 | 331 / 331 | 4,094 | 1,370 |

The owned totals are `115 × 256 + 2 × 255 = 29,950` on x86-64 and
`111 × 256 + 2 × 255 = 28,926` on i386, exact dimensionless counts. Both
ownerless runners reject their deliberately corrupted oracle. Matched runs
share source, probe, executable and IDA hashes; the signed plugin and the
expectation-only `CHERNOBOG_MOVS_LOCAL_BASELINE=1` setting differ. Every
captured transfer and SETcc outcome was compared: exactly seven x86-64 cases
change in each analysis path, with zero i386 changes. Four fixed sites raise
the edge denominator from 40 to 44. The x86-64 score changes from 33/44 to
36/44 correct edges, with zero false edges; i386 stays at 30/44, zero false.
The repeated-copy site remains unresolved. All 21 CTest suites pass.

The exact supplied `samples/foo_x86_vmp` initializer has byte-identical
prior/current protected inspection JSON. Its selected ownerless root has
75 nodes, 77 edges and three unresolved facts. Other protected roots,
runtime-entered bytes and binary-wide recovery remain unmeasured here.

Reproduce with fresh directories and hash-matched tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/movs-local-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/movs-local-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/movs-local-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/movs-local-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/movs-local-score-reproduction
```

The prior controls add `--movs-local-baseline` to both runners and use the
prior signed plugin. The evidence JSON records exact source, tool, binary,
report and protected-sample SHA-256 values. With S at most 64 retained stack
words, B at most 128 retained bytes and element width W in {8, 16, 32, 64}
bits, an exact copy costs O(S + (W/8) log B) time and O(1) additional space.
Unknown or repeated destinations clear at most B bytes in O(S+B) time. IDA
segment lookup and CFG iteration are outside these step bounds. One byte is
eight bits.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| M1 | Long-mode DS and ES bases are zero and IDA's implicit Op1/Op2 are matching DI/SI elements. All seven x86-64 gains depend on this. | Inspect decoded operands on both architectures; execute byte, word, doubleword and quadword forms; require i386 abstention. |
| M2 | A source element is read before the destination element is written. Self-copy and overlapping-word proofs depend on the pre-write snapshot. | Copy a locally stored pointer onto itself and copy a known word one byte forward; reload both. |
| M3 | An exact mapped destination cannot alias a disjoint mapped address in the modeled normal, nonconcurrent state. Two disjoint target proofs depend on retaining other bytes. | Copy both known and unknown source bytes to an exact disjoint destination and require the stored target to survive; replace DI with an entry-supplied pointer and require abstention. |
| M4 | Initial writable image contents do not establish a local source value. The negative initialized-source condition depends on this. | Copy from a nonlocally written source initialized to `0x5a` and require the following comparison to remain unresolved. |
| M5 | Repetition may write beyond one element, and i386 segment identity is unknown. Abstentions depend on these barriers. | Execute zero- and one-count repeats, require unresolved static transfer, and require no new i386 proof. |
| M6 | Prior/current source, probe, binary and IDA identities match while signed plugin bytes differ. Attribution of seven gains and the 44-edge score depends on this. | Compare recorded hashes, all captured outcomes, owned user edges, ownerless inventories and pinned scorer output. |
| M7 | The selected protected root represents one bounded static region. Its unchanged observation depends on its input hash and projection. | Require identical prior/current report bytes and inventories; test other roots and runtime-unpacked code before a wider claim. |

- **High impact:** three additional exact x86-64 native targets and four
  condition facts are available in both analysis paths.
- **Medium impact:** precise invalidation preserves unrelated local bytes even
  when the source element is unknown; repeated and i386 cases still abstain.
- **Low impact:** the selected protected root is unchanged; protected-wide
  effectiveness is unknown.

QG1: technical scope. QG2: M1–M7 include falsification probes. QG3: both
architectures, four widths, owned publication, ownerless inspection, native
results, negative controls, matched attribution and one protected root are
covered; the full review remains in progress. QG4: widths, counts and bounds
are explicit. QG5: overlap, alias, segment and repeat ambiguity are covered.
QG6: Intel manuals and hash-linked process/IDA reports support the bounded
claims. QG7: exceptional memory and wider protected scope are bounded above.
