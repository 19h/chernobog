# Exact local long-mode STOS writes

Review row 1b requires exact local memory effects where the destination and
value are established. Intel's
[STOS instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf)
specifies a store from AL/AX/EAX/RAX to ES:[DI], followed by a DF-dependent
index advance, without changing status flags. Intel's
[long-mode segment rule](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf)
sets the ES base to zero. For a plain long-mode `STOS`, the native abstract
step now resolves a matching-width implicit DI destination at the natural
address size. If the exact range lies in one mapped readable/writable segment,
it invalidates only those bytes and writes any known accumulator value. It
retains disjoint local bytes, clears the abstract stack because that destination
may alias a stack word, invalidates DI, and preserves the six modeled status
flags and the count. An unknown accumulator still overwrites only the exact
range; a known byte can repair one byte of a previously established word.

Unknown addresses or operand shapes, segment prefixes, address-size overrides,
repeats and i386 execution keep the earlier all-memory invalidation. The i386
ES base may differ from the DS base used by local writes. A repeated store may
touch more than its first element, and its count may be zero. No byte is
inferred from initial writable image contents. The state models normal
completion in flat, unchanged, nonconcurrent memory; faults, device memory and
external writes are outside this transfer.

The independent driver executes a known-byte store at a disjoint destination,
an unknown-value store at a disjoint destination, a same-byte overwrite of a
locally stored pointer, and a zero-or-one-count `REP STOSB` control. It also
stores and reloads byte, word and doubleword values, plus a long-mode quadword.
The three plain target cases reach the same native target on all 256 inputs;
the repeat control also reaches it natively but remains unresolved in static
analysis. The reload cases return true after executing the store and read. A
known byte followed by an unknown overlapping `STOSB` yields an input-dependent
native condition and remains unresolved statically.

| Architecture | Prior/current proved target sites | Prior/current proved reload conditions | Owned native checks | Prior/current owned IDA assertions | Ownerless native checks | Ownerless IDA assertions |
|---|---:|---:|---:|---:|---:|---:|
| x86-64 | 0 / 3 | 0 / 4 | 27,646 | 340 / 348 | 4,094 | 1,320 |
| i386 | 0 / 0 | 0 / 0 | 26,878 | 311 / 311 | 4,094 | 1,290 |

The owned native totals are `106 × 256 + 2 × 255 = 27,646` on x86-64 and
`103 × 256 + 2 × 255 = 26,878` on i386, exact dimensionless counts. Both
ownerless runners reject their deliberately corrupted oracle. Matched runs
share source, probe, executable and IDA hashes; the signed production plugin
and expectation-only `CHERNOBOG_STOS_LOCAL_BASELINE=1` setting differ. Every
captured transfer and SETcc outcome was compared: exactly the seven x86-64
cases above change in each path, with zero i386 changes. Four new fixed-edge
oracle sites raise the denominator from 36 to 40. The matched prior/current
x86-64 score changes from 30/40 to 33/40 correct edges, with zero false edges;
i386 remains 30/40 with zero false edges. The repeated-store site remains
unresolved. All 21 CTest suites pass.

On the exact supplied `samples/foo_x86_vmp` initializer, the prior/current
protected inspection JSON is byte-identical. Its selected ownerless root has
75 nodes, 77 edges and three unresolved facts. The inspection does not measure
other protected roots, runtime-entered bytes or a binary-wide recovery rate.

Reproduce with fresh directories and hash-matched tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/stos-local-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/stos-local-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/stos-local-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/stos-local-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/stos-local-score-reproduction
```

The prior controls add `--stos-local-baseline` to both runners and use the
prior signed plugin. The evidence JSON records exact source, tool, binary,
report and protected-sample SHA-256 values. With S at most 64 stack words, B
at most 128 retained bytes and element width W in {8, 16, 32, 64} bits, an
exact store costs O(S + (W/8) log B) time and O(1) additional space. Unknown or
repeated destinations clear at most B bytes in O(S+B) time. IDA segment lookup
and CFG iteration are outside these step bounds. One byte is eight bits.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| T1 | In long mode, ES has zero base; the decoded DI phrase and accumulator slice represent the same element width. All seven x86-64 gains depend on this. | Inspect actual IDA operands on both architectures; execute byte, word, doubleword and quadword stores; require i386 abstention. |
| T2 | An exact mapped destination cannot alias a disjoint mapped local address in the modeled normal, nonconcurrent state. Two target proofs depend on retaining disjoint bytes. | Store a pointer, then execute known- and unknown-value `STOSB` at a separate exact slot; require the target and user edge. Replace DI with an entry-supplied pointer and require abstention. |
| T3 | An exact known-byte overwrite replaces only its byte range. The overlap target and four reload proofs depend on this. | Re-store the pointer's locally read low byte and require the original target; reload independently stored 8/16/32/64-bit values and compare them. Overwrite a previously known byte with an input-dependent value and require the subsequent condition to remain unresolved. |
| T4 | Repetition may write beyond the first element and may execute zero times; 32-bit ES identity is unknown. Abstentions depend on these barriers. | Execute the repeat fixture with counts zero and one and require unresolved analysis; run every i386 fixture and require no new proof. |
| T5 | Prior/current source, probe, binary and IDA identities match, while production plugin bytes differ. Attribution of seven gains and the 40-edge score depends on this. | Compare all recorded hashes, all captured outcomes, owned user edges, read-only ownerless inventories and the pinned scorer. |
| T6 | The selected protected root is one bounded static region. Its unchanged observation depends on the exact input hash and projection. | Require identical prior/current protected report bytes and inventories; test other roots and runtime-unpacked code before making a wider claim. |

- **High impact:** three additional exact x86-64 native targets and four
  condition facts are available in both analysis paths.
- **Medium impact:** unknown destinations, repeats and i386 segment identity
  retain explicit abstentions.
- **Low impact:** the selected protected root is unchanged; protected-wide
  effectiveness remains unknown.

QG1: technical scope. QG2: T1–T6 include falsification probes. QG3: both
architectures, four widths, owned publication, ownerless inspection, native
results, negative controls, matched attribution and one protected root are
covered; the full review remains in progress. QG4: widths, counts and bounds
are explicit. QG5: alias, segment and repeat ambiguity remain unresolved.
QG6: Intel manuals and hash-linked process/IDA reports support the bounded
claims. QG7: exceptional memory and wider protected scope are bounded above.
