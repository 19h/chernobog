# Executable data-segment entry decoding

The paired protected corpus exposed a production gap before any VMP recognizer
could operate. The supplied protector emits sectionless executable Mach-O
segments. IDA maps their initialized bytes with RX permissions but classifies
them as `SEG_DATA`. Original function entries contain exact near jumps into
those segments; their target bytes remain undefined, so ordinary analysis stops.

Chernobog now validates and seeds decoding at those existing jump targets.
Across nine protected variants, all 18 selected entry targets change from
undefined to decoded. The original executable's inventory remains unchanged.
This is an entry-decoding result, not a complete protected-CFG recovery rate.
Artifact and source hashes are in
[VMP_DIRECT_JUMP_DECODE_EVIDENCE.json](VMP_DIRECT_JUMP_DECODE_EVIDENCE.json).

**Production behavior**

[native_engine.cpp](../src/ida_analysis/native_engine.cpp) queues direct near
`JMP` targets during instruction emulation and the existing bounded metadata
scan. Before creating an instruction it rechecks the source instruction, exact
existing jump reference, destination segment type, explicit execute permission,
matching 32/64-bit modes, absence of function ownership, and successful decode.
Every byte of the proposed instruction must be initialized and undefined. Defined
data, item tails and interior user labels prevent admission. A label at the
target itself is preserved: the protector relocates symbol names there.

The change calls IDA's instruction-creation API. It does not alter binary bytes,
segment permissions, or directly create a proof edge or function tail. Subsequent
ordinary xrefs and function-tail decisions belong to IDA. Generated code items
are ordinary IDA analysis metadata, not persistent semantic proof receipts;
they may remain after the originating jump is edited, subject to IDA reanalysis.

`CHERNOBOG_IDA_DIRECT_JUMP_DECODE=0` disables the feature.
`CHERNOBOG_IDA_DIRECT_JUMP_TARGETS` bounds validation attempts per native-engine
reset: default 256, hard maximum 4096, zero admits none. Cumulative attempts,
successful seeds and exhaustion are exposed by `chernobog_native_analysis()`.
For Q queued candidates and the fixed x86 instruction limit of 15 bytes, queue
maintenance costs O(Q log Q) time and O(Q) space; validation costs O(Q), assuming
bounded decoder/xref lookup. Existing metadata scanning retains its separate
head budget. These bounds do not bound all autoanalysis subsequently scheduled
by IDA.

**Matched corpus results**

[run_vmp_analysis.py](../tests/run_vmp_analysis.py) runs fresh isolated IDA
processes with the feature off and on for each original/protected binary.
All other Chernobog options match, and RAX execution is disabled in both profiles.
[ida_vmp_corpus_probe.py](../tests/ida_vmp_corpus_probe.py) requests native analysis,
then inventories current code xrefs without forcing function boundaries. It
traverses jumps and fallthroughs, records but does not traverse calls, caps each
entry at 4096 heads, and inspects at most 64 encountered function owners.
Read-only evidence inspection preserved the recorded code and xrefs in every
run. Neither traversal nor owner-inspection cap was reached.

| Artifact | Heads with feature off, transform / branch | Heads with feature on, transform / branch |
|---|---:|---:|
| Original | 6 / 11 | 6 / 11 |
| Mutation, seed 0 | 2 / 2 | 13 / 14 |
| Mutation, seed 1 | 2 / 2 | 11 / 17 |
| Mutation, seed 0xC0FFEE | 2 / 2 | 11 / 22 |
| Virtualization, seed 0 | 2 / 2 | 44 / 39 |
| Virtualization, seed 1 | 2 / 2 | 43 / 29 |
| Virtualization, seed 0xC0FFEE | 2 / 2 | 42 / 48 |
| Combined, seed 0 | 2 / 2 | 69 / 100 |
| Combined, seed 1 | 2 / 2 | 47 / 38 |
| Combined, seed 0xC0FFEE | 2 / 2 | 94 / 17 |

Each protected disabled-profile inventory contains the original jump and one
undefined target head. Enabled profiles have no undefined head in the traversed
prefix. The direct entry edge already exists in both profiles; the improvement
is code definition at its destination, not a newly proved target. An independent
check of the entry's `E9 rel32` bytes verifies all 18 destinations against both
inventories. Head counts include the entry and are observations, not instruction
coverage against a complete protected-program oracle.

The six mutation paths terminate at RET. VM and combined paths terminate at
RET or indirect JMP; a VM RET can itself transfer to a handler. No native proof
records, VM candidates, or solver records were returned for these inspected
prefixes. Consequently complete oracle-edge coverage, false-edge rate, semantic
lifting, literal accuracy and solver rejection distributions remain **unknown**.
The reserved corpus seeds are evaluated partitions, not a fresh blind test.

**Validation and reproduction**

The plugin rebuilt successfully. Twenty matched corpus runs pass, along with
205 live admission/budget checks and 38 existing native-proof inspection and
invalidation checks. All 18 configured CTest tests pass in 11.54 s; this single
run is not a performance estimate. Native fixture behavior remains the separately
validated 16,800-record result in [VMP_PAIRED_CORPUS.md](VMP_PAIRED_CORPUS.md).
No claim is made that Chernobog's recovered code has been independently executed.

The live admission probe checks defined heads/tails, interior data and labels,
unloaded bytes, non-executable and unspecified permissions, mixed bitness,
conditional/indirect transfers, label/byte/segment preservation, repeated
analysis, feature disablement, and zero/one-attempt budgets. IDA fixture segments
are synthetic controls; the matrix above uses unchanged protected binaries.

```sh
python3 -B tests/run_vmp_analysis.py \
  --corpus-report build/vmp-corpus-release/corpus.json \
  --ida "$IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-analysis-reproduction
```

Run `tests/ida_direct_jump_decode_probe.py` through `tests/run_ida_smoke.py` on
the original fixture, normally, with the feature disabled, and with target
budgets zero and one. Process elapsed nanoseconds and resident bytes are retained
in the analysis report. The outer runner's `wait4` accounting is not independently
validated as IDA-only peak memory. The explicit 120 s process timeout and output
threshold are polled by the corpus executor; see the corpus document's limits.

**Assumptions, falsification and scope**

| ID | Assumption / dependent conclusion | Falsification probe |
|---|---|---|
| D1 | Current IDB bytes and mode describe the direct transfer. All seed decisions depend on this. | Re-decode the source and target, require the existing exact edge and initialized bytes; retain unknown mode/permission abstentions. Runtime self-modification remains outside this static claim. |
| D2 | Instruction creation preserves user-defined items and names under the recorded IDA build. | Live positive/negative controls compare definitions, bytes, explicit names and segment metadata. Revalidate against another IDA build. |
| D3 | Existing xrefs describe only the discoverable static prefix. Inventory counts depend on this scope. | Record owner omissions, traversal exhaustion and unresolved terminal transfers; never infer full VM ownership from a decoded entry. |
| D4 | The matched profiles isolate this feature. Attribution depends on this. | Compare exact input/plugin/IDA/script hashes, recorded option policy and unchanged-source checks. |

High impact: loader classification can hide executable code before recognizers
run. Medium impact: relocated symbol names at instruction starts are compatible
with decoding, while names inside an instruction are a boundary constraint.
Medium impact: a seed-attempt budget cannot bound all downstream IDA work; retain
the independent process timeout. These findings do not establish packing recovery
or coverage of unrelated protection subsystems.

QG1: technical scope. QG2: D1–D4 include falsification probes. QG3: this decoder
admission change is covered; the complete review is still in progress. QG4:
counts are exact, time is recorded in ns and converted to s by multiplication by
10^-9, memory in bytes. QG5: entry decoding, static prefixes and full recovery
remain distinct claims. QG6: local source and artifact provenance is recorded.
QG7: adjacent loader, label and resource-budget consequences are bounded above.
