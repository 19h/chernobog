# Read-only candidate decoding at a packed Morok data entry

The explicit `chernobog_native_candidate_region(data_head_ea)` IDC API decodes
loaded bytes from one unlabeled data head in an executable x86/x64 segment.
It returns a bounded graph with `candidate_decode=true`, node marker
`candidate-bytes`, and record truth `conditional-byte-decode`. It leaves IDA
items, function owners, references and names unchanged. This advances review
rows 0b and 6a as an inspectable entry candidate; it does not classify the
bytes as code, prove reachability, recover runtime unpacked bytes, or publish
native/VM facts. Row 5 still requires linked visualization of these records.

The source-controlled fixed-time Morok keygen pair and its process oracle are
recorded in `VMP_MOROK_KEYGEN_PAIRED_CONTROL.md`. The fresh protected build
used here has SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`;
its independently built repeat has the same hash. Both differ from the user's
supplied Morok sample. The prior fresh-IDA boundary in
`VMP_MOROK_KEYGEN_IDA_BOUNDARY.md` places the packed application trampoline at
`0x418440` as one 64-byte data item with no function owner; ordinary
`chernobog_native_region_facts` returns `not_existing_code_head` there.

Two new fresh IDA 9.4 SP1 processes each report nine candidate instructions,
eleven graph edges and one unresolved branch condition. The first bytes at the
root are `50` (`PUSH RAX` in the selected mode). The graph exposes the direct
call target `0x4185f0` as `call_target_not_followed`, a `UD2` as
`unsupported_control`, and the direct jump to `0x430000` as
`segment_boundary`. The branch at `0x418458` has `outcome=unknown`; no
protected condition or target is claimed proved. The two reports are
byte-identical, SHA-256
`8d993edab1f3c7aa00b108c293429fddaeacff60e3f037dbc90b30ecc51ab14e`.
The checked IDB inventory before and after each query is identical: 38,006
heads, 40,917 outgoing references and digest
`aced12a072b293db11c869da5bc803a7fed070a05cce39f6119a84d8d09c2118`.
The inventory covers loaded bytes and masks, item flags and spans, function
owners/chunks, names, comments, segment modes/permissions and outgoing
references; it is not a hash of every IDB attribute.

The API rejects a data tail at `0x418441`, the existing startup code head at
`0x40021b`, and the selected nonexecutable address `0x4442f8`. Instructions
cannot cross an existing code item, a user-named data head, a function owner,
an unloaded byte or the selected segment. A reachable overlapping decode,
interior code reference or exhausted node/reference/round budget withholds
partial facts. The existing-code API is unchanged before and after the candidate
query. The supplied VMP initializer's ordinary 75-node region report remains
byte-identical to its prior recorded report, SHA-256
`fde5868e2a0d5e21a57f6837138c4358f1921964b84c5aab10a3898be141f0fa`.
The separate x86-64/i386 ownerless harness passes 4,094 native checks per
architecture, rejects its corrupted oracle, and passes 1,500/1,450 IDA
assertions respectively. All 21 CTest suites pass.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| C1 | The hashed fresh protected builds represent the paired keygen source and fixed-time process contract. The application-entry interpretation depends on this identity. | Rebuild from the recorded source/config/tool hashes and rerun the five-case process oracle; reject a hash or behavior mismatch. |
| C2 | The selected root is a candidate instruction entry under the recorded x86-64 mode. Every graph and record is conditional on this interpretation. | Independently trace actual execution through the startup callback and compare entered bytes; a different entry or unpacked bytes invalidates runtime interpretation. |
| C3 | File-backed bytes and IDA's selected segment mode are stable during this static query. The reported candidate graph depends on that snapshot. | Repeat fresh-process inventories; compare input, IDA, plugin and report hashes; capture runtime writes before interpreting any post-unpack state. |
| C4 | A flat unchanged-code normal-return model is applicable only up to displayed frontiers. Conditional branch facts depend on this local model. | Trace call return, exceptions, self-modification and side entries; retain `unknown` when they are unmodeled. |

## Bounds and scope

At most 128 decoded nodes, 128 dataflow rounds, 256 incoming references per
instruction, 15 bytes per decoded instruction and 64 MiB of inspected IDB
segments are admitted. For N nodes, E edges, X incoming references and R
rounds, existing compatibility work is O((X + N)E) plus ordered-map costs;
propagation is O(R(N + E)S), with bounded architectural state S. Retained
graph/state storage is O(N + E + X + NS), excluding O(N²) formatted support.
The probe inventory uses O(B + H + sum(x_i log x_i)) time over B segment
bytes, H heads and x_i outgoing references from each head; it uses O(B +
max(x_i)) temporary space for byte/mask blocks and sorted references. Its
inputs are bounded by 64 MiB of segments, 1,048,576 heads and 2,097,152
references. Counts and byte limits are exact; no performance gain is inferred
from process elapsed time.

- **High impact:** an otherwise unavailable packed application entry now has
  a reproducible, inspectable conditional graph without retyping the IDB.
- **Medium impact:** the call, unsupported-control and packed-section frontiers
  identify specific boundaries for runtime capture and later semantic models.
- **Low impact:** the present graph yields zero proved protected conditions and
  no evidence of runtime unpacked instructions.

`VMP_NATIVE_CANDIDATE_REGION_EVIDENCE.json` records exact local source,
binary, plugin, IDA and raw-report hashes. The measured plugin was built from
the listed source files before this checkpoint was committed; its hash is a
historical measurement artifact. Reproduce in fresh output
directories with hash-matched inputs:

```sh
python3 -B tests/run_ida_smoke.py \
  build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  tests/ida_native_candidate_region_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/keygen-candidate-reproduction \
  --set CHERNOBOG_CANDIDATE_ROOT=0x418440 \
  --set CHERNOBOG_CANDIDATE_CODE_CONTROL=0x40021b \
  --set CHERNOBOG_CANDIDATE_NONEXEC_CONTROL=0x4442f8
```

QG1: technical scope. QG2: C1–C4 have falsification probes. QG3: selected
candidate, negative roots, repeat build and existing-code regression are
covered; full review remains in progress. QG4: budgets and complexity are
explicit. QG5: data classification, file-byte interpretation and runtime
execution are distinct; frontiers remain unresolved. QG6: exact local
primary artifacts and raw reports are hash-linked. QG7: potential impact and
unmeasured runtime/semantic boundaries are labeled.
