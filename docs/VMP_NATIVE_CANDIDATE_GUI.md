# Conditional packed-entry graph in the Qt evidence view

The Qt companion now registers a separate **Chernobog candidate byte region**
action for `chernobog_native_candidate_region(data_head_ea)`. It opens the
existing bounded graph form with an API-specific recomputation guard. Candidate
edges are dashed and labeled `conditional-byte-decode` in the edge table;
the status, scope and detail panes identify conditional byte interpretation,
unresolved records, and `published=false`. The ordinary existing-code action
keeps its own API, `encoding` edge basis and exact-graph label. Form keys
include the API identity so equal numeric roots cannot mix the two modes.
The view changes neither IDA code classification nor source facts. This
advances review row 5's candidate visualization, subject to the limits below.

The two fresh protected Morok keygen builds from
`VMP_MOROK_KEYGEN_PAIRED_CONTROL.md` have identical SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
Fresh IDA 9.4 SP1 GUI processes produced byte-identical 12-check reports and
PNG screenshots for their data-head root `0x418440`. Each form shows nine
nodes, eleven edges and one branch-condition record with
`status=unresolved`, `outcome=unknown` and
`truth=conditional-byte-decode`. Polling the ordinary API in that form disables
navigation; exact candidate recomputation restores it. The registered action
handler opens the conditional form for the data head and rejects the existing
code head at `0x40021b`. Each GUI process retains an identical before/after
inventory of 38,006 heads, 40,917 outgoing references and digest
`330c75eb900024e13c78080b7aeb3abf235074e92832daad467e52453f56de4e`.

The ordinary view was separately rendered on the supplied VMP initializer
root `0x1002946b5`: 75 nodes, 77 edges, three unresolved records, five passing
GUI checks, unchanged selected IDA flags and the existing `encoding` basis.
All 21 CTest suites pass. Screenshots were visually inspected; the candidate
scope and unresolved branch are visible, and no personal path appears in the
checked visible status, scope or detail text.

An attempted full legacy ownerless GUI probe failed three checks in this
isolated GUI environment: opening its first form coincided with 38 additional
IDA references, and `get_screen_ea()` returned `BADADDR` after successful
`jumpto` calls. The exact same failures occurred with the installed view whose
hash matches the pre-change `HEAD` version, using the same fixture, native
plugin and GUI executable. Their cause is **unknown**. The new probe exercises
the registered handler with an explicit action context; this does not prove
menu dispatch or actual source navigation from the isolated GUI process.
The five-check ordinary smoke does not replace the legacy save/reopen,
navigation and mutation lifecycle matrix.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| G1 | The hashed keygen builds and selected data head have the packed-entry identity measured in `VMP_NATIVE_CANDIDATE_REGION.md`. The candidate UI interpretation depends on it. | Rebuild the paired source and compare process behavior, binary hashes, selected root bytes and API result. Trace actual entry before any runtime claim. |
| G2 | Exact API recomputation in the same database/context detects a changed displayed graph. Candidate navigation freshness depends on it. | Poll the wrong API and require navigation disabled; restore candidate API and require exact equality. Mutate bytes and reopen an IDB in a separate lifecycle probe. |
| G3 | GUI screenshots and row checks represent actual visible Qt widgets. The display claim depends on them. | Render in fresh GUI processes on both byte-identical protected builds; inspect screenshots and table rows; repeat at another viewport size. |
| G4 | The matched legacy failure is independent of this view edit at the compared source bytes. Attribution of that failure to the environment depends on the control. | Repeat the same input/probe/plugin/IDA with current and pre-change view hashes; compare failed check names and IDB reference deltas. A different failure set would defeat the attribution. |

## Bounds, cost and impact

The native API admits at most 128 nodes, 128 dataflow rounds and 256 incoming
references per instruction. With N rendered nodes, E edges, K records and J
JSON characters, rebuilding the view costs O(N + E + K + J) time and space,
excluding Qt layout/rasterization and the native API. Exact snapshot equality
costs O(J) in the displayed result. The form polls every 2 s and retains at
most eight region forms; maximum-size latency and memory remain unmeasured.
The probe inventory is bounded to 64 MiB of segments, 1,048,576 heads and
2,097,152 references. Byte counts and integer counts are exact; no latency
gain is inferred.

- **High impact:** the packed data-entry candidate and its unresolved frontier
  now appear in the same linked graph/table workspace as native regions.
- **Medium impact:** API-specific exact recomputation prevents a candidate
  graph from being treated as a current ordinary code graph.
- **Low impact:** isolated GUI menu dispatch, source navigation and full
  lifecycle coverage remain unverified by this checkpoint.

`VMP_NATIVE_CANDIDATE_GUI_EVIDENCE.json` records source, binary, IDA,
native-plugin and raw-output hashes. The native plugin was built at the prior
committed revision; the tested Python view has the listed source hash. Reproduce
the candidate run in a fresh output directory with the GUI executable and
installed native plugin:

```sh
python3 -B tests/run_ida_smoke.py \
  build/morok-keygen-evidence-final/protected-first/int_woma_keygen-linux-x86_64-static \
  tests/ida_native_candidate_gui_probe.py --ida "$IDA_GUI" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/candidate-gui-reproduction \
  --set CHERNOBOG_CANDIDATE_ROOT=0x418440 \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py"
```

QG1: technical scope. QG2: G1–G4 include falsification probes. QG3: both
candidate builds, ordinary protected rendering, negative handler context and
current/stale mode control are covered; full row 5 and the whole review remain
in progress. QG4: budgets and asymptotic costs are explicit. QG5: conditional
interpretation, legacy GUI failures and unverified dispatcher/navigation are
distinct. QG6: local primary binaries, source, executable, plugin and raw
reports are hash-linked. QG7: impact and lifecycle boundaries are labeled.
