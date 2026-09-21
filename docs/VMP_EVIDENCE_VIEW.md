# Linked evidence inspection

Requirement 5 of `VMP_REVIEW.md` now has a bounded inspection API and an IDA
Qt workspace. This checkpoint links instruction addresses, execution events,
allocation lifetimes, run outcomes, and hypothetical branch-claim checks.
Native proof records and SMT model details are not imported yet. The requirement
remains **in progress**; this is not a basic-block CFG recovery benchmark.

Subsequent extension: [native conclusion inspection](VMP_NATIVE_EVIDENCE_VIEW.md)
now adds independently checked native rows and green graph edges. The original
checkpoint and validation below remain historical; actual SMT model details
and the broader completion matrix remain outstanding.

## Interface and evidence contract

`chernobog_evidence_view(ea)` returns a JSON string for the captured function,
including a historical snapshot when its consumed bytes have changed.
`chernobog_evidence_state(ea)` checks availability and freshness without
rebuilding the projection. Addresses, seeds, sequences, generations, and
publication revisions are exact hexadecimal strings; consumers need not round
64-bit integers through a JSON floating-point representation.

The GUI companion is copied beside the plugin by CMake. With IDAPython and
PySide6 available, **View > Open subviews > Chernobog evidence** opens the
workspace. The existing **Show current-function rax evidence** GUI action also
dispatches to it when registered. The IDC `chernobog_rax_show()` command keeps
its text report. Opening the workspace inspects an existing capture; it does
not initiate execution or alter analysis metadata.

The workspace contains:

- An instruction-address graph: amber dashed edges are IDA-decoded targets or
  fallthroughs; blue solid edges are observed transfers with run, seed, and
  event sequence. Encoding is not a reachability proof, and repeated witnesses
  do not establish a unique target. The deterministic address layout is not
  execution order or a basic-block layout. Drag pans; Ctrl+wheel zooms; **Fit
  flow** fits the retained graph.
- An event table ordered within each `(run, seed)`, plus an allocation table
  that links allocation, use, and release by `(run, seed, object, generation)`.
  Selecting a graph address, allocation, or run filters the event table.
- Run outcomes with readable stop labels, source/target boundary addresses,
  environment/model flags, incomplete-context indicators, and temporal capture
  truncation. Missing memory observation is explicitly different from zero
  observed accesses.
- Branch-claim checks with matching/opposing counts and context-complete
  counterexample eligibility. These test hypothetical always-taken and
  always-fallthrough claims; they do not assert that a solver made either claim.
  Selecting a claim links its instruction to the retained events.
- A read-only detail pane with the selected record, database identity,
  function, generation, publication revision, and scope hashes. **Jump to
  source** rechecks freshness before navigating to a loaded address.

Release sequence is known, but the lifetime ledger does not retain the freeing
instruction. Release rows therefore report `site=0x0` and preserve the separate
`allocation_site`; they do not misattribute the release to the allocation call.
Use bytes remain a snapshot of that use after erasure or reuse. Wide memory
hooks expose their recorded low 64 bits, not fabricated complete read values.

Every valid evidence publication receives a nonzero monotonic revision within
the loaded C++ plugin instance. Clearing a session does not reset the counter;
counter exhaustion disables current-view admission. Freshness also requires
the exact current evidence object and existing consumed-byte/profile checks.
The workspace polls every 1 s, retaining stale data visibly as historical and
disabling navigation. Explicit reload obtains the current capture. Polling
avoids projection reconstruction, but still pays for the exact freshness check.
The revision is not a persistent identity across C++ plugin unload/reload.

## Bounds and complexity

| Retained item | Limit |
|---|---:|
| Decoded edges | 128 |
| Observed transfer edges | 128 |
| Ordered events | 1,024 |
| Allocation lifetimes | 128 |
| Run records | 128 |
| Hypothetical branch claims | 128 |
| Displayed byte prefix per use | 64 bytes |
| Registers per state record | 32 |
| Workspace slots | 8 |

Omission counts distinguish each capped family. Byte-display truncation is
separate from capture truncation. Event retention keeps the earliest sequence
positions across runs using a bounded ordered container; presentation then
groups records by run/seed. Independent runs have no shared event clock.

Let E be candidate event count, L=1,024, B branch-observation count, S distinct
branch sites, C<=128 retained claim checks, and I the remaining projected
instruction/run/lifetime records. Projection costs
`O(I + E log L + B log(S+1) + C*B log(B+1) + L log L)` time with the present
`check_branch_claim` implementation. Temporary claim run sets add up to O(B)
space; the unique-site set uses O(S), and retained output uses O(L) plus the
other fixed caps. Scanning an already bounded source snapshot is not a constant
time operation merely because output is capped. GUI filtering costs O(L); its
graph has at most 512 endpoint nodes. Neither peak process memory nor polling
latency on the largest admitted source snapshot has been measured.

## Assumption register and falsification probes

| ID | Assumption / dependent result | Probe and current boundary |
|---|---|---|
| E1 | Existing evidence capture and freshness contracts are authoritative for this inspection slice. | Patch a consumed key, require a historical view and disabled navigation, then restore it exactly. Clears and republication must not reuse the current-view revision. |
| E2 | The tested IDA GUI exposes the SDK PluginForm adapter and PySide6. GUI claims depend on this runtime. | Instantiate the actual Qt form, exercise linked selection, render it, and close it. Terminal IDA validates the API/helper path separately. Other IDA/Python/Qt releases are unmeasured. |
| E3 | Sequence values order observations within a run, not between runs. Timeline interpretation depends on this. | Feed unsorted multi-run events with overlapping sequences; check grouping and allocation/use/release order. |
| E4 | Decoded edges and observed edges have different evidentiary meanings. Graph interpretation depends on this. | Assert separate truth labels and independent quotas. No native proof badge is synthesized from an encoding or witness. |
| E5 | Display caps do not establish absent behavior. Negative inferences require complete underlying evidence. | Saturate events, edge families, runs, lifetimes, claims, byte prefixes, and register records; verify exact omission counts and retained incompleteness flags. |
| E6 | The C++ plugin instance remains loaded while its workspace identity is used. Publication identity depends on this. | Session clear/republication is tested. C++ unload/reload while Python forms survive, save/reopen, rebase, undo, and full multi-database UI lifecycle coverage remain outstanding. |

## Validation and remaining scope

The independent `vmp-temporal-strings` fixture exercises use/erase/reuse and
modeled calls in production IDA. It is not the supplied protected hello-world
binary and contains no conditional branch observations. Branch counterexample
projection, boundary/truncation display fields, and cap controls are tested by
the portable C++ regression instead. Exact artifact identities and final check
counts are recorded in `VMP_EVIDENCE_VIEW_EVIDENCE.json`.

The final checkpoint passed all 13 CTest targets (9.71 s for that single run),
31 production GUI checks, and 17 production terminal checks. These are
functional checks and one observed duration, not a latency distribution or a
protected-program recovery rate. The final rendered form was visually checked
for readable tables, visible graph nodes, controls, and scope details.

Reproduction uses the existing independent fixture from
`VMP_TEMPORAL_STRINGS.md`. `IDA_GUI`, `IDA_TERMINAL`, and `PLUGIN` below denote
local installation artifacts rather than committed filesystem locations:

```sh
cmake --build build -j 2
ctest --test-dir build --output-on-failure
QT_QPA_PLATFORM=offscreen python3 -B tests/run_ida_smoke.py \
  build/vmp-temporal-strings tests/ida_evidence_view_probe.py \
  --ida "$IDA_GUI" --plugin "$PLUGIN" \
  --output-dir build/evidence-view-reproduction-gui --enable-rax \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py"
```

Run from the repository root; the runner uses an isolated working directory,
so the command resolves the companion location through the current directory.
Repeat with `IDA_TERMINAL` and a distinct output directory for the terminal
variant. Reports use logical paths and artifact hashes.

The GUI test uses real offscreen Qt widgets, including a disassembly view for
action context. It checks graph, allocation, and run linkage; stale/restored
state; source-navigation gating; action dispatch; workspace reuse; and timer
shutdown. Visual inspection covers the retained feature form without an
application title or local filesystem paths. This does not measure interactive
usability across themes, monitors, or maximum-sized graphs.

Remaining requirement-5 work includes independently fresh native proof records,
actual solver/model details, protected branch/counterexample fixtures, a
basic-block presentation where ownership is established, and the lifecycle and
performance matrix above. The separate VM-region requirements remain separate.

## Bounded expansion and quality gates

| Impact | Additional finding | Consequence |
|---|---|---|
| High | A session generation can be reused after a clear/reopen lifecycle. | Publication revisions guard reuse within the loaded C++ plugin instance; unload/reload remains an explicit boundary. |
| Medium | Display quotas can hide later uses or one evidence family. | Separate quotas and omission counts expose this loss; an empty filtered table cannot prove absence. |
| Medium | Theme palettes can override base and alternate backgrounds independently. | Alternating row colors are disabled after an actual dark-theme render exposed poor contrast. |
| Medium | A small state response still performs potentially large exact byte checks. | Polling latency requires its own measurement before claiming responsiveness on maximum-size captures. |

QG1: no normative premise is required. QG2: assumptions and probes are above.
QG3: coverage is explicitly limited to this implementation slice; full review
coverage has not passed. QG4: counts are exact; byte limits and the 1 s polling
interval have explicit units. QG5: unsupported proof categories, missing release
sites, independent run clocks, and lifecycle boundaries remain explicit.
QG6: local source and artifact hashes provide provenance. QG7: bounded expansion
is recorded. These gates do not establish completion of the parent objective.
