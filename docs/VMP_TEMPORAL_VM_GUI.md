# Captured temporal VM visits in the IDA evidence view

Review rows 5, 6a, 6b and V now have a separate Qt view for the opt-in
`chernobog_vm_trace_temporal_check` capture. The action **Chernobog temporal VM
capture** appears under **View / Open subviews** in IDA Qt. It asks for an
explicit nonnegative seed, bounded native input JSON and named ABI binding
JSON. The binding prompt suggests exact currently named imports recognized by
the modeled-call policy; the user can edit that array. The Python companion
installed by `make install` invokes the existing IDC API once and retains that
response only in the form. **Recapture** and reopening the action run a new
query; the timer checks candidate instruction bytes but never reexecutes the
analyzed program.
The underlying API requires at least one mapped, exactly named supported ABI
binding. A binary without one cannot use this action under the current API
contract; supplying an invented binding does not satisfy the parser.

The form separates syntax candidates from candidate visits with captured entry,
transfer, exit and memory evidence. The graph draws only actual recorded
transfers incident to candidate role sites. Selecting a visit filters the
ordered memory table to its entry/output sequence interval; selecting a syntax
candidate uses its recorded first/last sequence interval. The detail pane puts
the local result, observed target, reason, query count and path before the raw
candidate record. It labels every query as a historical, fixed-seed capture.
It neither publishes ordinary function evidence nor asserts a persistent VM
identity. **Jump to matching bytes** is enabled only when the selected address's
current IDB bytes equal the captured planned bytes. That equality is a source
navigation guard, not a replay of register state, memory, environment or SMT
applicability.

## Actual Qt and negative-boundary evidence

Two isolated IDA 9.4 SP1 GUI runs used the installed signed plugin and the
source-generated x86-64 Mach-O strings corpus. The `virtualization-0` run
rendered four checked candidate visits and eight local SMT queries. The visit
at `0x1000d64db` links its observed `0x100007031` target and five ordered
memory accesses. The candidate's syntax row remains separately labeled
`not performed`. A controlled byte-reader substitution disabled source
navigation, and restoring the exact bytes restored it. Thirteen production Qt
checks passed. After queued IDA autoanalysis was drained, all 2,377 planned
heads retained the same bytes, item flags, function owners and outgoing xrefs
across the form interaction and a second capture. The initial inventory
comparison before that drain changed under the Qt event loop; it is retained
as a rejected setup, not evidence of view mutation.

The `combined-12648430` run stopped at the 4,096-instruction budget with an
incomplete temporal prefix and incomplete register sampling. The form rendered
three syntax candidates, zero candidate visits and zero SMT queries; its
selected detail says `syntax-only; no transition check`. Five actual Qt checks
passed, including unchanged bytes and flags at the candidate support sites.
The two screenshots, reports and runner manifests are in
[`VMP_TEMPORAL_VM_GUI_CAPTURE.json.gz`](VMP_TEMPORAL_VM_GUI_CAPTURE.json.gz).
[`VMP_TEMPORAL_VM_GUI_EVIDENCE.json`](VMP_TEMPORAL_VM_GUI_EVIDENCE.json)
records exact binary, IDA GUI, installed-plugin, Python source, screenshot and
archive SHA-256 values. `tests/verify_vm_temporal_gui_archive.py` restores the
18 checks and both PNGs without IDA or a current plugin binary.
The full CTest suite passed 23/23 at four jobs. A separate eight-job run
returned a 100 ms solver timeout in `chernobog.vm_transitions`; it did not
report a modeled counterexample. The result is a measured scheduling-boundary
observation, not evidence of deterministic eight-job completion.

## Admission, bounds and assumptions

The form displays at most 128 syntax rows, 128 visit rows, 256 relevant transfer
rows and 256 memory rows. It reports producer omissions and transfer/memory
display omissions separately. Candidate source-byte polling is restricted to
the retained candidate spans and role sites, at most the native plan's 4,096
heads, every 2 s while the form is open. Building that subset takes O(H + S)
time and O(H + S) temporary space for H planned heads and S retained support
spans; each poll reads O(C) selected instruction spans for C candidate source
heads. Filtering a selected memory interval scans O(A) retained accesses,
with A bounded by the temporal API's 4,096-event input cap. Qt rendering and
IDA byte-query latency are not assigned an unmeasured worst-case duration.

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| G1 | The exact installed plugin and pinned GUI IDA produced the two rendered captures. All UI counts depend on these binaries. | Rehash both runner manifests, plugin, IDA, fixture binaries, probes and screenshots; the packaging verifier checks each. |
| G2 | A matching current instruction byte span is sufficient for navigating to that span only. The Jump control depends on it. | Substitute a different byte for the selected source; navigation must disable. Restore the byte; navigation must reenable. Neither outcome upgrades the historical transition. |
| G3 | A settled IDA database is the baseline for the read-only UI inventory. The unchanged-head claim depends on this setup. | Drain queued autoanalysis, record planned-head bytes/items/owners/xrefs, interact with the form and recapture, then compare. The pre-drain mismatch is a counterexample to an unqualified inventory claim. |
| G4 | Syntax admission and checked temporal visits have different evidence requirements. The visible check labels depend on the API's separate result fields. | Render a complete-prefix checked run and an incomplete-prefix budget stop; assert four versus zero checked visits, eight versus zero queries, and three retained syntax-only candidates in the latter. |
| G5 | The prompted bindings are exact current IDB names accepted by the named-model parser. The default capture depends on them. | Resolve mapped import names and rerun the default binding array through the production API; the protected control produces four checked visits and eight queries. A database with no supported names must reject the action. |

**High impact:** the view makes a protected local transition and its abstention
inspectable without changing the IDB's candidate instructions. **Medium impact
risk:** current bytes can match while input state or memory differs; the UI
never calls that a current proof. **Low impact risk:** display quotas can hide
later rows; source and display omission counts remain visible. Full VM ownership,
whole-handler summaries, cross-input behavior and review completion remain
unproved.

QG1: no normative judgment is required. QG2: G1–G5 include falsification
probes. QG3: the action, two evidence classes, navigation guard and actual Qt
interactions are covered; the full review remains incomplete. QG4: byte,
instruction, event, row, time and complexity units are explicit. QG5:
historical-state, incomplete-prefix and autoanalysis boundaries are exposed.
QG6: exact local primary artifacts and source hashes are archived. QG7:
adjacent impact and limits are bounded above.
