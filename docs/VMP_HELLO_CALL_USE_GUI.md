# Protected hello call-use in the Qt evidence view

This checkpoint advances review row 5 for the explicit VMP hello use in
`VMP_HELLO_CALL_USE.md`. A separate **Chernobog shadow call use** action accepts
a caller-supplied native shadow file and JSON call selector at the selected
root. Its Qt form shows the bounded native heads, conditional transfer,
selected argument register and bytes, stop frontiers, and synthetic-state
provenance. It does not assert callee behavior, VM identity, or an ordinary
IDA function proof. The file path and request stay in the live form; neither
is written to the IDB by this view.

The form retains at most 256 heads, 256 edges and 256 frontiers. It displays
omission counts and a source SHA-256. Polling every 5 s recomputes the exact
native result and hashes the shadow file before and after the query. The
comparison ignores only the API's per-query `capture` counter. A changed
file, unavailable use, changed result, or detected change during the query
marks the view stale. Reload replaces the displayed capture only after a
stable file hash and available use. Equal byte contents at two different file
paths retain separate forms; at most eight forms are retained.

Two fresh IDA 9.4 SP1 GUI processes used the independently captured LLVM and
Apple LLDB windows from `VMP_HELLO_RUNTIME_SHADOW.md`. Both windows have the
same 40 bytes and SHA-256. Each run passed all 15 GUI checks and produced
byte-identical reports and screenshots. The form shows nine planned heads,
one dashed conditional CALL transfer and two stop frontiers. Its selected
argument is `RDI=0x10000145c` at CALL `0x10000144d` to `0x100001456`, with
12 bytes `48656c6c6f20576f726c6400` (`Hello World\0`, including the one-byte
NUL). The detail pane labels the state synthetic and reports
`callee_semantics_proved=false`, `function_evidence_published=false` and
`vm_identity_proved=false`. A changed file byte and a mutation during a
recomputation both make the form stale; restoring the exact file makes it
current. The registered action handler opens the form and reuses the exact
same-file capture, while an equal-byte second file gets a distinct form.

The full IDB inventory had 74 heads and 65 outgoing references before the
GUI event pump and after the shadow-use API call. Four idle Qt event pumps,
before this form opened, changed it to 278 heads and 275 references. The
inventory hash then remained identical through form display, action
registration and dispatch. The selected 40-byte region's flags, loaded
state, owner and incoming references were identical before and after. The
cause of the idle-pump database change is **unknown**; this experiment does
not establish full-IDB immutability. The synthetic graph is a transient
interpretation of caller-supplied bytes, not published source facts.

The two screenshots were visually inspected. At the measured 274 × 478 Qt
pixel graph viewport, the 346 × 381 scene is fitted at scale 0.699; node
labels, the conditional edge, the table value and the proof limits are
visible. Visible status, scope and detail fields contain no personal path.
The isolated probe invokes the registered handler with a supplied action
context and replaces its file-selector prompt; it does not test human menu
selection or prompt parsing.

## Reproduction and cost

Use the installed native plugin at the pinned revision and a fresh IDA GUI
output directory. Recreate the two debugger windows as specified in
`VMP_HELLO_RUNTIME_SHADOW.md`, then run:

```sh
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_hello_use_gui_probe.py --ida "$IDA_GUI" \
  --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-hello-use-gui-reproduction --enable-rax \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py" \
  --set "CHERNOBOG_VMP_HELLO_WINDOW=$PWD/build/vmp-hello-runtime-final-llvm/runtime-window.bin"
```

Repeat with the Apple LLDB window and another fresh output directory.
`VMP_HELLO_CALL_USE_GUI_EVIDENCE.json` pins inputs, source, tools, raw reports
and screenshots. The shadow file must contain 1–65,536 bytes; the native API
applies its own tighter query constraints. For H displayed heads, E edges, F
frontiers and J JSON characters, a rebuild uses O(H + E + F + J) time and
space, excluding Qt layout and the bounded native analysis. Each poll adds
two O(B) file hashes for B ≤ 65,536 bytes, plus the native query and O(J)
comparison. Query latency and eight-form peak memory remain unmeasured.
Byte counts, addresses, hashes and inventory counts above are exact.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| G1 | The two named windows belong to the supplied protected hello file. The same-use GUI comparison depends on this association. | Rehash the executable and windows, reproduce the debugger stops, and reject mismatched addresses or bytes. Protector settings and build lineage remain unknown. |
| G2 | Exact same-context API recomputation and a stable file hash establish display freshness. The current label depends on this check. | Mutate a byte before a poll and during the API call; require stale status. Switch the database or mutate and restore between both hashes to test limits of the guard. |
| G3 | The selected 40-byte inventory captures mutation at the shown call/use window. The local preservation result depends on those fields. | Save/reopen and compare wider metadata and netnodes; do not infer full-IDB immutability from this inventory. |
| G4 | A fresh GUI process with an idle event pump separates unrelated inventory movement from form activity. The form-specific inventory conclusion depends on this ordering. | Repeat without opening the form and compare the first divergent inventory; a later difference would defeat the conclusion. |
| G5 | The two screenshots and table checks reflect visible widgets at this viewport. The visual inspection result depends on their hashes. | Render at other viewport sizes and inspect the table, graph, status and detail again. |

- **High impact:** one protected call-use result is inspectable with its exact
  pointer, bytes, transfer and synthetic provenance.
- **Medium impact:** file changes invalidate the displayed capture, and the
  action keeps equal-byte files separate by path identity.
- **Low impact:** human prompt handling, other calls, wider database lifecycle,
  callee effects and performance at maximum limits remain unmeasured.

QG1: technical claims only. QG2: G1–G5 include falsification probes. QG3:
the two GUI runs, byte mutation, during-query mutation, same-file reuse,
second-file separation, idle-pump control and selected inventory are covered;
full review row 5 remains in progress. QG4: bounds, units and complexity are
explicit. QG5: API readout, synthetic interpretation and process observations
are distinct; the full inventory change is reported. QG6: local primary
source, binary, debugger windows, IDA/plugin builds and raw GUI outputs are
hash-linked. QG7: impact and unsupported cases are bounded above.
