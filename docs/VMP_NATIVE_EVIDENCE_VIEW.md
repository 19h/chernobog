# Native conclusions in the evidence workspace

The requirement-5 workspace now imports live native conclusions separately
from execution captures. `chernobog_native_evidence(ea)` is a read-only JSON
inspection API for the selected function. It does not run autoanalysis or
execute the function. The **Native proofs** tab and green graph edges expose
current local conclusions; blue witnesses and amber decoded edges retain their
separate meanings. The workspace also opens when native conclusions exist and
no rax capture has been made.

This extends the earlier checkpoint in `VMP_EVIDENCE_VIEW.md`; that checkpoint's
manifest records its historical source state. The native extension has its own
manifest, `VMP_NATIVE_EVIDENCE_VIEW_EVIDENCE.json`.

## Admission and provenance

The native engine now records an explicit conclusion family and a nonzero
publication identity in its live proof map. Families cover stack-mediated
transfers, get-PC calls and their context-specific returns, stack address
materialization, locally determined Jcc conditions, SETcc byte values, and
CMOV conditions. An unresolved stack transfer remains `truth=candidate` with
no target edge. A condition fact does not authorize deleting a CMOV memory
access or a partial-register write.

Inspection admits neither annotation text nor persisted ownership receipts as
proof. Receipts continue to authorize cleanup only. The inspector checks the
live record's consumed bytes, loaded state, segment permissions/bitness, and
code ownership, then reruns the corresponding bounded recognizer. A changed
entry topology or write-reference restriction can therefore reject a record
even when its instruction bytes are unchanged. Reclassification must agree
with the stored target or value. Inspection does not repair metadata when a
check fails.

Rows include source and conclusion-site addresses, publication, conclusion,
assumptions, validation result, target/value where applicable, and bounded
supporting bytes. Stack summaries retain width, stack delta and recorded
access counts or write size. CALL-derived stack deltas describe the complete
recognized sequence, explicitly not an isolated return edge. Immutable-memory
target facts state their IDA image/write-reference model; they do not establish
immutability against arbitrary external runtime writes.
Transfer conclusions describe the target when the recognized sequence reaches
its transfer under those assumptions. They do not assert successful stack or
memory access on every concrete machine state, nor prove that the sequence is
reachable. Inspection performs no instruction deletion or exception suppression.

Publication identities are monotonic across native engines in the loaded C++
plugin instance. Exhaustion yields identity zero and rejects current-view
admission. The GUI checks exact record equality, including publication and
dependency detail, rather than using a structural hash as proof. Each record
has its own current state: replacing one proof does not invalidate unchanged
neighboring records. Restoring bytes and recomputing a proof creates a new
publication; the old record remains historical until explicit reload.

Native freshness is independent of execution-capture freshness. Native rows
and edges dim when their own admission fails; the navigation button performs
the same current-state query immediately before jumping. The detail pane
reports selected-record freshness separately from execution-capture freshness.
The API and GUI perform these checks on IDA's main thread.

## Bounds and costs

At most 128 native conclusions are retained for one function, with exact
omission count. Each record shows at most 64 stored dependency ranges, each
already limited by the native engine to 16 bytes. A record reports both the
total dependency count and display omissions. Revalidation still checks every
stored dependency and reruns the bounded recognizer; displaying a prefix does
not weaken admission. The native graph adds at most 256 endpoint nodes to the
earlier 512-node execution/encoding bound.

Let P<=4,096 be the live native map size, K<=128 selected records, D their
stored dependency bytes, and R the total work of the K configured recognizers.
Inspection costs O(P + D + R), excluding costs inside IDA ownership/xref query
implementations. Retained detail uses O(K*64*16) byte payload plus bounded
field/format overhead. Native GUI polling rebuilds this projection every 1 s;
its maximum-size latency and process peak memory remain unmeasured. The quota
fixture measures functional truncation behavior, not performance.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| N1 | The existing bounded native recognizers model the admitted x86/x64 forms. Green edges and typed values depend on those contracts. | Independent existing native/ISA regressions plus positive and negative stack, flag, and get-PC inspection fixtures. Wider architectures and protected-program coverage are not inferred. |
| N2 | Current IDA code ownership, entry references, permissions, and immutable-image facts are the analysis model. | Changed consumed bytes reject; current recognizers recheck topology and memory restrictions. External runtime writes and missing IDB references are outside this model. |
| N3 | A live publication identifies a particular conclusion within one loaded plugin instance. | Patch, restore and reanalyze; require a distinct publication and reject the older GUI row. C++ unload/reload and complete multi-database UI coverage remain outstanding. |
| N4 | Native and execution evidence can become stale independently. | Open with no execution capture, require native navigation while capture freshness is false, then invalidate the native dependency and require navigation to disable. |
| N5 | Bounded display does not imply absent conclusions or omitted dependencies. | A 140-branch fixture exceeds the 128-record quota; a maximum-depth flag prefix exceeds 64 dependency rows. Exact omissions must be visible. |
| N6 | Inspection must not publish new analysis facts. | Repeated queries must preserve inspected function bytes, comments, item layout, and outgoing references, and return stable records. Broader third-party IDA hook side effects are not measured. |

## Verification and remaining work

`tests/ida_native_evidence_probe.py` checks the actual IDC API, current
conclusions, dependency detail, unresolved/rejected controls, byte invalidation,
publication replacement, forged annotation rejection, exact-record comparison,
and optional real Qt rendering and navigation gates. The cap fixture is
`tests/vmp_native/evidence_caps.S`; the other inputs are the independent stack,
flag, and get-PC fixtures already used by the native ownership regressions.
Artifacts and exact final counts are recorded in the extension manifest.

The final build passes 13/13 CTest targets. Production IDA checks pass as follows:

| Input / interface | Passed checks |
|---|---:|
| Stack / terminal | 38 |
| Flags / terminal | 35 |
| Get-PC / terminal | 20 |
| Quotas / terminal | 14 |
| Stack / real Qt GUI | 47 |
| Get-PC / real Qt GUI | 29 |
| Existing temporal workspace / real Qt GUI | 31 |

Thus native inspection has 183 passing production checks, plus 31 checks of
the existing execution/lifetime workspace. The quota fixture retains 128 of
140 conclusions and displays 64 of 66 dependencies for its deep proof. The
single CTest run reports 125.05 s; it is not a comparative performance
measurement. GUI renders were inspected as feature-form images without
application titles or personal filesystem prefixes. The graph can extend
beyond the viewport; **Fit flow** and panning expose retained offscreen nodes.

Reproduce from the repository root with local installation artifacts assigned
to `IDA_TERMINAL`, `IDA_GUI`, and `PLUGIN`. These variables are runtime inputs,
not committed installation paths:

```sh
cmake --build build -j 2
ctest --test-dir build --output-on-failure
python3 -B tests/run_ida_smoke.py build/vmp-lifecycle-stack \
  tests/ida_native_evidence_probe.py --ida "$IDA_TERMINAL" --plugin "$PLUGIN" \
  --output-dir build/native-inspection-stack --set CHERNOBOG_NATIVE_FIXTURE=stack \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py"
```

Use `vmp-lifecycle-flags`/`flags` and `vmp-get-pc`/`getpc` for the other existing
fixtures. Build the cap fixture as x86-64 Mach-O from `evidence_caps.S`, select
`caps`, and set `CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64`. The GUI variant uses
`IDA_GUI` with `QT_QPA_PLATFORM=offscreen` and checks actual widgets. None of
these native-inspection probes enables rax execution. Each run needs a distinct
output directory; the runner records the exact copied input/plugin/probe hashes.

Requirement 5 still needs actual SMT query/model detail, protected branch and
counterexample fixtures, the full save/reopen/rebase/undo/unload UI matrix,
and performance measurements. This view does not claim to cover native engine
heuristics that never entered its live proof map. It also does not establish
whole-program reachability or constitute VM semantic lifting.

Subsequent checkpoint: `VMP_SOLVER_EVIDENCE_VIEW.md` adds bounded actual-query
and assignment inspection with independent formula replay. The preceding
manifest and outstanding-work statement describe this native-only checkpoint.

## Bounded expansion and quality gates

| Impact | Finding | Consequence |
|---|---|---|
| High | Identical text or an owned xref can survive beyond the proof that created it. | Live proof identity and current recognition are required; text and cleanup receipts cannot supply a green edge. |
| Medium | Byte restoration can produce a new proof without changing its displayed target. | Exact publication equality distinguishes historical and current records. |
| Medium | One stale record need not invalidate unrelated local conclusions. | Freshness is evaluated per native record rather than inherited from the rax capture. |
| Medium | Rechecking recognizers every poll has a larger cost than comparing a small JSON envelope. | Latency needs measurement at the configured bounds before a responsiveness claim. |

QG1–QG2: no normative premise; assumptions and probes are explicit. QG3: this
is a native-inspection extension, not full review completion. QG4: widths are
bits, stack/dependency sizes are bytes, and polling is 1 s. QG5: unsupported
families, runtime assumptions and lifecycle gaps remain explicit. QG6: source,
fixture and executed artifact hashes establish checkpoint provenance. QG7:
bounded expansion is recorded above.
