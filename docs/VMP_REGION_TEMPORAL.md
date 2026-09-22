# Explicit temporal capture across native owners

`chernobog_vm_trace_temporal(ea, seed, input_json, bindings_json)` now executes
a bounded native region with explicitly selected ABI call models and preserves
ordered allocation/use/release observations. This removes the entry-owner stop
for the paired string corpus without changing ordinary function ownership or
publishing ordinary function evidence.

Original and mutation seeds 0 and 12648430 complete in all four tested entry
seeds, with both byte-exact results matching the independent native comparator.
Mutation seed 1 observes both lifetimes but stops before return at a rejected
16-bit BSWAP. All six virtualization/combined variants also stop at rejected
16-bit BSWAP instructions. Those 28 incomplete captures retain explicit stops.
No protected ctree annotations or cross-run string consensus are claimed by
this change: it establishes the separately scoped temporal observations needed
for that next step.

**Assumptions and falsification probes**

| ID | Assumption / dependent result | Stress test |
|---|---|---|
| T1 | A caller-selected name/address binding supplies the intended ABI model. Callee implementation equivalence is **unknown**. | Require an exact current IDA name and a recognized model; reject missing, duplicate, renamed, unknown, malformed and oversized bindings. Export every binding and the model contract. |
| T2 | A native CALL followed by one JMP thunk retains a callable return context. Thunk model application depends on this. | Require an admitted CALL, one exact admitted jump instruction, unchanged SP and the same stack return value equal to CALL fallthrough. Direct and observed-indirect calls pass; non-call entry and multi-instruction thunks stop. |
| T3 | The scoped return run has complete temporal observations under the selected models. Capture completeness depends on this. | Require sentinel return, available memory hooks and no byte/event/dependency quota, permissions, environment, changed-code or boundary failure. Instruction exhaustion remains incomplete; caller scratch objects are rejected because their current range overlaps the modeled heap. |
| T4 | The paired fixture provides a separate byte oracle. Native comparisons depend on its fixed input and host execution. | Reuse the hash-bound corpus and unchanged 67-byte comparator from `VMP_PROTECTED_STRINGS.md`; compare both final registers and stack delta. Source-to-protector attestation and native x86 hardware coverage remain **unknown**. |
| T5 | Native instruction admission agrees with an independent decoder and file bytes. Entered-span claims depend on this. | Capstone checks all 7,156 entered records, their bytes, sizes and linear successors; independently identify all 28 rejected 16-bit BSWAP frontiers. |

**Execution and publication contract [T1–T3]**

Input retains the bounded scalar argument format of `chernobog_vm_trace_input`:
`{"args":[],"objects":[]}` is the no-argument request. This API requires the
objects array to be empty. Bindings are a JSON array of 1–32 records, each with
exactly `address` (hexadecimal string) and `name` (current IDA name). For example,
the client resolves the fixture's `_malloc`, `_memset` and `_free` names and
passes their addresses. A recognized name is an explicit modeling assumption,
not proof that arbitrary code at that address implements that function.

The native plan and continuation retain exact instruction-byte checks, a
4,096-head cap, at most 64 extensions and one shared execution/time budget.
The production API allows at most 4,096 instructions and 250 ms, and retains at
most 65,536 temporal payload bytes. Binding text is bounded to 8,192 bytes with
nesting checked before JSON parsing. Existing per-event and allocation limits
remain in force. Modeled callee bodies are not native instruction observations.

The direct-call summary gate remains the default. In this explicit mode, it can
also follow one native JMP thunk immediately after an observed CALL. The thunk
must be the next executed instruction, match its planned bytes, and preserve
both SP and the observed return address. The summary uses the original CALL site
for allocation/use provenance. Its native CALL/JMP edges remain visible. A
dynamically admitted indirect-call target retains the same guard after resume;
the incoming transfer is not duplicated. No arbitrary tail jump or stack-forged
call is admitted by this rule.

`native_temporal_requested` and `native_temporal_complete` describe this separate
scope. `temporal_capture_complete`, ordinary `conclusive()` and consumed-context
proof completeness remain false. Modeled executions also keep
`data_trace_complete` false. Existing trace/walk/check APIs keep environment
models disabled. The new API returns raw use bytes and lifetimes, explicit
bindings, source EAs, event sequences, capture identity and stop information;
it writes no ordinary evidence, xrefs, ownership, comments or VM identity.
Capture results are ephemeral, not a persistent freshness lease.

**Paired production results [T4, T5]**

| Binary | Complete / scheduled | Instructions per run | Modeled calls | Outcome |
|---|---:|---:|---:|---|
| Original | 4 / 4 | 171 | 6 | Both byte values match; two released allocations |
| Mutation 0 | 4 / 4 | 303 | 6 | Both byte values match; two released allocations |
| Mutation 1 | 0 / 4 | 336 | 6 | Both lifetimes observed; rejected BSWAP16 before return |
| Mutation 12648430 | 4 / 4 | 331 | 6 | Both byte values match; two released allocations |
| Virtualization 0 / 1 / 12648430 | 0 / 12 | 50 / 14 / 40 | 0 | Rejected BSWAP16 before allocation |
| Combined 0 / 1 / 12648430 | 0 / 12 | 18 / 276 / 250 | 0 | Rejected BSWAP16 before allocation |

Each binary uses entry seeds 0, 1, 17 and 12648430. This is one fixed two-string
workload, not exhaustive input equivalence. Twelve completed captures provide
24 byte-value comparisons. The first implementation crossed owners but stopped
all mutation captures at an unmodeled external jump; those historical results
are retained separately. The checked CALL/JMP thunk rule resolves that stop for
all three mutation variants, exposing the later BSWAP16 stop in seed 1.

All 354 production checks and 23 ordinary native-string regression checks pass.
All 20 CTest suites pass (11.04 s). Portable tests cover lifetime reuse,
use-specific bytes, context/seed identity, shortened owner bounds, opt-in model
isolation, quota exhaustion, scratch overlap, and direct/indirect thunk controls.
The independent decoder reports zero byte, size or linear-successor mismatches.
Process measurements span 3.02–3.25 s and 192,724,992–257,851,392 peak resident
bytes per isolated IDA runner; they include process startup and waited-for child
accounting, and do not estimate analysis throughput.

**Reproduction**

```sh
python3 -B tests/run_vmp_region_temporal.py \
  --corpus-report build/vmp-protected-strings-release/strings.json \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-region-temporal-new
python3 -B tests/verify_vm_native_region_decode.py \
  --report build/vmp-region-temporal-new/region_temporal_analysis.json \
  --corpus-report build/vmp-protected-strings-release/strings.json \
  --capture-artifact region_temporal.json \
  --output build/vmp-region-temporal-new/decode_verification.json
ctest --test-dir build --output-on-failure
```

Accepted artifacts are under `build/vmp-region-temporal-final`, with the ordinary
regression in `build/vmp-region-temporal-final-ordinary`.
[VMP_REGION_TEMPORAL_EVIDENCE.json](VMP_REGION_TEMPORAL_EVIDENCE.json) records
source, runtime, corpus and observation hashes. The supplied primary source
`vmp/runtime/string_manager.cc` motivates lifetime tracking; these fixtures do
not claim to call that particular routine.

For M bindings, sorting costs O(M log M), then target lookup costs O(log M).
The one-instruction thunk guard adds O(1) time/space per entered instruction,
excluding retained events. Temporal capture remains bounded by the existing
event and byte quotas. These local costs exclude native-region planning,
emulation and snapshot construction.

**Bounded implications and quality gates**

- **High:** region bounds and library ABI models are separate admission contracts.
  Satisfying either alone did not reach the protected use sites in this corpus.
- **Medium:** preserving call provenance through an import thunk avoids treating
  every observed jump to a familiar name as a modeled call.
- **Medium:** an incomplete execution can contain useful raw lifetime evidence;
  it must remain distinguishable from a completed temporal observation.
- **Low:** wider architectures, caller object placement, longer thunk chains,
  protected string consensus/display and GUI integration remain incomplete.

QG1: technical implementation only. QG2: T1–T5 registered with probes. QG3:
driver, production API, corpus, independent decoder and ordinary regressions
cover this changeset; the full review remains incomplete. QG4: byte/count/time
units and complexity scope are explicit. QG5: rejected ISA semantics and model
assumptions remain explicit. QG6: primary source and accepted evidence are hash
bound. QG7: adjacent implications and remaining limits are stated above.
