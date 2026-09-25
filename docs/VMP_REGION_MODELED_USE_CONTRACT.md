# Native-region modeled-use contract

Review rows 3a, 3b, 5 and 6a include a separate native-region temporal string
projection. The ordinary selected-function modeled-use projector now requires a
named model contract and a matching observed CALL, but the region projector
previously admitted an exact modeled snapshot when only its callee address,
model kind and argument position matched a supplied binding. A mismatched
binding name or absent dynamic CALL could still produce a string. This change
brings the completed-region and completed-prefix paths under the same explicit
call provenance requirement. Region observations still confer neither ordinary
function proof nor VM identity.

## Admission and bounds

Every retained region binding must have a unique address and a name that the
IDA-free policy classifies to its declared model kind. A run containing a
modeled argument must report external-model use. For each such snapshot, the
region projector indexes the run's transfer edges by sequence and requires the
latest transfer before the snapshot to be a CALL from the exact use site to
the exact modeled callee. Duplicate transfer sequences make modeled uses from
that run ambiguous. Existing object lifetime, context, argument-slot, UTF-8,
capture-completeness and all-run agreement checks remain in force. A missing
edge can suppress one use while preserving a different, independently
corroborated use.

Both completed and prefix region captures now cap transfer edges at 4,096 per
run; the separate corpus cap is 16 runs. With `E_r` edges, `U_r` modeled uses,
`K` bindings and at most `L` bytes per binding name in run `r`, the additional
sort, classification and lookup cost is
`O(sum(E_r log E_r + U_r(log E_r + K) + K L))` time and
`O(sum E_r)` index space. Here `K <= 32`, `L <= 128`, and `E_r <= 4,096`.
This excludes emulation, existing object/read indexes and byte decoding.

## Executed controls

Portable evidence checks first failed on a same-address `strcmp` name paired
with a declared `strlen` kind. The revised projector rejects that contract,
an unreported model, a missing or non-CALL transfer, a wrong target, an
intervening transfer and duplicate transfer sequences. The nine supported
string-model input slots retain their expected results when both name and kind
agree. An actual RAX x86-64 regional execution observes two erased `strlen`
arguments; both the completed and bounded-prefix projectors retain them.
Removing the first use's CALL edge removes that one modeled observation in each
mode.

A fresh signed-plugin IDA 9.4 SP1 console run on an independent x86-64 Mach-O
fixture passes 38/38 checks and reports two executed-read and two
modeled-argument observations across four captures. Its native process exits
0; independently changed expected values exit 1 and 1. A fresh prefix
inspection passes 43/43 with the same four observations. The separate
interleaved executed-read fixture passes 35/35 and retains its two stream
values. All 21 configured CTest suites pass. These positives show that the
new gate retains the observed fixture behavior; the portable mutation and
real-backend edge-removal controls demonstrate rejection. Exact source,
binary, plugin, IDA and report hashes are in
`VMP_REGION_MODELED_USE_CONTRACT_EVIDENCE.json`.

Reproduce the completed console fixture with a fresh output directory:

```sh
python3 -B tests/run_native_use_snapshots.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/region-model-contract-reproduction
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The supplied binding vector is the exact named model contract used by the regional emulator. Model attribution depends on it. | Mismatched names/kinds, duplicate addresses and cross-run contract changes reject. A coherently forged contract and event trace remains outside this check. |
| R2 | Transfer edges and snapshot sequences describe the same dynamic run. CALL attribution depends on the ledger. | Remove or change the first CALL, duplicate its sequence and exceed 4,096 edges; each rejects the affected modeled result or capture. A falsely complete backend trace remains unknown. |
| R3 | `external_model_used` and native temporal completion accurately report the run. Publication depends on those flags. | Clear model-used in one synthetic run; reject. Existing complete/prefix controls reject incomplete, truncated and foreign-identity captures. |
| R4 | The independent fixture's native process oracle checks the two consumed values. The positive-value result depends on it. | Original exits 0; changed first and second expected values each exit 1. The x86-64 fixture runs under the macOS arm64 host loader, so direct hardware equivalence is unknown. |
| R5 | Four finite captures and an exact prefix cutoff define the observation scope. Cross-run conclusions depend on that scope. | Compare every scheduled capture; reject missing/conflicting uses and prefix-bound violations. Other inputs, protected emitters and whole-function semantics remain unknown. |

**High impact:** a modeled region string now requires a dynamic CALL witness
and a classified named contract. **Medium impact:** duplicate transfer
sequences suppress modeled candidates, while unrelated exact reads remain on
their separate path. **Low impact:** the 4,096-edge bound can reject a large
completed capture; this is explicit abstention, not a recovered value.
Protected-emitted modeled calls, same-name semantic replacement, runtime
throughput and complete review coverage remain unknown.

QG1: no normative premise. QG2: R1–R5 include falsification probes. QG3:
completed/prefix portable and actual-backend controls, native process oracles,
IDA positives and read-stream regression cover this scoped change; the full
review remains open. QG4: bounds, byte units and asymptotic cost are explicit.
QG5: ambiguous transfers, incompatible contracts and incomplete runs abstain.
QG6: local source, fixture, plugin, IDA and raw-report hashes identify primary
evidence. QG7: the impact and unmeasured protected scope are bounded above.
