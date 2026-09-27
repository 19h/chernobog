# Empty model contracts for bounded temporal VM traces

The explicit `chernobog_vm_trace_temporal` and
`chernobog_vm_trace_temporal_check` IDC APIs accept `[]` as a bounded empty
named-ABI contract. The same parser continues to require an exact mapped name
and supported summary for every supplied nonempty record. The separate
`chernobog_vm_temporal_strings` API retains the nonempty requirement because
its four-run consensus checks named-model provenance. The change is restricted
to the two VM trace call sites in `src/vm/ida_native_trace.cpp`; an empty array
does not assert that external calls are modeled or that a captured prefix is
complete.

## Actual IDA evidence

Pinned IDA console and the installed signed plugin ran the same read-only
probe on the two exact supplied static x86-64 ELF files. Each run passed ten
checks: both VM trace entry points accepted `[]`, retained an empty
`environment_bindings` array and did not publish ordinary function evidence
or a VM identity; four malformed arrays were rejected; the temporal string
API rejected `[]`; the selected entry's first 16 bytes and flags were
unchanged. Each capture entered 33 instructions from the selected startup
function. Neither returned a complete temporal prefix, so neither supplies a
checked VM transition. The second run is an independent binary control, not a
second protected-input oracle.
The prior protected `virtualization-0` Qt probe also passes all 13 checks
with nonempty named bindings against the revised installed plugin. The full
CTest suite passes 23/23 at four jobs.

The two full runner manifests and probe reports are retained in
[`VMP_VM_EMPTY_BINDINGS_CAPTURE.json.gz`](VMP_VM_EMPTY_BINDINGS_CAPTURE.json.gz).
[`VMP_VM_EMPTY_BINDINGS_EVIDENCE.json`](VMP_VM_EMPTY_BINDINGS_EVIDENCE.json)
records exact input, plugin, IDA, probe, runner, report and archive SHA-256
values. Recheck the archive without IDA:

```sh
python3 -B tests/verify_vm_empty_bindings.py \
  --archive docs/VMP_VM_EMPTY_BINDINGS_CAPTURE.json.gz \
  --evidence docs/VMP_VM_EMPTY_BINDINGS_EVIDENCE.json
```

## Assumption register and bounds

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| B1 | The two files are the user-supplied Morok outputs. The family label depends on that attribution. | Rehash both files against the archived manifest; compare a recorded source/build/seed chain before claiming stronger source lineage. |
| B2 | An empty binding list requests zero named ABI summaries, not a modeled environment. The VM trace interpretation depends on this distinction. | Require `environment_bindings == []`, reject malformed records, and retain the separate stop/prefix metadata. An unmodeled external effect must not be promoted to a checked transition. |
| B3 | The selected startup function is a bounded entry, not the unpacked application body. The narrow 33-instruction result depends on that scope. | Capture an independently observed runtime checkpoint with exact bytes and input state; compare a complete prefix before inferring a protected handler. |
| B4 | The trace APIs do not change the selected IDB source. The 16-byte/flag check depends on the probe's limited inventory. | Compare the complete planned head/owner/xref inventory under a settled IDB before making a region-wide unchanged-source claim. |

Parsing a JSON contract of length `n <= 8192` bytes scans O(n) characters
plus at most 32 records and stores O(32) bindings. Each native trace retains
the existing 4,096-instruction and event bounds. Instruction and check counts
are dimensionless exact integers; the 16-byte inventory is a byte count.

**Medium impact:** static binaries without supported named imports can now
reach the temporal trace API. **Medium impact risk:** accepting an empty
contract could be mistaken for environment completeness; explicit prefix and
publication fields prevent that interpretation in these two captures.
**Low impact risk:** the 16-byte source inventory does not establish that the
whole IDB is unchanged.

QG1: no normative judgment is required. QG2: B1–B4 include falsification
probes. QG3: both VM entry points, parser rejection, preserved string contract
and source check are covered; the full VMP review remains incomplete. QG4:
array, byte, instruction and complexity bounds are explicit. QG5: incomplete
prefixes are not treated as VM proofs. QG6: local primary runner artifacts and
hashes are archived. QG7: adjacent effects and limits are bounded above.
