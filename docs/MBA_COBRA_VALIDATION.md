# CoBRA validation and promotion

The runtime default remains `legacy`. `CHERNOBOG_MBA_BACKEND=cobra` selects the
experimental backend when `CHERNOBOG_WITH_COBRA=ON`. An unavailable backend
resolves to legacy with an explicit diagnostic. A failed or exhausted CoBRA
invocation never reruns legacy candidate search for that region.

Production handlers and the licensed SDK bridge share the same microcode
emitter, frame checks, dual proof receipts, and final mutation functions.
Microcode fixtures exercise all eight admitted byte widths. Ctree emission
admits the SDK's integral types at 8, 16, 32, and 64 bits. Neither a candidate-only
test nor the SDK bridge establishes installed-plugin corpus behavior.

```text
Frozen 42-fixture manifest
          |
          v
Candidate-only CTest --> actual SDK emission (Normal + Deep)
                                  |
                       injected faults and legacy control
                                  |
                    installed-plugin paired corpus capture
                                  |
                      independent unsigned native oracle
                                  |
                    six native targets, identical provenance
                                  |
                       fail-closed promotion aggregate
```

The native workflow is `.github/workflows/mba-cobra-runtime.yml`. Its `inventory`
operation reports only installer identity fields; `resolve` computes installer
SHA-256 digests. `accept` requires the ID of a successful native build of the
same master revision. It downloads the separate `cobra-sdk-*` test bundles and
the release plugin artifacts from that build. The protected `ida-runtime`
environment provides `HCLI_API_KEY` and `IDA_LICENSE_ID` only during provisioning.
Installer binaries, credentials, license files, databases, and provisioning
configuration are excluded from uploaded evidence.

`tests/fixtures/ida_cobra_runtime_manifest.json` freezes six IDA 9.4 installers
by exact asset key, byte count, and SHA-256. HCLI 0.26.3 binaries are independently
pinned in `tests/fixtures/hcli_0.26.3.json`. The authenticated catalog visible
at fingerprint resolution contained the six 9.4 installers; 9.5 runtime
qualification remains separate from this matrix.

The aggregate checker requires 504 successful SDK positives (42 fixtures times
two profiles times six targets), 126 negative mutation rejections, six positive
legacy deadline-fallback controls, and both unsigned corpus profiles for both
backends on every target. Missing reports, skipped targets, differing source
fingerprints, altered artifacts, and candidate-only evidence reject promotion.
Timing is measured in ns and memory in B. SDK backend processes are separate;
process RSS is a lifetime high-water mark. The 64 MiB and 256 MiB scratch limits
apply to instrumented container and AST payloads, separately from process RSS.

Local validation on the implementation source exercised 33 CTest suites, 84 SDK
positive rows, 21 negative SDK probes, and the positive legacy fallback control.
The installed-plugin nested corpus passed with both backends and both profiles;
each independently compiled unsigned profile checked 607,986 values. These
local results do not qualify the other native release targets.

| Assumption | Dependent result | Falsification probe |
|---|---|---|
| A1: The shared SDK library is the production emission implementation. | SDK proof and frame evidence applies to the handlers. | Link both handlers and the bridge to `chernobog_mba_sdk`; inspect build provenance and artifact identity. |
| A2: Cancellation or a scheduling pause can follow an observed Z3 UNSAT. | Post-query and final eligibility gates reject late work. | Inject cancellation and a 150 ms pause against a 100 ms allowance; require unchanged microcode and ctree. |
| A3: A preverified legacy ctree fallback retains only its deadline exception. | Existing fallback behavior survives strict CoBRA gating. | Require the positive legacy expiry control and reject cancellation, stale frame, and CoBRA waiver probes. |
| A4: Native runtime compatibility and performance require measurements. | Default promotion depends on the complete matrix. | Run `accept`; the aggregate rejects a missing native report. |

| Bounded finding | Impact | Contract |
|---|---|---|
| Same-generation edits can change proof context without changing the source expression. | High | Rebuild the typed microcode domain and compare the ctree body/local domain before the final clock gate. |
| A newly reconstructed polynomial can retain equal literal factors below its root. | Medium | Apply deterministic scalar factoring, then require the same proofs and strict emitted cost reduction. |
| Windows checkout newline conversion changes exact-byte patch and source digests. | Medium | Preserve patch bytes and normalize fingerprinted source checkout line endings. |
| Native installer identity does not establish license or decompiler entitlement. | High | Require actual provisioning, plugin loading, SDK execution, and unsigned oracle completion. |

The implementation follows the descriptive scope and assumptions of
`MBA_COBRA_SPEC.md` (QG1-QG2), separates candidate/SDK/installed boundaries (QG3),
uses explicit ns/B/bit units (QG4), rejects stale/late/malformed emissions (QG5),
records source, dependency, installer, and artifact identities (QG6), and bounds
the additional findings above (QG7). Native promotion remains an independent
execution gate.
