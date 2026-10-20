# CoBRA validation and promotion

The runtime default remains `legacy`. `CHERNOBOG_MBA_BACKEND=cobra` selects the
experimental backend when `CHERNOBOG_WITH_COBRA=ON`. An unavailable backend
resolves to legacy with an explicit diagnostic. A failed or exhausted CoBRA
invocation never reruns legacy candidate search for that region.

Production handlers and the licensed SDK bridge share the same microcode
emitter, frame checks, dual proof receipts, and final mutation functions. SDK receipts retain an immutable copy of the exact
emitted object lifted before Boundary 2; post-proof edits of temporary RHS values,
metadata, or parent targets reject before mutation.
The microcode adapter can reject a proved proposal that refers to operands it
cannot lower, then inspect other sites in the same immutable analysis. Admission
performs temporary lowering and a cost check; the accepted site's independent
emission proof, frame validation, and final eligibility gates remain mandatory.
The calls stage also runs contextual constant analysis after the SDK narrows
return values. Its CFG model executes physical register and ordinary memory
locations in order; value-number equality annotations add no assumptions.
This projection cannot enter algebraic generation. Local algebraic snapshots
retain their distinct value-number identities. Undefined flag writes and the
explicit carry/overflow flag operators do not invalidate unrelated scalar or
memory state; unresolved flag-dependent predicates still discard edge facts.
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

Windows acceptance is checked in the native HKCU registry: IDA does not use
`ida.reg` on Windows. Provisioning applies the pinned HCLI 9.x acceptance procedure through native
HKCU and verifies the readback. Startup failure artifacts contain fixed error
categories and numeric Windows error codes, excluding arbitrary license text.
Unix runners still require that file. The smoke runner
copies only platform-appropriate configuration and the selected Python startup
files. This follows the [SDK registry contract](https://python.docs.hex-rays.com/ida_registry/index.html); license and decompiler checks remain mandatory.

The native workflow is `.github/workflows/mba-cobra-runtime.yml`. Its `inventory`
operation reports only installer identity fields; `provision` validates the
selected `probe_target` without requiring a compiled test bundle; `resolve` computes installer
SHA-256 digests. `probe` exercises a successful trusted native artifact independently
of the other build jobs, using the current harness and recording both artifact
and harness revisions. Its report is always `diagnostic` and cannot qualify
promotion, including when both revisions match. `probe_sdk_only` isolates SDK
loading and faults; it omits installed-corpus qualification and is also rejected
by the aggregate.
`accept` requires the ID of a successful native build of the
same master revision, with the harness also at that revision. CMake embeds
`git --short=12`; that hexadecimal label must match the complete trusted bundle
commit, which remains bound to the exact checkout and artifact SHA-256 digests. It downloads the separate `cobra-sdk-*` test bundles and
the release plugin artifacts from that build. The protected `ida-runtime`
environment provides `HCLI_API_KEY` and `IDA_LICENSE_ID` only during provisioning.
Installer binaries, credentials, license files, databases, and provisioning
configuration are excluded from uploaded evidence. License resolution uses the
exact active ID across accessible accounts through the pinned official client;
it does not invoke the CLI's interactive customer picker. Native corpus inputs
are compiled with optimization disabled so the MBA source reaches the plugin.

`tests/fixtures/ida_cobra_runtime_manifest.json` freezes six IDA 9.4 installers
by exact asset key, byte count, and SHA-256. HCLI 0.26.3 binaries are independently
pinned in `tests/fixtures/hcli_0.26.3.json`. The authenticated catalog visible
at fingerprint resolution contained the six 9.4 installers; 9.5 runtime
qualification remains separate from this matrix.

The aggregate checker requires 504 successful SDK positives (42 fixtures times
two profiles times six targets), 186 negative mutation rejections, six positive
legacy deadline-fallback controls, and the frozen legacy regression manifest for both backends on every target.
The latter requires six nested, seven semantic, 32 caller/context, and five
flag/store captures; semantic captures also restore the Normal profile. Independent
UBSan oracles check 607,986 nested, 1,176,672 flag/store, 1,437,084 contextual,
and 17,768,781 semantic comparisons per captured profile. The source fixtures
retain their historical bytes and SHA-256 identities. Missing reports, skipped targets, differing source
fingerprints, altered artifacts, and candidate-only evidence reject promotion.
The aggregate reports nearest-rank p50/p95 phase timing distributions, solved
and applied counts, corpus deadline overshoot, and peak RSS; injected-fault
overshoots are recorded separately. Timing is measured in ns and memory in B. SDK backend processes are separate;
process RSS is a lifetime high-water mark. The 64 MiB and 256 MiB scratch limits
apply to instrumented container and AST payloads, separately from process RSS.
Complete extraction, invocation, reconstruction, and cleanup intervals partition
candidate elapsed ns. Exceptional unwinding is charged to the active interval;
`timings_complete=false` identifies these partial splits. A failed clock callback
publishes no candidate and reports unavailable timing as zero with that flag.

Local validation on the implementation source exercised 33 CTest suites, 84 SDK
positive rows, 31 negative SDK probes, and the positive legacy fallback control.
The installed-plugin nested corpus passed with both backends and both profiles;
each independently compiled unsigned profile checked 607,986 values with UBSan.
The expanded local corpus also passed seven semantic, 32 caller/context, and
five flag/store captures with both backends. Compiled UBSan oracles checked
17,768,781 semantic, 1,437,084 caller/context, and 1,176,672 flag/store values per
profile, including restored Normal semantic captures. These local results do not qualify the other native release targets.
The Windows-compiled x64 corpus also passed local macOS captures and compiled
UBSan oracles for both semantic backends after calls-stage constant recovery;
its nested, caller/context, and mask groups passed local CoBRA captures and
their corresponding oracles. Loading a Windows input under macOS is distinct
from executing the Windows plugin in its native runtime.

| Assumption | Dependent result | Falsification probe |
|---|---|---|
| A1: The shared SDK library is the production emission implementation. | SDK proof and frame evidence applies to the handlers. | Link both handlers and the bridge to `chernobog_mba_sdk`; inspect build provenance and artifact identity. |
| A2: Cancellation or a scheduling pause can follow an observed Z3 UNSAT. | Post-query and final eligibility gates reject late work. | Inject cancellation and a 150 ms pause against a 100 ms allowance; require unchanged microcode and ctree. |
| A3: A preverified legacy ctree fallback retains only its deadline exception. | Existing fallback behavior survives strict CoBRA gating. | Require the positive legacy expiry control and reject cancellation, stale frame, and CoBRA waiver probes. |
| A4: Native runtime compatibility and performance require measurements. | Default promotion depends on the complete matrix. | Run `accept`; the aggregate rejects a missing native report. |
| A5: Region scheduling affects generation cost and proof difficulty. | Unmasked linear arithmetic regions up to 32 bits try the complete region before its prefixes, after processing typed boundaries; wider, masked, and polynomial regions retain bottom-up proof lemmas. | Require all 42 frozen SDK positives in both profiles and the unchanged native Windows nested corpus; failed positives or retained nested MBAs reject the scheduling change. |

| Bounded finding | Impact | Contract |
|---|---|---|
| Same-generation edits can change proof context without changing the source expression. | High | Rebuild the typed microcode domain and compare the ctree body/local domain before the final clock gate. |
| A newly reconstructed polynomial can retain equal literal factors below its root. | Medium | Apply deterministic scalar factoring, then require the same proofs and strict emitted cost reduction. |
| Windows checkout newline conversion changes exact-byte patch and source digests. | Medium | Preserve patch bytes and normalize fingerprinted source checkout line endings. |
| Invariant-backed loop constants and Boolean-only selectors are outside an arithmetic-mixture-only admission rule. | High | Retain contextual constant proofs before generation and admit Boolean selectors to CoBRA without requiring an arithmetic node. |
| A canonical complement can inflate output cost despite reducing the algebraic core. | Medium | Prove local XOR-literal compaction; retain the fixed modular complemented-word sum identity before candidate acceptance. |
| An equal-cost local bit predicate can be discarded while simplifying a larger division. | Medium | Retain that local normalization inside the cheaper enclosing candidate; require strict cost reduction of both the complete term and actual emitted replacement, including 32-bit quotients. |
| A host cancellation callback can reset its signal after an earlier observation. | Medium | Latch positive cancellation for the session and verify that final commit and legacy fallback still reject it. |
| Complete-region generation can reduce repeated work but expose harder direct proofs. | High | Cache only instantiated fixed word identities proved UNSAT for arbitrary words in the same solver session; leave CoBRA inputs unchanged and retain both replacement proof boundaries. Wide, masked, and polynomial regions keep their established bottom-up schedule. |
| A narrow source argument annotation can make IDA 9.4 ARM64 overlap a helper argument with its wide return register. | Medium | Retain the inferred native argument carrier for the designated signed helper; require the original signed-byte result and compiled contextual oracle. |
| Restored project objects can be newer than checked-out headers and preserve incompatible class layouts. | High | Discard top-level project compilation state after cache restore; retain dependency builds and content-checked compiler caches. |
| Removing an empty statement changes the domain after a proved replacement. | Medium | Advance the mutation epoch and refresh the domain snapshot after owned structural cleanup. |
| An unlowerable first proposal can hide later reductions and discard inference statistics. | High | Reject that site through the adapter admission predicate, continue in the same immutable analysis, and retain accumulated statistics; exercise both backends. |
| x64 local-stage return carriers can be wider than the declared result, while narrowed calls-stage expressions carry value-number annotations. | High | Prove constants over a sequential CFG at the calls stage, without using value-number equalities or algebraic generation; preserve full source/frame checks and both value proofs. |
| Repeating calls-stage analysis on straight-line functions can consume the Normal allowance without supplying loop facts. | High | Run that extra constant pass only for reachable CFG cycles; retain the prior LOCOPT and ctree allowances for acyclic functions. Cycle detection uses O(V + E) time and O(V) space, with V bounded by 64 blocks. |
| GCC loop-counter copies can carry `DONT_COMB` and split metadata without changing their copy semantics. | High | Model only direct propagatable ordinary copies, preserve the original instruction and flags, exclude protected copies from replacement, and continue rejecting `DONT_PROP`, assertions, persistence, floating-point instructions, and memory barriers. |
| Native installer identity does not establish license or decompiler entitlement. | High | Require actual provisioning, plugin loading, SDK execution, and unsigned oracle completion. |

The implementation follows the descriptive scope and assumptions of
`MBA_COBRA_SPEC.md` (QG1-QG2), separates candidate/SDK/installed boundaries (QG3),
uses explicit ns/B/bit units (QG4), rejects stale/late/malformed emissions (QG5),
records source, dependency, installer, and artifact identities (QG6), and bounds
the additional findings above (QG7). Native promotion remains an independent
execution gate.
