# Chernobog / Assist analysis synchronization

## Boundaries

This synchronization compares committed Chernobog
`dc6cc401189642d14a4ffef14376137bdcb3659b` through
`84308f8393723fe22ff090351b3d37c65a171434` against Assist baseline
`059d98372d2a1a5b1e36aa0954814982e4397932`.
The upstream interval contains 129 commits. Nine of the 34 distinct upstream
paths represented by the 37 provenance entries changed. Uncommitted Chernobog
stack-stub work and its modified RAX documentation were excluded from the
upstream source baseline. During validation that work was committed as
`f621c1a` and `482a2da`; the backport was applied over `482a2da8dc73`
without changing those commits.

## Semantic mapping

| Direction | Change | Disposition |
|---|---|---|
| Chernobog to Assist | Multi-site permuted reads and disjoint string spans | Imported into function-mode read reconstruction |
| Chernobog to Assist | Completed spatial prefix before an incomplete suffix | Imported; this is distinct from execution call-prefix admission |
| Chernobog to Assist | Non-overlapping stack writes during heap reads | Imported with overlap, width, overflow and lifetime rejection |
| Chernobog to Assist | Single-read corroboration | Require the original matching memory event and retain its witness |
| Chernobog to Assist | Named model contracts and preceding call transfers | Retain the supplied contract and reject ambiguous/missing evidence |
| Assist to Chernobog | Function call-prefix completeness and boundary argument text | Inspection access only; complete-run and decompiler consumers retain their prior admission contract |
| Assist to Chernobog | Cooperative cancellation and call-site visit bound | Optional callbacks; at most 256 examined incoming references; explicit truncation accounting |
| Both | IDA 9.4/9.5 handshake | Already equivalent; no compatibility rewrite |
| Both | RAX dependency | Pins retained independently: Chernobog API 1.3 and Assist API 1.11 |

The six applicable upstream commits are `61bfa95`, `d6ffcb1`, `828a027`,
`1184922`, `737d033`, and `bfd9856`. The other eight commits touching the
hybrid subsystem in this interval concern excluded native-region/VM work.
Cancellation and call-prefix admission were pre-existing Assist adaptations
that this synchronization makes available to Chernobog inspection.

Assist still excludes native/VM regions, symbolic solving, instruction overrides,
specialized decryptors, rewrite handlers and Chernobog session/UI orchestration.
Its schema 2, 500 ms cooperative request budget, cache identity and owner-thread
seam remain unchanged.

## Changed upstream paths

| Path | Relevant delta |
|---|---|
| `src/hybrid/evidence.cpp`, `src/hybrid/evidence.hpp` | Named model contracts and memory-event corroboration imported |
| `src/hybrid/native_read_strings.cpp` | Multi-site, permuted, disjoint and completed spatial-prefix reconstruction imported |
| `tests/evidence_tests.cpp` | Applicable function-mode regression corpus adapted |
| `src/hybrid/emu_driver.cpp`, `src/hybrid/emu_driver.hpp`, `src/hybrid/emu_input.hpp` | Changes since the previous sync concern excluded native/VM regions |
| `src/hybrid/program_model.cpp`, `src/hybrid/program_model.hpp` | Native-region modeling changes excluded; function capture retained |

The separately tracked `src/hybrid/session.cpp` extraction also changed; its
four-seed function scheduling contract remains equivalent. Assist does not
import Chernobog session orchestration.

## Observation contracts

Modeled arguments require the recorded model name, kind and argument position,
the preceding matching CALL, and a run reporting model execution. Executed
reads require matching address, width, scope, sequence and original bytes.
Boundary arguments require an admitted stop at the unexecuted callee and a
matching CALL; they do not claim that the callee consumes the text.

Every scheduled run must qualify. Duplicate run identities and conflicting
transfers are rejected. Heap generations and allocation lifetimes remain
per-run witness constraints. Prefix observations do not establish return,
no-return, consumed-context completeness, or a rewrite precondition.

Reconstruction retains the existing snapshot and event bounds. With E retained
events, sorting/indexing costs O(E log E) time and O(E) auxiliary storage;
intervening attributed-write checks remain capped at 256 per stream check.

## Assumption register

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | Function-mode producers apply to Assist's bounded immutable snapshots | Previous extraction and current mapped source diff | Imported consensus behavior | Relocated heap objects, mixed complete/prefix runs, partial captures | Shared upstream fixture disagrees after namespace adaptation | Confirmed for the shared corpus; not a universal equivalence claim |
| A2 | Both pinned RAX versions stop before retiring the callee's first instruction | Existing hook contract and prior Assist behavior | Prefix observations | x86-32 stack arguments, x86-64 and ARM64 register arguments | Callee sentinel executes before the reported stop | Confirmed for x86-32, x86-64 and ARM64 on both pinned runtimes |

## Change surfaces

Affected: function analysis, model projection inputs, internal evidence types,
native/ACP/MCP delivery of findings, Chernobog inspection, tests, and source
provenance. Shared source lists cover plugin, idalib CLI and Qt harness.
The bridge transports the existing structured result. No public C SDK layout,
persisted schema, authorization policy, network transport or updater contract
is changed. Chernobog inspection JSON gains additive observation/count fields;
it remains an ephemeral view, with no persisted-state migration.

| Plane | Impact and reason |
|---|---|
| Plugin lifecycle | Existing entry points and teardown retained; recompiled plugin verified |
| UI state | Chernobog inspection adds observation rows; no Assist widget changes |
| Conversation and backend | Existing findings transport and rendering; native/ACP request policy unchanged |
| Prompt/context | Improved evidence feeds the existing projection; prompt sources unchanged |
| Tool schema | Assist public schema unchanged; Chernobog IDC result adds observation metadata |
| Permissions/mutation | No new mutation call; prefix evidence remains inspection-only in Chernobog |
| Main-thread dispatch | Existing owner-thread collector path retained; bounded collectors gain cancellation |
| Mesh/MCP/crypto | No transport, identity, framing or cryptographic changes |
| Persistence/SDK/ABI | Internal C++ evidence only; no persisted format or public C ABI changes |
| Optional engines | Each RAX pin retained and tested independently; Z3 behavior unchanged |
| Update/release | No updater or package-layout change |
| Targets/platforms | Shared sources compiled in macOS plugin/CLI/harness, portable Windows/Linux runtimes and IDA adapters |
| Tests/docs | Behavior corpus, native probe, CI test selection and provenance updated |

## Validation

Before changes, six existing pure suites passed. Current upstream multi-site
and single-read regressions failed against the old Assist implementation.
The initial custom-compiler attempt lacked a coherent system SDK; the baseline
was rerun successfully using Apple Clang with an explicit macOS SDK.

Post-change evidence (2026-10-18 UTC):

| Check | Result | Boundary |
|---|---|---|
| Assist plugin, `assist_idalib_cli`, `assist_qt_harness` | Built on macOS ARM64 | Apple Clang, IDA 9.4 and its Qt libraries |
| Assist model, program model, evidence, temporal, RAX, idalib, no-engine and GUI tests | 8/8 passed | CTest selected exact names; idalib/no-engine/GUI executed 122/83/127 checks with zero failures; no skips |
| Chernobog plugin | Built on macOS ARM64 | Isolated committed-source worktree |
| Chernobog program model, evidence, RAX hybrid, analysis-prefix and stack-stub tests | 5/5 passed | Combined tree including the concurrent stack-stub commits; both ordinary and prefix admission checked |
| Chernobog static-analysis traversal/cancellation regression | Passed | IDA traversal stubs; does not establish live UI cancellation latency |
| Portable program/evidence/temporal suites | 5/5 passed on Windows ARM64; 5/5 on Linux x86-64 | MSVC native Windows; GCC in Linux container |
| Linked RAX sentinel corpus, both dependency pins | Passed on macOS ARM64, Windows ARM64 and Linux x86-64 | x86-32, x86-64 and ARM64 guest code; independent callee-write controls; Linux container uses emulated host execution on the ARM64 development machine |
| Changed IDA adapter translation units | Compiled on Windows ARM64 and Linux x86-64 | Chernobog collectors/session/inspection/IDC; Assist entry state and RAX projection |
| Assist temporal AddressSanitizer/UndefinedBehaviorSanitizer | Passed | Includes 470 interleaved-read checks |
| `make check-ui-seam` | Passed | Source boundary check |
| Chernobog isolated IDA 9.4 probe | Passed | Exact 256-reference bound, prefix inspection through IDC and JSON, no returned runs |

The isolated IDA probe used fixture SHA-256
`833452bfd90f6948aea6150649d792eb4187aa2d84df164d61ffcaed691f9c6f`
and plugin SHA-256
`3b6f8c6ee7ea9184a0b87dfc69196760c3a2800a45d930d690a71ceb2f885752`.
It observed four prefix runs containing `prefix-stack`. Input, plugin, script
and IDA executable hashes were unchanged across the run. These identify the
validated artifact before final source formatting and integration; subsequent
plugin builds may differ byte-for-byte.

Reproduction uses the registered targets, for example:

```text
ctest --test-dir <assist-build> --output-on-failure -R '^assist_function_analysis_(model|program_model|evidence|temporal|rax|idalib|no_engines|gui)_tests$'
ctest --test-dir <chernobog-build> --output-on-failure -R '^chernobog\.(program_model|evidence|rax_hybrid|analysis_prefix)$'
python3 tests/run_ida_smoke.py <chernobog-build>/chernobog_analysis_sync_fixture tests/ida_analysis_sync_probe.py --ida <idat> --plugin <chernobog-plugin> --enable-rax --output-dir <in-tree-output>
```

The integration build exposed a missing `cancel_token.cpp` in three Assist
analysis test targets; their source lists now include it. Native MSVC exposed
missing lambda captures in the new sentinel test; both copies now capture the
callee address. These were corrected without weakening assertions.

Native Windows/Linux IDA processes, full Windows/Linux product linking,
package generation and remote CI execution were not exercised. Their runtime
status is unknown; portable runtime tests and adapter compilation are not
claims of full product validation. Existing SDK deployment-target and
deprecation warnings remain outside this synchronization.

## Bounded findings

| Impact | Finding | Blocking condition |
|---|---|---|
| High | Chernobog's existing Windows jobs compiled with testing disabled | Addressed by selecting the shared analysis tests in those same jobs |
| High | RAX versions differ between repositories | Each linked runtime corpus must pass against its own pin |
| High | Native/VM and rewriting functionality is intentionally excluded from Assist | Does not block the selected observation scope |
| Medium | Full native Windows/Linux product runtime and packaging were not executed | Remains unverified; shared runtime and adapter checks do not replace those lanes |
| Medium | Work stops at the first unmodeled callee | Later behavior remains unobserved |
| Medium | Chernobog's original worktree contains concurrent edits | Build committed-source changes in the isolated worktree and preserve original ownership |
