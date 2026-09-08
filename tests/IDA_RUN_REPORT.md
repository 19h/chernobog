# Isolated IDA run reports

`run_ida_smoke.py` writes `run.json` alongside `ida.log`. Use `--output-dir`
to retain successful runs; the default disposable directory is removed after
success. Failed runs retain the artifacts. Schema version 2 records SHA-256
identities for the copied input, installed plugin, executed probe, and IDA
executable; integrity checks; a Chernobog configuration digest; process elapsed
time in nanoseconds; process and runner exit codes; and the required-log result.
No environment values or license data are written to the report.

The runner executes a byte-exact probe copy at `probe/<original-name>` within
the run directory. Repository probes import only standard-library/IDA modules
and do not depend on their original directory. A custom probe that uses sibling
imports or files relative to `__file__` must supply those dependencies explicitly;
copying the main file does not capture its import graph. `script_sha256` and
`script_unchanged` describe the executed copy. `source_script_sha256` and
`source_script_unchanged` describe the original. Editing the original during a
run cannot replace the executed copy and does not itself fail the run.

Inherited `CHERNOBOG_*` variables are removed before runner defaults and explicit
`--set` assignments are applied. Thus a parent shell's `CHERNOBOG_DISABLE=1`
or instruction budget cannot silently change the workload. Runner-owned
variables still cannot be overridden with `--set`. Other inherited environment
variables remain available, including the host's loader and Python settings.

`chernobog_environment_sha256` hashes the effective child `CHERNOBOG_*` mapping,
excluding only `CHERNOBOG_PLUGIN_PATH`: the installed plugin has its own digest,
and its per-run path would otherwise prevent equal configurations from matching.
Canonical bytes are Python `json.dumps(mapping, sort_keys=True,
separators=(",", ":"), ensure_ascii=True).encode("utf-8")`, with no newline.
Duplicate `--set` assignments use the last value. This digest is independent of
assignment order and the disposable plugin path; changing an effective option
changes its input. Other `CHERNOBOG_*` path options, if supplied, remain exact
strings. Non-Chernobog `--set` values are neither serialized nor hashed.
The digest tests equality; it cannot reconstruct the experimental settings or
establish equality of the complete environment.

`process_elapsed_ns` measures the synchronous `subprocess.run` call with
`time.perf_counter_ns`. It includes process launch, binary loading, IDA analysis,
the complete probe, and shutdown. It excludes fixture preparation, hashing,
and report writing. Convert to seconds by multiplying by 10⁻⁹ s/ns. This is
not decompiler-only latency. The duration is a single observation, with no
estimated confidence interval or claim about clock accuracy.

Integrity checks have precedence over process and log status. Source-input
mutation/deletion, a copy differing from the original input's initial hash,
or mutation/deletion of the installed plugin, executed probe, or IDA executable
produces runner status 125. IDA is hashed before and after the process;
`ida_sha256` is the initial digest, and `ida_sha256_after` is null when the
executable becomes unreadable. `artifacts_unchanged` combines these pass gates.
A nonzero process status otherwise takes precedence even if the log contains
PASS. A successful process lacking the required marker, including a missing
log, produces status 124. Reports follow normally returned subprocess calls;
launch exceptions and external runner termination may prevent report creation.

## Assumption register

- R1: Artifact contents do not change and then revert between observations.
  Before/after hashes detect persistent changes, not every possible concurrent
  mutation. Tests change the executed probe and executable, delete the installed
  plugin and original input, and mutate the original probe while executing its
  stable copy. Artifact attribution depends on this observation boundary.
- R2: Process duration measures the intended workload. Probe-specific phases
  need separate instrumentation. Compare retained logs, matching probe/input/IDA
  hashes and configuration digests, and passing integrity checks before
  interpreting timing differences. A differing plugin hash is expected when
  comparing implementations; preserve their source/build attribution separately.
- R3: Host load, IDA configuration, libraries, non-Chernobog environment, imported
  probe dependencies, and caches influence timings. They are not fully captured.
  Preserve those experimental settings separately and alternate repeated
  baseline/modified runs; a single result cannot establish a speedup.
- R4: PASS is an assertion of the selected probe, not universal correctness.
  Tests explicitly check missing logs, process failure with a PASS marker, and
  integrity-failure precedence over both process and log failure.
- R5: Explicit settings define the intended Chernobog configuration. Tests prove
  that inherited options are removed, explicit overrides reach the executed
  probe, canonical order/duplicate assignments do not affect the effective
  digest, and changed values do. Reports contain no plaintext override values.

Hashing B total file bytes takes O(B) time and O(1) streaming hash memory.
Reading a log of L decoded characters uses O(L) space; pattern-matching time
is determined by the selected regular expression (arbitrary `--expect-log`
patterns have no general linear-time guarantee). Canonical configuration
serialization uses O(E) memory for E encoded bytes and sorts the option keys.
All of this work occurs outside the reported process interval.

## Verification and bounded scope

Run `python3 tests/test_run_ida_smoke.py`. Ten tests execute subprocess fixtures
that run the copied probe and verify reporting, configuration isolation,
canonical digests, mutation classification, and failure precedence. They passed
on 2026-09-08. These fixtures do not load IDA.

The earlier schema-1 live UTF-8 probe passed on 2026-09-08 in
`/tmp/chernobog-report-smoke`, recording 2,696,689,875 ns = 2.696689875 s
(2.70 s to three significant figures). Both exit codes were zero and the
required marker was present. That run validates the earlier report integration;
it does not validate the subsequent schema-2 isolation changes and supplies no
baseline comparison or error bound.

Schema-2 live integration subsequently passed the static-budget comparison's
six processes plus the existing UTF-8 and Aldaz decompilation probes. Matching
configuration/artifact identities and integrity checks for the comparison are
documented in [STATIC_ANALYSIS_BUDGET.md](STATIC_ANALYSIS_BUDGET.md).

Medium impact correction: inherited plugin toggles no longer silently alter
live workloads. Medium impact opportunity: stable configuration and artifact
identities permit stronger process-timing comparisons. Medium impact limitation:
environment, import dependencies, and cache differences can still dominate.
Low impact correction: missing artifacts after execution yield classified
attribution failures instead of aborting report creation with a traceback.

Provenance is the runner source, executable regression fixtures, and retained
live-run artifacts. Quality review covers explicit assumptions and probes,
nanosecond units, failure precedence, measurement boundaries, and known limits;
no broader plugin speedup follows from adding reporting or isolation controls.
