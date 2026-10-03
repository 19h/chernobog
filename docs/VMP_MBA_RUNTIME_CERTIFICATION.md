# MBA runtime catalog certification timeout

## Observation and change

Two isolated IDA runs on the i386 `virtualization-0-on` corpus, using the same
plugin binary, registered 108 rules but verified only 90. The other 18 were
rejected as `UNKNOWN` with Z3 reason `timeout`. The production verifier used a
250 ms deadline; the catalog test used 10,000 ms. The affected rule set varied
by one rule between the two runs, consistent with a scheduling-sensitive
deadline. Each run still completed its protected MBA probe, so a probe PASS
alone does not establish a complete runtime catalog.

The registry now retries only `UNKNOWN` results whose reason is exactly
`timeout`, first with a 2,000 ms verifier and, if that also times out, with a
10,000 ms verifier. `DISPROVED`, `UNSUPPORTED`, and other `UNKNOWN` results
remain rejected. A rule is admitted only after a `VERIFIED` result covering
8, 16, 32, and 64 bit widths.

The final plugin passed the same isolated protected probe with 108 verified,
zero rejected, and two requested corpus entries. All 23 CTest suites passed.
The 10,000 ms fallback is present for slower hosts; the probe does not prove
that this fallback executed. The observed process durations are whole-process
measurements and cannot isolate certification time.

## Evidence

| Run | Plugin SHA-256 | Report SHA-256 | Verified / registered | Rejected | Process duration |
| --- | --- | --- | ---: | ---: | ---: |
| baseline 0 | `e112d00d24806f5263d817c3d8b6271bdf04c37411d45da027be86a90901708c` | `ac6025aed7f3f5195353eb1ff3386b0a54c893d8560d2cba0666060b6f59153b` | 90 / 108 | 18 | 19.904895167 s |
| baseline 1 | `e112d00d24806f5263d817c3d8b6271bdf04c37411d45da027be86a90901708c` | `bd249579164783e06d058199599eed9a3453d3f07736562dec5b8dfee6a133c6` | 90 / 108 | 18 | 24.771681709 s |
| final | `9bd8f870e79bc3af5cf5d4ec507cba4711d3bb8af6a85973139e7b767ad51cbd` | `e09062e42a279e46e5fe994bcbded7fe1953aa835a0ce53ead3a8a20f513a12f` | 108 / 108 | 0 | 4.886061125 s |

All runs used input SHA-256
`0da574daf01766471ae23496582be42945ed77dec97726de080f68feba45f2d6`
and probe script SHA-256
`f4b52bc7a6bb987e67f8ba679b6a1c50e3007d797ab9904f8a94bbb99c16cca2`.
The final `src/deobf/rules/rule_registry.cpp` SHA-256 is
`f1731de21fbb180d02293492f9d24170c22754fc8033f08c35ee22dd9b5d0be4`.
Logs and full reports are retained in the ignored
`build/mba-address-live-i386-v0/`, `build/mba-address-live-i386-v1/`, and
`build/mba-rule-timeout-final/` directories. The table is a transcription of
those reports, not a portable archive of the IDA run.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | `timeout` denotes a deadline exhaustion. The retry applies only to that exact Z3 reason. | Force a deterministic resource-limit `UNKNOWN`; verify it remains rejected. Other Z3 reasons are not retried. |
| A2 | Reverification in a fresh solver context can prove rules whose first attempt timed out. The 108/108 result depends on this. | Run the protected probe in a fresh IDA process and assert `verified == registered == 108` and `rejected == 0`. Repeat under host load to probe deadline sensitivity. |
| A3 | The protected probe's two entries are sufficient to detect startup catalog loss on this corpus. The finding is limited to catalog registration, not transform accuracy. | Compare the registry counts in the IDA log and report; test other architectures and corpora separately. |

## Bounded scope and quality gates

- **High impact:** A host-dependent timeout can silently remove certified MBA
  rules from the runtime matcher. The change restores them in the observed
  i386 process while preserving the proof gate.
- **Medium impact:** Worst-case startup work increases for identities that
  repeatedly time out. At most two additional bounded proofs are attempted
  per timed-out identity; whole-process timings above are not comparative
  performance evidence.
- **Low impact:** A future Z3 version may use a different timeout reason
  string; it will remain fail-closed and require a separate diagnosis.

QG1: no normative conclusion. QG2: A1–A3 have falsification probes. QG3:
the observed runtime loss, bounded fix, and direct IDA validation are covered.
QG4: timeout and duration units are milliseconds and seconds respectively;
the reported nanosecond durations were divided by 1,000,000,000. QG5: a
timed-out final attempt remains rejected. QG6: claims are pinned to source,
plugin, input, probe, and report hashes and the executed CTest/IDA checks.
QG7: related performance and Z3-reason risks are bounded above.
