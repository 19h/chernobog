# Supplied Morok keygen packed-section execution census

The exact supplied keygen ELF64 passes Morok's native-pack and sealed-manifest
format checks, and its five selected stdin cases match a clean build of the
candidate source at process output. Neither result establishes that those
executions enter its packed code section. This checkpoint measures that
specific question with QEMU x86-64 10.0.13 translated-block logs.

The supplied executable is SHA-256
`7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9`.
An independent ELF64 section-table parser identifies its unique allocated,
executable 262,144-byte section at `[0x4c0000, 0x500000)`, file offset
786,432 bytes and file-section SHA-256
`119e147cb06e47eb427e2f4ee6d1ff8b0eda601520d71b16882477f38bb9a42d`.
The positive control is the separate fixed-seed Morok protected keygen,
SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`,
with a 65,536-byte executable packed section at `[0x430000, 0x440000)`.
Its byte-identical two-build and behavior control was regenerated from the
Morok source; that build report has SHA-256
`f41301ca38b60e7330c5896cb5ef0acf15ec2e44076367e28ad2f51f80296a81`.
The positive control is not the supplied artifact.

QEMU's own `-d help` defines `exec` as logging before each executed
translation block and `nochain` as disabling chaining so that execution logs
show chained blocks. The first provisional `exec`-only capture was rejected
because it could omit chained blocks. Every accepted run uses
`-d exec,nochain`. The raw logs, exact stdout/stderr, full parsed PC-count
maps and report are retained in
`VMP_SUPPLIED_MOROK_PACKED_CENSUS_NOCHAIN_CAPTURE.json.gz`, SHA-256
`ca331305f90453a5ece6097a8bb63ddaa67379fdc44e37391ff4d4d25bca1f1d`.
The offline verifier re-parses every raw `Trace` record and rejects a changed
PC inside the supplied valid-v14.1 trace even when its raw-log hash is
updated to match the mutation.

| Executable and stdin | Exit | Logged blocks | Unique block starts | Starts in selected packed section |
|---|---:|---:|---:|---:|
| Supplied, empty | 1 | 986,481 | 2,326 | 0 |
| Supplied, invalid MathID | 1 | 975,911 | 2,326 | 0 |
| Supplied, valid v14.1 | 0 | 976,115 | 2,328 | 0 |
| Supplied, valid v14.0 | 0 | 990,424 | 2,315 | 0 |
| Supplied, default expiry | 0 | 991,180 | 2,326 | 0 |
| Fixed-seed packed control, valid v14.1 | 0 | 38,870 | 1,157 | 9,638; first `0x430000` |

All six logs begin at their ELF entry points. Each supplied run has its
expected exit and password/rejection path. The fixed-seed positive control
prints the previously pinned 255-byte valid-v14.1 output. The five supplied
logs contain 4,920,111 translated-block records in total and no block start
in the supplied packed-section range. The full raw-log byte total is
352,088,821 bytes. These are QEMU block-start observations, not instruction
counts, native edge proofs, or a claim that no other code in `.text` is
obfuscated. Forked-child trace coverage and other input paths are unknown.

This result changes benchmark eligibility: the five supplied inputs are
process-behavior controls, but they do not provide a positive oracle for
execution of the supplied native-pack section in the retained QEMU logs.
The fixed-seed control does provide such a positive oracle for its own
distinct binary. The sample's verified pack format and finite output
equivalence remain intact.

## Reproduction and complexity

Use the pinned Linux/arm64 QEMU 10.0.13 image in the evidence manifest. The
current local tag is `chernobog-vmp-qemu10-gdb:local`. A rebuild can start
from `chernobog-linux-ci:latest` and install `qemu-user` and
`gdb-multiarch`; a rebuilt image must be reidentified by SHA-256 and QEMU
version before comparison. With a fresh output directory:

```sh
python3 -B tests/run_morok_keygen_control.py \
  --morok-dir ../morok \
  --output-dir build/morok-keygen-trace-reproduction \
  --supplied-sample samples/int_woma_keygen-linux-x86_64-static
python3 -B tests/run_morok_packed_execution_census.py \
  --sample samples/int_woma_keygen-linux-x86_64-static \
  --control build/morok-keygen-trace-reproduction/protected-first/int_woma_keygen-linux-x86_64-static \
  --output-dir build/morok-packed-census-reproduction \
  --image chernobog-vmp-qemu10-gdb:local
python3 -B tests/verify_morok_packed_execution_census.py \
  --archive docs/VMP_SUPPLIED_MOROK_PACKED_CENSUS_NOCHAIN_CAPTURE.json.gz
```

The containers have no network, a read-only root, no capabilities, a 2 GiB
memory limit and a 128-process limit. The child process timeout is 12 s,
container timeout 25 s, raw trace cap 100,663,296 bytes per run, stdout and
stderr caps 2,097,152 bytes each, and temporary space 134,217,728 bytes.
For `T` raw trace bytes and `U` distinct block starts, one census takes
`O(T)` parse time and `O(U)` in-memory count state, plus `O(T)` retained raw
evidence bytes. The archive verifier materializes the six raw logs and uses
`O(T)` memory. No process-speed comparison is inferred.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | The two selected ELF sections are the packed address ranges for these exact binary hashes. The range census depends on those addresses. | Parse ELF64 section headers and require one matching allocated executable section, exact size, file offset and byte hash; reject altered binary hashes. |
| C2 | `exec,nochain` logs block starts on the observed QEMU processes. The zero/positive counts depend on that logging contract. | Check QEMU's own log-option descriptions, require ELF entry as the first logged PC, reparse every raw record, and require 9,638 positive-control packed blocks. Forked-child coverage remains unknown and requires separate per-process tracing. |
| C3 | The five finite stdin cases are the intended supplied-sample benchmark paths. The zero count depends on those inputs only. | Check guest input SHA-256, exits and output path; add independent inputs and runtime entry observations. |
| C4 | QEMU 10.0.13 on the identified arm64 Linux image executes the selected x86-64 paths consistently. The observations depend on that engine. | Repeat on physical x86-64 or an independent emulator; a QEMU 8.2.2 exploratory run exited 139 on the supplied valid path and is excluded. |
| C5 | The fixed-seed protected binary is a valid positive instrumentation control, distinct from the supplied ELF. The parser-sensitivity result depends on it. | Rebuild the two identical fixed-seed artifacts, check native-pack verification and valid output, then require the first packed PC at `0x430000`. |

**High impact:** pack-format validity and output equivalence no longer stand
in for executed packed-code coverage on the supplied test inputs. **Medium
risk:** the trace is bounded to logged QEMU process activity; forked children,
runtime remapping and untested inputs can change the coverage conclusion.
**Low impact:** translation-block frequency measures neither architectural
instruction count nor Chernobog recovery accuracy.

QG1: technical claims only. QG2: C1–C5 have explicit falsification probes.
QG3: exact sections, five supplied inputs, one known positive, full raw logs
and a mutation control are covered; the complete review remains in progress.
QG4: addresses, bytes, process counts, caps and complexity are explicit.
QG5: the preliminary chained-log omission, distinct artifact identities and
process-coverage limit are resolved or bounded. QG6: local primary ELF,
QEMU self-description, binary/tool/image hashes and full raw captures are
retained. QG7: the benchmark consequence and its limits are labeled above.
