# Source-controlled Morok packed ELF64 pair

The user's Morok checkout supplies `boo.c`, `cross_build.sh`, the pass plugin,
and the native-pack finalizer. `tests/run_morok_paired_control.py` built a clean
static x86-64 Linux executable from that source and two protected executables
from the same source. Both protected builds used `tests/e2e/native_pack.toml`,
seed 31337, `-O3`, C11, static musl linking, and the checkout's native-pack
link/finalization pipeline. The static-link derived config disabled
`function_call_obfuscate`; sealing and release auditing were disabled explicitly
for this process control. The runner used Clang 23 for the clean and protected
source builds and the same musl CRT/libgcc lookup and strip tool.

The native-pack finalizer verified a nonempty 65,536-byte protected region.
The two fixed-seed protected binaries have identical SHA-256
`632b7e1eae573155f1f5a99567ce16c03da28f93d05083c4a15b62886e55356f`.
The clean binary has SHA-256
`0b21610edd3644ab5c54b74b53ef4458678321e3d614a68c56129d6a2903330a`.
The supplied `samples/boo-linux-x86_64-static` has a different SHA-256,
`730f6adfba4cb7179320c96a3a5b24856059f1c4ba24bad25b969d74e4054a27`.
This fresh source-controlled pair does not establish the source, settings, or
expected behavior of that earlier supplied ELF.

An identified Linux/amd64 Ubuntu 24.04 container ran each executable three
times with no arguments. All nine processes exited 0 with empty stderr and
identical 411-byte stdout, SHA-256
`3dffc0fdfd3e8cbcd4f1e4cce638ff2a5b23e14de27304312c785cec718f9659`.
The runner compares exact output bytes, exit status, and stderr, then rehashes
each executable. Runs had a 10 s timeout, a 2 MiB polled output limit, a
512 MiB container memory limit and a 64-process limit. The Docker image ID,
tool hashes, source/config/derived-config hashes, artifact hashes, individual
elapsed times and process peak-resident measurements are retained in the raw
`build/morok-paired-evidence-final/report.json` with SHA-256
`20fca46a94542969de498c3680005b49d568782ae07d8417b6f509a6b4dc2c14`.
The committed `VMP_MOROK_PAIRED_CONTROL_EVIDENCE.json` retains the hashes
needed to identify that ignored report. Elapsed times span
160,836,208–1,080,747,208 ns (0.161–1.08 s to three significant figures);
host Docker launch and translation are included. Peak resident accounting
spans 47,464,448–48,398,336 bytes and measures the host Docker client process,
not the guest executable's memory usage.

Reproduce in a new output directory with the Morok checkout and supplied sample
available locally:

```sh
python3 -B tests/run_morok_paired_control.py \
  --morok-dir "$MOROK_DIR" \
  --output-dir build/morok-paired-reproduction \
  --supplied-sample samples/boo-linux-x86_64-static
```

The runner performs two protected builds, pack verification, nine bounded
executions, whole-output comparison, and artifact identity checks. For artifact
size `B` bytes and output size `O` bytes, each full-file hash/compare costs
`O(B + O)` time and `O(B + O)` peak host memory; the fixed number of builds and
guest runs dominates elapsed time. The runner does not establish a protected
edge oracle or Chernobog recovery rate.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| M1 | The local Morok source, plugin, finalizer and config are the inputs for this **fresh** pair. The source-controlled designation depends on their recorded hashes and invocation. | Rehash every recorded input and runner; rebuild twice in a fresh directory. Changed input hashes invalidate comparison with this checkpoint. |
| M2 | The clean executable is an oracle for this source's no-argument process behavior under the selected Linux engine. The equality claim depends on that one invocation. | Compare exact status/stdout/stderr for each run; add varied inputs or physical x86-64 execution before broadening the behavioral contract. |
| M3 | The pack verifier's nonzero byte count identifies a native-pack output. The protected-artifact claim depends on that tool's local implementation. | Inspect the packed section and independently observe unpacking on a validated engine; compare finalizer output against a non-packed build. |
| M4 | Fixed seed and stable toolchain make this specific build reproducible. The repeated-hash result depends on the recorded environment. | Rebuild under another toolchain/container; byte equality outside this environment is unknown. |
| M5 | The supplied `boo` ELF is a separate Morok output. Any relation to `boo.c` beyond the user's attribution remains unknown. | Obtain the original build invocation, source hash, effective config and compiler/finalizer hashes for the supplied ELF; fresh output hash inequality precludes treating this pair as its build record. |

**High impact:** a controlled original/protected behavior pair is now available
for later Chernobog recovery measurement on native-packed Morok code.
**Medium impact:** output equality covers a single no-argument process path;
packed application entry and protected control-flow recovery remain unmeasured.
**Low impact:** fixed-seed hash equality detects build-environment drift for
this one fixture, without implying cross-toolchain reproducibility.

QG1: the checkpoint has technical scope. QG2: M1–M5 state assumptions and
falsification probes. QG3: the claimed source-controlled no-argument pair is
covered; the complete VMP review remains open. QG4: counts, byte units, time
conversion and host-memory accounting are explicit. QG5: fresh-build lineage
is distinct from the supplied ELF. QG6: the runner, local Morok primary inputs,
image, output and raw-report hashes are recorded. QG7: edge recovery, other
inputs, physical-x86 behavior and cross-toolchain reproducibility remain
bounded unknowns.
