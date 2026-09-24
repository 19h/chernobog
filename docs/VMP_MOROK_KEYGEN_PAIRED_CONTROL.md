# Source-controlled Morok keygen ELF64 pair

The Morok checkout contains `programs/int_woma_keygen.c`, a plausible but
unverified source counterpart for the supplied keygen ELF. The fresh paired
fixture compiles that unmodified source with
`tests/vmp_corpus/morok_fixed_time.c`, which defines `time()` as the constant
1,700,000,000 s since the Unix epoch. The clean and protected builds both
use that shim. This controls the source's `srand(time(NULL))` call and the
default-date path, allowing exact process-output comparisons. It does not
claim that the supplied ELF used this source, shim, config or seed.

`tests/run_morok_keygen_control.py` built one clean static x86-64 Linux
executable, two Morok native-packed executables with fixed seed 31337, and a
clean negative control with the epoch increased by 1 s. All use Clang 23,
musl CRT/libgcc, C11, `-O3`, `-lm` and the same strip tool. The protected
builds use `tests/e2e/native_pack.toml` with the static-link derived config;
sealing and release auditing were disabled for this process control. The two
protected binaries have identical SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
Morok's finalizer verifies 65,536 protected bytes. The clean binary has
SHA-256 `a429003d65f05f73af04d0d6b32f7950a84daaa6a1cb5ed6a2db96db2166af94`.
The supplied sample differs, with SHA-256
`7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9`.

Five stdin cases cover empty input, an invalid MathID, both valid version
paths, and the default-expiry path. For each case, the clean executable and
both protected builds ran twice under the same identified Linux/amd64 image:
5 × 3 × 2 = 30 process observations. Exact exit status, stdout and stderr
match within every six-run case. The three valid cases exit 0 and print a
password; the two rejection cases exit 1. A separately built clean control
with the fixed epoch increased by 1 s changes the valid-v14.1 stdout SHA-256
from `2ff6c69467f441be9b4db70e72dc935503171785b53d1d60f54ed290db965855`
to `ccbf33f35e771d110751fc7af38f05fb205c05846323c18d91f22dbb58d91fcc`.
This checks that the output oracle detects a source-input difference.

Guest executions use a 10 s timeout, a 2 MiB polled output limit, a 512 MiB
container memory limit and a 64-process limit. The 30 paired processes took
134,575,917–189,794,541 ns each (0.135–0.190 s to three significant figures).
Host Docker-client peak resident measurements were 46,956,544–48,660,480
bytes; they do not measure guest-executable memory. Exact case input/output
hashes, individual process measurements, source/tool/config/image hashes and
artifact sizes are in ignored `build/morok-keygen-evidence-final/report.json`,
SHA-256 `6447c7b5bc4e01f0bfccc5aa1e3f93059a1b3da8fd83107aed2fb62b3e379e31`.
`VMP_MOROK_KEYGEN_PAIRED_CONTROL_EVIDENCE.json` retains its identifying
hashes and the case contract.

Reproduce with the Morok checkout and supplied sample available locally:

```sh
python3 -B tests/run_morok_keygen_control.py \
  --morok-dir "$MOROK_DIR" \
  --output-dir build/morok-keygen-reproduction \
  --supplied-sample samples/int_woma_keygen-linux-x86_64-static
```

The runner requires a new output directory, checks two fixed-seed protected
builds for byte equality, verifies packing, executes the cases under process
limits, checks the shifted-time rejection control and rehashes all artifacts.
With `K` fixed cases, `R` runs per artifact, artifact size `B` and retained
output size `O`, comparisons and hashing take `O(B + KRO)` host time and
`O(B + KRO)` retained host memory apart from compiler, protector, Docker and guest
costs. Here `K = 5` and `R = 2`; the process count is exact. No protected-edge
or Chernobog recovery metric follows from process equivalence.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| K1 | The checkout's keygen source and Morok pipeline generated this **fresh** pair. This depends on recorded source, tool, shim, config, invocation and output hashes. | Rehash inputs and repeat both protected builds in a new directory. Changed hashes invalidate this checkpoint. |
| K2 | Replacing `time()` controls the observed time-dependent source path in this static link. Exact output comparison depends on that link behavior. | Shift the fixed epoch by 1 s in a separate clean binary; the valid output changes. Inspect the linked symbol and test further time sources before broader claims. |
| K3 | The clean binary is the oracle for these five finite stdin cases under the selected engine. The equality claim depends on those exact inputs. | Compare byte-exact status/stdout/stderr, repeat each case, add more inputs and physical x86-64 execution before generalizing. |
| K4 | Morok's verifier identifies a nonempty native-packed region. The protected-artifact claim depends on its local implementation. | Inspect mapped packed bytes and independently observe unpacking on a validated engine. |
| K5 | The supplied keygen ELF is separate from the fresh fixture; its exact source and settings are unknown. | Obtain its source-to-output build record and matching original binary; the fresh output hash differs from the supplied hash. |

**High impact:** valid-input behavior now has an exact original/protected oracle
on a source-controlled packed program with arithmetic, strings, branching and
generated output. **Medium impact:** fixed-time injection narrows the source
contract and cannot establish the supplied ELF's behavior or provenance.
**Low impact:** a one-second shifted control demonstrates output sensitivity
for one valid case, without proving all path differences are detected.

QG1: technical scope. QG2: K1–K5 include falsification probes. QG3: all five
claimed input cases and the negative control were executed; the complete VMP
review remains open. QG4: process counts, seconds, byte limits, exact hashes
and complexity are explicit. QG5: fresh-fixture behavior and supplied-ELF
lineage remain separate. QG6: local primary source and exact tool, image,
artifact, runner and raw-report hashes are recorded. QG7: other inputs,
physical-x86 behavior, guest memory and recovered-edge accuracy remain
bounded unknowns.

Subsequent runtime check of K4: `VMP_MOROK_UNPACKED_ENTRY.md` records the
packed 65,536-byte region matching ELF bytes at entry and callback, then
changing before its first execution at `0x430000` on the fixed valid-v14.1
path. Both fixed-seed protected builds yield identical mapped bytes at that
breakpoint. This observation remains specific to the fresh pair.
