# Supplied protected-sample inventory and bounded process observations

Five additional files are present under `samples/`. The two Mach-O x86-64
`foo` files have the same hashes as the original/protected candidate pair in
`VMP_HELLO_FIXTURE.md`. The user identifies the two Linux ELF files as output
from their Morok obfuscator. Each matches the identically named binary in the
local Morok source checkout byte for byte by SHA-256. That checkout's
`morok-audit.json` records the keygen ELF's exact hash and 52 sealed manifests;
the audit does not list the `boo` ELF. Two local, byte-identical candidate
configuration files have SHA-256
`81a735e6df2335105073701eb4dfc212d31e72fe58f76899d63b1a35d9bcaf06`
and specify preset `max`, 74 pass tables and 72 enabled passes. No recorded
per-binary build invocation links those files to either ELF, so their effective
settings remain unknown. These files are untracked local inputs; this document
records hashes so subsequent analysis can reject a changed sample.

| Local input | Bytes | SHA-256 | Format and bounded static observation |
|---|---:|---|---|
| `samples/foo_x86_orig` | 12,456 | `443b0a464d7de68c5a26a3e31a92e694356ccd1eef3127d522309ac672ecc7c7` | Thin x86-64 Mach-O executable; one imported libSystem |
| `samples/foo_x86_vmp` | 2,618,368 | `c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5` | Thin x86-64 Mach-O executable; libSystem and CoreFoundation; packed section/entry observations in `VMP_HELLO_FIXTURE.md` |
| `samples/boo-linux-x86_64-static` | 1,049,528 | `730f6adfba4cb7179320c96a3a5b24856059f1c4ba24bad25b969d74e4054a27` | Static ELF64/x86-64, entry `0x40025b`; executable `.morok_npack_rx` section |
| `samples/int_woma_keygen-linux-x86_64-static` | 1,250,120 | `7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9` | Static ELF64/x86-64, entry `0x40025b`; executable `.hdmoh1mxteam2f` section |
| `samples/hikari-console-max-stable.uu` | 1,536,488 | `20824d7dfdc0d8353bb31e9ab1b8aed24ca506da3ef7e2df40f89a9c24598faa` | Thin arm64 Mach-O executable; architecture-distinct control candidate |

## Matched hello-world process check

`tests/run_supplied_hello_pair.py` admits distinct thin x86-64 Mach-O
executables, checks their hashes before and after each run, and uses the
existing bounded `wait4` process runner. Three no-argument trials compare
exit status and exact stdout/stderr bytes. Every process exits 0; every stdout
is the 11 bytes `Hello World` without a newline, and stderr is empty. Both
binaries repeat the same observation across the three runs. The common stdout
SHA-256 is
`a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e`.

| Trial | Original elapsed, s | Protected elapsed, s | Original peak resident, bytes | Protected peak resident, bytes |
|---:|---:|---:|---:|---:|
| 0 | 0.029014750 | 0.356918625 | 3,457,024 | 14,094,336 |
| 1 | 0.028040416 | 0.384195041 | 3,391,488 | 14,180,352 |
| 2 | 0.029275667 | 0.392444166 | 3,416,064 | 13,955,072 |

Elapsed seconds are the runner's wall-clock nanoseconds divided by
`10^9 ns/s`; the displayed nine decimal places preserve its integer-nanosecond
resolution. Resident byte counts are the macOS `wait4` `ru_maxrss` values for
each process. These are three translated-host observations, not a performance
distribution or physical-x86 measurement. Equality of one no-argument output
does not establish equality of memory, stack, flags, exception behavior, or
all possible inputs. It also does not prove which protected functions were
mutated or virtualized.

Reproduce using the exact hash-matched local files:

```sh
python3 -B tests/run_supplied_hello_pair.py \
  --original samples/foo_x86_orig --protected samples/foo_x86_vmp \
  --output-dir build/supplied-foo-pair-new --runs 3
xcrun clang -arch x86_64 -g0 -Wl,-no_pie tests/vmp_native/get_pc.S -o build/vmp-get-pc
python3 -B tests/run_supplied_hello_pair.py \
  --original samples/foo_x86_orig --protected build/vmp-get-pc \
  --output-dir build/supplied-foo-negative-new --runs 1
# The deliberately different program exits 0 but emits no stdout; expect runner status 1.
```

The runner source SHA-256 is
`8d48c9d9f2cbd586cab3f376ae4f6fa6b5600ff7a398a2d33041b8efb7895a32`.
The exact three-run measurements, identities, output hash and limits are in
`VMP_SUPPLIED_HELLO_EVIDENCE.json`; its fields were checked against
`build/supplied-foo-pair-final/paired_process.json` and the current input
bytes. The earlier static `VMP_HELLO_FIXTURE.md` evidence remains historical.
The negative control uses the independent x86-64 get-PC fixture with SHA-256
`1142cf1154e97106fca4b43e9f5e6dc626943599e3c97fcc70f5485e003065b6`.
Both processes exit 0, but the fixture emits no stdout, so the comparator
returns status 1. This tests rejection of an unequal observable without using
a crash or timeout as the difference.

## Protected startup in fresh IDA databases

The installed plugin SHA-256
`29a49df64771f1144a01d71a208e755a2223c445827a574e54e0a9b29858fca2`
was compared in two isolated IDA 9.4 SP1 runs of the protected input. RAX was
disabled. The only Chernobog option changed between runs was
`CHERNOBOG_IDA_DIRECT_JUMP_DECODE` (`0` versus `1`). The existing bounded
`tests/ida_vmp_corpus_probe.py` inspected the `LC_MAIN` entry
`0x100001436` and the `__mod_init_func` jump stub `0x10000143b`. Its generic
JSON keys `corpus_transform` and `corpus_branch` map to those two addresses,
respectively; they do not imply this sample belongs to the generated corpus.

| Selected entry | Direct jump decode off: reachable/code/unknown heads | On: reachable/code/unknown heads | Native/VM/solver records in both |
|---|---:|---:|---:|
| `LC_MAIN` | 2 / 1 / 1 | 2 / 1 / 1 | 0 / 0 / 0 |
| `__mod_init_func` | 2 / 1 / 1 | 76 / 76 / 0 | 0 / 0 / 0 |

With decoding off, both entry jumps are code but their destinations remain
unclassified. With it on, IDA decodes the initializer target at `0x1002946b5`
in its `.dlC1_hidden` segment and follows code xrefs to 76 heads. The
database-wide plugin counters report 18 direct jump decode attempts, one
newly decoded target and no truncation; with decoding off all three counters
are zero. The original `_main` location `0x100001440` remains undecodable in
both profiles because the protected `__text` is zero filled. Each selected
traversal and owner inspection stayed within its limit, and read-only
inspection preserved the code/xref inventory. No native, VM or solver records
were returned for the two selected owners. The counters do not establish an
edge-recovery rate; a complete independent protected-edge oracle is absent.

The exact input, tool, probe and report hashes, and run checks are in
`VMP_SUPPLIED_HELLO_IDA_EVIDENCE.json`. Reproduce with the hash-matched local
binary and the installed plugin, substituting local IDA and plugin paths:

```sh
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_corpus_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/supplied-foo-ida-off-new \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=0 \
  --set 'CHERNOBOG_CORPUS_ENTRIES={"corpus_transform":"0x100001436","corpus_branch":"0x10000143b"}'
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_corpus_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/supplied-foo-ida-on-new \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set 'CHERNOBOG_CORPUS_ENTRIES={"corpus_transform":"0x100001436","corpus_branch":"0x10000143b"}'
```

## Other supplied binaries

The two static Linux x86-64 samples were run in bounded, network-disabled,
read-only containers with a 5-second timeout, 512 MiB memory limit, and 64
process limit. The pinned arm64 Linux image's `qemu-x86_64` reported an
**internal** SIGSEGV for each sample, with container status 139. The translator
SHA-256 is
`120db995affa96ef3c18933813efd57029c358f6fc96f18becb773fc0fea9ccd`.
An amd64 Ubuntu 24.04 image under OrbStack translation, image ID
`sha256:6232b38791000e3818b58d8847b5a8f5612d606929e01156dd8febc423e0f2ef`,
returned status 132 with no captured output for `boo`. With no stdin,
`int_woma_keygen` returned status 1 after printing a two-choice version menu
and `Bad choice`. The backend's failure/status is not an independent oracle
for `boo` or the keygen's valid-input behavior. Their expected inputs, original
counterparts, exact protector configuration and physical-x86 outcomes are
**unknown**.

The local Morok checkout also contains plausible `boo.c` and
`programs/int_woma_keygen.c` source counterparts, but no source-to-output build
record establishes that either file produced the supplied ELF. A subsequent
matched enabled/disabled IDA 9.4 SP1 inspection of each ELF's entry and direct
jump target finds identical 47/35-head startup inventories and zero native or
VM records at the two inspected owners; the solver API is unavailable. See
`VMP_MOROK_ENTRY_CONTROL.md` and its raw-report manifest. The selected paths
do not establish full-binary specificity or application recovery.

A separate exact-file audit using the user's Morok checkout passes the supplied
keygen's native-pack and sealed-manifest checks (262,144 protected bytes and
52 sealed manifests). The supplied `boo` file has a native-pack-named section,
but its GNU build ID does not match its current bytes and the audit finds no
recognized sealed manifests. Correcting only the note in a disposable copy
still leaves no finalized native-pack manifest. These static results do not
identify the cause of the earlier process failure. See
`VMP_SUPPLIED_MOROK_AUDIT.md` and its evidence JSON.

The arm64 Hikari file exits 0 and repeats the same 90-byte stdout with empty
stderr in three no-argument macOS runs; stdout SHA-256 is
`ffa6745f736de22dc84fe556a570d0f262bc22f17fb3f207ad18ec82d8dbd349`.
No original counterpart or expected semantic result is supplied. It is an
architecture-distinct control, excluded from VMP recovery denominators. A
subsequent matched enabled/disabled IDA inspection records identical
2,643/7-head `_main`/wrapper inventories and zero native records at the two
selected owners. The VM and solver APIs are unavailable for this arm64 input;
see `VMP_HIKARI_ENTRY_CONTROL.md`. This does not establish binary-wide
specificity.

## Assumption register and quality gates

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | The two `foo` files are the intended original/protected pair. Pair interpretation depends on this; process equality does not establish source-build lineage. | Hashes match the earlier static inspection. Record compiler input, protector command/settings, seed and pre/post-protection hashes to establish lineage; these are currently **unknown**. |
| S2 | The arm64 host's x86-64 process execution correctly implements the observed path. The paired process result depends on this. | Repeat on physical x86-64 macOS or an independent translation engine. Translation implementation/version and ISA-wide correctness are **unknown**. |
| S3 | The bounded no-argument path represents only one input and environment. All equality claims depend on this scope. | Vary arguments, environment and relevant input state while comparing output, memory, stack and defined flags; those cases have not been measured. |
| S4 | Linux container failures reflect the tested backends, not necessarily the samples' architectural behavior. No Linux behavior oracle is derived from them. | Run on physical x86-64 Linux or another verified engine with recorded inputs; capture decoder/process state at the stop. |
| S5 | The Hikari file is a distinct architecture/control candidate. Any negative-control claim depends on non-VMP provenance. | Obtain source/build attestation and run the VMP recognizer with a stated candidate threshold; no false-positive rate is claimed here. |
| S6 | The two fresh IDA profiles are comparable except for the direct jump decoder setting. The observed initializer traversal difference depends on this. | Verify `run.json` input, plugin, IDA and probe hashes; compare the controlled environment, then repeat with identical IDA settings and a second IDA version. The independently run profiles do not establish a protected-edge oracle. |
| S7 | The two Linux ELF samples are Morok outputs, as identified by the user. Protector-family attribution depends on that statement and the matching checkout binaries; effective settings do not follow from the nearby candidate configurations. | Recheck both checkout and sample hashes; the local audit independently names and hashes the keygen ELF. A per-binary build command or manifest linking the config hash to each output would establish settings. Neither is currently recorded. |
| S8 | The two inspected Morok startup paths bound only selected entry behavior. The matched inventory and zero-record result depend on this scope. | Recheck source, sample, plugin, IDA and report hashes in `VMP_MOROK_ENTRY_CONTROL_EVIDENCE.json`; inspect more owners and runtime-entered bytes before estimating binary-wide recovery or specificity. |

High impact: the real protected `foo` pair can anchor startup and output checks,
but its exact transformation matrix and code visibility after initialization
remain unknown. High impact: the direct jump decoder exposes 76 initializer-path
code heads in a fresh database while the packed original `_main` stays absent;
this separates reachable loader code from application recovery. Medium impact:
an emulator's internal failure cannot be scored
as an application failure. Low impact: section names suggest packaging families
but do not prove protector version or exact settings. The local Morok audit
strengthens keygen provenance while the build configuration of both ELF files
remains unknown.

QG1: technical scope. QG2: S1–S8 include falsification probes. QG3: this
inventory and bounded process check advance review rows 0b and V; the complete
benchmark and implementation ledger remain open. QG4: byte counts, SI seconds,
integer nanoseconds and size units are explicit. QG5: process equality, static
packing observations, IDA code inventory and compiler/protector lineage are
distinct claims.
QG6: exact local input/runner/report and Morok configuration hashes, and direct
binary/process observations are recorded. QG7: adjacent backend and specificity limits are
bounded above.

Subsequent static control: the Morok entry-path profiles and candidate source
hashes are recorded in `VMP_MOROK_ENTRY_CONTROL.md`. This does not alter the
historical process outcomes or establish source-build lineage.
