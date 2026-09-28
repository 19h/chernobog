# Supplied Morok keygen process-tree and packed-page syscall census

The earlier `exec,nochain` census observed no translated-block start inside the
exact supplied keygen's packed section on five stdin cases. QEMU's `-strace`
option logs guest system calls. This independent run determines whether those
cases fork and whether any logged process changes the packed section's page
protection. The executable and fixed-seed positive control are the same pinned
binary hashes as in `VMP_SUPPLIED_MOROK_PACKED_CENSUS.md`.

The supplied section is `[0x4c0000, 0x500000)`, 262,144 bytes; the separate
fixed-seed control section is `[0x430000, 0x440000)`, 65,536 bytes. The
identified QEMU 10.0.13 Linux/arm64 image is
`sha256:a4d366ca019230fb6e3f0423bf0cbebaab63d7f32336f19ab007cb18063a7d12`.
QEMU's own `-h` calls `-strace` “log system calls.” The adjacent Morok source
`../morok/runtime/native_pack_loader.c`, SHA-256
`42fd68c3d7882a76fd8737d8aa5a96373e63eac0be2459ab9fbd6466a486cf91`,
calls `mprotect` on the full isolated region to change it to read/write before
decryption and to read/execute afterward. The exact supplied artifact's source
revision remains unknown; that source contract is a hypothesis, not proof of
its implementation.

| Executable and stdin | Exit | Parsed syscall tokens | Forks | Clone calls | `mprotect` calls | Packed-range `mprotect` |
|---|---:|---:|---:|---:|---:|---:|
| Supplied, empty | 1 | 920 | 4 | 1 | 14 | 0 |
| Supplied, invalid MathID | 1 | 921 | 4 | 1 | 14 | 0 |
| Supplied, valid v14.1 | 0 | 920 | 4 | 1 | 14 | 0 |
| Supplied, valid v14.0 | 0 | 920 | 4 | 1 | 14 | 0 |
| Supplied, default expiry | 0 | 920 | 4 | 1 | 14 | 0 |
| Distinct fixed-seed positive, valid v14.1 | 0 | 19 | 0 | 0 | 2 | 2 |

Each supplied run's QEMU log names the parent, four fork children and one
cloned thread; it records each fork child exiting. Across the five runs there
are 20 forks, 70 parsed `mprotect` calls, and no call whose address interval
intersects the selected packed section. The positive control logs successful
`mprotect(0x430000,65536,PROT_READ|PROT_WRITE)` and then successful
`mprotect(0x430000,65536,PROT_EXEC|PROT_READ)`; its exact stdout SHA-256 is
`2ff6c69467f441be9b4db70e72dc935503171785b53d1d60f54ed290db965855`.
The five supplied cases reach their expected rejection or password path.

The six raw guest syscall logs and stdout streams total 197,610 syscall-log
bytes and are retained with the report in
`VMP_SUPPLIED_MOROK_SYSCALL_CAPTURE.json.gz`, SHA-256
`8f2d29aa068b9133ceba89d30619dc8902c216c6ca110d010cc21722dbf8b99d`.
The offline verifier reparses every `fork` and `mprotect` token, checks that
none is left unparsed, checks the complete logged page-protection inventory,
and rejects a forged supplied packed-page call even after updating its raw-log
hash and report inventory. QEMU writes concurrent process records to one
stream; some adjacent text is interleaved. “Parsed syscall tokens” is a
reproducible parser count, not a proof of complete per-process syscall counts.

Together with the independent block-start census, these observations give no
positive evidence that the supplied artifact's packed section runs on the five
inputs. They also expose actual child processes, so the older trace's
forked-child caveat is concrete. The syscall log includes child records but
does not prove completeness for every child instruction or every possible
packed-code execution mechanism. An independent native host or emulator, and
the exact artifact's build lineage, are still needed for broader claims.

## Reproduction and bounds

With the pinned local image and a separately regenerated fixed-seed control:

```sh
python3 -B tests/run_morok_syscall_census.py \
  --sample samples/int_woma_keygen-linux-x86_64-static \
  --control build/morok-keygen-trace-control/protected-first/int_woma_keygen-linux-x86_64-static \
  --output-dir build/morok-syscall-reproduction
python3 -B tests/verify_morok_syscall_census.py \
  --archive docs/VMP_SUPPLIED_MOROK_SYSCALL_CAPTURE.json.gz
```

The runner requires a new output directory, the exact sample and control
SHA-256 values, and the exact image ID. Each isolated container has no network,
a read-only root, no capabilities, a 2 GiB memory cap, a 128-process cap, and
128 MiB of temporary space. The guest timeout is 12 s, container timeout 25 s,
and each captured output stream is capped at 2 MiB. For `T` raw trace bytes,
scanning is `O(T)` time; retained raw evidence is `O(T)` space. Parsed PID and
page-protection inventories add `O(P + M)` space for `P` observed processes or
threads and `M` parsed `mprotect` calls.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | The exact section intervals describe these pinned binaries. All intersection counts depend on them. | Reparse ELF section and load headers; reject any changed binary hash, region or image ID. |
| S2 | QEMU `-strace` includes the observed children and their page-protection calls. The 20-fork and zero packed-page counts depend on this logging behavior. | Require fork-child exit records and all `mprotect(` tokens to parse; repeat with independent process tracing on native x86-64. |
| S3 | The positive control exercises the candidate Morok native-pack loader. Parser sensitivity to packed-page transitions depends on this. | Require the exact two successful read/write and read/execute transitions at `0x430000` plus pinned stdout. |
| S4 | The adjacent loader source describes the supplied binary's packed-page opening path. Any interpretation of absent `mprotect` as absent *loader opening* depends on this. | Recover the exact artifact's build record or identify and execute its actual packed-entry stub; reject the mapping if it uses a different mechanism. |
| S5 | The five finite inputs are the benchmark paths of interest. The negative result depends on that input set. | Add path-targeting inputs and record their syscall and block traces separately. |

**High impact:** child process activity is measured rather than left as a
hypothetical qualification, and the positive control confirms that the same
syscall capture sees a packed-region opening. **Medium risk:** QEMU's
concurrent text output can interleave records; token checks and raw retention
bound parser omissions, not complete process semantics. **Low impact:** syscall
frequency does not measure instruction coverage or Chernobog recovery.

QG1: technical claims only. QG2: S1–S5 have falsification probes. QG3: five
supplied inputs, child activity, one positive and mutation rejection are
covered; full review implementation remains in progress. QG4: exact byte,
address, process and complexity units are stated. QG5: source lineage and
cross-run instruction coverage remain separate from syscall observations.
QG6: exact binaries, local Morok source, QEMU help, raw logs and hashes are
primary evidence. QG7: impact and limitations are bounded above.
