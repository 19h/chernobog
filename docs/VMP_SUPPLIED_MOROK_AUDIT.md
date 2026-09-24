# Supplied Morok ELF artifact audit

The user identifies the adjacent Morok checkout as their obfuscator. Both
supplied Linux ELF64 files are byte-identical to the corresponding files at
that checkout root. This establishes artifact identity and user-attributed
family provenance. The exact source revision, build command, seed and effective
settings for either supplied file remain **unknown**. The two adjacent derived
TOML files have the same SHA-256, but no build record links them to these ELF
bytes.

The checkout's `tools/morok-audit.py` and `morok-native-pack verify` distinguish
the two artifacts:

| Supplied artifact | ELF section observation | Native-pack verification | Release audit with sealed-manifest and native-pack requirements |
|---|---|---|---|
| `samples/boo-linux-x86_64-static` | `.morok_npack_rx`, 393,216 bytes; `.morok_npack_ro`, 128 bytes | Fails: GNU build ID does not describe the current full file | Fails: native-pack check and no recognized post-link sealed manifests |
| `samples/int_woma_keygen-linux-x86_64-static` | Executable packed section, 262,144 bytes; 128-byte companion section, both with scrubbed names | Passes: 262,144 protected bytes | Passes: 52 recognized sealed manifests |

The finalizer's build-ID verifier locates the 20-byte GNU note, replaces that
field with zero bytes, computes SHA-1 over the **entire current file**, and
compares it with the recorded note. For `boo`, the note records
`bd87f92dc8f576184400b54d41438ec46a97930d`; the current file recomputes
`73a256d7962b6d6b7d807709cfff906b8690ed3f`. The keygen note and
recomputed digest both equal `512ab07d6df839cbfa1a3c46cdfe23c771d54492`.
The 20-byte note field begins at file offset `0x210` in both pinned files.
The mismatch establishes that `boo`'s note does not cover its current bytes;
the time, mechanism and intended build state of the difference are **unknown**.

To separate the two verifier failures, a disposable copy of `boo` in `build/`
was given the recomputed build-ID value, with every other byte unchanged.
`morok-native-pack verify` then reported `no finalized native-pack manifest
found`. This is a diagnostic copy only; the supplied file was not changed.
The executable section name alone therefore does not establish a finalized,
valid native pack. The absence of recognized seal manifests is independently
reported by the audit without its native-pack requirement. Earlier process
status 132/139 for `boo` cannot be assigned a unique cause from these static
checks.

Reproduce with the hash-matched adjacent checkout and supplied artifacts:

```sh
python3 ../morok/tools/morok-audit.py samples/boo-linux-x86_64-static \
  --release --require-sealed-manifest --require-native-pack \
  --native-pack-tool ../morok/build/src/packer/morok-native-pack
python3 ../morok/tools/morok-audit.py samples/int_woma_keygen-linux-x86_64-static \
  --release --require-sealed-manifest --require-native-pack \
  --native-pack-tool ../morok/build/src/packer/morok-native-pack
../morok/build/src/packer/morok-native-pack verify samples/boo-linux-x86_64-static
../morok/build/src/packer/morok-native-pack verify samples/int_woma_keygen-linux-x86_64-static
```

Exact source, tool, input and diagnostic-copy hashes and the observed results
are in `VMP_SUPPLIED_MOROK_AUDIT_EVIDENCE.json`. The audit scans each file and
its recognized manifests; the build-ID calculation uses O(B) time and O(B)
space for B file bytes in this implementation. Counts and section sizes above
are exact byte counts.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | The supplied and checkout-root files are the same artifacts. The provenance comparison depends on their exact hashes. | Rehash both copies; reject the comparison on any mismatch. |
| A2 | The pinned Morok finalizer and audit implement the stated format checks. The pass/fail classifications depend on these versions. | Rehash both tools and source, repeat with a fresh build of the finalizer, and inspect the build-ID and manifest rules. |
| A3 | The one-field diagnostic edit isolates the build-ID gate. The second failure classification depends on no other byte changing. | Compare the disposable copy against the original at every offset except the 20-byte note and require the distinct manifest failure. |
| A4 | The keygen audit establishes validity only under these format checks. Any runtime or semantic conclusion would require a separate oracle. | Execute controlled inputs on a verified x86-64 engine and compare original/protected state and output. |

- **High impact:** `boo` cannot be counted as a verified finalized native-pack
  fixture under the current Morok format contract.
- **Medium impact:** the keygen supplies a verified packed and sealed artifact,
  but its exact settings and source-build lineage remain unknown.
- **Low impact:** adjacent derived TOML equality is a candidate configuration
  clue, not an output-to-settings proof.

QG1: technical artifact analysis. QG2: A1–A4 include falsification probes.
QG3: both supplied Morok artifacts and the distinct verifier failures are
covered; wider recovery requirements remain open. QG4: bytes, SHA-1/SHA-256
and O(B) costs are explicit. QG5: section presence, format verification,
runtime behavior and source lineage are separate claims. QG6: local primary
source, tool hashes, exact binaries and observed audit outputs are recorded.
QG7: effects on benchmark eligibility and adjacent settings uncertainty are
bounded above.
