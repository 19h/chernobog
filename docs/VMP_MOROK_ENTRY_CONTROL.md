# Morok packed-entry control

The two user-supplied static Linux ELF files match identically named binaries
in the local Morok checkout by SHA-256. The user identifies that checkout as
their obfuscator. It also contains `boo.c` and
`programs/int_woma_keygen.c`, plausible source counterparts. No recorded
source-to-binary build invocation or verified unprotected executable links
either source file to the supplied ELF. The two nearby per-file TOML settings
are byte-identical, but their effective use for these binaries remains
**unknown**. The keygen audit names and hashes the protected keygen file; it
does not establish its pre-protection input.

Fresh IDA 9.4 SP1 databases were created for each exact supplied binary, with
the installed plugin enabled and with its transformations disabled. The
existing bounded corpus-inspection probe selected the ELF entry `0x40025b`
and the entry stub's direct jump target. The target is `0x47072b` for `boo`
and `0x4aa80b` for the keygen, independently decoded from the original ELF
bytes. RAX execution was disabled; these are static startup observations.

| Input | Selected entry | Heads, enabled/disabled | Owners inspected | Native / VM records; solver API, enabled |
|---|---:|---:|---:|---:|
| `samples/boo-linux-x86_64-static` | `0x40025b` | 47 / 47 | 2 | 0 / 0; unavailable |
| `samples/boo-linux-x86_64-static` | `0x47072b` | 35 / 35 | 2 | 0 / 0; unavailable |
| `samples/int_woma_keygen-linux-x86_64-static` | `0x40025b` | 47 / 47 | 2 | 0 / 0; unavailable |
| `samples/int_woma_keygen-linux-x86_64-static` | `0x4aa80b` | 35 / 35 | 2 | 0 / 0; unavailable |

For each input, the two selected traversals overlap and inspect the same two
owners; the rows are not independent recovery trials. Every selected head was
decoded as code, neither traversal reached its 4,096-head cap, and inspection
preserved the code/xref inventory. The enabled and disabled reports have
identical instruction and owner inventories for each selected address. The
solver-evidence API reports unavailable, so its empty record list is not a
solver-negative result. Native direct-jump decoding reports zero attempts and
zero newly decoded targets in both enabled profiles. All four IDA runs
complete without probe errors.
These observations establish neither a protected-edge oracle nor a
binary-wide false-positive rate. Unentered packed payloads, dynamic unpacking,
and the behavior of valid keygen inputs remain unmeasured.

Exact input, candidate-source, configuration, tool, plugin and raw-report
hashes are in `VMP_MOROK_ENTRY_CONTROL_EVIDENCE.json`. Reproduce the `boo`
enabled profile with a fresh output directory, then repeat with
`--set CHERNOBOG_DISABLE=1` and a second output directory:

```sh
python3 -B tests/run_ida_smoke.py samples/boo-linux-x86_64-static \
  tests/ida_vmp_corpus_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/morok-boo-entry-new \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set 'CHERNOBOG_CORPUS_ENTRIES={"corpus_transform":"0x40025b","corpus_branch":"0x47072b"}'
```

## Assumption register and scope

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| E1 | The exact copied ELFs represent the supplied Morok outputs. Sample-family attribution depends on the user's statement and local hash matches. | Rehash the supplied files and checkout binaries; obtain signed build records or source-to-output invocation for stronger lineage. The keygen audit corroborates only its protected output hash. |
| E2 | The selected static paths represent packed startup, not the hidden application body. The narrow startup observation depends on this interpretation. | Inspect the `.morok_npack_rx`/`.hdmoh1mxteam2f` sections, capture runtime unpacking on a validated x86-64 Linux engine, and compare entered bytes with file bytes. No application recovery claim follows from the startup counts. |
| E3 | The enabled/disabled profiles differ only by the plugin transformation switch. Inventory comparison depends on this. | The runner manifests record equal input, plugin, IDA and probe hashes per pair; raw instruction/owner arrays are compared exactly. A changed loader or IDA analysis configuration would invalidate the pair. |
| E4 | Zero records at the inspected owners mean only those owners produced no published findings. Any specificity interpretation depends on the inspected scope. | Inspect more owners and independent protected families with a ground-truth source/protector matrix. Whole-binary and held-out false-positive rates are **unknown**. |
| E5 | The Morok checkout source files are plausible originals, not verified build inputs. Any source-level oracle derived from them depends on future lineage evidence. | Record compiler, flags, linker, input hash, Morok invocation, seed/config hash and output hash for each binary; independently compare valid-input behavior. |

The probe traverses at most 4,096 code heads per selected entry and inspects
at most 64 function owners. With `H` visited heads, `X` outgoing code xrefs and
`O` inspected owners, traversal is `O(H + X)` time and `O(H + X)` retained
space, before the bounded owner API work. The observed head/owner counts are
integers; no SI physical quantity is inferred from them.

**Medium impact:** exact Morok outputs provide a non-VMP packed-entry control
for startup-specific plugin behavior. **Medium impact:** their identical
startup inventories do not measure application recovery or binary-wide
specificity. **Low impact:** candidate source and TOML hashes allow later
lineage checks without assigning unverified settings to either output.

QG1: no normative premise. QG2: E1–E5 include falsification probes. QG3:
the bounded startup control covers the stated sample comparison; the full
review remains open. QG4: head, owner and work limits are explicit. QG5:
candidate source, output lineage and scope are separated. QG6: primary local
source, exact binaries, runner, plugin, IDA and raw reports are hash-linked.
QG7: full-binary behavior and broader specificity remain explicit unknowns.
