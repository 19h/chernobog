# Hikari arm64 entry-path control

The user supplied `samples/hikari-console-max-stable.uu` as a Hikari sample.
Despite its filename suffix, the exact file is a thin arm64 Mach-O executable.
Its `LC_MAIN` entry and `_main` symbol are at `0x100000598`; its symbol table
also names `_HikariFunctionWrapper` at `0x10013c880`. The protector settings,
source-to-output invocation and original counterpart are **unknown**. This
file is an architecture-distinct control, excluded from VMP recovery
denominators. Its separately recorded three no-argument process runs have
identical output; see `VMP_SUPPLIED_SAMPLES.md`.

Fresh IDA 9.4 SP1 databases inspected those two exact entry addresses with
the same signed installed plugin enabled and disabled. RAX execution was
disabled. The existing bounded corpus probe followed IDA code xrefs, then
queried the native, VM-region and solver-evidence APIs for the selected owner.
The generic probe keys `corpus_transform` and `corpus_branch` denote `_main`
and `_HikariFunctionWrapper` here; they do not classify either address as a
VMP transformation or branch.

| Selected entry | Heads enabled / disabled | Code heads | Owners | Native records | VM and solver API |
|---|---:|---:|---:|---:|---|
| `_main`, `0x100000598` | 2,643 / 2,643 | 2,643 | 1 | 0 | unavailable |
| `_HikariFunctionWrapper`, `0x10013c880` | 7 / 7 | 7 | 1 | 0 | unavailable |

The two traversals are disjoint. Their complete instruction arrays and owner
starts are exactly equal between enabled and disabled runs. Neither traversal
reaches the 4,096-head or 64-owner limit, and each inspection preserves its
code/xref inventory. Direct-jump decoding records zero attempts, decoded
targets and truncations in both profiles. Each run reports zero probe errors.
The native API is available when enabled and reports zero records for each
selected owner; with transformations disabled, it reports unavailable. VM and
solver API unavailability is an abstention. No binary-wide false-positive
rate, protected-edge oracle or application recovery claim follows from these
two static paths.

The exact input, probe, runner, IDA, plugin and report hashes are in
`VMP_HIKARI_ENTRY_CONTROL_EVIDENCE.json`. Reproduce the enabled profile with
a fresh output directory; repeat with `--set CHERNOBOG_DISABLE=1` and a
second output directory:

```sh
python3 -B tests/run_ida_smoke.py samples/hikari-console-max-stable.uu \
  tests/ida_vmp_corpus_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/hikari-entry-repeat \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set 'CHERNOBOG_CORPUS_ENTRIES={"corpus_transform":"0x100000598","corpus_branch":"0x10013c880"}'
```

## Assumption register and scope

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| H1 | The exact supplied binary is a Hikari output, as identified by the user. Family-specific interpretation depends on that attribution. | Rehash the sample; obtain a build record linking Hikari source, settings and output hash. The named wrapper symbols alone do not establish the full transformation configuration. |
| H2 | The selected addresses represent `_main` and one named wrapper in this exact Mach-O. The two-path inventory depends on those entries. | Check `LC_MAIN` and the symbol table against the hash-matched binary; inspect other wrappers and entry points separately. |
| H3 | The paired IDA profiles differ only by the plugin transformation switch. The equal-inventory result depends on this. | Compare input, plugin, IDA and probe hashes and exact instruction/owner arrays. A changed loader configuration would invalidate the pair. |
| H4 | Zero native records describe only the two selected owners. Any specificity interpretation depends on that bounded scope. | Inspect additional owners, live execution and a source/build-attested positive/negative matrix. VM and solver APIs must first be available to test their specificity. |

For H visited heads and X observed outgoing code xrefs, traversal takes
O(H + X) time and O(H + X) retained space, bounded by 4,096 heads. At most 64
owners per selected entry are queried. Head, owner and record counts are
dimensionless integers; no rounded quantity is reported.

- **Medium impact:** an arm64, user-identified non-VMP sample provides a
  distinct selected-entry control for native record publication.
- **Medium impact:** unavailable VM and solver APIs prevent scoring their
  arm64 specificity at these sites.
- **Low impact:** the named wrapper gives a reproducible second path, but its
  seven-head inventory cannot represent all Hikari-transformed code.

QG1: no normative premise. QG2: H1–H4 have falsification probes. QG3: both
selected entries, paired plugin modes and API availability are recorded; the
broader review remains open. QG4: limits and counts are explicit. QG5: zero
records are separated from unavailable APIs and whole-binary claims. QG6:
exact local binary, tool and raw-report hashes support the observations.
QG7: settings, other paths and full specificity remain explicit unknowns.
