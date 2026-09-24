# Supplied protected sample identities

The files below are the current user-supplied corpus. Sizes are byte counts;
SHA-256 identifies each exact artifact. Format and architecture were read
from file headers. Protector labels for the VMP pair and Hikari file are
user attribution; their exact protector builds, settings and seeds are
unknown.

| Repository-relative file | Format | Bytes | SHA-256 |
|---|---|---:|---|
| `samples/foo_x86_orig` | Mach-O x86-64 executable | 12,456 | `443b0a464d7de68c5a26a3e31a92e694356ccd1eef3127d522309ac672ecc7c7` |
| `samples/foo_x86_vmp` | Mach-O x86-64 executable | 2,618,368 | `c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5` |
| `samples/boo-linux-x86_64-static` | stripped static ELF x86-64 | 1,049,528 | `730f6adfba4cb7179320c96a3a5b24856059f1c4ba24bad25b969d74e4054a27` |
| `samples/int_woma_keygen-linux-x86_64-static` | stripped static ELF x86-64 | 1,250,120 | `7d1971b1db221174caac0a5922a7452e1bebe214ca2355ab36c889a635699fd9` |
| `samples/hikari-console-max-stable.uu` | Mach-O arm64 executable | 1,536,488 | `20824d7dfdc0d8353bb31e9ab1b8aed24ca506da3ef7e2df40f89a9c24598faa` |

The `.uu` suffix does not describe the last file's encoding: its file header
is Mach-O arm64. It should be loaded as a binary without a uuencode decode
step.

The user identified both Linux static binaries as outputs of their Morok
obfuscator. They are byte-identical to the corresponding binaries in the
sibling Morok checkout. That checkout contains `boo.c` (SHA-256
`3c0c301481a4a25930426cd6a6e84b03ad4b23a9925b9b4eeac804c33444fd5b`)
and `programs/int_woma_keygen.c` (SHA-256
`988a6144b6b3924c7ed432486d114c327f837e4ef424abb29c220fe6ee4f3628`)
as candidate original sources. Its two static config files are byte-identical
(SHA-256 `81a735e6df2335105073701eb4dfc212d31e72fe58f76899d63b1a35d9bcaf06`).
They select the `max` preset, 50% virtualization probability for at most 16
functions, and disable static-link-incompatible function-call obfuscation.
The config hash alone does not establish which exact config revision or seed
produced either supplied binary. The Morok release audit (SHA-256
`50ada89cf93c8167b384a835277ccf8ab2d9be636e27968be59ff16ef6fba149`)
does pin the supplied keygen SHA-256 and records 52/52 sealed manifests with
native packing required. It contains no `boo` audit record.

The separate fixed-seed keygen used in
[the branch continuation](VMP_NATIVE_BRANCH_CONTINUATION.md) and
[owned-call checkpoint](VMP_NATIVE_OWNED_CALL_CHECKPOINT.md) has SHA-256
`f479ae1ab6f03857a0598d61df4674e24c787328dcec77461be532e3d962bbae`.
Its replay measurements do not transfer to the supplied keygen by filename
or source lineage. The VMP original/protected pair is a comparison fixture,
but behavioral equivalence and emitted transformation settings remain
unknown. No original executable counterpart is pinned here for the Morok
or Hikari samples.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | User protector labels identify intended families. Family-specific benchmark grouping depends on this attribution. | Obtain build logs, protector version/settings and seed; compare protected headers and emitted code with the exact toolchain. |
| S2 | The sibling Morok source files are plausible originals for the two static artifacts. Source-level comparisons depend on this. | Rebuild clean and protected pairs, pin compiler/linker versions and seed, then compare complete-process outputs over a recorded input set. |
| S3 | The Morok audit record applies to the exact supplied keygen hash. The 52 sealed-manifest and native-pack claims depend on its integrity. | Rehash the audit, rerun `morok-audit.py` on that binary and reject a changed manifest count or pack finding. |
| S4 | Header-based file classification reflects the intended load architecture. Tool selection depends on it. | Parse the full Mach-O/ELF headers and successfully load each file in a matching architecture-specific analysis process. |

- **High impact:** the exact VMP pair and Morok keygen audit hash provide
  stronger fixture identities for subsequent differential work.
- **Medium impact:** the Hikari suffix is misleading for format detection.
- **High impact risk:** missing protector seeds/build logs and executable
  originals constrain behavioral-equivalence and transformation claims.

QG1: technical claims only. QG2: S1–S4 include falsification probes. QG3:
all five supplied files and the Morok provenance reply are represented. QG4:
sizes use bytes and SHA-256 digests are exact. QG5: the reproducible keygen
and supplied keygen identities are distinct. QG6: file headers, hashes,
source and audit are local primary artifacts. QG7: build settings and
behavioral equivalence remain bounded unknowns.
