# Certified catalog replay and refreshed predicate corpus

Review rows 0b, 4a, 4b and V receive a complete paired corpus refresh and a
correction to the independent catalog checker. The installed predicate module
at `b89d23fc` and the saved prior module at `0e9dbb49` each complete 40 fresh SDK
processes on the same regenerated binaries.

## Actual validation failure and correction

The initial two-worker run produced all 40 captures but its checker stopped
after 35 result rows. Two enabled i386 captures certified 103 and 102 of the
108 registered rules; the excluded rules returned UNKNOWN with `timeout`.
The checker incorrectly required the certified population to equal the entire
registered population. A one-worker trial also encountered certification
timeouts. Reduced concurrency does not guarantee complete certification.

`mba_match_replay.catalog` now checks that certified rules form a unique,
registered subsequence in registration order. Empty and partial certified
catalogs are valid. `check_probe` independently checks registered, verified and
rejected counters, their accounting, and the certified pattern count. Matcher
events replay against the actual certified catalog. Production verification
and UNKNOWN exclusion retain their existing behavior.

The runner accepts `--workers 1` or `--workers 2`, retaining default 2. Known
validation and I/O errors produce failed terminal rows, preserving subsequent
profiles; the complete matrix still returns failure if any row fails.

The two accepted one-worker matrices expose the same reserved-seed i386
virtualization profile with different startup availability: prior 88 verified
and 20 rejected; current 102 verified and six rejected. All these rejections
are UNKNOWN/timeouts. The evidence records every excluded rule. These are
availability observations, not counterexamples to those catalog identities.

## Paired observations

The native population is:

```text
2 architectures × (1 original + 3 modes × 3 protector seeds)
  × 3 input seeds × 560 records = 33,600 behavior records
2 architectures × 10 binaries × 2 transformation profiles = 40 SDK processes/module
2 modules × 40 processes = 80 SDK processes
```

The architectures are x86-64 Mach-O and i386 ELF. The i386 native oracle executes
through the pinned independent QEMU translator. Mutation, virtualization and
combined modes each retain three seeds. Reserved protector seed 12648430 and
input seed 3518319157 remain represented. All 18 protected binaries reproduce
identically on repeated protection. Both originals and all 18 variants match
the 20 historical binary SHA-256 pins; historical evidence remains unchanged.

The paired SDK audit preserves 152 native-row pairs, all 456 outcomes, 454
captured CFG/typed-tree pairs and all recorded instance-verifier results.
Terminal matcher outcomes remain 8,103 unindexed roots, 4,474 structural
mismatches, 1,483 constant-constraint failures and five catalog applications.
The current transient-input inventory retains 3,950 keys covering 5,266 of
14,065 events; 8,799 omitted events remain explicit. Every attempted input has
complete capture status; retention quotas still limit attribution.

No additional protected simplification is observed for predicate integration
on this population. The separately observed mixed-width native predicate
improvement remains documented in `VMP_TYPED_PREDICATES.md`. Exact recorded
tree equality here does not establish whole-function or native fault equivalence.

## Regression and resource evidence

The matcher CTest passes 36 controls, including partial/empty catalogs and
reordered, unregistered and duplicate certified-rule corruptions. Revalidation
accepts all 40 original captures, including both partial catalogs. A scheduling
control corrupts one actual certification count: the matrix fails, retains all
40 terminal rows, and preserves later held-out results. SDK launch is mocked
in that control; its synthetic process fields are excluded from measurements.
The paired production audit rejects nine diagnostic corruptions. Each fresh
matrix additionally checks three certification-counter corruptions per profile.

| Process measure | Prior module | Current module |
|---|---:|---:|
| SDK wrapper elapsed range, ns | 923,170,750–76,144,814,584 | 926,451,833–99,445,301,375 |
| SDK wrapper peak resident range, bytes | 104,103,936–203,751,424 | 104,939,520–205,225,984 |
| Complete serial matrix wrapper, ns | 238,529,375,333 | 231,038,994,333 |

These single-run measurements include process launch, IDA analysis, solver
startup and capture work. Catalog availability differs. Plugin-only costs,
repeatability error bounds and the cause of the higher current maximum are
unknown. The per-process cap is 300 s. One worker is used in both accepted runs.

## Durable capture and reproduction

`VMP_TYPED_PREDICATES_CORPUS_CAPTURE.json.gz` retains 233 exact UTF-8 artifacts:
native observations, both SDK capture/manifest matrices, reports and selected
receipts. SHA-256 pins cover each artifact. Its uncompressed canonical JSON is
99,354,940 bytes; the gzip archive is 2,578,998 bytes, with timestamp zero.
A separate temporary checkout restores all 233 files and reproduces the exact
paired audit. Independent integer replay verifies all 33,600 archived native
observation records; this replay does not execute the native binaries.
Executables and plugin modules are referenced by hashes rather than embedded.
The companion evidence JSON pins the archive, source files, primary SDK header,
protector references and observations. The supplied console's equivalence to
the reference-source build and implicit license-dependent options remain unknown.

From the repository root, restore the archived observation files with:

```sh
python3 -B - <<'PY'
from pathlib import Path, PurePosixPath
import gzip, hashlib, json
data = json.loads(gzip.decompress(
    Path('docs/VMP_TYPED_PREDICATES_CORPUS_CAPTURE.json.gz').read_bytes()))
for name, record in data['files'].items():
    path = PurePosixPath(name)
    assert not path.is_absolute() and '..' not in path.parts and path.parts[0] == 'build'
    raw = record['text'].encode()
    assert hashlib.sha256(raw).hexdigest() == record['sha256']
    target = Path(name)
    if target.exists():
        assert target.read_bytes() == raw
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
PY
python3 -B tests/verify_mba_matching_capture.py \
  --current build/predicate-matrix-installed-b89d23fc-v3/protected_mba_analysis.json \
  --baseline build/predicate-matrix-prior-0e9dbb49-v1/protected_mba_analysis.json \
  --output build/predicate-corpus-archive-reproduction.json
```

Use the pinned source revision for replay. Fresh executable generation uses
`run_vmp_corpus.py` once per architecture with the pinned console/reference
tree and immutable Linux32 image. Fresh SDK capture uses
`run_protected_mba_corpus.py --native-analysis --matcher-inputs --workers 1`
with both complete corpus reports, once per module. Artifact directories are
new for each run. Native execution requires those regenerated binaries.

Catalog population/order validation uses expected O(R + C) hash/set work and
O(R + C) space for R registered and C certified rules, plus bounded grammar
traversal. Catalog encoding remains limited to 32,768 bytes and 8,192 grammar
visits. Matcher/solver costs retain their separate bounds and contracts.

## Assumption register and bounded expansion

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| C1 | Exact regenerated bytes define the matched population. | Verify all 20 historical pins, 18 repeated protection pairs, seed attestations and native oracles. |
| C2 | The SDK catalog snapshot represents the certified registration subsequence. | Reject unregistered, reordered and duplicate rules; cross-check counters and replay actual matcher events. |
| C3 | Pinned IDA/module/probe bytes and selected ownership identify observations. | Check capture manifests, unchanged native bytes, owned rows, SDK outcomes and all paired typed trees. Native reachability and fault equivalence remain unknown. |
| C4 | Recorded process measurements describe these runs. | Preserve raw receipts; repeat matched cold serial waves before attributing latency or estimating error bounds. |
| C5 | Archived bytes retain these observations after build cleanup. | Verify gzip/canonical/file hashes, restore into a separate checkout and replay the paired audit. Executable bytes require regeneration. |

Bounded expansion: **medium**, startup UNKNOWN exposes variable catalog
availability that affects miss interpretation; **medium**, terminal failure
rows preserve complete batch accounting; **low**, committed compressed captures
retain observation replay after cache loss. Wider ownership, complete aliases,
native fault contracts, protected recovery gains and full review implementation
remain in progress.

QG1: technical scope. QG2: C1–C5 and probes. QG3: actual failure, correction,
negative controls, regenerated native population and matched installed/prior
matrices. QG4: exact populations, SI process measures and bounded complexity.
QG5: partial catalogs, omissions, measurement variability and executable/archive
limits are explicit. QG6: actual native/SDK observations and primary SDK/source
pins are preserved. QG7: bounded expansion and remaining full-review scope are
explicit.
