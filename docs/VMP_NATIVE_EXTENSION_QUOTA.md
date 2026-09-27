# Joined native-target quota and snapshot hashing

Review rows 1b, 6a and V remain in progress. This checkpoint corrects observed
native-target extension at the existing head bound. It preserves the separate
native-region model and does not publish ordinary function evidence or logical
VM identity.

## Implementation

The predecessor first validated the previous region against the input image,
then planned from the observed target using the remaining head quota. That
second plan charged previously admitted joined heads again. A four-head new
path joining an existing long tail could therefore lose its own fallthrough
heads despite sufficient total capacity. The predecessor also recomputed the
whole-image content fingerprint in both validation and addition planning.

The internal builder now charges only scheduled addresses absent from the
previous plan. Joined heads are decoded again and merged under the original
exact byte, flow and overlap checks; they are not accepted through an unchecked
cache lookup. Newly scheduled invalid or unsupported addresses still consume
quota and retain their frontier. The existing source/target, architecture,
generation, image-fingerprint and frontier limits remain. A successful extension
reuses the fingerprint just validated for the same const input snapshot,
removing its second full traversal. Public planning still computes its own
fingerprint, and no public API accepts a caller-supplied trusted hash.

The fingerprint is noncryptographic. Runtime instruction admission continues
to compare exact fetched bytes. Neither fingerprint equality nor a region
identity establishes semantic equivalence.

## Counterfactual and independent verification

The portable hybrid fixture runs in both supported x86 modes. Seven previous
heads join four new heads: the candidate retains all 11 at an 11-head quota.
A 10-head quota retains three new heads and reports truncation. Nine addition
instructions, including the five joined heads, are each decoded once. Conflicting
joined control semantics reject the complete extension. Changes to an unrelated
image byte, initialized-byte mask, permissions or mode reject despite an
unchanged cached `content_hash`. Existing stale-generation, interior-target,
decoder rejection, wall-time and extension-count controls also pass.

`tests/vmp_native/native_extension_quota.c` supplies an independently executed
x86-64 Mach-O fixture. Its main returns success only when the assembly routine
returns 42. Two builds differ by one old NOP; each succeeds in three native
process executions. The predecessor is the installed and signature-verified
artifact of `7a7a0effc85721cce7689ecb8e90267417ba9595`.

| Case | Initial heads | Added heads | Final heads | Entered instructions | Completion |
|---|---:|---:|---:|---:|---|
| Predecessor, exact capacity | 4092 | 2 | 4094 | 6 | Incomplete, truncated |
| Candidate, exact capacity | 4092 | 4 | 4096 | 8 | Return sentinel, RAX = 42, SP delta = 8 bytes |
| Predecessor, one excess head | 4093 | 2 | 4095 | 6 | Incomplete, truncated |
| Candidate, one excess head | 4093 | 3 | 4096 | 7 | Incomplete, truncated |

Each case is captured twice in isolated IDA. All 66 probe checks pass and each
query preserves the full head/function inventory. The independent verifier
uses Capstone 5.0.7 and file-backed Mach-O spans, reconstructing the old linear
tail and new path directly from instruction bytes and the RIP-relative LEA.
It checks all 32,762 head records and 54 entered records against those
inventories. Four changed-byte, missing-head, wrong-path or completion
corruptions are rejected. This is a fixture-specific byte/path oracle, not a
general native CFG or callee-equivalence proof. All 23 CTest suites pass.

## Protected regression measurements

Two fresh 40-run matrices use the unchanged paired corpus and explicit temporal
ABI models. All common instruction-entry prefixes match exactly. All 16
previously completed runs retain their return oracles. The candidate's 31
distinct undefined-result certificates, containing 264 instruction occurrences,
pass the unchanged independent symbolic dependence verifier. Its 200 entered
abstract steps remain explicit; four unsafe symbolic controls are refuted.

| Protected label | Predecessor instruction counts / four runs | Candidate instruction counts / four runs |
|---|---|---|
| Virtualization 0 | 2721, 2721, 2721, 2721 | 2876, 2876, 2876, 2876 |
| Virtualization 1 | 2738, 2738, 2738, 2738 | 3587, 3587, 3587, 3587 |
| Virtualization 12648430 | 40, 40, 40, 40 | 40, 40, 40, 40 |
| Combined 0 | 2983, 2983, 2983, 2983 | 3823, 3823, 3823, 3823 |
| Combined 1 | 2758, 2758, 2758, 2758 | 2758, 2758, 2758, 2758 |
| Combined 12648430 | 4096, 3007, 1384, 1874 | 4096, 4096, 4096, 4096 |

Time-limited counts are observations of these processes. The shared execution
deadline remains 1000 ms and the instruction cap remains 4096. These counts do
not establish a general speedup or additional completed protected recovery.
All six virtualized/combined variants remain incomplete. Startup, initial image
capture and initial planning are outside the execution deadline; one extension
can finish after that deadline, but the next resume checks the remaining time.
Strict whole-query latency remains unproved.

## Provenance and replay

`VMP_NATIVE_EXTENSION_QUOTA_EVIDENCE.json` pins the candidate sources,
predecessor source revision, binary receipts and reports.
`VMP_NATIVE_EXTENSION_QUOTA_CAPTURE.json.gz` contains canonical JSON with gzip
mtime 0: `files` entries retain UTF-8 text and SHA-256, `binary_files` retain
base64 fixture bytes and SHA-256. Protected binaries are referenced through the
unchanged, hash-verified `VMP_UNDEFINED_RESULTS_CAPTURE.json.gz`; their exact
paths and hashes are retained in `external_binary_files`.

The matrix reports' `source_sha256` fields describe the capturing checkout.
They do not attribute the predecessor binary to the edited candidate sources.
Exact predecessor production sources are archived separately under its revision.
Plugin binaries are identified by SHA-256 and are not archived.

After restoring the containers' files and referenced binary inputs:

```sh
uv run --no-project --with capstone==5.0.7 python tests/verify_native_extension_quota.py --output build/native-extension-independent-replay.json
uv run --no-project --with capstone==5.0.7 --with z3-solver==4.16.0.0 python tests/verify_native_undefined_slices.py --report build/native-extension-candidate-matrix/region_temporal_analysis.json --corpus-report build/protected-strings-db33-v1/strings.json --output build/native-extension-symbolic-replay.json
```

## Assumption register and bounds

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| N1 | The const input snapshot remains stable throughout one planning call. Reused validated fingerprint and planning results depend on this. | Full fingerprint revalidation rejects byte, mask, permission and mode edits without trusting cached metadata; runtime exact-byte checks remain. Concurrent caller mutation is outside this contract. |
| N2 | Mode-aware decoder results describe the supported native instruction inventory. Head admission depends on this. | Joined heads are redecoded; conflicts and overlaps reject. Independent file-backed Capstone inventories and four refuted mutations check the scoped fixture. |
| N3 | The same input, pinned plugin and isolated probe describe each predecessor/candidate observation. Counterfactual results depend on this. | Runner hashes, repeated captures, unchanged IDB inventories, exact source revision and six native process outcomes. |
| N4 | Existing temporal ABI and closed-dependence contracts describe the protected prefixes. Protected comparison depends on this. | All common entered prefixes match; 31 independent symbolic proofs and four unsafe controls. Native callee equivalence and complete VM semantics remain unknown. |
| N5 | Process instruction counts describe only the retained deadline-limited observations. Coverage measurements depend on this. | All four per-label counts, stops and raw receipts are preserved; no general latency or completed-recovery gain is inferred. |

Let M be total image bytes and mask bytes, S the segment count, H the preceding
heads, Q newly scheduled addresses and F retained/temporary frontiers.
Fingerprint work remains O(M + S), with one traversal per validated extension
instead of two. Admission visits at most H + Q distinct addresses, performs
O((H + Q + F) log(H + Q + F)) set/merge work, and retains O(H + Q + F) heads,
frontiers and worklist state, excluding decoder and segment lookup costs.
The public hard head bound is 16,384; this execution path retains 4,096 heads,
64 observed-target extensions and the existing frontier cap. Initial planning
and unsupported scheduled addresses retain their existing bounds.

Bounded scope: **high impact** restores a complete joined native path at the
existing quota; **medium impact** removes redundant snapshot traversal;
**high remaining impact** complete topology, strict query latency, broader
environment effects and VM-region semantics remain open.

Quality gates: QG1 requires no normative content; QG2 records N1-N5 and probes;
QG3 covers this change while retaining the full review scope; QG4 uses exact
counts, bytes, bit modes, ms limits and scoped complexity; QG5 preserves quota,
conflict, stale-image and incomplete-path cases; QG6 retains exact source,
binary and capture provenance; QG7 records impacts and remaining work.
