# Native-region scalar and modeled string snapshots

The separate native-region string projection now includes single executed reads
and modeled argument snapshots as well as contiguous read streams. It retains
the original producer and all scheduled-run witnesses. This advances review
rows 3a, 3b and 5; function evidence, protected ctree annotations and VM identity
remain separate requirements.

## Assumption register

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| S1 | The completed native capture and explicitly named ABI bindings describe the observed uses. Callee equivalence remains unknown. | Keep the existing all-run admission gates. Require a modeled use's callee and kind to match its binding, and its argument index to be an input actually captured by that model. Reject invalid slots and unrelated model kinds. |
| S2 | A scalar use describes the following original memory-read event. Scalar literals depend on this correspondence. | Match sequence, site, address, width, scope and every byte against `DataAcc`; a changed scalar value removes the affected candidate. |
| S3 | Modeled bytes describe a use within the recorded object lifetime. They do not independently establish machine reads. | Validate context, allocation origin, generation, range and release order. Retain the original use sequence and full snapshot; export no invented data-event sequence. |
| S4 | Finite cross-run agreement establishes an observation for this corpus. Universal values remain unknown. | Require every scheduled run and the same semantic use/shape. Contradicting values, invalid duplicates and missing witnesses suppress that use while preserving an unrelated valid lifetime. |
| S5 | The new native fixture provides an independent value oracle. | Compare both consumed 64-bit values after re-encryption with a separate volatile oracle key; two independently changed expected values must each produce exit status 1. The valid fixture must return 0 and contain neither plaintext literal. |

## Admission and projection [S1–S4]

The existing native-region capture type and completeness contract remain in
force. Ordinary function proof flags cannot admit this corpus. A failed or
incomplete scheduled run still rejects the entire native projection.

Executed scalar reads contain 1–8 observed bytes and require exact correspondence
with the following read event. They retain producer `executed-read` and one
original read fragment per witness. Multi-read candidates retain producer
`executed-read-stream` and their existing lifetime, ordering and memory-barrier
requirements. Both use the existing bounded UTF-8 prefix validator and require
an observed NUL terminator.

Modeled argument admission covers the captured input slots of `strlen`,
`strnlen`, `memchr`, `strcmp`, `memcpy`, `memmove`, `strcpy` and `strncpy`.
The model kind and exact callee address must belong to the common binding
contract. Models that do not capture an input string cannot supply a candidate.
Snapshots retain their full bytes, including bytes beyond a scalar data event's
eight-byte value field. The string value remains the validated prefix.

Each run retains at most 4,096 use snapshots, 4,096 bytes per snapshot and
1 MiB of total snapshot bytes. The projection now checks both per-snapshot and
aggregate raw-byte bounds when indexing its input ledger. Existing allocation,
memory-event, derived-byte and output-row limits still apply.

The inspector reports `producer`, `callee`, `argument`, `model_kind`,
`read_count` and `snapshot_count` for every witness. A modeled witness has
`read_count = 0`, `snapshot_count = 1` and an empty `data_sequence` in its byte
row. Its original use sequence remains present. The Qt panel labels that row
`modeled-argument`, displays the read/snapshot counts, and navigates to the use
site only after the existing exact freshness check. The modeled snapshot is not
inserted into the raw machine-read ledger.

## Validation [S5]

The new x86-64 fixture allocates, decrypts, reads a full scalar, calls `strlen`,
erases and frees each of two values. Its original and two negative oracle builds
return 0, 1 and 1 respectively. Compilation uses `-fno-builtin` and
`-D_FORTIFY_SOURCE=0` so SDK expansion does not eliminate the erase calls.
Neither plaintext value appears in any of these binaries.
The runner process reports arm64; the x86-64 executables run through the macOS
loader. Hardware differential validation remains unknown.

Production console and actual Qt probes validate four use-specific observations:
two scalar reads and two modeled arguments. Each inspection retains 16 capture
witnesses and 16 original byte snapshots. The console passes 38 checks and the
Qt run passes 44, including distinct producers, byte attribution, selection,
changed-input navigation, exact restoration, supersession and timer shutdown.
The rendered modeled-snapshot view was inspected.

The ten-binary protected read-stream regression passes 183 checks and retains
its previous 4/18 protected value-occurrence coverage. Seven incomplete binaries
publish no values. The ordinary function/ctree regression passes 24 checks.
Together these are 289 production checks. All 20 CTest suites pass. Portable
controls cover every admitted model input slot, a wider-than-scalar snapshot,
invalid lifetime/context/model/argument metadata, conflicting duplicates,
contradicting bytes, scalar-event mismatch and snapshot quotas.

Hashes and exact runtime results are recorded in
[VMP_USE_SNAPSHOTS_EVIDENCE.json](VMP_USE_SNAPSHOTS_EVIDENCE.json).
Historical evidence manifests continue to describe their original revisions.

```sh
python3 -B tests/run_native_use_snapshots.py \
  --ida "$IDA_CONSOLE" --gui "$IDA_GUI" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-use-snapshots-new
```

For E retained events, U uses, B retained bytes and K explicit bindings,
indexing and consensus cost O(E log E + B + U K), with bounded semantic-key
comparisons; K is at most 32. Retained memory is O(E + B). These bounds exclude
emulation, IDA snapshot creation and UI rendering.

## Bounded implications and quality gates

- **High:** model snapshots and directly executed reads need distinct displayed
  provenance even when their bytes and use sites agree.
- **Medium:** the new scalar/modeled fixture is unprotected. Wider architectures,
  protected modeled-use coverage, interleaved algorithms and protected ctree
  display remain incomplete.
- **Medium:** full close/reopen/rebase coverage and worst-case inspection latency
  remain unknown; this change retains the existing exact freshness mechanism.

QG1: technical scope. QG2: S1–S5 with falsification probes. QG3: native scalar and
modeled projection, linked display and regressions covered; the complete review
remains open. QG4: byte widths, quotas, counts and complexity scope explicit.
QG5: modeled snapshots acquire neither machine-read sequences nor function-proof
flags. QG6: source, fixture and accepted artifacts are hash bound. QG7: remaining
corpus, lifecycle and display limits are explicit.
