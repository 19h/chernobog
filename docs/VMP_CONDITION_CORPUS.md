# Condition-consumer measurements on the protected corpus

Forty matched IDA runs now measure the condition consumer on the existing
paired corpus: original plus mutation, virtualization and combined variants
for three recorded generator seeds, in x86-64 Mach-O and i386 ELF. The exact
plugin is the one validated in `VMP_CMOV_MEMORY_EVIDENCE.json`.

**Observed result: zero SETcc/CMOV lowering events in this corpus scope.**
The enabled and disabled profiles produced identical captured initial
microcode and identical final pseudocode wherever comparison was available.
The earlier independent-fixture successes do not establish effectiveness on
these protected functions.

## Measurement and result

`tests/ida_vmp_conditions_probe.py` follows existing non-call code references
from the two selected entries. It records reachable condition instructions,
their current owners, and generation/decompilation outcomes for those owners.
It does not create instructions, functions, tails or replacement ownership.
The normal configured native analysis runs identically in both profiles; RAX
execution is disabled. The sole profile difference is
`CHERNOBOG_IDA_CONDITION_CODEGEN=0` versus `1`.

Each architecture has ten binary artifacts and twenty runs. The following
counts are **per profile**, summed across those ten artifacts; shared owners
and sites within an artifact are deduplicated.

| Observation | x86-64 | i386 |
|---|---:|---:|
| Selected-entry reachable SETcc/CMOV sites | 10 | 3 |
| Reachable sites without function ownership | 10 | 0 |
| Condition sites in the inspected owners | 0 | 3 |
| Existing function owners inspected | 20 | 39 |
| Successful initial-microcode generations | 20 | 39 |
| Successful final decompilations | 20 | 38 |
| Condition-lowering events | 0 | 0 |
| Enabled/disabled initial-IR differences | 0 | 0 |
| Enabled/disabled final-pseudocode differences | 0 | 0 |
| Traversal, owner, native-head or capture limits reached | 0 | 0 |

Across both profiles there are 118 successful initial-microcode generations
and 116 successful final decompilations. The two unsuccessful final
decompilations are the same i386 owner in the reserved-seed virtualization
artifact, once per profile. Both report SDK code −12, `MERR_BADCALL`: call
arguments could not be determined. This is an observed decompiler failure,
not a measurement-process failure or a successful recovery. The installed
`hexrays.hpp` enumeration and its hash are recorded in the evidence manifest.

Native instruction inventories and selected-entry reachability were preserved
through every inspection. All paired inputs matched before generation,
including ownership, native bytes, instruction counts and function flags.
All comparable IR and pseudocode hashes matched. Source, binary, plugin and
IDA executable identities remained unchanged during the measurements.

The ten x64 sites occur in `combined-0` (4), `combined-1` (1),
`combined-12648430` (3), and `virtualization-12648430` (2). The three i386 sites
occur in `virtualization-0` (2) and `combined-12648430` (1). These are sites
reachable through the current IDB code references, not a complete protected
instruction census.

The reachable census contains no memory-source CMOV in either architecture.
It therefore supplies no protected-code exercise of the new read intrinsic;
broader paired instruction shapes are still required for that claim.

The protected x64 owners inspected here are entry jump stubs. Successful
decompilation of a stub does **not** demonstrate recovery of its ownerless
protected body. Conversely, the three owned i386 sites reach microcode
generation without being folded. This measurement establishes their lack of
lowering; it does not establish that no stronger state analysis could prove
their conditions. Neither an increased prefix depth nor new recognizer patterns
were selected or tuned using the reserved seed.

## Evidence and reproduction

The primary reports are:

- `build/vmp-condition-corpus-x64/conditions_analysis.json`
- `build/vmp-condition-corpus-x86/conditions_analysis.json`

`VMP_CONDITION_CORPUS_EVIDENCE.json` records their hashes, all 80 per-run
report/capture hashes, the upstream corpus-report hashes, the fixture-validation
plugin identity, and the harness/SDK identities. The input corpus artifacts
remain the behavior-validated artifacts described in `VMP_PAIRED_CORPUS.md`
and `VMP_ELF32_CORPUS.md`; this experiment does not re-execute protected code
or establish exact source-build attestation for the supplied protector.

Use a new output directory for each architecture:

```sh
python3 -B tests/run_vmp_conditions.py \
  --corpus-report build/vmp-corpus-release/corpus.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/condition-corpus-reproduction-x64

python3 -B tests/run_vmp_conditions.py \
  --corpus-report build/vmp-elf32-release/corpus.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/condition-corpus-reproduction-x86
```

Optional repeated `--label` arguments select a subset, which is explicitly
marked partial. A report's `passed` field means that measurement and identity
checks completed; its separate outcome fields retain decompiler failures,
budget skips and absence of lowering.

The accepted matrices ran concurrently, with sequential off/on runs inside
each matrix. The summed runner elapsed times were 61.076237043 s for x64 and
95.249520292 s for i386; these sums are not the concurrent wall-clock duration.
Maximum reported peak resident sizes were 217,153,536 bytes and 168,263,680
bytes respectively. These are process-accounting observations with launch,
analysis and output overhead, a polled timeout and no repeated timing trials.
They establish neither a speedup nor an architecture performance ranking.

Five new harness tests distinguish ownerless sites from emissions, failures
from successful recovery, and truncated captures from unchanged results. They
also reject changed native inputs or an active disabled baseline, and locate
changed condition captures. All 15 corpus-harness tests and all 18 configured
CTest suites pass. The final suite log is
`build/vmp-condition-corpus-ctest.log`.

## Assumptions, limits and next work

| ID | Assumption / dependent result | Falsification probe or explicit limit |
|---|---|---|
| P1 | The archived paired artifacts and earlier behavior oracles identify the intended inputs | All binary and corpus-report hashes are checked; altered identities reject. Commercial-version or source-build identity is not inferred |
| P2 | Existing IDB code references and ownership define the measured scope | Both profiles' initial inventories must match. Ownerless sites and limits are explicit. Complete native/VM control-flow coverage is unknown |
| P3 | The condition toggle isolates the consumer for the inspected owners | All other controls and input identities match; the disabled profile must emit no condition events. Whole-program semantic equivalence is not inferred from text equality |
| P4 | Generation counters describe emission activity, not semantic recovery | Harness controls retain emitted events separately from failed generation/decompilation. No event is counted as a recovered edge or literal |
| P5 | One paired run per artifact establishes these observations | No statistical performance estimate, held-out generalization guarantee or exhaustive architecture coverage is claimed |

The probe caps each traversal at 4,096 heads and 16,384 xref records, inspects
at most 64 owners with 4,096 native items each, and retains at most 65,536
microinstructions or 4 MiB of serialized microcode per owner. Host runs have a
180 s process timeout. Budget exhaustion is recorded, never counted as complete
comparison. IDA index lookup and decompiler internals are outside the probe's
algorithmic bound. Excluding those internals, inventory work is O(H + X), and
capture hashing is O(B) in retained serialized bytes; explicit caps bound H,
X and B. Native snapshots and condition snippets occupy O(H + B) space per owner.

- **High impact:** function/region admission limits x64 coverage before the
  condition consumer can run. Whole-body recovery requires evidence for region
  membership and entries; forcing function tails would change this benchmark.
- **High impact:** stronger state propagation requires its own proofs and
  counterexamples. Zero observed lowering does not justify guessing a condition.
- **Medium impact:** call-argument recovery is independently incomplete at the
  matched i386 failure; initial microcode availability alone does not close it.

QG1: no normative judgment is required. QG2: P1–P5 and falsification probes are
explicit. QG3: protected-corpus applicability is now measured, while complete
recovery metrics and lifecycle coverage remain open. QG4: bytes, seconds,
profile counts and comparison denominators are explicit. QG5: stub success,
partial captures and failed decompilation cannot be promoted to whole-body
recovery. QG6: hashed local primary evidence and installed SDK definitions
support the claims. QG7: adjacent work is bounded above.
