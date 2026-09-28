# Complete protected MBA matcher inventory

This checkpoint advances review row 4a by removing the matcher-input sample
omission in the paired VMP corpus. It does not establish a new MBA identity or
protected recovery gain. The opt-in diagnostic limit is 1,024 keys per stage;
the ordinary plugin limit remains 64. The process report limit rises from
8,388,608 to 33,554,432 bytes only for the expanded diagnostic profile.

## Paired result

Each paired profile has 40 IDA processes using the same IDA and built-plugin
hashes, two architectures, the original and nine protected variants, with the
plugin enabled and disabled. Each profile has 456 selected microcode stages.

| Quantity | Default 64 keys | Expanded 1,024 keys |
|---|---:|---:|
| Matcher events | 14,047 | 14,047 |
| Retained event keys | 3,945 | 9,729 |
| Retained events | 5,261 | 14,047 |
| Omitted events | 8,786 | 0 |
| Stages with omissions | 43 | 0 |

All 152 native rows, 456 stage outcomes, 454 captured typed trees and matcher
outcome counts agree. The first retained keys and their counts agree in all
456 stages. There are five catalog applications in each profile, with no
additional verified admissions. The expanded profile's 20 enabled IDA
processes have maximum observed elapsed time 35.502865584 s and maximum
observed peak resident memory 234,930,176 bytes. These observations are
process maxima, not population latency or memory bounds.

The complete independent semantic audit classifies the 14,047 events as
13,000 refuted constant/current-operand reductions, 1,042 unsupported cases
and five existing catalog applications. It replays 25,281 SAT witnesses and
1,377 rejected-rule counterexamples; 100 rejected-rule instances remain
unsupported. Unsupported cases comprise 341 nested values or loads, 290
arithmetic children containing explicit reads, 159 nested instruction shapes
outside the bounded contract, 117 reserved or condition microregister cases,
61 unsupported roots, 48 operand effects or storage kinds, and 26 nonzero
root instruction properties. No tested input proves a new value reduction.
These counts describe unconstrained normal-completion snapshots, not all
identities or native reachability.

## Evidence and reproduction

`VMP_MBA_COMPLETE_CAPTURE.tar.gz` (SHA-256
`b261b5054e117f394c20428b47f2f6303132ffc41298b816c6899919c59381e2`)
contains a manifest with SHA-256 for 166 files: both aggregate reports, all
80 IDA probe reports and 80 run manifests, the semantic and paired audits,
and the two original corpus reports. It excludes IDA databases, IDA/plugin
binaries and protected executables. The expanded aggregate report SHA-256 is
`b2a56f35acaf3983203b993fb33a1eab858167163b77d4e3dc94554677412cba`;
the same-version default report is
`6f04127822890f1a88cfc0722062660f24f83df2d11ed40c82351ac4fd517c0d`.
Both aggregate reports pin the exact IDA, plugin, source and per-run artifact
hashes. The archive permits replay of the stored audits from this revision;
recapturing native behavior additionally requires the pinned protected
executables and IDA installation.

```sh
tar -xzf docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz -C .
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --output build/mba-expanded-semantic-audit-replay.json
python3 -B tests/verify_flag_corpus.py \
  --current build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --baseline build/mba-default-matrix-v2/protected_mba_analysis.json \
  --output build/mba-expanded-paired-audit-replay.json
```

The component recorder passes its default and expanded quota tests; CTest
passes 23/23. The capture source, Python replay, formatter checks and archive
manifest are verified at this revision. Fresh audit elapsed-time fields are
run-specific, so compare substantive counts and proofs when replaying.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| C1 | A 1,024-key stage limit covers this fixed corpus; complete-event claims depend on this. | Check every stage's reported limit, zero unrecorded count, complete event accounting and the 40-process manifest. A larger corpus may hit the cap. |
| C2 | Only diagnostic retention differs between the paired runs; unchanged-tree claims depend on this. | Pin identical IDA/plugin/binary hashes; compare native rows, typed trees, matcher outcomes and the first 64 retained keys at each stage. |
| C3 | Typed snapshot witnesses are suitable for ruling out the tested reductions; semantic counts depend on this. | Independently replay every SAT witness with integer arithmetic; reject corrupted witnesses and abstain on effects, unknown state and unsupported shapes. |

| Impact | Remaining opportunity or risk |
|---|---|
| High | The 1,042 unsupported events contain explicit reads, nested shapes and condition state requiring new semantics or alias constraints before identity claims. |
| Medium | The expanded diagnostic profile permits 33,554,432-byte reports and 1,024 retained keys; a larger sample can exceed either bound and must fail with explicit accounting. |
| Low | The default 64-key profile and its existing catalog behavior remain unchanged in the paired run. |

Quality gates: all claims are descriptive; C1–C3 have falsification probes;
event, key and witness totals reconcile; bytes and seconds use explicit units;
unsupported cases remain unsupported; primary IDA/process reports and source
hashes provide provenance; remaining risks are bounded. Full-state
equivalence, arbitrary missing identities and protected recovery remain
unknown.
