# Bounded nested MBA miss classification

This checkpoint extends the independent semantic miss audit to one pure
arithmetic child beneath a scalar root. It advances review row 4a; the full
review remains in progress. The complete 21,169,863-byte audit is retained in
`VMP_NESTED_MBA_AUDIT.json.gz` (SHA-256
`83b5be257ee481197edbead03db6d89a26aa860e088b716c1a489c93fa9749d8`).
The historical `VMP_INTEGER_FLAGS_CAPTURE.json.gz` is unchanged.

## Contract and result

The child must have a width of 1, 2, 4 or 8 bytes, zero operand properties,
zero instruction properties, an ADD/SUB/MUL/AND/OR/XOR opcode, two primitive
operands and an embedded instruction whose opcode, operands and destination
match the captured node. Its 16-bit value number may be nonzero. Nested
effects, deeper trees and absent original predicate metadata abstain. Root and
child share exact snapshot-byte identities; witnesses are replayed through
separate integer arithmetic. This tests a constant or current-operand
reduction, not arbitrary algebraic identities.

The source-pinned protected matrix contains 14,047 matcher events: 5,261
retained and 8,786 unrecorded under capture quotas. The former 627
`nonprimitive arithmetic subtree` events now split into 624 refuted
reductions and three reserved-microregister abstentions. Across all retained
events, 5,219 refute these reductions and 42 abstain: six unsupported
nested values/loads, 33 reserved or condition microregister cases, and three
unsupported roots. No retained nested event proves a new value reduction.
There are 9,262 SAT witness replays and 521 independently replayed rejected
rule-instance witnesses. The 325 unique proofs correspond to 3,945 retained
keys; weighting by sample count gives the event totals.

## Source provenance and reproduction

The old capture's source hashes differ from three present production files.
`--archive` checks the report's exact bytes and every recorded source hash
against the historical source archive, rather than the current working tree.
The current audit checker, replay helpers, report and archive are also hashed
before and after execution. The captured matcher report SHA-256 is
`3652101f0c11758b821c48219846a79422e5703750b0cf7079ae0956a00cc4dc`;
the source archive SHA-256 is
`65355f4838956515681c9750bb4dc6bee2458968fd6ccb41e7eecc61f72b34a3`.
The complete audit records all checker hashes, Z3 4.16.0 package/library
hashes, inputs, solver states and witnesses.

```sh
python3 -B tests/mba_semantic_miss_tests.py --fixtures build/flag-component-fixtures.json
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/flag-matrix-candidate-v1/protected_mba_analysis.json \
  --archive docs/VMP_INTEGER_FLAGS_CAPTURE.json.gz \
  --output build/flag-matrix-semantic-audit-nested.json
```

The inputs can be restored from the named entries in the historical archive.
The component suite passes 527 controls, including child metadata rejection,
value-number, depth and overlapping-byte cases. No refuted retained case has
the same nonzero value number assigned to different captured operand storage
identities. The [Hex-Rays SDK `mop_t` declaration](https://cpp.docs.hex-rays.com/hexrays_8hpp_source.html)
specifies the value-number equality contract.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| N1 | A zero-effect embedded arithmetic instruction denotes its captured scalar operation; all 624 newly classified refutations depend on this. | Check opcode, input descriptors, destination, width and properties against the node; reject altered metadata; compare concrete SDK evaluation where available. |
| N2 | Stable snapshot bytes represent each ordinary register/stack/global/local operand; witness replay depends on this. | Shared-byte overlap and distinct version controls; enumerate nonzero value-number collisions; reject reserved registers, explicit reads and effects without a contract. |
| N3 | Captured source and report are the historical matrix inputs; event totals depend on this. | Rehash every archived source and exact report against recorded hashes; repeat with the archive path and compare event accounting. |

| Impact | Remaining opportunity or risk |
|---|---|
| High | The 8,786 unrecorded events and native reachability can alter the population of actual protected simplification opportunities. Expand capture quotas and acquire execution/definition constraints. |
| Medium | Reserved condition microregisters and explicit reads need a state and alias contract before classification. |
| Low | The 624 newly refuted shallow cases do not justify adding a current-operand or constant rule under this unconstrained snapshot model. |

Quality gates: the audit is descriptive; the assumptions have rejection probes;
the 627 nested cases and event accounting reconcile; widths and byte counts
are exact; no unsupported case is presented as proved; primary SDK metadata
and pinned source hashes provide provenance; the remaining opportunity/risk
set is bounded. Native path equivalence, faults, missing identities, full
state and protected recovery remain unknown.
