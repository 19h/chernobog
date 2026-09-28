# Nested explicit-read MBA miss audit

This checkpoint extends the independent, read-only semantic miss audit for
review row 4a. One arithmetic child may contain a typed explicit load.
The matcher, production verifier, rule registry and protected capture are
unchanged. The complete audit is `VMP_MBA_NESTED_READ_AUDIT.json.gz` (SHA-256
`c9894684df4dd09b48776e551311e556d91ec7ed4daca35561ae6c6f9b01271d`).

## Read-occurrence contract

The existing primitive decoder accepts `m_ldx` only with zero instruction and
operand properties, an anonymous destination of 1, 2, 4 or 8 bytes, a 2-byte
selector and a 4- or 8-byte offset. Both address operands must be numeric or
ordinary nonreserved microregisters. The nested child must still have matching
embedded opcode, operands, result width and destination, and the root must
meet its original typed and predicate-property checks.

Each load occurrence receives separate snapshot bytes. A root load and a child
load remain distinct even when their path labels, source EA and address
descriptors are identical. The checker shares ordinary register, stack, local
and global bytes according to their existing captured identities; it does not
infer equality between two explicit reads. Reported read paths include
`root/` or `child/` so their effect occurrences remain inspectable. The
symbolic solver and separate integer replay both use these identities.

This is an unconstrained normal-completion snapshot model. It does not prove
whether two native reads alias, are stable across time, fault, or occur on a
reachable native path. A SAT witness only refutes a constant/current-operand
reduction under that declared model. It does not authorize a production rewrite.

## Complete-matrix result

The source-pinned expanded matrix still contains 14,047 events, 9,729 retained
keys, zero omissions and five existing catalog applications. The prior audit
left 290 shallow nested-load events unsupported. All 290 now refute the tested
reductions; none proves a value reduction. Totals become 13,290 refuted,
752 unsupported and five existing terminal outcomes. There are 25,575
independently replayed SAT witnesses and 1,377 rejected-rule counterexamples.
The 752 abstentions are 341 unsupported nested values/loads, 159 nested
instruction shapes, 117 reserved or condition microregister cases, 61
unsupported roots, 48 operand effects/storage kinds and 26 nonzero root
instruction-property cases. These categories are weighted event counts.

The 529 component controls include matching and altered load metadata,
independent equal-address root/child reads, shared ordinary byte cells,
widths, value numbers, deeper-tree abstention, and integer witness replay.
The complete audit checks 1,229 unique proofs over 9,724 candidate findings;
five catalog applications are terminal without candidate queries.

## Provenance and reproduction

The original expanded matrix report SHA-256 is
`b2a56f35acaf3983203b993fb33a1eab858167163b77d4e3dc94554677412cba`.
The exact protected capture and paired 64/1,024-key controls are retained in
`VMP_MBA_COMPLETE_CAPTURE.tar.gz` (SHA-256
`b261b5054e117f394c20428b47f2f6303132ffc41298b816c6899919c59381e2`).
The new audit records checker and Z3 source/library hashes, each captured
input, solver state and replayed witness. Its uncompressed size is 77,226,789
bytes; the compressed evidence is 1,525,343 bytes.

```sh
tar -xzf docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz -C .
python3 -B tests/mba_semantic_miss_tests.py --fixtures build/flag-component-fixtures.json
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --output build/mba-complete-read-audit-replay.json
```

The fixture JSON can be restored from `VMP_INTEGER_FLAGS_CAPTURE.json.gz`.
Elapsed-time fields are process observations and can differ on replay; compare
counts, proof states, captured inputs and witnesses. No new IDA run or native
behavioral claim is made by this semantic-only audit.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| R1 | Distinct explicit-load occurrences have independent snapshot values in this model; the 290 refutations depend on it. | Give equal-address root and child loads separate bytes; verify solver witnesses with integer replay; introduce an explicit stability/alias contract before native-path claims. |
| R2 | Captured `m_ldx` metadata identifies a supported read occurrence; admission depends on it. | Mutate opcode, properties, widths, address operands or destination; require abstention. |
| R3 | The 1,024-key matrix contains every observed event in this fixed corpus; totals depend on it. | Recheck source/report hashes, 456 stage limits, exact event accounting and zero unrecorded counts. |

| Impact | Remaining opportunity or risk |
|---|---|
| High | Native memory identity and intervening writes could constrain the two read values; execution-path proof is needed before applying a simplification. |
| Medium | The 752 unsupported events contain deeper instructions and condition state beyond this scalar checker. |
| Low | Production matching and mutation remain unchanged by this audit-only extension. |

Quality gates: the analysis is descriptive; R1–R3 have rejection probes; all
14,047 events reconcile; widths and byte counts are exact; unsupported cases
remain unsupported; source-pinned captures, integer witnesses and the SDK load
contract provide provenance; additional risks are bounded. Native alias
relations, arbitrary missing identities and protected recovery remain unknown.
