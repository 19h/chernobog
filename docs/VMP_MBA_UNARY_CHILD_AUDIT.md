# Bounded child and explicit-read offset coverage in the protected MBA miss audit

This checkpoint extends review row 4a's read-only, typed semantic audit.
One arithmetic child beneath a captured scalar root may now contain a direct
`m_neg`, `m_bnot`, `m_mov`, `m_xdu`, `m_xds`, `m_low` or `m_high` operation. The
child may itself contain one arithmetic child, for a maximum of two checked
children in one chain. Every embedded instruction must match its captured
opcode, operands and result width, with zero instruction and value properties;
unary/conversion instructions also require the captured void right operand
descriptor. The existing evaluator supplies the integer and bitvector
meanings. A third child, unsupported load or malformed descriptor abstains.
Production matching, verification and rewriting are unchanged.

An `m_ldx` value may use a captured 4- or 8-byte `mop_S` stack variable
as its offset operand. Its selector remains a checked 2-byte register or
numeric operand; the stack descriptor must retain a two-integer owner/offset
identity and zero properties. The offset may also be a captured `mop_d`
instruction that computes same-width `m_add` or `m_sub` from an ordinary
register and an in-width numeric operand, with zero instruction/value
properties and an exact result descriptor. The explicit read's result remains
an independent snapshot value. A stack-sourced read that overlaps an ordinary
stack scalar in the same captured expression abstains. This audit does not
solve either offset into a concrete address or infer alias and fault behavior.
The local SDK `hexrays.hpp` identifies `mop_S` as a stack variable and its
reference as an MBA owner plus decompiler stack offset (SHA-256
`7ced9073b5b1fe06357f51e5983e041cae0b6b0f8f69d790f443031ec05022ff`).
The capture serializer records those two fields in
`src/deobf/analysis/match_capture.cpp` (SHA-256
`c97a34330e049cd909fc59f1a82e639cca2515e6fa4c8e1c02203a3fb76af7c6`).

The source-pinned 1,024-key protected matrix has 14,047 events, 9,729 retained
keys and zero unrecorded events. Against the previous shift audit, all 117
weighted events formerly rejected by the child instruction contract change
classification: 93 now have SAT counterexamples to a constant and each
eligible current-operand replacement, 23 reach an unsupported embedded-call
result, and one exceeds the two-child depth budget. A further 231 events
with checked `m_ldx` offsets now have SAT counterexamples: 208 use `mop_S`
(124 XOR roots and 28 each of SETZ, SETP and SETS roots with an XOR child),
while 23 use a checked add/sub register-plus-constant expression.
The totals are **13,717 refuted, 325 unsupported and 5 existing catalog
applications**, with no newly proved reduction. There are 1,229 distinct
proofs, 9,724 candidate findings, 26,598 independently integer-replayed SAT
witnesses and 1,377 rejected-rule counterexamples. The 325 abstentions are
133 unsupported nested values/loads, 117 reserved or condition microregister
cases, 48 operand effects/storage cases, 26 root instruction-property cases
and one depth-budget case.
The delta verifier further classifies their captured descriptors: 133 contain
an embedded `m_call` result; 117 contain a reserved microregister; 48 contain
an address-of operand; 26 are `m_xdu` roots marked `IPROP_COMBINED` (`0x0800`); and one
exceeds the child-depth budget. These are descriptor counts, not claims that
the calls or loads are reachable or that the address expressions are solvable.
An in-memory counterfactual replaces reserved microregister IDs with distinct
unconstrained ordinary register IDs. All 117 such weighted events then have
SAT counterexamples under the byte-snapshot model. Their actual audit status
remains **unsupported**: the renaming does not establish the captured
microregister's possible values or reaching flag definitions on a native path.
The 48 address-of events reference one stack owner/offset descriptor. A second
in-memory counterfactual replaces each captured `mop_a` value with one shared,
unconstrained pointer-sized register. All 48 weighted events then have SAT
counterexamples, while their actual status remains **unsupported**. The SDK
defines `mop_addr_t` with read/write sizes in addition to its referenced
operand; the historical serializer records the operand but omits those sizes.
It also does not establish the stack-frame base or its relation to the other
captured register. The counterfactual cannot establish a native-path fact.

The component suite passes 607 controls, including all seven unary/conversion
child families, shared byte identity across two levels, distinct same-address
read occurrences, altered inner instruction rejection, a third-child bound,
stack-offset read admission, add/sub computed-offset admission, overlap
abstention, malformed-descriptor rejections, solver/integer witness agreement
and prior rejection cases. A wrong source
revision and an invalid capture archive are rejected.
An independent delta verifier aligns every retained finding with the prior
shift audit, checks exact sample identity and weighted event counts, requires
SAT queries for each newly refuted finding, and verifies that the 208
stack-offset and 23 computed-offset events have their respective captured
descriptors. It confirms 324 new refutations, 23 embedded-call abstentions
and one depth-budget abstention; changing one retained event count is rejected.
It also verifies the five unsupported descriptor categories above and checks
the 117-event reserved-register and 48-event address-of counterfactuals.
Its source SHA-256 is
`5d7611833b3d4a844c4b681f13a4ba5a6518344fc3987738bf442cd8d72de8a6`.
The exact original matcher report is retained in
`VMP_MBA_COMPLETE_CAPTURE.tar.gz` (SHA-256
`b261b5054e117f394c20428b47f2f6303132ffc41298b816c6899919c59381e2`);
its extracted report SHA-256 is
`b2a56f35acaf3983203b993fb33a1eab858167163b77d4e3dc94554677412cba`.
All 21 source hashes recorded by that report match Git revision
`5756071e69c4626db2419bc0e45531bf21f5f2a2`. This revision pin keeps the
historical capture verifiable after later changes to `src/plugin/idc_api.cpp`.
The new checker, component controls and audit runner have respective SHA-256
values `24be487bede7c489e80dd1fc615054687cb9f8bbfe23cdc75238a6d882caf0d3`,
`d006f8adf925b4ff9e43eb8ddff728d6f91741e18353dd44d497f8ad5ac7cb2f`
and `a91829d57c17cb560e0deea82b134fcd94b709098d54c3ebd6c13a63bf9a6fba`.

The full audit can be regenerated from the tracked capture:

```sh
tar -xzf docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz \
  build/mba-expanded-matrix-v2/protected_mba_analysis.json
python3 -B tests/mba_semantic_miss_tests.py \
  --fixtures build/flag-component-fixtures.json > build/mba-unary-controls.json
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --capture-tar docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz \
  --source-revision 5756071e69c4626db2419bc0e45531bf21f5f2a2 \
  --output build/mba-unary-audit.json
python3 -B tests/verify_mba_bounded_delta.py \
  --prior docs/VMP_MBA_SHIFT_AUDIT.json.gz \
  --current build/mba-unary-audit.json \
  --controls build/mba-unary-controls.json \
  --capture-tar docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz \
  --output build/mba-bounded-delta.json
```

The fixture JSON is retained in `VMP_INTEGER_FLAGS_CAPTURE.json.gz`. The
accepted audit reports `passed: true`, the counts above and the pinned source
revision. Its elapsed-time field varies between runs. Each candidate contains
at most two root operands and two operands for each of two children, each at
most eight bytes, so `K ≤ 48` captured operand bytes before shared identity.
The fixed-size address descriptors are checked separately. Snapshot
construction is `O(K)` time and space for `K` captured operand bytes; each
SMT query has explicit 250 ms and 100,000 resource-unit limits.
This is a per-candidate bound, not a total solver runtime guarantee.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| U1 | The captured report and its source revision describe the tested protected matcher events. All matrix totals and deltas depend on this identity. | Check the report against the tracked tar member, verify all 21 source hashes at the full Git object ID, align all 9,724 findings with the prior audit, and reject a wrong revision or altered event count. |
| U2 | The admitted unary/conversion and two-level arithmetic operators have the typed normal-completion meanings encoded by the integer and Z3 evaluators. The 93 refutations depend on this model. | Compare boundary-width SDK operator executions with both evaluators; reject nonvoid right operands, altered inner instructions, width mismatches and unsupported properties. |
| U3 | The 208 stack-offset and 23 computed-offset loads have valid captured descriptors. Their classifications depend on treating the loaded result as an independent snapshot value, without solving its address. | Reject changed selector, stack width, properties, owner/offset identity, overlapping stack scalar, computed operation, width, register and constant; execute SDK load fixtures and constrain actual addresses before any native-path claim. |
| U4 | Snapshot bytes are unconstrained, while ordinary same-identity bytes share values and distinct explicit reads do not. SAT counterexamples depend on this state model. | Replay each witness with integer arithmetic; add native reaching-definition, alias and fault constraints before claiming path-specific reductions. |
| U5 | The captured opcode and operand tags follow the pinned SDK definitions. The five unsupported descriptor categories depend on this decoding. | Recheck `m_call = 0x38`, `IPROP_COMBINED = 0x0800` and `mop_a`/`mop_S`/`mop_d` tags against the hashed SDK header; reject an altered capture tag or category total. |
| U6 | Counterfactual ordinary-register renaming preserves only the scalar expression shape, not the original reserved microregister's reachable state. The 117 SAT results depend on the counterfactual model alone. | Require all original findings to remain unsupported; derive each microregister's native reaching definition and value domain before using a result as path-specific evidence. |
| U7 | Counterfactual address-of renaming preserves shared pointer identity in one expression but omits frame-base relations and `mop_addr_t` access sizes. The 48 SAT results depend only on the unconstrained pointer model. | Require all originals to remain unsupported, check the exact stack descriptor, capture address metadata and verify a concrete frame-base/reaching-state relation before any native-path claim. |

| Impact | Remaining opportunity or risk |
|---|---|
| Medium | Three hundred twenty-four formerly unsupported captured events have concrete counterexamples under the declared state model. |
| High | The 325 remaining abstentions include embedded calls and condition-state contracts; they require separate semantics. |
| High | Treating the 117 counterfactual register renamings as native-path facts would omit the missing flag-state contract. |
| High | Treating the 48 address-of counterfactuals as native-path facts would omit the frame-base and complete address descriptor. |
| Low | This audit changes no production rewrite or protected execution behavior. |

QG1: descriptive technical claims. QG2: U1–U7 carry falsification probes.
QG3: all 14,047 events reconcile; 324 delta refutations, 325 abstention
descriptors and both counterfactual inventories have explicit checks. QG4:
widths, counts, resource limits and complexity are explicit.
QG5: deeper expressions and native reachability remain separate. QG6: the
original capture, historical source revision, checker hashes and integer
witness replay provide provenance. QG7: unsupported forms and production
recovery remain bounded unknowns. The full review remains in progress.
