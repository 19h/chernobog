# Ownerless saved-flags regression

The saved status-flag transfer in `VMP_SAVED_FLAGS.md` is also consumed by
the explicit-root ownerless native-region inspector. This follow-up removes
IDA function ownership from five exact x86-64/i386 fixture prefixes and
inspects the resulting regions through the read-only API. Each region
converges without truncation; its inspected IDB inventory is unchanged.

| Ownerless prefix | Expected `SETcc` fact | x86-64 | i386 |
|---|---|---|---|
| Saved CF through `PUSHF*`/`POPF*` | `1` | proved | proved |
| Fully defined OF through `PUSHF*`/`POPF*` | `1` | proved | proved |
| Literal flags word through `PUSH`/`POPF*` | `1` | proved | proved |
| Saved word overwritten in memory | unknown | unresolved | unresolved |
| Dynamic pushed flags word | unknown | unresolved | unresolved |

The complete ownerless suite passes 402 IDA assertions per architecture. Its
existing native process oracle passes 4,094 checks per architecture and rejects
the deliberately corrupted expected result; that oracle does not call the
five newly inspected prefixes. Those prefixes have separate executed x86-64
and i386 result controls in `VMP_SAVED_FLAGS.md`. The installed plugin used
here has a later build revision than the prior owned-fixture measurement but
the saved-flags source transfer is unchanged. Exact hashes and reports are in
`VMP_SAVED_FLAGS_OWNERLESS_EVIDENCE.json`.

One concurrent 21-suite CTest attempt failed an existing VM-observation
assertion concerning a malformed guarded witness. The isolated VM-observation
suite and a subsequent complete 21/21 rerun passed. The cause of that
intermittent result is **unknown**; the final passing CTest log is hashed in
the evidence manifest. No saved-flags conclusion uses the VM-observation
assertion as an oracle.

## Assumption register and scope

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| O1 | Removing IDA function ownership leaves the decoded instruction bytes and selected root intact. Ownerless attribution depends on this. | Probe decodes the contiguous prefix through its first RET, checks all admitted nodes have no owner and hashes the whole IDB inventory before and after each inspection. |
| O2 | The ownerless inspector uses the same `State::step` saved-flags transfer as owned analysis. Extending the production result depends on this code path. | Inspect the exact `chernobog_native_region_facts` results on both architectures; require three proofs and two unresolved facts. A divergent future transfer path would require a new control. |
| O3 | The five fixtures represent only local normal-completion status-flag behavior. The result does not establish protected recovery. | Compare executed fixture behavior from `VMP_SAVED_FLAGS.md`; inspect independent protected roots and exceptional modes separately. |
| O4 | The isolated/full CTest passes are representative of the current build. Suite-wide stability depends on this assumption. | Repeat the VM-observation assertion under controlled parallel load and record solver state at a failure. Its observed intermittent cause remains unknown. |

Each extra flag transfer visits six tracked bits in O(1) time and space.
Each added ownerless inspection retains the existing 128-node, 128-round and
256-incoming-reference-per-node caps; five independent calls have at most
five times one call's bounded work. Counts and masks are dimensionless.

- **Medium impact:** the same bounded flag restoration now has direct
  production controls under both ownerless and owned analysis.
- **Medium impact:** the intermittent VM-observation assertion is a test-suite
  reliability issue with unknown cause, separate from these five facts.
- **Low impact:** these synthetic prefixes do not change the supplied VMP
  initializer's three unresolved records.

QG1: no normative premise. QG2: O1–O4 include falsification probes. QG3:
all five ownerless outcomes, both architectures, read-only inventory and
existing native controls are recorded. QG4: bit and graph bounds are explicit.
QG5: unresolved controls and the intermittent unrelated suite failure remain
visible. QG6: hash-matched local source, fixture and IDA reports support the
measured facts. QG7: protected effectiveness and suite-flake cause remain
explicit unknowns.
