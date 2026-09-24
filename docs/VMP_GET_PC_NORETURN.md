# Owned get-PC noreturn correction

IDA 9.4 SP1 inferred `FUNC_NORET` for two returning ELF32 get-PC functions
before their detached gadget tails were admitted. After explicit fixture tail
admission, the existing native get-PC proof recognized both CALL contexts, but
Hex-Rays rendered empty noreturn functions. The prior installed plugin failed
three of six matched assertions: inferred flags remained set, no correction
receipt existed, and neither function showed `return 7;`.

The production native engine now corrects this flag only for a published get-PC
CALL proof at the function entry. It requires the recognized gadget RET inside
that function, no explicit user type or noreturn address attribute, and a
contained, linear continuation ending in a plain RET with zero IDA stack delta.
The continuation admits at most 16 instructions: scalar MOV, NOP, and bounded
SP-based LEA operations before the RET. Each continuation instruction is an
exact-byte proof dependency. The engine writes a version-two ownership receipt
before clearing `FUNC_NORET`; version-one receipts remain valid for other native
proofs. A changed CALL, continuation byte, or tail topology revokes the proof,
restores the prior flag, and removes the receipt. Restoration failure retains
the receipt and disables new proof publication so the lease can be diagnosed.

| Matched IDA 9.4 SP1 control | Result |
|---|---:|
| Prior plugin, same ELF32 input and final probe | 3/6 pass; both pseudocode results empty |
| Corrected plugin, two admitted tails | 6/6 pass; both functions show `return 7;` |
| Saved database, reopened in a separate process | 16/16 pass; both receipts recovered, CALL and continuation mutations revoke, byte restoration republishes, tail removal revokes |
| No contained gadget | 2/2 pass; inferred flags retained |
| Unbalanced continuation stack | 2/2 pass; flag retained |
| Explicit user noreturn type | 3/3 pass; type and flag retained |
| Existing x64 and ELF32 native get-PC suites | 53/53 and 16/16 pass |
| CTest | 21/21 pass |

The fixture is `build/vmp-get-pc-regions32-noret`, linked from
`tests/vmp_native/get_pc32.S` and `tests/vmp_native/get_pc_regions32.S`.
`gp32_backward` and `gp32_nonzero` each have an inferred flag `0x5401`
before admission. The corrected flags are `0x5400`. The latter continuation
restores a 4-byte stack displacement before its outer RET. The probe explicitly
admits the known gadget tails and invokes the public native-analysis IDC entry
after IDA autoanalysis, so callback ordering does not affect the measurement.
It does not demonstrate automatic region admission.

A later checkpoint adds bounded automatic admission of closed, automatic
get-PC gadget functions. Its version-three donor receipt extends the flag
ownership described here; the historical version-two measurements and hashes
above remain revision-specific. See [VMP_GET_PC_REGIONS.md](VMP_GET_PC_REGIONS.md).

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| N1 | With no user type and no noreturn address attribute, the observed flag was inferred by IDA. Attribution of the corrected metadata depends on this. | The probe records both flags before tail admission and checks the two user-contract markers. A manually set bare `FUNC_NORET` with neither marker is indistinguishable and remains an open case. |
| N2 | A contained recognized gadget and zero stack delta at a natural continuation RET establish this bounded returning path. The correction depends on both. | No-tail and unbalanced-stack controls retain `FUNC_NORET`; a backward tail and a nonzero intermediate stack delta pass only after exact tail admission and final balance. Other control-flow shapes abstain. |
| N3 | Exact support bytes and topology remain current while the correction is owned. Receipt validity depends on this. | Patch the CALL and outer RET independently, restore each, remove the backward gadget tail, and reopen the saved database in a separate IDA process. Each transition checks flag and receipt together. |
| N4 | The fixture return value is seven and its intended function boundary includes the gadget. The pseudocode result depends on this fixture contract. | Verify the assembler source and decompile both corrected roots. The prior-plugin same-input run is the negative control. |

The check scans at most 16 continuation instructions and at most 4,096
published native proofs per analysis pass: `O(P × 16)` time for `P` proofs,
`O(16)` transient path space per proof, excluding IDA decoding and persistence.
The receipt bound is 623 bytes: 4-byte header + two 8-byte node IDs + 1-byte
edge count + at most 8 ten-byte edges + 2-byte comment length + at most
512 comment bytes + optional 8-byte noreturn root. The ELF32 stack word is
32 bits = 4 bytes; counts and addresses are dimensionless or byte units.

**High impact:** a proven returning get-PC path now produces returning
pseudocode after region admission. **Medium impact:** exact continuation
dependencies revoke stale corrections on ordinary code patches. **Medium
impact:** automatic gadget ownership, broader structural rollback, and
unmarked manual flag attribution remain outside this result.

QG1: technical scope only. QG2: N1–N4 include falsification probes. QG3:
the stale-flag checkpoint is covered; the complete review remains active.
QG4: 16-instruction, 4,096-proof, 623-byte, and 4-byte bounds are explicit.
QG5: inferred and explicit user contracts, current and prior plugins, and
automatic versus staged region ownership are separated. QG6: source, SDK
contract, fixture, plugins, IDA executable, probe, runner, and raw reports are
hash-linked in [VMP_GET_PC_NORETURN_EVIDENCE.json](VMP_GET_PC_NORETURN_EVIDENCE.json).
QG7: unmarked manual flags and broader region shapes are explicit unknowns.

The primary SDK contracts are `FUNC_NORET`, `set_func_flag`, and function
containment in IDA SDK 9.40 `funcs.hpp`, plus `get_spd` in `frame.hpp`.
Source integration is in
`src/ida_analysis/native_engine.cpp` and the receipt schema is in
`src/ida_analysis/proof_receipt.hpp`.
