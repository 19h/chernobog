# Re-inferred get-PC flags and explicit caller contracts

An owned get-PC CALL proof may outlive an IDA function-flag update. In the
ELF32 fixture, setting bare `FUNC_NORET` again after automatic gadget
admission left the previous plugin's version-three donor receipt present,
but both returning decompilations failed. The prior plugin passed 7/11
assertions: both re-cleared-flag checks and both returning-pseudocode checks
failed. The staged flag was visibly set at both entries. A second control
applied an explicit user noreturn type to an already joined x86-64 caller.
The previous plugin retained the donor lease and merged function (4/6
assertions passed), despite the user contract.

The engine now distinguishes these transitions. When a proof already owns
the inferred flag, its current bytes, gadget structure, continuation path,
function ownership, and absence of explicit user type or noreturn address
attribute are rechecked. If IDA sets `FUNC_NORET` again while those premises
remain true, the existing lease clears it; no new ownership receipt is
issued. An explicit caller user type or noreturn address attribute instead
invalidates a donor-ownership conclusion. Revocation restores the separate
donor and removes its receipt. New automatic donor transfers also reject
callers with either explicit contract marker.

| IDA 9.4 SP1 control | Previous installed plugin | Corrected plugin |
|---|---:|---:|
| ELF32 bare flag reassertion, two callers | 7/11 | 11/11 |
| ELF32 saved-IDB reopen after correction | — | 8/8 |
| x86-64 bare flag update request, two callers | 11/11 | 11/11 |
| x86-64 saved-IDB reopen after correction | — | 8/8 |
| ELF32 explicit caller noreturn type | 6/6 | 6/6 |
| ELF32 saved-IDB reopen with user contract | — | 4/4 |
| x86-64 explicit caller noreturn type | 4/6 | 6/6 |
| x86-64 saved-IDB reopen with user contract | — | 4/4 |

The x86-64 bare flag is already clear immediately after the update request
under both plugins. That control establishes a stable returning result, but
does not isolate the new re-clear branch. The ELF32 prior/fixed comparison
does: both prior staged flags remain set, while the corrected engine clears
them during the update callback. The explicit-type control isolates the
x86-64 donor-lease revocation. The corrected plugin also passes the original
automatic-region matrix (53/53 assertions for each architecture), the
existing native get-PC suites (16/16 ELF32 and 53/53 x64), and 21/21 CTest
suites. Exact input, code, plugin, runner, executable, and report hashes are
recorded in
[VMP_GET_PC_LEASES_EVIDENCE.json](VMP_GET_PC_LEASES_EVIDENCE.json).

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| L1 | A bare `FUNC_NORET` reassertion with no user type or noreturn address attribute is inferred metadata under the existing owned lease. The re-clear depends on this attribution. | Record the two user-contract markers and the staged function flags. The previous ELF32 plugin retains both flags and loses returning pseudocode; the corrected plugin re-clears them. An unmarked manual flag is indistinguishable and remains unknown. |
| L2 | The original owned proof still establishes the same returning path. Re-clearing depends on its exact bytes, current donor ownership, and bounded continuation. | Recheck `proof_is_fresh` and `current_proof_conclusion` before clearing; CALL, continuation, tail, and stack mutation controls in `VMP_GET_PC_REGIONS.md` exercise revocation rather than a stale correction. |
| L3 | A user type or noreturn address attribute supersedes an automatic donor lease. Restoration depends on a current explicit marker. | Apply a user noreturn type after admission in each architecture; assert the retained type and flag, separate donor, missing donor receipt, and the same state after process reopen. |
| L4 | The fixture's normal return is seven. The pseudocode result depends on that source contract. | Inspect both assembler fixtures and assert `return 7;` for both corrected ELF32 callers; use the previous installed plugin on the same saved IDB as the negative control. |

The re-clear branch visits at most 4,096 retained proofs per completed
analysis pass. For a qualifying owned CALL, the continuation recognizer
examines at most 16 instructions; `proof_is_fresh` and
`current_proof_conclusion` also inspect the proof's bounded exact-byte
dependencies. Thus the added scan is `O(P × (D + 16))` time for `P ≤ 4,096`
proofs and `D` stored dependency bytes, with `O(16)` transient continuation
space, excluding IDA API costs. No receipt-format or stack-width change is
made here; near-CALL stack words remain 4 bytes on x86 and 8 bytes on x64.

**High impact:** a valid returning ELF32 function remains decompilable after
IDA reasserts inferred noreturn metadata. **Medium impact:** an explicit
caller contract now releases a previously automatic x86-64 donor lease.
**Low impact:** unmarked manual flag provenance remains unknown. General
detached regions and protected-corpus behavior remain outside this result.

QG1: technical scope only. QG2: L1–L4 state assumptions and falsification
probes. QG3: reasserted inferred flags, explicit later contracts, reopen,
and same-input previous-plugin controls are covered. QG4: byte widths,
continuation depth, proof cap, and complexity are explicit. QG5: the ELF32
re-clear contrast and x64 explicit-type contrast are separated from the
non-causal x64 bare-flag observation. QG6: raw report and code provenance
is hash-linked. QG7: unmarked manual flags and broader region/corpus behavior
are bounded unknowns.

Primary local contracts are IDA SDK 9.40 `funcs.hpp` (`FUNC_NORET` and
function flags), `nalt.hpp` (`is_userti`, `is_noret`), and the callback
sequence in `idp.hpp`. The implementation is in
`src/ida_analysis/native_engine.cpp`; the exact controls are in
`tests/ida_get_pc_region_probe.py`.
