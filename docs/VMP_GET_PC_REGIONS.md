# Automatic ownership of closed get-PC gadgets

IDA 9.4 SP1 forms separate functions at two get-PC gadget targets in each
reviewed fixture. The existing CALL proof can identify the gadget, but a
separate function prevents the caller from owning its control-flow and stack
effects. The previous-plugin ELF32 control retains separate donors at both
targets. This checkpoint transfers only a closed, automatic donor whose exact
RET ends the recognized gadget. It records the donor's original function
boundary, flags, stack offsets, and stack word width before changing IDA's
function topology.

The transfer requires a current published CALL proof, a single-chunk donor
starting at the gadget entry, no user name or type, no function comment or
data reference at the entry, permitted automatic flags, and a RET exactly at
the donor end. A backward gadget becomes one caller tail; a forward gadget
adjacent to the caller becomes part of the caller entry range. The support
instructions must have bounded IDA stack offsets. On the completed analysis
pass, the engine assigns the caller's incoming CALL stack displacement to the
gadget entry and projects the remaining exact offsets. It retains the
previously proven continuation dependencies and clears an inferred
`FUNC_NORET` only under the existing bounded return-path proof.

Version-three ownership receipts include up to 32 ordered donor stack points
and a 4- or 8-byte stack word. Version-one and version-two receipts retain
their existing decoding. On reopen, ownership is restored from the receipt
before current proofs are recomputed; donor stack offsets are reconstructed
from the receipt rather than from the previously shifted IDB values. CALL
patches and user renaming revoke the lease and restore the separate donor.
For explicit tail removal, the deletion callback first protects the lease
against IDA's intermediate topology events. A successful deletion persists
an exact source/target exclusion, and the completed analysis pass restores
the donor. The exclusion survives a second process reopen and is removed by
a source-byte patch. A failed tail deletion has no completed-event exclusion.

A later lifecycle checkpoint re-clears a re-inferred `FUNC_NORET` under an
unchanged owned proof and revokes donor ownership when an explicit caller
noreturn type appears. See [VMP_GET_PC_LEASES.md](VMP_GET_PC_LEASES.md).

| Production IDA 9.4 SP1 control | ELF32 | x86-64 Mach-O |
|---|---:|---:|
| Initial transfer, exact joined offsets, returning pseudocode, saved IDB | 11/11 | 11/11 |
| Reopen, exact joined/original offsets, CALL patch/rejoin, tail removal | 22/22 | 22/22 |
| Reopen after explicit tail exclusion; source patch clears exclusion | 7/7 | 7/7 |
| User rename of an already owned gadget | 4/4 | 4/4 |
| Stage user name and alternate entry with analysis disabled | 3/3 | 3/3 |
| Reopen with analysis enabled; neither donor merged | 6/6 | 6/6 |
| Existing native get-PC regression | 16/16 | 53/53 |

Both admitted callers decompile with `return 7;`. For the backward gadget,
the donor offsets before its three support instructions are 0, +4, 0 bytes
in ELF32 and 0, +8, 0 bytes in x86-64. The joined offsets are −4, 0, −4
bytes and −8, 0, −8 bytes, respectively. For the forward nonzero gadget,
the donor offsets are 0, 0, −4 bytes and 0, 0, −8 bytes; the joined offsets
are −4, −4, −8 bytes and −8, −8, −16 bytes. The mutation controls restore
the original donor offsets exactly. All 21 CTest suites pass. The built
plugin, fixtures, source, test script, IDA executable, and individual run
reports are hash-linked in
[VMP_GET_PC_REGIONS_EVIDENCE.json](VMP_GET_PC_REGIONS_EVIDENCE.json).

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | An unnamed, untyped single-chunk function with the permitted automatic flags and no function comment or entry data reference is an automatic donor. Safe transfer depends on this attribution. | Stage a user name before analysis and rename a joined target afterward; both remain separate or are restored. A bare manually modified flag with none of these markers is indistinguishable and remains unknown. |
| R2 | The exact CALL recognizer and all gadget support instructions describe one returning path without an alternate entry. The recovered owner and pseudocode depend on this. | Add a user code reference into the forward gadget before plugin analysis; no transfer occurs. Different or non-RET endings and extra tails fail the admission predicate. |
| R3 | The saved donor stack offsets are the original IDA offsets, and a 32- or 64-bit near CALL pushes one stack word. Stack projection and rollback depend on both. | Assert every support-head offset after initial admission, after a separate-process reopen, and after CALL patch or tail removal. The two architectures exercise 4- and 8-byte words and nonzero intermediate offsets. |
| R4 | IDA reports a completed tail deletion after its pre-deletion event and permits `add_func` on a later analysis pass. Explicit user exclusion depends on that sequence. | Remove a tail, check the persisted exclusion and restored donor, save, then reopen in another process. The implementation delays restoration until completed analysis and records exclusion only after the completed deletion event. |
| R5 | The assembler fixture's intended function returns seven and admits the exact gadget bytes. The pseudocode assertion depends on this fixture contract. | Inspect `tests/vmp_native/get_pc_regions32.S` and `tests/vmp_native/get_pc_regions.S`; compare both production decompilations to `return 7;`. The previous-plugin ELF32 run retains separate donors. |

The receipt bound is 786 bytes: 4-byte header + two 8-byte node IDs +
1-byte edge count + at most eight 10-byte edges + 2-byte comment length +
at most 512 comment bytes + a 43-byte donor header + at most 32 four-byte
stack records. `786 < MAXSPECSIZE = 1024` bytes in IDA SDK 9.40. The donor
range is at most 4,096 bytes and each recorded stack displacement is within
−4,096 to +4,096 bytes. The configured gadget scan depth is at most 64
instructions, but this transfer abstains above 32 support points. At most
4,096 native proofs are retained. For `P` proofs and `S ≤ 32` stack points
per donor, completed-pass stack projection takes `O(P × S)` time and `O(P)`
failure-list space, excluding IDA API costs. Receipt serialization takes
`O(E + C + S)` time and space for `E ≤ 8` edges and `C ≤ 512` comment bytes.
The region traversal remains subject to the existing configured post-scan
head bound.

**High impact:** automatic bounded ownership exposes a returning get-PC
function to Hex-Rays in both architectures. **Medium impact:** persisted
donor and exclusion metadata make rollback and user tail removal stable across
processes. **Low impact:** manually changed bare function flags without a
user marker cannot be distinguished from automatic flags; this case remains
unattributed. General detached regions, multi-tail donors, exceptional paths,
and protected-corpus effectiveness remain outside this result.

QG1: technical scope only. QG2: R1–R5 state dependencies and falsification
probes. QG3: automatic closed-donor transfer, exact stack projection, and
mutation/reopen controls are covered; the broader review remains active.
QG4: widths, offsets, receipt size, and computational bounds are explicit.
QG5: adjacent entry growth, backward tails, user names, alternate entries,
source patches, and completed versus attempted deletion have distinct
outcomes. QG6: the evidence file records exact fixture, source, SDK-version,
plugin, executable, and report provenance. QG7: the additional attribution
limit and more general region forms are bounded above.

Primary contracts: IDA SDK 9.40 `funcs.hpp` (`append_func_tail_ea`,
`remove_func_tail_ea`, `set_func_end`, `add_func`), `frame.hpp` (`get_spd`,
`add_user_stkpnt`, `set_func_auto_spd`, `del_func_stkpnt`), `idp.hpp`
(function-tail event ordering), and `netnode.hpp` (`MAXSPECSIZE`). Production
integration is in `src/ida_analysis/native_engine.cpp`; receipt validation
is in `src/ida_analysis/proof_receipt.hpp`.
