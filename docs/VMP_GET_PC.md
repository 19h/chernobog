# Native get-PC implementation checkpoint

This checkpoint implements bounded address materialization and call-context
target facts from review requirement 1c, plus their local register/stack
consumers. The complete review remains **incomplete and active**; see
[VMP_IMPLEMENTATION.md](VMP_IMPLEMENTATION.md). Results below concern the
independent fixtures, not measured recovery of the supplied protected program.

The subsequent [microcode checkpoint](VMP_MICROCODE.md) fixes the legacy RET
lowering issue identified below and verifies effects under explicit region
contracts. The source hashes and native-run results in this earlier checkpoint
remain historical; structural ownership and automatic noreturn freshness are
still incomplete.

The later [ELF32 execution control](VMP_GET_PC32_EXECUTION.md) verifies 32-bit
get-PC and stack behavior under QEMU. It also records a current-plugin
regression in the separate IDA materialization annotation; the 16/16 IDA result
below remains evidence for its original plugin artifact only.

The primary transformation source is `vmp/core/intel.cc:16218–16248`: a near
CALL-next becomes a 32-bit PUSH of its continuation, or a full-width x64
PUSH-register / LEA-address / XCHG-stack sequence. Source, fixture, plugin,
probe, and run hashes are recorded in
[VMP_GET_PC_EVIDENCE.json](VMP_GET_PC_EVIDENCE.json). All paths in this report
and manifest are relative or logical artifact identifiers.

**Implemented behavior**

- The portable classifier describes the 32-bit PUSH-next and x64
  PUSH/LEA/XCHG forms, including width, negative SP delta, saved-register
  restoration, supporting addresses, and ordered modeled stack accesses.
  The XCHG descriptor retains its implicit lock and read-modify-write effect.
- The IDA adapter validates decoded operands, addressing size, function and
  segment ownership, scratch-register identity, and unique interior entry.
  Wrong widths, SP as scratch, nonzero offsets, indexed or segment-overridden
  exchanges, and incomplete sequences are rejected.
- Local replay tracks at most 64 relative stack words. PUSH, POP, full-word
  MOV from the stack top, and XCHG with the stack top can supply exact register
  values to existing stack-transfer and flag consumers. Initial stack memory
  remains unknown. Potentially aliased writes and unsupported SP changes
  invalidate the stack state. Long-mode immediate PUSH values are sign-extended.
- A 32-bit PUSH-next can be marked as a basic-block end by IDA despite having
  only a fallthrough edge. Replay may include that one PUSH as its first
  instruction when its sole code edge is the verified fallthrough; it stops
  at that boundary. This is not a general cross-block replay facility.
- CALL-context summaries retain the pushed return address, modeled reads and
  writes, actual net SP delta, flag-preservation status, and summary boundary.
  CALL-next/POP is admitted. Far transfers, RET adjustment, width mismatches,
  POP into SP, alternate entries, unknown stack aliases, and unsupported effects
  prevent an extended return-target proof. Re-entry into the summarized body is
  rejected because it requires another logical stack/register state.
- Native annotations and exact CALL/RET edges use ownership receipts. Deferred
  return-edge installation rederives the current proof. Unresolved register
  candidates now retain the prefix they inspected, allowing a restored
  definition to requeue its consumer. The CALL stack hint uses the decoded
  summary width rather than the database-wide address size.

These are normal-execution address and stack-effect facts. They retain native
instruction bytes and do not establish exception, concurrent-memory, or
whole-program equivalence. A modeled stack-access list is not a complete trace
of all reads performed by intervening instructions.

**Verification of the final artifact**

| Check | Observed result and scope |
|---|---|
| Portable core suite | Pass; includes 32-bit modular return-address arithmetic, nonzero net stack deltas, multiple pushes, partial/far/adjusted returns, aliasing, and sequence boundaries |
| Executed x64 fixture | Exit 0; checks saved register, materialized address, final SP, six defined arithmetic flags, successful positive transfers, and imm8/imm32 PUSH sign extension |
| Execution environment | arm64 host; x86-64 process translation reported 1. This is translated execution, not an independent physical x86 CPU measurement |
| IDA x64 get-PC probe | 53 assertions pass: recognizers, exact consumers, SETcc values, rejected forms, byte-edit and alternate-entry revocation, and restoration of materialization and CALL/RET facts |
| IDA linked ELF32 probe | 16 assertions pass: PUSH-next, register/immutable-memory transfers, unknown/writable sources, negative transfer controls, CALL-next and call-context return metadata |
| IDA-only ELF32 baseline | 6 assertions pass; four rejected-case edge and comment sets exactly match the enabled run. IDA itself retains some targets that Chernobog declines to summarize |
| Existing flag and stack probes | 33 flag cases and 12 stack-transfer cases pass |
| Existing lifecycle probes | Both flag and stack lifecycle probes pass with the same final plugin artifact |
| CTest | 12/12 pass; reported elapsed time 8.22 s for this run |
| Artifact integrity | All seven IDA runs exit successfully, retain matching artifacts, and have no runner-detected internal-error diagnostic |

The final plugin SHA-256 is
`3d850f341057e622ab2e7117812f0214fe6c8d1759e138de5588f538d4afa322`.
Retained run directories use `build/vmp-get-pc-release-` followed by
`get-pc`, `get-pc32`, `get-pc32-baseline`, `flags`, `stack`,
`flags-lifecycle`, or `stack-lifecycle`. Earlier failed diagnostic runs remain
separate and are not counted as passes. The final CTest log is
`build/get-pc-release-ctest.log`.

**Reproduction**

Configure `CHERNOBOG_IDAT` and `CHERNOBOG_PLUGIN` for the local installation.
Choose unused output directories for the isolated runner.

```sh
cmake --build build --target chernobog chernobog_core_tests -j 4
ctest --test-dir build --output-on-failure
xcrun clang -arch x86_64 -g0 -Wl,-no_pie tests/vmp_native/get_pc.S -o build/vmp-get-pc
build/vmp-get-pc
clang -target i386-unknown-linux-gnu -c tests/vmp_native/get_pc32.S -o build/vmp-get-pc32.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32.o -o build/vmp-get-pc32
python3 tests/run_ida_smoke.py build/vmp-get-pc tests/ida_get_pc_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64
python3 tests/run_ida_smoke.py build/vmp-get-pc32 tests/ida_get_pc32_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --output-dir build/get-pc32-enabled --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64
python3 tests/run_ida_smoke.py build/vmp-get-pc32 tests/ida_get_pc32_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --output-dir build/get-pc32-disabled --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64 --set CHERNOBOG_IDA_ANALYSIS=0 --set CHERNOBOG_GET_PC32_BASELINE=1
python3 tests/verify_get_pc32_baseline.py build/get-pc32-enabled build/get-pc32-disabled
```

The ELF32 fixture was decoded in IDA, not executed. Its entry point is supplied
for a separate compatible execution environment; no native 32-bit execution
result is claimed here. Faulting negative controls in both fixtures are never
called by their executable entry points.

**Assumption register and falsification probes**

| ID | Assumption and dependent result | Stress test / remaining falsification probe |
|---|---|---|
| G1 | The local source remains relevant to the target corpus; this supports recognizer selection only | Source hash and emitter inspection retained. Paired protected fixtures and protection settings are still required for coverage claims |
| G2 | Ordinary 32/64-bit, normal-completion instruction semantics govern each admitted form | Executed x64 effect checks; decoded width/far/alias controls. Native 32-bit execution, fault paths, and concurrency remain unverified |
| G3 | A bounded, contiguous, uniquely entered prefix supplies the consumer state | Alternate-entry tests, SP and alias invalidation, explicit decoder-boundary handling. General joins and loop contexts remain outside replay |
| G4 | Supporting bytes and ownership records remain attributable to this engine | Synchronous edit revocation and restoration tested. New get-PC facts have not received the complete save/reopen/rebase/undo matrix from the earlier ownership checkpoint |
| G5 | Existing IDA metadata is independent of Chernobog's acceptance decision | Matched disabled/enabled ELF32 control runs with identical input, probe, plugin, and IDA hashes |

For D replayed instructions, R = 16 registers, and S ≤ 64 retained stack words,
the conservative time bound is O(D·(R+S)) and working/provenance storage is
O(R+S+D), with D ≤ 64. The linear CALL-context classifier costs O(K) time and
space for K inspected instructions; the adapter admits at most one entry plus
64 following instructions. These bounds exclude IDA scheduling, ownership
invalidation over other records, and decompilation. Large-corpus latency and
peak-memory improvements are **unknown**.

**Bounded findings and remaining requirements**

High impact: unsuccessful value proofs need dependencies too; otherwise later
edits cannot reliably turn an abstention into a recovered fact. The x64
edit/restore probe exposed this and now tests the corrected behavior.

Medium impact: IDA's semantic block markers can differ from architectural
control transfers. The PUSH-next case needs an explicit, narrow admission
rule; removing every block boundary would not satisfy the single-entry contract.

High impact, unresolved: the legacy CALL handler also changes function tails,
gap typing, non-function flags, and user stack hints. Its new receipts own
edges and comments, not full rollback of those older structural mutations.
The legacy Hex-Rays RET-to-JMP filter also needs a separate stack-load/SP-effect
audit before claiming decompiler-level equivalence. Native byte preservation
does not settle either issue. Requirement 1c therefore remains in progress.

Checkpoint quality gates: assumptions and probes are explicit; counts and
integer widths are exact; source and run hashes supply primary provenance;
positive, negative, baseline, and lifecycle controls pass at the stated scope.
The full requirement-coverage gate remains open. This report does not claim
completion of string lifetimes, MBA corpus work, linked visualization, VM
summaries, the paired protected corpus, or the full benchmark matrix.
