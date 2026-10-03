# REX-encoded 16-bit BSWAP in bounded native replay

## Transfer and scope

A protected x86-64 sample contains `66 41 0F C9` at `0x10007012e`.
The prior bounded region transfer rejected this instruction as
`unsupported_bswap_width`. The exact instruction is a 16-bit BSWAP of `r9w`:
operand-size prefix `66` selects the undefined 16-bit result and `REX.B`
extends the opcode register field. Intel specifies that BSWAP does not change
flags and that its 16-bit result is undefined. The transfer now accepts the
exact three-byte `66 0F C8..CF` form or four-byte `66 40/41 0F C8..CF` form
when the decoded destination matches the opcode register. The four-byte form
requires 64-bit mode and a cleared `REX.W` bit. It clears the complete
destination register's known bits, preserves flag facts and adds a normal
fallthrough edge. Other prefixes and mismatched decoded registers abstain.

Primary sources: Intel [BSWAP instruction definition](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)
and [instruction documentation corrections](https://cdrdv2-public.intel.com/819710/252046-sdm-change-document.pdf)
for the `REX.B` opcode extension.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
| --- | --- | --- |
| BR1 | The decoded four-byte instruction has the same prefix and destination as its byte encoding. The new transfer depends on that agreement. | The production gate checks exact bytes, 64-bit mode, operand width and opcode-to-register identity. The paired protected and fixture IDA reports pin `66410fc9`. A mismatch rejects normal transfer. |
| BR2 | A normally completed 16-bit BSWAP leaves flags unchanged and gives no defined register bits. Both fixture condition proofs and the unknown-result control depend on this rule. | An x86-64 fixture executes carry and zero flag paths, both returning one. IDA proves their two SETcc values after the change. A `TEST r9w,r9w` path after BSWAP remains unresolved; its undefined-result path is not executed as an oracle. |
| BR3 | A root-scoped ownerless static region is an appropriate bounded view of the protected bytes. The protected topology count depends on this scope. | The probe removes the original function owner in a disposable IDB, retains the exact code head, queries `chernobog_native_region_facts`, and checks read-only inventory. The paired run manifests pin identical input, IDA, probe and environment hashes. |
| BR4 | The prior/current plugins differ at the new BSWAP16 gate for these observations. The measured delta depends on plugin provenance. | The certificate pins both plugin SHA-256 values, all four raw reports and run manifests, the source and fixture hashes. Its verifier checks matched inputs and graph invariants. |

## Evidence and bounds

The source-pinned `VMP_BSWAP16_REX_EVIDENCE.json` identifies the two paired
IDA experiments at their recorded source revision. The later
`VMP_INDIRECT_JUMP_MEMORY_EVIDENCE.json` pins the current combined source;
its handoff checks repeat the BSWAP protected region under that build. In the
three-case fixture, the prior plugin stops at BSWAP
in each case. The current plugin traverses six nodes per case, proves two
one-valued SETcc conditions based on preexisting flags, and leaves the
condition based on the undefined register result unresolved. The native
x86-64 executable exits with status zero for the two defined-flag paths.

The protected sample's ownerless region grows from one node and one
unsupported-width frontier to 104 nodes and 104 edges with five records.
The root BSWAP has a fallthrough to `0x100070132` and an
`undefined-register-result` effect. Every protected record remains unresolved.
The current plugin's ordinary owned-function diagnostic examines 105 heads
across the bounded replay from an unchanged 25-head IDA owner; its four
condition sites are all unresolved. The final changeset script repeats the
fixture, ownerless region and owned diagnostic checks with both the freshly
built and installed plugins. These observations do not establish
a recovered protected function, concrete post-BSWAP execution, VM identity or
an indirect-target proof. The separate BSWAP certificate in
`VMP_PARTIAL_BSWAP_EVIDENCE.json` retains its historical source hashes; it
describes an earlier revision.

The prefix gate and state update inspect at most four instruction bytes and a
constant number of register fields, so time and auxiliary space are `O(1)`
for the architectural width limit. High-impact opportunity: the additional
protected topology can expose later bounded facts when incoming state or
indirect-target evidence becomes available. Medium-impact measured gain:
two local fixture condition proofs. High-impact risk: treating the undefined
`r9w` result as a known value would create false predicates; the unknown
control and protected unresolved records check that this does not occur.

Quality gates: QG1 technical claims only; QG2 BR1–BR4 with falsification
probes; QG3 exact encoding, flags, undefined result, fixture and protected
paths; QG4 binary widths, node counts and complexity checked; QG5 ownerless
scope and unresolved facts explicit; QG6 Intel primary sources and source-
pinned paired IDA evidence; QG7 bounded opportunity and risk stated above.
