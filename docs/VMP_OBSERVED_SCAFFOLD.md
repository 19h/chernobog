# Read-only VM scaffold observation in ownerless protected code

Baseline: `b9bc479c282fb061e2e9f743a0d615e99428d5f0`. The fixture is the
generated x86-64 `virtualization-0` protected strings binary, SHA-256
`f94eddb8f3430fe9e286630b47ff2c8922e7044beaa410fe4a4b65ba8b155f57`.
The exact input, IDA executable, plugin, sources, captured row, and independent
instruction decoding are recorded in
[`VMP_OBSERVED_SCAFFOLD_EVIDENCE.json`](VMP_OBSERVED_SCAFFOLD_EVIDENCE.json).

IDA identifies the five probed scaffold instructions as loaded bytes in an
executable 64-bit segment, but gives none a code head or owning function. The
existing `chernobog_vm_regions` function-root query therefore cannot inspect
them. The explicit temporal native trace already enters their exact bytes. A
read-only projection now re-decodes the bounded plan, checks every entered
instruction's span and order against it, and scans the captured path for local
read/decode/dispatch candidates. It neither creates IDA instructions nor assigns
a function or logical VM identity. The five-site IDB inventory is equal before
and after the query.

The target candidate has a backward 4-byte VIP advance at `0x1000d64db`, a
bytecode read at `0x1000d64ea`, key register R8, and a relative dispatch via
R10 ending at `0x10008ef17`. An exact captured jump edge reaches
`0x100007031`. The candidate includes `RCL AX,0xB9`, `SETB AH`, `LAHF`, and
`XCHG R8B,R8B`. The first three write the value register before `MOV EAX,[R11]`
fully replaces it; the fourth is an exact byte-register self-exchange. They
remain in the full support path. The 28 recorded instruction spans pass
independent Capstone 5.0.7 decoding, and all five directly probed IDB byte
strings match the capture. A separate matrix capture enters the same 28 spans
in order with the same exact head bytes and independently records the jump
edge to the same target. Four local candidates appear in this 2,876-entry
fixed-seed trace; this document specifies one of them. The run has a complete
event prefix and an incomplete temporal execution result.

The full 10-binary, four-seed temporal matrix passes its existing checks. Its
16 original/native-mutation runs report zero candidates and complete execution.
The 12 virtualized and 12 combined runs report 31 and 48 local candidate
occurrences respectively; all 24 retain incomplete execution. One virtualized
seed variant reaches no such scaffold in its 40-instruction prefix. Counts are
observations of reached local paths, not rates of VM recovery or proof that the
candidate sites are distinct VM handlers.

The symbolic instruction model follows the Intel instruction reference:
`RCL` rotates through CF with the architectural count mask and leaves OF
undefined for an effective count greater than one; `SETB` writes byte 0 or 1
according to CF; `LAHF` writes `SF:ZF:0:AF:0:PF:1:CF` into AH. Consuming an
undefined required flag rejects a summary. `LAHF` in long mode is conditioned
on the `LAHF_LM` CPU feature. The IDA decoder admits only checked scalar legacy
encodings and exact register operands for these additions. See the primary
[Intel Software Developer's Manual](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
[Volume 2 instruction reference](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf).
The captured protected candidate has **no claimed semantic transition proof**:
its output says `semantic_validation: not performed`. Portable 32/64-bit
summary tests check that these pre-read writes and the exact no-op preserve the
complete modeled final effect when the value is overwritten.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | The fixed-seed protected strings file and pinned IDA run identify the intended generated fixture. The four-candidate count depends on these exact bytes and input. | Rehash the binary and runner inputs; the verifier requires their recorded hashes. Re-run with another seed and compare candidates separately. |
| A2 | A captured entered native instruction and its checked plan bytes represent the run's local normal-completion path. Candidate spans and observed dispatch depend on this. | Change a planned instruction byte or entered size; `decode_native_semantic_heads` or the span check must abstain. The independent verifier decodes all 28 bytes and checks the target edge. |
| A3 | Intel x86-64 scalar semantics, flat successful memory access, and `LAHF_LM` apply to a local symbolic summary. Modeled effects depend on this. | Reject unsupported encodings and undefined flag consumers; portable count 0, 1, and `0xB9` controls check the admitted cases. A CPU without `LAHF_LM` falsifies the normal-completion premise. |
| A4 | One observed entry path is a local candidate only. All recognition claims depend on the exact entered sequence; other entries, VM identity, complete memory state, and cross-input equivalence are unknown. | Inspect incoming entries and independent executions. A foreign entry, altered key/memory, or differing target prevents promotion to a complete handler summary. |

## Bounded scope and checks

The projection accepts at most 4,096 planned heads, 65,536 entered instructions,
4,096 candidate starts, 32,768 path steps, 256 instructions per path, and 64
retained rows. It reports limits and omissions explicitly. At fixed architecture
width, checked decoding costs O(H) plus its byte reads; execution validation
costs O(N); candidate scanning costs O(P), where H is planned heads, N entered
instructions, and P is capped path steps. The retained map and rows cost
O(H + min(P,64·256)) memory. The edge witness search costs at most O(64·E),
where E is the captured edge count.

| Impact | Remaining risk or opportunity | Boundary |
|---|---|---|
| High | Other entry points can reach the same bytes with different register or memory state. | The record says `other_entries: unknown`; no VM identity, target uniqueness, function publication, or summary reuse is inferred. |
| Medium | Native runtime writes can make IDB bytes differ from the executed plan. | The projection abstains when any planned head fails exact IDB byte and mode comparison. An explicit runtime shadow decoder needs a distinct validation path. |
| Low | Candidate enumeration can reach its fixed quota. | `limited` and `omitted` expose the bound; the observed run reports both false/zero. |

Quality gates for this changeset: QG1 requires no normative judgment; QG2 is
the assumption register above; QG3 covers the stated local recognition and
preserves the review ledger's incomplete items; QG4 uses exact integer sizes,
counts, and byte hashes; QG5 keeps incomplete execution and unknown entries
explicit; QG6 uses the Intel manual and independently decoded capture; QG7 is
the bounded risk inventory above. All 23 CTest suites pass. The exact protected
fixture probe, independent verifier, formatter checks, and full paired temporal
matrix are reported by their generated evidence and runner outputs. Full VM
recovery and the remaining `VMP_REVIEW.md` requirements remain in progress.
