# Immediate-push effects and conditional stack-check paths

VM candidates can now retain an immediate payload read/decode, virtual-stack
decrement and store, the taken fast stack check, and dispatch in one ordered
summary. Payload and dispatch widths and register roles remain separate. The
summary includes its input domain; equality at the unsigned stack threshold
does not belong to the fast path.

The supplied source's full immediate-push handler always enters stack-check
machinery. A payload/store followed directly by dispatch is therefore labeled
as a local scaffold, not as an entire emitted handler. Stack relocation remains
unsupported. This advances review rows 6a–6c without establishing complete VM
state, unconditional handler equivalence or protected full-handler recovery.

## Source contract

Primary references in the supplied tree are `core/intel.cc`, particularly
`AddReadCommand`, `AddEndHandlerCommands`, stack-check construction and immediate
push generation, and `core/processors.cc::ValueCryptor::Init` and
`OpcodeCryptor::Init`. The evidence manifest records their hashes. Those hashes
identify inspected source; they do not authenticate the protected binary's build.

| Payload width | Load destination | VIP movement | Virtual-stack decrement | Store width |
|---|---|---|---|---|
| 8 bits | 32 bits, zero-extended | 1 byte | 2 bytes | 16 bits |
| 16 bits | 32 bits, zero-extended | 2 bytes | 2 bytes | 16 bits |
| 32 bits | 32 bits | 4 bytes | 4 bytes | 32 bits |
| 64 bits, x64 only | 64 bits | 8 bytes | 8 bytes | 64 bits |

Forward reads precede VIP advancement; backward reads follow its subtraction.
The source cryptor uses XOR with the key, 4–101 ordered value transforms, then
XOR feedback. In x64, dword feedback uses PUSH/key, a low-dword native-stack
update, and POP/key, retaining the key's upper 32 bits. The summary retains
those reads and writes. Its byte-array memory model allows the payload store
or native-stack scratch to alias later bytecode/table reads.

Basic dispatch performs the stack check before reading the next byte opcode.
Advanced dispatch first decodes a signed dword delta and updates the dispatch
base, then performs the check. The admitted check is:

```text
scratch = native_SP + threshold_bytes
compare virtual_SP, scratch at the native address width
take JA only if unsigned virtual_SP > scratch
continue to dispatch
```

The source thresholds are 96 or 128 bytes in x86 and 256 or 320 bytes in x64.
LEA performs no data read. CMP flags and the scratch-register write remain
modeled, including when the scratch aliases the payload or dispatch register.
Reserved VIP, VSP, key, dispatch-base and native-SP roles remain distinct.
The final payload-register snapshot may have been overwritten by dispatch or
guard work; the stored payload is the value of the ordered payload-store event.

The source relocation arm changes native SP and copies context with additional
effects. It is not erased or summarized as the fast path. Other native entries,
exceptions, concurrent mutation and complete VM ownership remain outside this
local normal-completion contract.

## Recognition, proof and observation contracts

The portable recognizer admits both address widths, both VIP directions, all
supported payload widths, distinct or reused scratch registers, and the two
source guard placements. It rejects conflicting roles, incorrect byte-push
widths, wrong strides, substituted keys, unretained branches, overlapping code,
alternate entries, unsupported effects and out-of-bound support. Broader local
ADD/SUB key mixtures remain portable semantic cases; the inspected source's
opcode cryptor selects XOR.

Semantic reuse requires three solver results: a satisfiable union of input
domains, no input on which the domains differ, and no effect difference within
their common domain. Effects include all architectural GPRs under the existing
bijective role mapping, defined flags, ordered accesses, final memory and next
PC. Empty domains, mismatches and UNKNOWN cannot authorize reuse. Captured
transition checking includes the taken-JA condition in its initial input
consistency query, before testing output agreement.

Static inspection follows existing taken-JA links as conditional candidate
paths. Native and ordinary observations retain every intervening transfer state
and its matching edge, source, target, run and sequence. Intermediate native
transfer samples must also agree with the next instruction-entry register/flag
sample. Missing,
duplicate, foreign, unexpected or inconsistent witnesses prevent validation of
the full path. A shorter independently valid dispatch suffix may still be
reported; it is not counted as a validated payload/guard transition.

Summary display prioritizes the domain expression and explicitly marks omitted
or truncated expressions. Candidate/state metadata exposes payload read/store
sites and widths, the VSP register hypothesis and guard information. Captured
VSP values do not establish VM context or memory identity:
`logical_state_complete` remains false and state merging remains unadmitted.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Probe or limit |
|---|---|---|
| P1 | The inspected tree supplies the intended handler grammar. | Source hashes and exact emitted widths/order/cryptor rules are retained. Synthetic fixtures use four legal transforms; protected source-build attestation remains unknown. |
| P2 | Flat little-endian, unchanged-code, normal-completion semantics apply to the admitted path. | Independent byte-memory oracles test overlapping payload, bytecode, table and native-stack storage, and complete register/defined-flag effects. Faults, devices, segmentation and relocation remain excluded. |
| P3 | A fast-path summary is applicable only on its explicit input domain. | Strict equality, false predicates, different domains, empty domains and output mismatches are negative controls. Domain and output proofs remain separate. |
| P4 | Captured instructions and transfer witnesses describe the same exact visit. | Both projections test missing/duplicate/wrong-run/wrong-target witnesses, unexpected transfers and repeated visits. Native controls additionally corrupt every intermediate GPR and flags; ordinary controls validate intermediate provenance, with effects checked from entry to output. Exact code bytes and data access ordering remain required. |
| P5 | Fixture and replay oracles are independent of the symbolic evaluator. | C process and Python integer/byte oracles, Capstone instruction replay and deliberate expected-store corruption are compared. Host translation and QEMU are explicit; hardware-only validation is not claimed. |

## Validation

| Check | Result |
|---|---|
| Portable push-handler oracle | 85,148 checks across 1,340 concrete cases |
| Ordinary observation projection | 631 checks, including 24 guarded transitions and 216 witness corruptions |
| Native observation projection | 822 checks, including eight guarded configurations and 304 intermediate-witness corruptions |
| x64 production matrix | 16 configurations; 96 native cases and 96 IDA captures; 1,304 assertions |
| i386 production matrix | 12 configurations; 72 native cases and 72 IDA captures; 978 assertions |
| Independent full fast-path replay | 48 x64 and 36 i386 captured transitions |
| Corrupted C expected-store controls | Six rejections per architecture |
| Independent guard replay controls | 12 valid cases accepted and 24 corrupt cases rejected per runner |
| Actual Qt display probe | 24 assertions; domain, conditional scope, captured VSP and unknown-role views visually verified |
| Existing ordinary-driver production probes | 92 assertions; 40 corroborated primary direct/near-return transitions |
| Portable CTest suites | 21/21 pass in 12.18 s |

The production fixtures span payload width × direction × dispatch form. Each
configuration uses three value/key vectors and both fast and strict-equality
paths. Advanced dispatch includes -32, INT32_MAX and INT32_MIN deltas. The equal
path enters an explicit test stub; it does not implement or validate relocation.
All original fixture bytes and IDA metadata inventories remain unchanged during
inspection and capture after explicit fixture preparation.

The Qt probe displays a real static summary and adapts real native-capture rows
to the ordinary state-view presentation for display testing. That adaptation is
explicitly labeled, keeps ordinary freshness unavailable and navigation disabled,
and does not publish ordinary execution evidence. The full domain and its
completeness marker, fast-path scope, VSP samples and unchanged unknown-role text
are visible in retained screenshots.

A matched existing protected x64 virtualization-seed-1 case retains 80/80
corroborated dispatch-only transitions across 32 captures, with 1,396 assertions,
1,792 independently replayed instruction visits and 36,800 file-backed decode
checks. It produces zero full payload/guard candidates. Every capture stops at
unsupported 16-bit BSWAP; none returns. This measures preserved local dispatch
coverage, not a gain in protected full-handler recovery.

Initial fixture attempts are retained as failures. Transfers to immediate native
fallthrough produced no driver transfer witness; final fixtures use distinct
targets and leave that driver limitation explicit. ELF end and relative-dispatch
symbol aliases required exact fixture symbol handling. Decoding nonexecuted
INT3 gaps introduced alternate incoming flow, correctly rejecting the static
candidate; preparation now asserts those original gap bytes and defines them as
data. No production entry rule was relaxed to accommodate the fixtures.

Reproduce with new output directories and local runtime configuration:

```sh
python3 -B tests/run_vm_push_handlers.py --architecture x86_64 \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/push-handlers-x64-new
python3 -B tests/run_vm_push_handlers.py --architecture i386 \
  --linux32-image "$PINNED_LINUX32_IMAGE" --docker-context orbstack \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/push-handlers-i386-new
```

Use `--native-only` to execute only independent process oracles. Detailed source,
runtime, accepted-report and retained-failure hashes are in
[VMP_PUSH_HANDLERS_EVIDENCE.json](VMP_PUSH_HANDLERS_EVIDENCE.json).

## Bounds and quality gates

Instruction support is now capped at 256, admitting two independently allowed
101-transform cryptors without truncation. A 257th instruction rejects the path.
Static/native scanning retains its 8,192 path-step budget; native observation
retains 128 rows, 64 accesses per checked transition and 16 transition attempts.
Ordinary observations include edges in their existing 262,144-event input bound.
Longer candidates consume the same path budget faster; no other quota increases.

For N support instructions, overlap validation and scratch normalization cost
O(N²) time and store O(N) instructions. Ordered concrete memory
replay is linear in accessed bytes. Symbolic arrays and solver queries retain
the existing time/resource limits; no polynomial SMT-solving bound is claimed.

- **High:** preserving the guard domain prevents equal outputs on one path from
  becoming an unconditional handler-equivalence claim.
- **High:** protected coverage remains constrained by execution frontiers and
  missing complete VM state; synthetic recognition does not resolve either.
- **Medium:** relocation, shared-entry static ownership and fallthrough-target
  transfer capture require separate contracts and evidence.

QG1: technical scope. QG2: P1–P5 with falsification controls. QG3: the admitted
fast path, both frontends and both architectures are covered; the full review
remains incomplete. QG4: bit/byte widths, signs, counts and bounds are explicit.
QG5: guard, aliasing, witness and exhaustion controls reject unsupported claims.
QG6: primary source hashes, independent oracles and matched captured artifacts.
QG7: protected effectiveness, relocation and remaining identity limits stated.
