# Separate VM-region candidate analysis

This checkpoint's contiguous, function-owned scope is extended by
[VMP_VM_PATHS.md](VMP_VM_PATHS.md): bounded existing-xref paths can include
ownerless code, with retained instruction spans and no VM execution admission.
The results below describe the original checkpoint.

`src/vm` introduces a separate analysis family for bounded native read/decode/
dispatch candidates. It does not depend on `prog_bb_*` names or the `vm_mba`
handler's admission rules. `chernobog_vm_regions(ea)` inspects the selected
IDA function without modifying the database. **VM candidates** in the evidence
workspace displays direction, register roles, support bytes, normalized syntax,
scope limits and unresolved effects. Candidate endpoints appear as source nodes;
recognition creates no CFG target edge and admits no execution region.

This implements the first recognition/visualization portion of review items
6a–6b. Region ownership beyond the selected function, entry/context recovery,
validated semantic summaries and proved summary reuse remain incomplete.
`VMP_VM_REGIONS_EVIDENCE.json` attributes this checkpoint. Earlier manifests
describe their own historical source states.

## Source-derived contracts

The supplied tree's `core/intel.cc` defines these native emission paths:

| Source location | Observation | Implemented candidate contract |
|---|---|---|
| `AddReadCommand`, lines 27795–27827 | Forward read then advance, or backward decrement then read; optional decode and key feedback | Exact adjacent load/update ordering, matching byte count, distinct VIP/value/key roles |
| `AddEndHandlerCommands`, lines 27838–27860 | Signed dword offset added to a dispatch register; indirect jump | Dword read, explicit x64 sign extension, full-width base addition and register jump |
| `InitCommands`, lines 28762–28781 | Byte opcode indexes a pointer table | Byte zero-extension, pointer-width indexed jump; x64 base register or x86 absolute table displacement |
| `InitCommands`, lines 28595–28660 | Register-role selection varies | Canonical register slices and role-based data dependencies; no fixed register names |
| `CloneHandler`, lines 27863 onward; lines 30169–30188 | Handlers are cloned | Native addresses remain distinct; normalized syntax is available for comparing candidates |
| `core/processors.cc`, `ValueCryptor::Init`, lines 713 onward | Up to 101 immediate/unary transforms | A 128-instruction window covers this transform-count bound and dispatch scaffold |

Supported decoder operations are add, subtract, XOR, rotate left/right,
increment/decrement, negate, NOT and dword byte-swap. Stateful candidates must
contain the corresponding key-feedback operation. The x64 dword key-update
form retains its push, low-dword stack operation and pop; it is not treated
as an unqualified full-register XOR. No stack access or exception is erased.
The inspected source currently selects XOR for the initial key mixing; the
candidate recognizer also admits the structurally corresponding add/subtract
forms without attributing them to that generator revision.

Candidates require one contiguous sequence of decoded instructions with no
alternate entry inside it. Unsupported prefixes, high-byte aliases, address
size overrides, extra writes, register-role aliases, wrong read/update widths,
wrong strides, missing x64 sign extension and unsupported operations reject
the sequence. Recognition is local syntax/data-dependency analysis. An ordinary
interpreter or table dispatcher may satisfy it; VM or vendor identity is not
established. A function containing no candidate is not proved non-virtualized.

Each descriptor retains its half-open native interval, read and dispatch
addresses, address/read widths, traversal direction, register-role hypotheses,
table displacement, key-update form and complete admitted instruction sequence.
The production adapter adds the exact loaded bytes. IDA function ownership,
executable segment permissions, address mode and current entry topology are
checked on each inspection. Shared-tail ambiguity and unsupported ownership
remain abstentions. The inspector does not follow or enumerate dispatch targets.

Numeric register IDs in the detailed schema use canonical x86 GPR order:
0–7 are A, C, D, B, SP, BP, SI, DI; 8–15 are R8–R15. The address/read width
fields distinguish full address roles from low-width decoder operands.

## Logical state and reuse boundary

The portable `LogicalState` type separates native handler address from logical
state. Its comparison requires a nonzero region publication, context and memory
epoch, known equal VIP, virtual-stack and dispatch-base values, and a known
equal decoder key for a stateful decoder. Unknown values do not merge, including
an unknown VIP compared with itself. Different bytecode positions or decoder
keys at one native address therefore remain distinct.

This type is a tested contract for subsequent region-state analysis; production
recognition does not yet recover these values, allocate a VM execution region,
or use it to explore transitions. The existing current-function execution
boundary remains intact. Its publication/context/memory identifiers still need
integration with future admitted VM-region ownership and invalidation.

Role-normalized syntax preserves operation order, operand widths, constants,
addressing and register roles. Full string equality groups identical syntax
within an inspection. This grouping is neither a semantic proof nor a cache
admission rule. Handler flags, memory effects, exception behavior, input-state
contracts and transitions have not been validated as semantic summaries. The
UI explicitly reports summary reuse as unproved; item 6c remains pending.

## Inspection bounds and freshness

One call visits at most 1,024 instruction heads, considers windows of at most
128 instructions and retains at most 64 candidates. Recognized candidates
beyond the retention cap increment `omitted`; exhaustion of the instruction
budget sets `truncated`. The omission count describes only the scanned prefix;
it does not estimate candidates beyond a truncated scan. Supporting bytes are
bounded by 128 × 15 = 1,920 bytes per candidate. Serialized normalized syntax
and container overhead are additional bounded fields, not a measured process
memory limit.

With N scanned heads and L the window bound, suffix construction/recognition
has a conservative O(N L²) time bound, excluding IDA decode, ownership and xref
lookup implementations. Workspace is O(L); retained candidates and normalized
syntax use O(K L), K≤64. Full GUI polling repeats recognition for a loaded
nonempty candidate snapshot every 1 s. Maximum-size responsiveness and total
peak memory remain unmeasured. An empty snapshot is rescanned on explicit reload.

Current candidate navigation requires an exact recomputed row match in the
same database/function. Patching support bytes or adding a middle entry can
invalidate it. Restoring the original local contract can restore navigation;
the row remains a candidate throughout. The UI checks again immediately before
jumping. These checks do not assert current semantic effects, VM identity or
whole-region completeness. Multi-database context reuse and plugin unload/reload
still require dedicated lifecycle coverage.

## Assumption register

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| V1 | The supplied source's native dispatch scaffolds are relevant to the target corpus. Source-specific expected coverage depends on this. | Hash the source; use independent x86/x64 motifs derived from its contracts. Protected emitted-fixture equivalence and protector settings remain unknown. |
| V2 | IDA's decoded widths, register slices, function ownership and entry xrefs describe the inspected native sequence. | Execute production decoding on both architectures; reject altered bytes, alternate entries, wrong strides, aliases and unsupported partial writes. Missing external entries cannot be inferred from absent IDB xrefs. |
| V3 | Structural recognition supports candidate classification only. | Require `truth=candidate`, explicit unresolved effects and no target/edge or execution-admission field. Do not infer a VM or vendor from the motif. |
| V4 | Logical state requires more than a native handler address. | Compare changed VIP/key/context/memory/publication values and unknown state; require inequality. Production state recovery remains pending. |
| V5 | Renaming and cloning preserve role-normalized syntax for the admitted forms. | Compare distinct native byte sequences with permuted registers and relocated addresses; retain constants and widths so changed transforms compare unequal. Semantic equivalence is not inferred. |
| V6 | Inspection does not change analyzed code or run its dispatcher. | Repeated real IDC queries must preserve bytes and return stable rows. Test probes deliberately construct fixture ranges and patch/restore bytes outside the inspection call. Wider metadata/third-party hook side effects remain unmeasured. |
| V7 | Bounds must not silently present a prefix as complete. | 70 candidates retain 64 and report six omissions; a 1,030-NOP prefix reports exhaustion at 1,024 heads and never claims the later dispatcher was inspected. |

## Verification

The portable tests exercise both modes, both directions, table/relative
dispatch, keyed/unkeyed forms, role permutations, clone relocation, entry
rejection, width/stride/address/alias controls, the 101-transform budget and
logical-state identity. Independent assembly fixtures provide x64 Mach-O and
x86 ELF inputs to `tests/ida_vm_regions_probe.py`. The x86 extra-write negative
case and x64 missing-sign-extension case have architecture-specific meanings.
Neither dispatcher fixture is executed; these are decoder/inspection tests,
not native semantic-equivalence or protected-program recovery tests.

Reproduce from the repository root with local installation variables:

```sh
cmake --build build -j 2
ctest --test-dir build --output-on-failure
python3 -B tests/run_ida_smoke.py build/vmp-vm-regions \
  tests/ida_vm_regions_probe.py --ida "$IDA_TERMINAL" --plugin "$PLUGIN" \
  --output-dir build/vm-regions-terminal \
  --set "CHERNOBOG_VIEW_MODULE=$PWD/python/chernobog_evidence.py"
```

Build `tests/vmp_native/vm_regions.S` with the macOS x86-64 assembler/linker.
Build `vm_regions32.S` with `clang --target=i386-linux-gnu -c`, then link using
`ld.lld -m elf_i386 -e _main --build-id=sha1`. The GUI variant uses `IDA_GUI`
with `QT_QPA_PLATFORM=offscreen`. Rax is disabled for all candidate probes.
Each run needs a fresh output directory. The manifest records exact hashes,
checks, truncation results and regressions of the existing workspace.

The final build passes 14/14 CTest targets, including 347 portable VM checks.
The single CTest run reports 8.23 s; this is not a comparative benchmark.
Production IDA passes 41 x64 terminal checks, 41 x86 terminal checks and 47
x64 Qt GUI checks. Existing SMT, native-proof and lifetime GUI regressions pass
28, 47 and 31 checks respectively: 129 candidate checks plus 106 regressions.
Both architecture probes report 64 retained/six omitted candidates and the
explicit 1,024-head scan limit. The feature-only GUI render shows source nodes,
the candidate tab and unresolved-contract details; no target edge is invented.

## Bounded expansion and quality gates

| Impact | Finding | Consequence |
|---|---|---|
| High | Native handler identity can recur at distinct bytecode/key states. | State identity must retain logical inputs and memory/context epochs. |
| High | The source's long cryptor limit exceeds a short local recognizer window. | Cover 101 transforms within an explicit 128-instruction bound and report scan exhaustion. |
| Medium | Normal table dispatch can match a VM-like scaffold. | Recognition remains a candidate; entry/context/semantic evidence is still required. |
| Medium | Role-normalized clones can share syntax without proved full effects. | Syntax groups support inspection only; semantic reuse needs independent proof. |

QG1: technical analysis without a normative premise. QG2: assumptions and
falsification probes are explicit. QG3: this checkpoint covers bounded candidate
recognition/model/visualization, not all review requirements. QG4: widths are
bits, support sizes bytes and polling seconds; complexity excludes IDA internals.
QG5: ownership, unsupported forms, incomplete scans and semantic gaps are
explicit. QG6: source, fixtures, plugin and executed artifacts are hashed.
QG7: bounded adjacent findings are above. The full objective remains active.

Subsequent checkpoint: `VMP_VM_SEMANTICS.md` adds bounded normal-completion
local-effect summaries and proof-gated reference reuse. This document and its
manifest retain the historical candidate-recognition checkpoint and its limits.
