# Protected Morok continuation after an observed syscall

This checkpoint extends the owned-call replay for review rows 0b, 6a and V.
The fixed-seed Morok keygen binary is the source-controlled protected fixture
with SHA-256 `f479ae1a…`, separate from the supplied keygen file. The two
tracked stdin files have the exact hashes already used for its distinct
version-14.1 and version-14.0 process paths.

The earlier owned replay stops before `SYSCALL` at `0x41d78d`. QEMU/GDB
executes that instruction and observes the call at `0x41d792` into the
existing helper at `0x41d364`. The new capture records four helper entries
(`CMP`, `JA`, `MOV`, `RET`) and the state when it returns to `0x41d797`.
The helper is decoded against the exact ELF bytes, but this change does not
emulate its instructions or infer the syscall result. The entry registers,
RFLAGS, 4,096 writable-data bytes, 1,280 stack bytes and 256 code bytes are
read directly from each process after the helper returns.

The read-only `chernobog_vm_trace_owned_shadow_replay_memory` API now accepts
an observed **code head within** an existing owned function. It still requires
x86-64, loaded executable code, an exact IDA code head, a caller-supplied
shadow and memory snapshot, and an explicit 1–4,096 instruction budget. An
interior head additionally requires `observed_pc` equal to the selected root;
the original function-start request remains accepted without that field. The
same equality check applies whenever another memory-replay request supplies
`observed_pc`. The snapshot uses the actual owner start, while the planned native region and
entry state start at the selected head. The result exposes both the selected
`function` field and `checkpoint_owner`. Ordinary function evidence and VM
identity remain unpublished.

Two fresh IDA 9.4 SP1 queries from `0x41d797` each plan 48 heads, enter
19 instructions and stop at the observed return to the caller at `0x41b885`.
Independent Capstone decoding checks all planned heads against the ELF file
and all entered bytes against process memory. After explicit stack-address
translation, **608/608 GPR values**, **38/38 RIP values**, **38/38 raw RFLAGS
values** and **228/228 architecturally defined status-flag bits** match across
the two entries. Applying each replay's final writes to its own entry memory
reproduces the **10,752/10,752 selected boundary bytes** across both inputs.
Each process changes one data byte and zero bytes in the selected stack
window; the replay retains 24 final-written bytes. These counts concern the
bounded path after the observed helper return.

The previous function-start request remains admitted on a fresh database: it
enters its original 26-instruction prefix, stops at the syscall frontier and
still rejects its wrong-root and missing-budget controls. That regression
capture is included in the archive.

The verifier rejects altered process registers, planned instruction bytes and
final writes. The IDA probe rejects an interior instruction byte, missing or
mismatched observed RIP, and a request without the instruction budget. Both
disposable databases retain the same segment, loaded-byte, item, reference,
function and name inventory before and after inspection. All 23 CTest suites
pass.

The exact binary, raw branch, owned-call and post-syscall process reports,
code shadows and IDA captures are in `VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz`;
their hashes, plugin and IDA executable hashes, source hashes and exact comparison
counts are in `VMP_NATIVE_POST_SYSCALL_EVIDENCE.json`. GDB's nested `source`
executes the older owned-call script in the wrapper's Python namespace, so
that intermediate report's `source_sha256` field identifies the **wrapper**.
The verifier tests that binding and separately pins the older script's bytes.
No source-identity claim is inferred from the intermediate field alone.

Offline verification uses only the tracked scripts and committed evidence:

```sh
python3 -B tests/verify_native_post_syscall_archive.py \
  --archive docs/VMP_NATIVE_POST_SYSCALL_CAPTURE.json.gz \
  --evidence docs/VMP_NATIVE_POST_SYSCALL_EVIDENCE.json
```

For a workspace-local build when the SDK plugin directory is not writable:

```sh
cmake -S . -B build \
  -DCHERNOBOG_PLUGIN_OUTPUT_DIR="$PWD/build/local-plugins"
CCACHE_DIR="$PWD/build/.ccache" cmake --build build --parallel 20
```

The production and regression IDA runs used the signed
`build/local-plugins/chernobog.dylib` from that build. The CMake option is
empty by default, retaining the existing SDK output path.

For total parsed report bytes `B`, planned heads `H=96` across both inputs,
entered instructions `I=38`, `R=18` compared scalar fields and
selected boundary bytes `W=10,752`, verification takes `O(B + H + IR + W)`
time and `O(B + H + W)` retained space, excluding library internals. All
reported memory spans are in bytes; time and processor resource costs are not
estimated from this verifier.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| P1 | The hash-pinned binary and two input files identify these paths. All paired comparisons depend on those bytes. | Rehash the tracked inputs and fixture binary; reject any changed identity, and repeat the clean/protected process-output control. |
| P2 | GDB captures state before each reported instruction. Register and byte equality depends on this timing. | Compare every entered PC and 16-byte window with the independent IDA replay; repeat with a second tracer or physical x86-64 machine. |
| P3 | The observed state after the helper includes effects relevant to the next 19 entries. The replay depends on the selected code, data and stack windows. | Mutate one observed register, planned byte and final write; expand memory windows and reject any observed access beyond them. |
| P4 | The selected head, observed RIP and existing IDA owner describe the intended native range. The owner label and read-only result depend on the checked database state. | Reject an interior byte, missing/mismatched observed RIP and omitted budget; compare IDB inventories, and repeat after save/reopen or ownership changes. |
| P5 | The nested GDB `source` binding explains the intermediate source field. Source attribution depends on the separate source hash and exact wrapper behavior. | Execute the owned script in an isolated Python namespace and require its field to change to the older script hash while the path and state remain equal. |

- **High impact:** the protected native replay continues past a real syscall
  and an observed helper return on both distinct inputs.
- **Medium impact:** a bounded owned code-head checkpoint can inspect later
  in-function paths without changing IDA ownership or retyping code.
- **High impact risk:** syscall semantics, the helper's independent emulation,
  execution after `0x41b885`, unobserved memory and logical VM state remain
  unknown.

QG1: technical claims only. QG2: P1–P5 include falsification probes. QG3:
both inputs, observed helper boundaries, 38 entered instructions, 96 planned
heads, state, memory and negative controls are covered. QG4: byte counts,
scalar counts and complexity are explicit. QG5: observed syscall effects are
not attributed to the replay and the nested source-field discrepancy is
identified. QG6: exact local primary binaries, process reports, source bytes,
IDA captures and tool identities are hash-linked. QG7: later paths and VM
semantics remain bounded unknowns. The complete review remains in progress.
