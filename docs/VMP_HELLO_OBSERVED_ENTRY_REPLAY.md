# Observed entry-state replay for the supplied VMP hello

This checkpoint extends `VMP_HELLO_RUNTIME_SHADOW.md` for review rows 0b, 6a
and V. The user attributes the hash-pinned `foo_x86_vmp` Mach-O to VMP;
protector settings, seed and exact build lineage are **unknown**. The paired
`foo_x86_orig` supplies an exact 40-byte code, import-stub and literal oracle.
The protected file marks its `__text` and `__cstring` sections as zero-fill,
then restores this window during initialization. The earlier checkpoint
captured the restored window at `printf`; this one stops at protected `_main`
after restoration and records actual process state.

LLVM LLDB 23 and Apple LLDB 2103 each launched the protected process stopped
at dyld entry, set a breakpoint at its `0x100001436` entry stub, then set a
breakpoint at `_main` `0x100001440`. At both stops the restored 40 bytes were
identical. Each debugger recorded the 16 x86-64 GPRs, RIP, RFLAGS, 128 bytes
of entry stack, six successive instruction-entry states and the next state
at `printf`. Capstone 5.0.7 decodes the entered instructions as `PUSH RBP`,
`MOV RBP,RSP`, `LEA RDI,[RIP+0x11]`, `MOV AL,0`, `CALL 0x100001456` and the
six-byte indirect import-stub `JMP`. The `LEA` sets `RDI=0x10000145c`, the
restored `Hello World\0` literal. The next observed RIP equals the earlier
debugger capture's `printf` RIP.

`chernobog_vm_trace_candidate_shadow_replay` was given the stopped `_main`
entry GPRs and RFLAGS, 128 stack bytes, and explicit annotations for seven
stack-relative GPRs and five stack-relative words. It translated those
pointers to an isolated scratch stack with the same 4,096-byte page offset.
No binary file or IDA database item was patched. In two fresh IDA 9.4 SP1
runs, the plugin entered the same six instruction addresses. After reversing
only the annotated stack translation, **all 108 scalar values per run**
(16 GPRs, RIP and RFLAGS at six entries) equal the debugger observations:
216/216 across both implementations. The 16 bytes at the final stack write
also match after pointer translation: an eight-byte call return address and
an eight-byte saved frame pointer. Wrong stack-pointer requests and a missing
stack-pointer annotation are rejected. Independent verifier mutations of a
runtime register, candidate RIP and stack write are detected. The checked
IDA segment/item/reference/name inventory is unchanged.

The replay stops at `0x100001456` with `environment-model-failure` because
the indirect import target is outside the bounded native environment. LLDB
does step through that stub to `printf`; the plugin's six compared states
stop at the stub entry. These observations establish one no-argument,
restored native prefix with matching scalar state and stack effects. Other
VMP paths, callee effects, a VM region and logical VM state are **unknown**.

## Reproduction

First create the two runtime windows from `VMP_HELLO_RUNTIME_SHADOW.md`.
LLDB may return zero if an embedded script raises; the verifier requires
both JSON outputs and checks their content.

```sh
CHERNOBOG_HELLO_MAIN_STATES_OUTPUT="$PWD/build/vmp-hello-main-states-llvm.json" \
  lldb --batch -o 'target create samples/foo_x86_vmp' \
  -o 'process launch --stop-at-entry' \
  -o "script exec(open('tests/lldb_vmp_hello_main_states.py').read())" \
  -o 'process kill'
CHERNOBOG_HELLO_MAIN_STATES_OUTPUT="$PWD/build/vmp-hello-main-states-apple.json" \
  /usr/bin/lldb --batch -o 'target create samples/foo_x86_vmp' \
  -o 'process launch --stop-at-entry' \
  -o "script exec(open('tests/lldb_vmp_hello_main_states.py').read())" \
  -o 'process kill'
```

Set `IDA_CONSOLE` to the IDA 9.4 SP1 text executable and
`CHERNOBOG_PLUGIN` to the installed plugin. Use fresh output directories:

```sh
for variant in llvm apple; do
  python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
    tests/ida_vmp_hello_entry_replay_probe.py \
    --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
    --output-dir "build/vmp-hello-entry-replay-$variant-final2" \
    --set "CHERNOBOG_VMP_HELLO_WINDOW=$PWD/build/vmp-hello-runtime-final-$variant/runtime-window.bin" \
    --set "CHERNOBOG_VMP_HELLO_MAIN_STATES=$PWD/build/vmp-hello-main-states-$variant.json" \
    --set CHERNOBOG_VMP_HELLO_BINARY_SHA256=c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5
done
python3 -B tests/verify_vmp_hello_entry_replay.py \
  --original samples/foo_x86_orig --protected samples/foo_x86_vmp \
  --window build/vmp-hello-runtime-final-llvm/runtime-window.bin \
  --runtime build/vmp-hello-main-states-llvm.json \
  --runtime build/vmp-hello-main-states-apple.json \
  --ida build/vmp-hello-entry-replay-llvm-final2/vmp_hello_entry_replay.json \
  --ida build/vmp-hello-entry-replay-apple-final2/vmp_hello_entry_replay.json \
  --paired-runtime build/vmp-hello-runtime-final-llvm/report.json \
  --paired-runtime build/vmp-hello-runtime-final-apple/report.json \
  --output build/vmp-hello-entry-replay-verification-final.json
```

The verifier compares `K=6` entries and `R=18` scalar values per entry in
`O(KR + S)` time and space for `S=128` captured entry-stack bytes, excluding
JSON parsing and IDA's bounded trace. For `M` segment bytes, `I` item
records and `r_i` references at item `i`, the IDA inventory takes
`O(M + I + Σ r_i log r_i)` time and
`O(max_segment_bytes + max_i r_i)` extra space. Addresses, byte counts and
scalar counts are exact integers. The only pointer
normalization is an explicitly annotated 64-bit stack displacement.
`VMP_HELLO_OBSERVED_ENTRY_REPLAY_EVIDENCE.json` pins input, source, tool,
runtime, IDA and independent-verifier hashes.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| E1 | The hash-pinned original/protected files are the user-attributed pair. The original-window comparison depends on their lineage; protector settings are unknown. | Obtain the protector invocation and compare another original/protected build. Rehash both files and reject any changed section geometry or window. |
| E2 | The LLDB stops and single-step states reflect the protected process at this no-argument invocation. The observed-prefix claim depends on that execution. | Reproduce on physical x86-64 or an independent instruction tracer, vary input and environment, and reject differing entered addresses or state. |
| E3 | Values within 32,768 bytes of observed RSP and five selected stack words are stack-relative pointers. Normalized equality depends on those annotations. | Change or remove each annotation and compare with an oracle for stack aliasing. The missing-RSP control currently abstains. |
| E4 | The restored 40-byte window stays stable from stub through the selected prefix. The replay depends on that timing. | Capture the same interval at each instruction or vary initializer inputs; reject a changed byte. The two debugger windows at stub and `_main` already agree. |
| E5 | The checked IDA inventory covers relevant persistent changes. The read-only claim is limited to that inventory. | Save/reopen a disposable database and compare additional netnode and analysis state. |

- **High impact:** actual protected `_main` state seeds native replay; 216
  observed scalar values match across two debugger implementations.
- **Medium impact:** the call return address and saved frame pointer match
  observed process stack bytes under explicit translation.
- **Low impact:** the indirect `printf` target, other inputs, later native
  execution and VM identity remain outside the replay environment.

QG1: technical claims only. QG2: E1–E5 have falsification probes. QG3:
both debugger captures, fresh IDA runs, 216 scalar comparisons, stack
effects, negative requests, mutation controls and IDB inventory are covered;
the full review remains in progress. QG4: byte counts, scalar counts, units
and complexity are explicit. QG5: the plugin stops at the import stub while
LLDB reaches `printf`; these distinct boundaries are stated. QG6: exact
primary artifact, source and tool hashes are in the evidence JSON. QG7:
unsupported paths, callee effects and VM conclusions are bounded above.
