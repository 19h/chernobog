# Bounded return-tail checkpoint for the supplied VMP hello

This checkpoint advances review rows 6a and V. The supplied protected Mach-O
has a restored 40-byte window at `0x100001440`; the first six native entries
were previously replayed from an observed `_main` state. That replay stops at
the indirect `printf` import stub. The code after the call occupies four bytes
at `0x100001452`: `XOR EAX,EAX; POP RBP; RET`. The bytes and instruction
effects are checked against the supplied file's restored runtime window and
the [Intel x86 instruction reference](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf).

`chernobog_vm_trace_candidate_shadow_checkpoint(observed_pc, seed, entry_json)`
adds a read-only replay entry for a caller-supplied x86-64 register/stack
checkpoint. The root must be an unnamed, unloaded, unknown byte in an
executable nonexternal segment outside any IDA function. The request includes
bounded shadow bytes starting at that exact root, 16 GPRs, RFLAGS, a translated
stack window and an explicit `max_insns` in `[1,64]`. The existing native
planner and instruction-state capture execute from that state. The response
labels the checkpoint provenance unverified, publishes no function evidence,
and makes no VM-identity claim. A loaded import stub, missing or excessive
budget and missing stack-pointer translation abstain.

The production test derives a **synthetic** state at `0x100001452` from the
earlier stopped `_main` capture. It sets `RSP=entry_RSP−8`, `RBP=RSP`, and
places the saved frame pointer and original caller return word at offsets 0
and 8 bytes of the new stack window. It chooses `RAX=11` as a test input;
this does not assert a measured `printf` return value. For that input the
plugin enters three heads, sets `RAX=0` at the second, restores `RBP` and
increments `RSP` by 8 bytes at the third, then transfers to the original
caller's return address. The defined `XOR` status bits agree with the
independent mask check: CF=0, PF=1, ZF=1, SF=0, OF=0. AF is excluded because
it is undefined. These are conditional tail effects from the supplied state,
not a proof of the preceding callee's effects.

Fresh IDA 9.4 SP1 runs seeded from the earlier LLVM and Apple LLDB main-entry
reports each pass 13/13 checks. Both plan and enter three tail heads and stop
at the same external caller target. A one-byte shadow change replaces the
first `XOR` with `NOP` and preserves the test input's `RAX=11` at the second
entry. Both runs leave the selected 40-byte IDA inventory unchanged.

A separate x86-64 Mach-O interposer supplies a process-derived checkpoint.
It redirects this exact call through a wrapper that calls the dyld-resolved
original `printf` symbol. The wrapper checks that the resolved symbol is named
`printf`; disassembly of the signed test library confirms the indirect call,
register save/restore and final `RET`. The no-conversion `Hello World` format
uses no variadic values. Immediately
before the interposer returns to the four-byte tail, it saves all 16 GPRs,
RFLAGS, 128 bytes above the return-adjusted RSP and the 40-byte restored
window in a 328-byte record. The record's RSP includes the eight-byte pop
performed by the interposer's final `RET`; the recorded return PC is the
tail address. The assembler restores the captured registers and flags before
that `RET`. This is the tail-entry state of an **instrumented** process,
conditioned on the wrapper's call frame and register effects; it is not a
direct observation of the unmodified call path.

Two launches of each original/protected file produce one capture apiece.
All four captures contain the same 40-byte window as the earlier debugger
capture. The interposed and unmodified no-argument launches each exit with
status zero and emit the exact 11 bytes `Hello World`. The two protected
captures have distinct ASLR slides and caller return addresses. Their raw
records are checked byte-for-byte against the runner's report before use.
Two fresh IDA runs seeded from those protected captures each pass 11/11
checks: the 16 input GPRs, RIP and RFLAGS agree after only declared stack
translation; the `XOR`, `POP` and `RET` effects agree with the independent
architectural checks; and the selected 40-byte IDA inventory is unchanged.
Each query plans and enters three heads, then stops at that process capture's
external caller return address. All 21 configured CTest suites pass.

The initial sandbox prevented both debugger implementations from launching
the process before the first stop. After full filesystem access was enabled,
both launched successfully. That exposed a capture-script issue: a breakpoint
planted at `_main` before restoration was overwritten by the loader. The
corrected script stops at the existing entry stub after restoration, then sets
the `_main` and post-call breakpoints. With ASLR enabled and
`DYLD_INSERT_LIBRARIES` absent, LLVM and Apple LLDB each capture all 16 GPRs,
RIP, RFLAGS and stack bytes at three tail entries and after `RET`. Their image
slides are `0x213c000` and `0x2852000`, respectively. This is a debugger-observed
call path without the `printf` interposer, not an uninstrumented process trace.

Two fresh IDA replays of those checkpoints [P1, P5, P6] each pass 12/12 checks
and 72/72 scoped scalar comparisons: 16 GPRs, RIP and RFLAGS at each of four boundaries.
RFLAGS is compared in full at entry and through the five defined XOR status
bits after it; undefined AF is excluded. Stack-relative fields use explicit
translation and in-image PCs use the captured slide. The two recorded stack
reads match their observed addresses and words, and three comparator mutations
(GPR, defined flag and final return PC) reject. An AF-only mutation is excluded
as intended. The selected IDA inventory remains unchanged. The whole trace's
`data_trace_complete` remains false at the external caller frontier; the two
recorded tail reads do not establish a complete external execution trace.
The debugger processes are killed after the observed return, so these captures
are not completed-process output or latency measurements. A complete protected
path and VM recovery remain **unknown**.

## Reproduction and complexity

The synthetic probes consume the two hash-pinned main-entry reports and
restored windows from `VMP_HELLO_OBSERVED_ENTRY_REPLAY.md`. Use a current plugin
and fresh IDA output directories:

```sh
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_hello_postcall_checkpoint_probe.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/vmp-hello-postcall-synthetic-llvm \
  --set "CHERNOBOG_VMP_HELLO_WINDOW=$PWD/build/vmp-hello-runtime-final-llvm/runtime-window.bin" \
  --set "CHERNOBOG_VMP_HELLO_MAIN_STATES=$PWD/build/vmp-hello-main-states-llvm.json" \
  --set CHERNOBOG_VMP_HELLO_BINARY_SHA256=c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5
```

Repeat with the Apple report/window and a fresh `-apple` directory. The
process-derived capture and IDA replay are:

```sh
xcrun clang -arch x86_64 -dynamiclib -O2 -fPIC -Wall -Wextra -Werror \
  -o build/libvmp_hello_postcall_capture.dylib \
  tests/vmp_hello_postcall_interpose.c
codesign -s - -f build/libvmp_hello_postcall_capture.dylib
python3 -B tests/run_vmp_hello_postcall_interpose.py \
  --original samples/foo_x86_orig --protected samples/foo_x86_vmp \
  --library build/libvmp_hello_postcall_capture.dylib \
  --window build/vmp-hello-runtime-final-llvm/runtime-window.bin \
  --output build/vmp-hello-postcall-interpose-report.json
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_hello_postcall_interpose_probe.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/vmp-hello-postcall-interpose-0 \
  --set "CHERNOBOG_POSTCALL_REPORT=$PWD/build/vmp-hello-postcall-interpose-report.json" \
  --set CHERNOBOG_POSTCALL_INDEX=0 \
  --set CHERNOBOG_VMP_HELLO_BINARY_SHA256=c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5
```

Repeat the IDA command with index 1 and a fresh output directory. The
independent debugger capture command, when a debugger can launch the process,
is:

```sh
env -u DYLD_INSERT_LIBRARIES -u CHERNOBOG_HELLO_POSTCALL_CAPTURE \
  CHERNOBOG_HELLO_POSTCALL_OUTPUT="$PWD/build/vmp-hello-postcall-observed-llvm.json" \
  lldb --batch -o 'target create samples/foo_x86_vmp' \
  -o 'settings set target.disable-aslr false' \
  -o 'process launch --stop-at-entry' \
  -o "script exec(open('tests/lldb_vmp_hello_postcall.py').read())" \
  -o 'process kill'
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_hello_postcall_observed_probe.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/vmp-hello-postcall-observed-verified-llvm \
  --set "CHERNOBOG_POSTCALL_STATES=$PWD/build/vmp-hello-postcall-observed-llvm.json" \
  --set CHERNOBOG_VMP_HELLO_BINARY_SHA256=c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5
```

Repeat with `xcrun lldb`, the `-apple` capture path and a fresh IDA directory.

The request cap is 64 entered instructions and 65,536 shadow bytes. For `K`
entered instructions and `R=18` recorded scalars per state (16 GPRs, RIP,
RFLAGS), state recording costs `O(KR)` time and space, excluding the existing
bounded image snapshot and native planning. Each tested fixture has `K=3`,
or 54 scalar slots per IDA run. The interposer copies a fixed 328-byte record
once per process; the runner performs four instrumented and two baseline
process launches. The synthetic and interposer probes compare the captured
entry state and selected subsequent architectural effects; they do not assert 54 directly observed
post-call scalar values. The separate direct-debugger comparison has four
boundaries and 18 scalars each, or 72 scoped comparisons per debugger and 144
in total. Its later RFLAGS comparisons use mask `0x8c5`, not raw-flag equality.
Addresses, counts and byte comparisons are exact.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| P1 | The restored 40-byte window remains stable across the selected call. Replay input and tail-byte claims depend on this. | Compare each raw interposer capture and direct-debugger window with the earlier window; all agree. The direct script also compares its `_main` and post-call reads. |
| P2 | The interposer's saved registers and flags, plus one architectural eight-byte `RET` pop, describe its process's tail entry. The process-derived replay depends on this assembly contract. | Disassemble the signed interposer, capture the tail directly under a debugger or second tracer and compare all 16 GPRs, RFLAGS and 128 stack bytes. |
| P3 | The wrapper resolves and calls the original `printf` symbol, but its extra call frame can affect callee execution and caller-saved registers. Equality with the separate debugger-observed state is not assumed. | Check the resolved symbol and signed-library disassembly; compare baseline and instrumented exit/output as done here. A same-process dual-tracer capture would test the wrapper state directly. |
| P4 | The selected 40-byte IDA inventory detects persistent mutation relevant to the query. The read-only observation depends on that inventory. | Save/reopen a disposable IDB and compare additional netnodes and analysis metadata. |
| P5 | GPRs and stack words within 32,768 bytes of observed RSP are declared stack-relative by the probe. The translated state comparison depends on these explicit annotations. | Replace a declaration or value and require a comparison failure; obtain independent pointer provenance before transferring this classification to another fixture. External return PCs are retained as scalars. |
| P6 | The debugger's breakpoint and single-step states describe this normal-completion tail under debugging. The direct oracle does not establish debugger-neutral behavior of the preceding protector. | Compare with a hardware-breakpoint or independent tracer capture; retain the debugger's exact bytes, registers and process identity as done here. |

- **High impact:** a protected native return tail now replays from two distinct
  interposed process checkpoints and two debugger checkpoints, with 144 direct
  scoped scalar comparisons and exact recorded stack-read checks.
- **Medium impact:** the exact unloaded-root gate, instruction budget, raw
  capture check and shadow mutation expose admission and byte dependence.
- **High impact risk:** these bounded checkpoints do not establish the complete
  protected path, debugger-neutral protector behavior or VM recovery.

QG1: technical claims only. QG2: P1–P4 include falsification probes. QG3:
the API, two synthetic IDA runs, four interposed captures, two interposed
IDA runs, two direct-debugger captures, two direct IDA runs, negative requests,
mutation controls and selected inventory are covered; the full review remains
in progress. QG4: instruction,
byte and scalar counts are explicit. QG5: unmodified, instrumented and
synthetic and debugger process states are distinct, and full-trace completion
is not inferred from two recorded reads. QG6:
local primary artifacts, source and reports are hash-pinned in
`VMP_HELLO_POSTCALL_CHECKPOINT_EVIDENCE.json`; Intel semantics use the cited
primary manual. QG7: complete callee semantics, the external frontier and
debugger dependence are bounded above.
