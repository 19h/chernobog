# Bounded call-argument bytes in the supplied VMP hello

This checkpoint extends `VMP_HELLO_RUNTIME_SHADOW.md` for review rows 3a,
3b, 6a and V. The exact supplied original/protected Mach-O pair and its
40-byte stopped-process window are pinned in that report. Protector settings
and build lineage remain **unknown**. The new query makes one call-argument
byte observation available from the ephemeral protected native trace; it
does not execute or summarize the callee.

`chernobog_vm_trace_candidate_shadow_use(root, seed, shadow_file, use_json)`
accepts an explicit call source, target, selected x86-64 argument register and
maximum byte count. It runs the existing bounded candidate shadow. The
selected source must be a planned CALL, an exact CALL edge to the requested
target must have occurred once, and a same-sequence transfer-target state
must contain the selected 64-bit register. The query reads from that pointer
only through loaded, readable, nonwritable image bytes and requires a NUL
within 1–256 bytes. It returns raw bytes including the NUL, the pointer and
transfer sequence. Ambiguous calls/states, missing registers, unloaded or
writable bytes, incomplete termination and malformed requests abstain.
The result marks its state as synthetic and `callee_semantics_proved=false`.
No IDA item, function evidence or persistent string annotation is created.

For the supplied VMP hello, the caller-selected contract is CALL
`0x10000144d` → import stub `0x100001456`, register `RDI`, limit 32 bytes.
Two fresh IDA 9.4 SP1 runs, one for each independently captured runtime
window, return the same pointer `0x10000145c` at sequence 7 and the exact
12 bytes `48656c6c6f20576f726c6400` (`Hello World\0`). The trace graph,
states and frontiers equal the original shadow query in both runs. Direct
CALL and six-byte indirect JMP stub bytes decode independently under
Capstone 5.0.7. Each of four protected LLDB `printf` stops has `RDI` equal
to the same pointer after subtracting the image slide, and the same 12 bytes
at that address. This cross-tool match is a finite observation at one use.
The process was stopped at `printf`, not at the import stub; equivalence of
the intermediate `RDI` relies on the decoded stub's register-preserving JMP.

Wrong source, target, register, short bound, unsupported register and bound
above 256 all abstain. A disposable one-byte literal mutation in the caller
shadow changes the returned first byte from `48` to `49`; it leaves the
original sample and capture untouched. The independent verifier rejects
in-memory mutations of the returned pointer, byte string and call source
against the debugger reports. A matched prior plugin has the ordinary shadow
trace but no shadow-use query. The selected 40-byte IDA flag/loaded/owner
inventory remains unchanged in both current runs.

## Reproduction and bounds

Recreate the two debugger windows using `VMP_HELLO_RUNTIME_SHADOW.md`.
Build the current plugin and use fresh IDA output directories. The first run
is:

```sh
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_hello_use_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$(realpath ../ida-sdk/src/bin/plugins/chernobog.dylib)" \
  --output-dir build/vmp-hello-use-release-llvm --enable-rax \
  --set "CHERNOBOG_VMP_HELLO_WINDOW=$PWD/build/vmp-hello-runtime-final-llvm/runtime-window.bin"
```

Repeat with the Apple LLDB window and an `-apple` output directory. Rebuild
the pinned prior revision `5a02881c69e5` for the prior probe with a fresh
`-prior` directory. Then verify all reports:

```sh
python3 -B tests/verify_vmp_hello_use.py \
  --runtime build/vmp-hello-runtime-final-llvm/report.json \
  --runtime build/vmp-hello-runtime-final-apple/report.json \
  --ida build/vmp-hello-use-release-llvm/vmp_hello_use.json \
  --ida build/vmp-hello-use-release-apple/vmp_hello_use.json \
  --prior build/vmp-hello-use-prior/vmp_hello_use_prior.json \
  --output build/vmp-hello-use-verification-release.json
```

For `E` retained edges, `T` retained states, `B ≤ 256` selected bytes and
`S` snapshot segments, the use projection costs `O(E + T + B·S)` time and
`O(B)` additional space, excluding the existing bounded native trace.
The 11-byte payload and one-byte NUL total 12 bytes; all byte counts and
hash comparisons are exact. The selected call source, pointer and payload
are one sample, not a protected-corpus recovery rate.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| U1 | The exact supplied files and independently captured window identify the same user-attributed pair. The protected/original comparison depends on this identity. | Rehash both files and windows; obtain a recorded protector invocation to test build lineage. |
| U2 | The x86-64 CALL reaches the decoded JMP stub and then the observed `printf` entry without changing `RDI`. The cross-tool argument comparison depends on this path. | Break at the stub and capture `RDI` under an independent tracer; reject the comparison if a different transfer or register value occurs. |
| U3 | The caller-selected source, target and register describe an argument use. The query itself proves only a transfer state and loaded bytes. | Supply wrong call and register selectors; require abstention. Inspect ABI and call target separately before labeling other call arguments. |
| U4 | The shadow bytes represent this stopped-process interval. The one-use runtime comparison depends on that timing. | Capture before/after the call and other inputs; reject any differing window or pointer. The one-byte shadow mutation demonstrates input dependence. |
| U5 | The selected 40-byte IDA inventory detects persistent mutation relevant to this query. The read-only claim is limited to those fields. | Save/reopen and compare broader IDA state and netnodes before claiming full database immutability. |

- **High impact:** a protected, initially unloaded literal now has an explicit
  bounded use-site byte record linked to its call transfer and register.
- **Medium impact:** the result can be compared directly with two debugger
  implementations while preserving the prior native graph and IDA inventory.
- **Low impact:** heap uses, other call sites, callee effects, complete VMP
  paths and logical VM state remain unknown.

QG1: technical claims only. QG2: U1–U5 include falsification probes. QG3:
the explicit API, two current IDA runs, a matched prior run, debugger pair,
negative selectors and byte mutations are covered; the full review remains
in progress. QG4: byte bounds, addresses and complexity are explicit. QG5:
synthetic transfer state, caller contract and observed process state are
separate. QG6: primary sources, binaries, tools and reports are pinned in
`VMP_HELLO_CALL_USE_EVIDENCE.json`. QG7: unsupported uses and call/VM
limitations are bounded above.
