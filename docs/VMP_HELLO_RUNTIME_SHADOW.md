# Supplied VMP hello runtime shadow

The supplied `foo_x86_orig` and `foo_x86_vmp` are the hash-pinned x86-64
Mach-O pair in `VMP_SUPPLIED_SAMPLES.md`. The user attributes the protected
file to VMP. A build invocation, protector settings and seed for that file
are **unknown**. Three earlier no-argument process runs matched exit status,
stdout and stderr; the present checkpoint observes one call site and does not
extend that behavioral claim to other inputs.

In the original file, `__text` at `0x100001440` is 22 file-backed bytes and
`__cstring` at `0x10000145c` is 12 file-backed bytes. The protected file has
the same addresses and lengths, but both section headers specify
`S_ZEROFILL`. The intervening six bytes are an import stub. At a `printf`
breakpoint, two runs each under LLVM LLDB 23 and Apple LLDB 2103 captured
the protected process's entire 40-byte interval
`[0x100001440, 0x100001468)` after accounting for the image slide. All four
captures match the original file's 22 code bytes, six stub bytes and
`Hello World\0` literal exactly. The x86-64 `RDI` value at the breakpoint
equals the captured literal address. Each debugger also captured the
original program twice. Byte, stub and literal mutations in the verifier
are rejected. The 40-byte SHA-256 is
`b9e3295c519d3f937c884f6cbab4e1e708ba16cd94314c15e4e962ddc081a023`.

`chernobog_vm_trace_candidate_shadow(root, seed, local_file_path)` now
accepts an explicit, unknown and unloaded executable root only if IDA already
has a code xref to that exact address and there is no function owner. The
prior data-head contract remains available. Its 1–65,536-byte input may cross
contiguous, readable, nonwritable 64-bit image segments. It overlays bytes
and loaded masks in a temporary image, then plans and executes under the
existing bounds. No IDA retyping or ordinary function proof is published.
The API counts previously loaded bytes that changed, newly loaded bytes and
the number of image segments traversed. The overlay is caller-supplied;
runtime provenance comes from the separate stopped-process capture.

In two fresh IDA 9.4 SP1 runs, the protected `_main` address is unknown,
unloaded and ownerless, with a code xref from `0x100001436`. The current
plugin admits the captured window across two image segments: 34 newly loaded
bytes and four changed previously loaded bytes. The independent IDA mask
oracle agrees with both counts. It plans nine heads and enters six
instructions, stopping at the indirect import stub
`0x100001456` with `environment-model-failure`. Capstone 5.0.7 independently
decodes all nine reported head bytes and lengths. The two candidate graphs
are byte-identical. The prior plugin rejects the same root with
`not_unlabeled_executable_data_head`; ordinary candidate inspection and
interior, literal-only, existing-code, missing-file and oversized-file
controls remain unavailable. The checked IDB segment inventory is unchanged
before and after each query.

This is a **40-byte runtime restoration and bounded native trace**, not a
complete path through `printf`, a VM-region proof or devirtualization.
`environment-model-failure` records the absent import/call environment.
The report contains a return frontier and an indirect-target frontier;
neither is scored as a recovered external edge.

The later `VMP_HELLO_CALL_USE.md` checkpoint adds an explicit byte snapshot
for the call's selected argument register at this frontier. It does not
change the original runtime-shadow report or model the external call.

## Reproduction

Run the paired debugger captures with fresh output directories:

```sh
python3 -B tests/run_vmp_hello_runtime.py \
  --original samples/foo_x86_orig --protected samples/foo_x86_vmp \
  --output-dir build/vmp-hello-runtime-final-llvm --lldb lldb
python3 -B tests/run_vmp_hello_runtime.py \
  --original samples/foo_x86_orig --protected samples/foo_x86_vmp \
  --output-dir build/vmp-hello-runtime-final-apple --lldb /usr/bin/lldb
```

Run the IDA probe with each runtime window in a fresh output directory:

```sh
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_vmp_hello_shadow_probe.py \
  --ida '/Applications/IDA Professional 9.4-sp1.app/Contents/MacOS/idat' \
  --plugin "$(realpath ../ida-sdk/src/bin/plugins/chernobog.dylib)" \
  --output-dir build/vmp-hello-ida-final2-llvm --enable-rax \
  --set "CHERNOBOG_VMP_HELLO_WINDOW=$PWD/build/vmp-hello-runtime-final-llvm/runtime-window.bin" \
  --set "CHERNOBOG_VMP_HELLO_OVERSIZED=$PWD/samples/foo_x86_vmp"
```

Repeat with the Apple window and an `-apple` IDA directory. For the prior
plugin comparison, substitute the hash-pinned prior plugin, use a fresh
`-prior` directory and set `CHERNOBOG_VMP_HELLO_EXPECT_AVAILABLE=0`.
Then run the independent verifier:

```sh
python3 -B tests/verify_vmp_hello_runtime_shadow.py \
  --runtime build/vmp-hello-runtime-final-llvm/report.json \
  --runtime build/vmp-hello-runtime-final-apple/report.json \
  --ida build/vmp-hello-ida-final2-llvm/vmp_hello_shadow.json \
  --ida build/vmp-hello-ida-final2-apple/vmp_hello_shadow.json \
  --prior build/vmp-hello-ida-final2-prior/vmp_hello_shadow.json \
  --output build/vmp-hello-shadow-verification.json
```

The runtime capture checks four process stops per debugger, eight total.
The maximum accepted shadow is 65,536 bytes. For `B` shadow bytes, `S`
image segments and `H` planned heads, overlay search takes at most
`O(BS)` time and `O(B)` extra snapshot bytes, excluding the existing planner
and decoder; the independent head check takes `O(H)` time and space. Counts
are integer byte/instruction counts; SHA-256 comparisons are exact.
`VMP_HELLO_RUNTIME_SHADOW_EVIDENCE.json` pins the primary artifacts, tool
versions, source and report hashes.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | The two pinned files represent the user-attributed original/protected pair. Pairwise restoration depends on that relationship; build lineage is unknown. | Obtain a recorded protector invocation or compare further original/protected code and use sites. Reject the paired claim if provenance or bytes differ. |
| A2 | The LLDB `printf` stop and `RDI` observe an actual string use in these runs. The use-site conclusion depends on breakpoint and register interpretation. | Independently trace the call on physical x86-64 or instrument the argument and compare the address and bytes. |
| A3 | The four protected captures characterize this selected runtime window and input. The restoration claim is limited to these observations. | Capture earlier/later boundaries and other inputs; report any differing byte or address. |
| A4 | IDA's code xref identifies this exact unloaded entry in the pinned database. Candidate admission depends on that metadata. | Remove or redirect the xref in a disposable IDB; require abstention. The interior and literal-only controls already abstain. |
| A5 | The checked segment byte/mask and selected-site inventory detect relevant persistent mutation. The no-mutation result depends on that coverage. | Save/reopen and compare broader IDA state and netnodes if persistent-state coverage is required. |

- **High impact:** a protected, initially unloaded code and literal window can
  be compared with its observed runtime bytes without converting it into an
  ordinary IDA function.
- **Medium impact:** a code xref plus explicit shadow enables a nine-head
  native graph where the prior plugin abstained; the six entered instructions
  stop at a stated import frontier.
- **Low impact:** other VMP regions, runtime mutation schedules, external-call
  semantics and VM identity remain unknown.

QG1: technical artifact and algorithm claims only. QG2: A1–A5 each have a
falsification probe. QG3: exact-file identity, two debugger implementations,
two current IDA runs, one prior run, admission controls and mutation controls
are covered; the larger review remains in progress. QG4: byte counts,
addresses, limits and complexity are explicit. QG5: runtime bytes, IDA
metadata and synthetic execution are distinct. QG6: exact primary artifact,
source, binary and report hashes appear in the evidence JSON. QG7: additional
protected regions and call/VM limitations are bounded above.
