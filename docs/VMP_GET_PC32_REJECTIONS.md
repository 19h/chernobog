# Executed ELF32 stack-transfer abstention controls

Review items 1a and 1b require unresolved targets to remain unresolved and
stack effects to remain explicit. A new static ELF32/i386 fixture executes the
same four rejection shapes that the linked analysis fixture previously checked
only in IDA. The production probe inspects **the same binary** that QEMU
executes. The binary is not a protected VMP sample; it tests the architectural
contract underlying those review items.

The process executes seven cases in order:

| Transfer | Inputs and observed result | Stack observation |
|---|---|---|
| `push %edi; ret` | `%edi` points first to a function returning 7, then to one returning 8 | ESP returns to its entry value after each call |
| `push gp32_rw; ret` | The writable 4-byte object is set first to the address returning 7, then to the address returning 8 | ESP returns to its entry value after each call |
| Conditional predecessor followed by `push target; ret` | `%edi=0` takes the pushed target and returns 7; `%edi=1` skips the push and returns the caller's preset EAX value 42 | Both paths restore ESP |
| `push target; ret $4` | A supplied continuation is reached after RET discards the CALL return address; the marker below the continuation remains intact | The caller consumes the marker and ESP returns to its entry value |

The adjusted-return case uses 32-bit stack words. If initial ESP is `S`, the
caller pushes a marker at `S−4`, a continuation at `S−8`, and CALL places its
return address at `S−12`. The callee pushes the target at `S−16`. `ret $4`
pops that target and advances ESP by another 4 bytes to `S−8`. The target's
RET then pops the supplied continuation, leaving ESP at `S−4`; consuming the
marker restores `S`. Each offset is in bytes. This trace explains why a
plain push/RET summary would have the wrong return-address effect.

The positive binary exits 0 only after all seven cases pass. A build that
changes the second target's result from 8 to 9 exits 1. Under the installed
plugin, IDA reports no unique edge for the register and writable-memory RETs,
and annotates both as unresolved candidates. It makes no Chernobog summary for
the conditional or adjusted-return RET. The matched disabled-plugin run has
the same edge sets and no Chernobog comments; the edge that IDA itself places
on the conditional form is not attributed to Chernobog.

## Assumption register

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | The pinned QEMU i386 translator implements these normal-execution instructions and Linux `int $0x80` exit behavior. All process observations depend on this. | Positive status 0 and result-mutation status 1 under the pinned image. Physical i386 and another independent emulator are **unknown**. |
| R2 | The two calls of each dynamic transfer can reach distinct target functions. Unique-target rejection depends on this. | Same-binary process requires results 7 and 8, and IDA confirms distinct target addresses. Source and disassembly show the two EDI values and two writes to `gp32_rw`. |
| R3 | IDA's enabled and disabled runs load identical input and plugin bytes; metadata attribution depends on this. | Compare `run.json` input/plugin hashes, return codes, edge sets, and comments in the two retained run directories. The runner isolates IDA state. |
| R4 | The crafted adjusted-return stack has the intended word order. The RET-effect conclusion depends on this. | Process checks the marker, result, and final ESP. Disassembly shows the two caller PUSHes, CALL, callee PUSH/`ret $4`, and target RET. Fault/exception behavior outside this admitted path is **unknown**. |

## Reproduction and provenance

```sh
clang -target i386-unknown-linux-gnu -c tests/vmp_native/get_pc32_rejections.S -o build/vmp-get-pc32-rejections.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32-rejections.o -o build/vmp-get-pc32-rejections
clang -target i386-unknown-linux-gnu -DGP32_NEGATIVE_CONTROL -c tests/vmp_native/get_pc32_rejections.S -o build/vmp-get-pc32-rejections-negative.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32-rejections-negative.o -o build/vmp-get-pc32-rejections-negative
docker --context orbstack run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --mount type=bind,src="$PWD/build",dst=/output,readonly \
  sha256:7b1781979ac73774803cdcd1ce8797d345cbae204731e0e684c1d74e89bef654 \
  /usr/bin/qemu-i386 /output/vmp-get-pc32-rejections
# Repeat with vmp-get-pc32-rejections-negative; expect status 1.
python3 -B tests/run_ida_smoke.py build/vmp-get-pc32-rejections \
  tests/ida_get_pc32_rejections.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/get-pc32-rejections-new-enabled \
  --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64
python3 -B tests/run_ida_smoke.py build/vmp-get-pc32-rejections \
  tests/ida_get_pc32_rejections.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/get-pc32-rejections-new-disabled \
  --set CHERNOBOG_IDA_ANALYSIS=0 \
  --set CHERNOBOG_GET_PC32_REJECTION_BASELINE=1
python3 -B tests/verify_get_pc32_rejections.py \
  build/get-pc32-rejections-new-enabled build/get-pc32-rejections-new-disabled
```

| Artifact | SHA-256 or result |
|---|---|
| Assembly source | `faa957ed5ace171115bc5c76d9275cfe21cc061c10ba90675ad17cc90f1a9245` |
| IDA probe source | `dce2b2a3a67b283c3e1a91672e267fa98c69d3470d2a8a4e9756c2dbe5a1f1d2` |
| Matched-run verifier source | `d456826784a5956fcc117818f68dce9257d59f098466abfbf59fda25a0e933e8` |
| Positive ELF32, QEMU status | `dcb4f45c1a01e1d952b6717ebc4134af5f23e7714d33253143858a654c9520ea`, 0 |
| Negative ELF32, QEMU status | `860501c77fd2a1abc5a0309b198b11dfaa2c4f0ea347020cd22eb71c17bbf32a`, 1 |
| Container image ID | `sha256:7b1781979ac73774803cdcd1ce8797d345cbae204731e0e684c1d74e89bef654` |
| `qemu-i386` SHA-256 | `25939c0dba72ea1b8124b583c00d7c9b9afa6b4cb38a182f5808f2ca31b3b566` |
| Installed plugin SHA-256 | `8a4565bdbc682ec3f59eb4ea0b298c9a6accee993109a298003fe5279d50f3c6` |
| IDA 9.4 executable SHA-256 | `387d681d6fb4f4c1c485a60025cae3f0affa6f5ea1efce3b1809639cb1aaeb28` |
| Enabled / disabled IDA probes | 11/11 assertions each, process status 0 each |
| Matched-run verifier | Pass; identical input/probe/plugin/IDA identities and four RET edge sets |

The final IDA reports and runner manifests are in
`build/get-pc32-rejections-final-enabled` and
`build/get-pc32-rejections-final-disabled`. Both verify the same input, probe,
plugin and IDA hashes. The source file is not added to the historical
`VMP_GET_PC_EVIDENCE.json` manifest, whose hashes describe an earlier revision.

## Bounds and quality gates

The executable performs seven fixed transfers and O(1) local checks, excluding
the loader and translator. The IDA probe reads four RET sites, two target
addresses, one 4-byte object, and its two write references; its local work and
retained report are O(1), excluding SDK analysis. No latency or universal
recovery rate is inferred from this one fixture.

High impact: a writable initial target can be correct at load time and wrong at
use time. Medium impact: IDA can supply an edge for a conditional shape that
the plugin correctly declines to own. Low impact: the custom adjusted-return
caller is intentionally nonstandard; only its explicit stack contract is
validated.

QG1: technical analysis only. QG2: R1–R4 state stress tests. QG3: the bounded
rejection controls are covered; the full review ledger remains in progress.
QG4: 32-bit words, 4-byte object, byte offsets, results and statuses are exact.
QG5: enabled/disabled metadata ownership and observed dynamic multiplicity are
separate. QG6: source, binaries, plugin, IDA and translator identities are
recorded. QG7: adjacent memory and IDA-edge risks are bounded above.
