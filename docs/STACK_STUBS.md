# Bounded 32-bit stack stubs

Chernobog recognizes two saved-register dispatch forms: two PUSH operations,
LEA pairs materializing a continuation and handler, a continuation store at
`[ESP+4]`, and either `PUSH; MOV reg,[ESP+4]; RET 4` or
`XCHG [ESP],reg; RET`. Each PUSH can also be `LEA ESP,[ESP-4]; MOV [ESP],reg`.
The seven non-ESP general registers are supported. Prefixes, unmodeled
instructions, conflicting registers and alternate interior entries are rejected.
Parsing is bounded to 128 bytes and 32 instructions. The independent byte
classifier takes O(bytes) time and bounded storage; the IDA return-site search
checks at most 32 candidate starts.

At handler entry, relative to incoming `ESP=S` and saved register `R`:

```
EIP = handler, ESP = S-4, [ESP] = continuation, saved register = R
```

All original stack accesses remain, including the implicit lock of memory
XCHG. The continuation is reported separately and is not a bypass target.
Native annotations and handler edges use existing ownership receipts and
dependency invalidation. Early Hex-Rays lowering requires the complete stub
and handler to already belong to the same function. It retains the original
instructions, replaces the final return with one natural-width POP, an optional
4-byte ESP adjustment, and a GOTO to the handler. RET's immediate adjustment
does not read the skipped word. Cross-function handlers retain native evidence
without this lowering. Existing PUSH/RET and early call/pop controls apply.

This is independently implemented recognition of instruction semantics. It
does not import Peacestone code or implement WARBIRD decryption, continuation
tables, MAC routines, PE rewriting or entry-point replacement.
The analyzed instruction patterns are recorded in
[Peacestone's notes](https://github.com/UMSKT/peacestone/blob/3e6e17ab7dd76207e0534701646c365b2ad94eb9/notes.txt).

## Validation and assumptions

`stack_stub_tests.cpp` covers all 84 register/form/PUSH-substitution variants,
truncated encodings, malformed returns, address wrap and rejected aliases.
`stack_stubs32.S` independently executes all variants under 64 arithmetic-flag
profiles, checking registers, ESP and residual stack words. Defining
`STACK_STUB_NEGATIVE_CONTROL` introduces a flag clobber that the oracle must
reject; `STACK_STUB_NEGATIVE_STACK` corrupts an otherwise untouched stack word.
The executable is a freestanding multiboot ELF32 image; successful
QEMU `isa-debug-exit` status is 33 and rejection is 35.
`ida_stack_stub_smoke.py` checks native proof records, initial microcode and
synchronous revocation after a byte patch or alternate interior entry in an
isolated IDB. All 84 cases passed with IDA 9.4 SP1 and its 32-bit x86
decompiler, including adjacent and non-adjacent handlers. Scripted reanalysis
explicitly invokes `chernobog_native_analysis()` after IDA finishes, matching
the plugin post-analysis callback used during ordinary interactive analysis. Its explicit function ownership is fixture setup, not evidence
that arbitrary protected inputs recover function ownership automatically.

The initial native run completed 84 x 64 = 5,376 combinations with exit status
33. The deliberate flag-clobber and stack-corruption builds exited 35.
The portable parser tests, including 10,000 deterministic malformed inputs, passed with AddressSanitizer
and UndefinedBehaviorSanitizer enabled.

Reproduce the independent machine check with:

```sh
mkdir -p out/stack-stub-validation
clang -target i386-unknown-linux-gnu -c tests/vmp_native/stack_stubs32.S -o out/stack-stub-validation/positive.o
ld.lld -m elf_i386 --image-base=0x100000 -e _start out/stack-stub-validation/positive.o -o out/stack-stub-validation/positive.elf
qemu-system-i386 -kernel out/stack-stub-validation/positive.elf -display none -monitor none -serial none -no-reboot -device isa-debug-exit,iobase=0xf4,iosize=4
```

Compile again with `-DSTACK_STUB_NEGATIVE_CONTROL` and separate output paths
for the negative control. The CMake test is `chernobog.stack_stubs`; run the
IDA probe with `tests/run_ida_smoke.py` and the exact plugin artifact under test.

| Assumption | Dependent behavior | Falsification probe |
|---|---|---|
| Flat 32-bit near transfers and ordinary readable/writable stack | Handler-entry summary | Prefix, far-return, stack alias and truncation rejection; independent machine execution |
| Complete instruction boundaries and incoming-edge inventory | Native edge and microcode lowering | Add an interior branch; patch a supporting instruction; verify immediate revocation |
| QEMU models the admitted instructions correctly | Executed register/flag/stack comparisons | Run the deliberate flag-clobber control; repeat on physical i386 for independent hardware evidence |

Physical i386 execution and whole-program WARBIRD deobfuscation are untested.
High impact: handler bypass requires separate semantic proof. Medium impact:
cross-function ownership can prevent lowering despite a valid native target.
Low impact: syntactically equivalent encodings outside the admitted grammar
remain unresolved. Source semantics, executed machine checks and IDA checks
are distinct evidence; none establishes whole-program equivalence.


## Supplied WARBIRD samples

An executable-section byte census using `classify_stack_stub32` found:

| Supplied sample label | File version | Bytes | RET 4 form | XCHG/RET form |
|---|---|---:|---:|---:|
| `rootfs/sppsvc.exe` | 6.0.6001.16460 | 2,595,152 | 16,657 | 162 |
| `sppsvc.exe` | 10.0.14361.1000 | 4,970,360 | 0 | 0 |

Sample SHA-256 identities:

- `rootfs/sppsvc.exe`: `d32fd90a270eb0cc462d0412711297f21d90a89b448f7dd8031f484bdff10faa`
- `sppsvc.exe`: `424702e276c09d5a578055fa0e8f50e1f174028cd8bb593aaa4896e74b168636`

The census scans each raw-backed executable section at every byte offset,
using `ImageBase + section.VirtualAddress + offset` as the candidate address.
It counts byte matches before IDA's instruction-boundary and ownership checks.
It does not establish that every match is reachable or admitted by the IDA
adapter. In the Vista sample, 9,574 matches target VA `0x0120f7fb` and 6,928
matches target VA `0x0120f753`. These dominate the observed legacy grammar.
The newer sample requires additional pattern and metadata research; zero
matches for this grammar does not imply the absence of WARBIRD protection.
Neither sample has been rewritten or executed by these checks.
