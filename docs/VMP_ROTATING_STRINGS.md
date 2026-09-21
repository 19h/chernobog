# Bounded rotate/add/XOR string recognition

Chernobog recognizes a restricted class of native integer loops implementing
the supplied source tree's rotate/add/XOR string transform. It proves the value
expression for every admitted loop index and every possible byte or word input,
then separately validates the resulting text. The current ctree printer adds a
transient annotation with the key, bound, unit width, encoding candidate, and
plaintext. Instruction bytes, data bytes, expressions, and saved comments are
unchanged by this feature.

This is a bounded implementation of review requirement 3c. The independent
fixtures cover x64 Mach-O and linked x86 ELF ctree recognition; only the x64
fixture was executed. They were not produced by VMP. Coverage of the supplied
protected hello-world and the broader protected corpus remains **unknown**.
Exact source and artifact hashes are recorded in
[VMP_ROTATING_STRINGS_EVIDENCE.json](VMP_ROTATING_STRINGS_EVIDENCE.json).

**Primary source basis**

The local source snapshot contains these distinct contracts:

| Logical source reference | Observed operation |
|---|---|
| `vmp/core/intel.cc:22388–22396` | `EncryptString(const char *, key)` XORs each byte with the low 8 bits of `ROL32(key, i) + i`; emits the encrypted plaintext terminator |
| `vmp/core/intel.cc:22399–22408` | The `os::unicode_char` overload uses `PushWord` and the low 16 bits of the same schedule; `i` counts words, including the terminator |
| `vmp/runtime/string_manager.cc:139–153` | `VirtualString` iterates the recorded byte size and applies the byte transform, regardless of a later text interpretation |
| `vmp/runtime/crypto.h:29–35` | The GNU `_rotl32` implementation uses a 32-bit native rotate with the count in CL |

For unit width w in {8, 16} bits and zero-based unit index i, the admitted
contract is:

```text
mask(i) = (ROL32(key, i mod 32) + i) mod 2^w
plain[i] = cipher[i] XOR mask(i)
```

Addition before truncation and addition modulo 2^32 have the same low w bits.
The implementation verifies the actual typed expression, including extensions
and truncations. Integer operations are finite-width bitvector operations;
this is not a claim about undefined signed overflow in a recompiled C program.
Floating-point conversions, Boolean normalization, enums, volatile scalar
operations, and unsupported operations are outside the admitted expression
language.

The byte transform alone cannot identify whether code came from the loader,
`VirtualString`, or another producer with the same formula. The annotation
therefore names the operation and its proven parameters. It does not assert
vendor identity or a unique source routine. UTF-16 text never selects the
16-bit transform: the byte-encrypted UTF-16 fixture retains an 8-bit unit label.

**Implementation and proof boundary**

| Component | Responsibility |
|---|---|
| `src/common/rotating_string_transform.h` | Typed expression evaluation, finite-index symbolic proof, byte recovery, independent explicit encoding validation |
| `src/deobf/handlers/rotating_string_ctree.cpp` | Bounded loop extraction, native-origin guards, loaded-byte and permission checks, current-function proof receipts and print annotations |
| `src/plugin/deobf_plugin.cpp` | Captures at final ctree maturity for admitted functions; renders under current function policy; clears receipts with database processing state |
| `tests/rotating_string_tests.cpp` | Independent rotate oracle, byte/word and endian checks, input-bit instantiation, malformed-program and wrong-transform controls |
| `tests/vmp_native/string_transforms.c` | Independent compiled positive and negative native fixtures with exact expected output |
| `tests/ida_string_transform_probe.py` | Actual decompiler shape capture, annotation assertions, byte/permission invalidation and comment/byte preservation controls |

The current adapter accepts one top-level bounded do/while/for loop, a
zero-initialized unit counter incremented by one, optional independently bounded
offset counters, and one byte or word store per iteration. Scalar temporaries
may precede the store; only admitted counter increments may follow it. Source
and destination use resolved image objects and exact unit strides. The key is
literal. A source range must be wholly loaded, readable, and non-writable; the
destination must be writable, nonoverlapping, and contained in one segment.
Source loads and stores must have compatible native memory operand widths;
the rotate helper must map to a native 32-bit rotate in the same function.

The proof represents each output bit as a constant XOR a set of symbolic input
bits. Casts and XOR preserve that exact representation. Index substitution
makes the schedule operands constant; addition, subtraction, and rotation are
admitted only on constants. Equality with the required input identity and
schedule constant proves every possible unit value for that index. No cipher
input is sampled to decide equivalence.

```text
extract bounded typed loop and exact source/destination unit strides
for each index in [0, units):
    substitute the concrete index into the expression
    evaluate casts/XOR over symbolic input bits
    reject unsupported nonconstant arithmetic
    require output constant == mask(index)
    require output bit coefficients == input identity
recover exact bytes from the current loaded ciphertext
validate UTF-8; otherwise validate UTF-16LE independently
retain a receipt only for terminated text with at least four scalar values
before each print:
    re-extract and compare the exact typed shape
    recheck function owner, chunk bounds, bitness, permissions and loaded bytes
    annotate the matched store with a bounded, escaped text candidate
```

This proves a value expression under the extracted loop and memory contract.
It is not an independent proof of Hex-Rays translation, all native execution
paths, exceptions, external entries, or concurrent writes. No control-flow or
instruction removal follows from the result. The text is the loop output under
that contract, not the destination's final value after arbitrary later code.

**Bounds and complexity**

| Limit | Bound |
|---|---|
| Ciphertext B | At most 8,192 bytes, including the terminator |
| Unit count N | 1–8,192 byte units or 1–4,096 word units |
| Typed expression D | At most 128 nodes; widths 8, 16, 32, or 64 bits |
| Native function C | One chunk, at most 65,536 fully loaded bytes |
| Ctree structure | At most 64 root statements and 32 loop statements; bounded recursion |
| Retained receipts K | At most 64 across open databases/functions |
| Text shown | At most 128 UTF-8 payload bytes, ending at a scalar boundary; longer text explicitly marked truncated |

For fixed maximum bit width W = 64, the proof costs O(N·D·W) time and O(D·W)
working space. Extraction, byte checks, and decoding add bounded tree work and
O(B+C) byte work. Receipt storage is O(K·(B+C+D·W)); printing rechecks the stored
shape and bytes without rerunning the symbolic proof. These are algorithmic
bounds, not measured latency or memory-consumption claims.

**Measured validation**

The final validation uses the same plugin and probe hashes for both production
architectures. The manifest records exact artifacts and elapsed times.

| Check | Result and scope |
|---|---|
| Full CTest run | 13 suites pass, zero failures |
| AddressSanitizer / UndefinedBehaviorSanitizer | Portable proof tests pass with both enabled; no diagnostic emitted |
| Independent schedule oracle | 64 keys × 2 unit widths × 257 indices = 32,896 exact comparisons; seed `0x845719`, with zero/all-one corner keys |
| Symbolic byte instantiation | 65 indices × 256 inputs = 16,640 exact comparisons, including signed extension followed by truncation |
| Portable negative controls | Wrong direction/index/key/rotate width/input width, nonconstant addition, cyclic nodes, excess bounds, and signed counter overflow abstain |
| Encoding controls | UTF-8, explicit UTF-16LE/BE, byte-encrypted UTF-16, wrong-unit schedule, invalid surrogate, and missing terminator |
| Native x64 oracle | Executes three positive routines and compares every output byte/word; exit status 0 |
| Production x64 Mach-O | 12 routines, 51 assertions pass: three positive and nine abstaining negative routines plus freshness/preservation controls |
| Production x86 ELF | The same 12 routines and 51 assertions pass; static decompilation only, no native x86 execution claim |

Production positives recover `VMP byte` as 8-bit units, `VMPΩ` as 16-bit units,
and `Wide` as UTF-16LE using 8-bit units. Negatives cover right rotation,
off-by-one schedule, unknown key, absent terminator, 8-bit rotation, byte-indexed
word schedule, writable ciphertext, in-place aliasing, and an extra loop write.
For every positive, ciphertext or native-byte edits and writable-source
permissions remove the annotation on refresh; exact restoration restores it.
Every fixture retains its native bytes and has no saved/saveable comments.

The portable oracle does not independently validate compiler code generation.
The native execution check and production ctree checks supply different evidence;
none establishes general protected-program coverage. Intermediate captures are
retained separately from the final manifest's runs.

Reproduction uses the existing configured build and local toolchain:

```sh
cmake --build build --target chernobog chernobog_rotating_string_tests -j 4
ctest --test-dir build --output-on-failure
clang -arch x86_64 -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
  -O1 -fno-unroll-loops -fno-vectorize -fno-slp-vectorize \
  tests/vmp_native/string_transforms.c -o build/vmp-string-transforms
build/vmp-string-transforms
clang -target i386-unknown-linux-gnu -ffreestanding -fno-pic -fno-stack-protector \
  -O1 -fno-unroll-loops -fno-vectorize -fno-slp-vectorize -c \
  tests/vmp_native/string_transforms.c -o build/vmp-string-transforms32.o
ld.lld -m elf_i386 -e main --build-id=sha1 \
  build/vmp-string-transforms32.o -o build/vmp-string-transforms32
```

For each fixture, run `tests/run_ida_smoke.py` with
`tests/ida_string_transform_probe.py`, the configured IDA/plugin locations,
a new output directory, and `--set CHERNOBOG_EXPECT_STRING_TRANSFORMS=1`.
No rax execution is needed for this static feature. The ELF entry is a
decompilation fixture entry, not a complete Linux process-startup implementation.

**Assumption register and falsification probes**

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| S1 | Source claims refer only to the hashed local snapshot | Rehash the three primary source files and inspect the referenced overloads; a difference invalidates the snapshot attribution |
| S2 | Typed final ctree correctly represents execution from the function entry through the admitted loop | Compare recorded ctree/native operands and native expected outputs; inconsistent translation, extra control, unsupported types, or offsets reject admission or invalidate this assumption |
| S3 | Loaded source bytes and IDB non-writable permissions describe immutable input during this loop | Cipher/code edits and permission changes invalidate display; runtime remapping or external mutation is outside the contract |
| S4 | Strict decoding establishes a possible text interpretation, not source identity or program intent | Byte-encrypted UTF-16 and wrong-unit fixtures distinguish these claims; malformed or unterminated text rejects publication |
| S5 | Retained facts describe the same current function and expression | Re-extract the complete typed shape and compare all function/cipher bytes, owner, chunk bounds and bitness; full reopen/rebase/undo/type-edit lifecycle coverage remains incomplete |

All recovery claims depend on S2/S3/S5; source attribution depends on S1 and text
interpretation on S4. Dynamic keys, heap destinations, noncanonical loops,
multiple stores, most optimized loop variants, and unsupported architectures
remain explicit abstentions. Further protected fixtures and the remaining
lifecycle matrix are required before requirement 3c can be marked complete.

**Bounded expansion and quality gates**

High impact: separating transform units from text encoding prevents choosing a
word key schedule merely because bytes decode as UTF-16. Medium impact: symbolic
input bits prove a restricted transform over all unit values without an SMT
solver; unsupported nonlinear input arithmetic still requires another proof
method. Medium impact: exact current-tree and byte checks keep transient text
from becoming a persistent stale comment. Low impact: literal-key/image-buffer
constraints limit coverage; relaxing either needs new provenance and lifetime
contracts, not just a looser pattern match.

QG1: technical scope only. QG2: S1–S5 include falsification probes. QG3: this
bounded 3c slice has implementation and measured production checks; the full
review remains incomplete. QG4: counts and finite-width arithmetic are exact;
bytes, bits, and elapsed seconds are distinct. QG5: unknown native/protected and
lifecycle coverage is explicit. QG6: primary source and exact build/run hashes
are recorded. QG7: adjacent opportunities and limits are bounded above.
