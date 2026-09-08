# Numeric CFString address display

The writable-memory constant-folding correction leaves some CFString uses as
64-bit address numerals. Replacing a numeral with a C string literal changes the
stored pointer. This display path instead constructs an integer cast of the
address of the same IDB object. Its line annotation separates the descriptor
relation in the current IDB from backing bytes observed at a specific address
in eligible runtime runs.

The benign fixture decodes `projection-one` and `projection-two` by XOR with a
writable key, then stores ten descriptor-related values through a writable
destination pointer. Each plaintext is 14 ASCII bytes plus NUL. The native
executable checks both buffers and every stored value, then repeats with a
nonzero arithmetic offset and the alternate store-entry branch taken.

Two stores have consecutive AArch64 `ADRP; ADD; STR` address construction.
Negative stores supply malformed flags, a length mismatch, a different class,
a payload without a runtime witness, an intervening MOV, address arithmetic,
an alternate native store entry, and a 32-bit store.

Local assembly labels identify the stores through an exported table of 32-bit
function-relative offsets. Exporting code labels caused the linker to add
function starts and IDA to split the function; that preliminary build was
discarded. The final fixture has no artificial store-site functions.

## Reproduction

```sh
xcrun clang -arch arm64 -O1 -g0 -fno-builtin -Wall -Wextra -Werror \
  tests/runtime_strings/numeric_cfstring_fixture.c \
  tests/runtime_strings/numeric_cfstring_fixture.S \
  -framework CoreFoundation -o /tmp/numeric_cfstring_fixture_v2
/tmp/numeric_cfstring_fixture_v2
python3 tests/run_ida_smoke.py --ida /path/to/idat \
  --plugin /path/to/chernobog.dylib --enable-rax --verbose \
  --output-dir /tmp/chernobog-numeric-cfstring-validation \
  /tmp/numeric_cfstring_fixture_v2 tests/ida_numeric_cfstring_smoke.py
```

The framework supplies the normal class-reference import; no CoreFoundation
API is called. The probe never creates xrefs, changes permissions, or injects
plaintext. It first runs the independent runtime-analysis action, recording
the resulting automatic interior `unk_` names and checking unchanged bytes.
All later decompilation/display stages require exact monitored bytes, names,
ordinary/function comments, and saved ctree-comment counts to remain unchanged.

Each stage checks the ctree assignment and uses `find_item_coords()` to require
the exact descriptor/payload/plaintext annotation on that assignment's line.
It checks repeated rendering and rejects saveable ctree comments. Three
explicit, restored IDB edits test a descriptor retargeted to the second
witnessed payload, a length mismatch, and a payload without a runtime fact.
Each is followed by uncached decompilation.

## Assumptions and falsification probes

- N1: The target is little-endian AArch64 with 64-bit flat addresses. Original
  and replacement store types remain signed 64-bit integers, and the address
  AST identifies the exact original numeral. Other address models are untested.
- N2: The supported descriptor uses the non-Swift narrow compiler layout:
  class pointer, 32-bit flags plus padding, backing pointer, target-long length.
  The probe checks all four slots and tests bad class, flags, and length.
- N3: Runtime strings are final-memory witnesses, not use-time object
  observations or universal input proofs. The annotation names the current IDB
  relation and runtime backing address separately. Header retargeting must
  update that relation or reject it while preserving the original address.
- N4: Native admission depends on the bounded instruction pattern and
  IDA-visible control flow. MOV-only and arithmetic cases test rejection.
  Missing IDA xrefs do not exclude unknown indirect entries.
- N5: Coverage depends on actual ctree shape, recorded in the report. The first
  seven stores have numeric RHS operands; arithmetic remains an addition.
  IDA already renders alternate-entry and narrow stores as address casts in
  the baseline, so those cases test overlay rejection and width preservation.
- N6: Live observations use IDA 9.4 on arm64 macOS. Native execution, raw
  instructions, ctree structure, rendering coordinates, and runner hashes
  supply independent observations on that configuration.

High-impact constraint: plaintext display preserves object addresses and does
not admit writable bytes into constant propagation. Medium-impact limitation:
other address constructions and CFString representations remain unannotated.
The probe is linear in visited ctree nodes and monitored bytes per stage; its
retained reports/cfuncs grow with the fixed six-stage test. No speedup is claimed.

For the production traversal, let N be ctree nodes, C runtime candidates, T
their total payload bytes, K candidate stores, D inspected incoming code xrefs,
and S the total existing text on annotated lines. Excluding the existing
runtime-evidence getter and opaque SDK symbol/type/coordinate-query costs
(unknown here), time is
`O(N + C log C + T + D + sum_i(L_i + log C) + K log K + S)`,
where descriptor payload lengths satisfy `1 <= L_i <= 4095` bytes.
Candidate maps, new address-expression nodes, and collected annotations require
`O(C + T + K)` additional space. Each rendered fact exposes at most 128 payload
bytes, escaped as needed, and each line receives at most two facts. These
bounds describe the added work; they are not measured latency claims.

## Provenance

Clang's [constant CFString emitter](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/CodeGenModule.cpp)
uses `0x7C8` for ASCII and `0x7D0` for UTF-16, with a class reference, backing
pointer, and target-long length. Non-ASCII or embedded-NUL source literals use
UTF-16. The object is not a constant LLVM global; its section does not establish
operating-system immutability.

The SDK describes [number-format fields](https://cpp.docs.hex-rays.com/structnumber__format__t.html)
as representation metadata and [offset resolution](https://cpp.docs.hex-rays.com/offset_8hpp.html)
as an operand-specific calculation. A numeral's radix/type alone does not prove
address origin.

The live callback diagnostic
`/tmp/chernobog-numeric-cfstring-aldaz-gate/maturity_events.json` observed
`CMAT_FINAL` event value 8 while `cfunc->maturity` was still 7. The caller must
pass the event maturity into this final-stage transformation; checking only
the lagging cfunc field suppresses it. This is an observed IDA 9.4 lifecycle
behavior, not an assumed ordering for every SDK.

The installed IDAPython source
`/Users/int/dev/ida-sdk/src/plugins/idapython/swig/hexrays.i:526` implements
`cfunc_t.__str__` using `print_func(qstring_printer_t)`. It prints the ctree
directly and omits the `sv` decoration added by `hxe_func_printed`.
`get_pseudocode()` returns that rendered line collection. The probe therefore
checks repeated rendered lines directly and saves both displayed output
(`numeric_cfstring_<stage>.txt`) and direct AST output
(`numeric_cfstring_<stage>_ast.txt`). A plaintext overlay is deliberately not a
`cot_str` pointer replacement.

## Baseline evidence

On 2026-09-08, the final native fixture exited 0; SHA-256:
`553c6578af32a79f2a9f400ba1e1703b5b709ef2be94d7505eff5d51e45b21fd`.
The final executed probe SHA-256 was
`54d9071ead9dd3cd324b6919b182eaacafef14a55530331363b3245376654e72`.

The preserved baseline plugin
`/tmp/chernobog-numeric-cfstring-baseline-artifact/chernobog.dylib` had SHA-256
`dc88aca772593f79c8d4f113a3697ee165e5a14c51f72b86d004e149b7a99797`.
The decisive baseline `/tmp/chernobog-numeric-cfstring-before-04` exited 6:
valid uses stayed numeric and lacked the requested annotations. All six stages
completed, negative-use checks passed, and display metadata remained unchanged.
Runner artifact-integrity checks passed.

The first modified artifact, SHA-256
`d44f19dc53326b6a4155422a3b10dd4412dda42ecd9ab2d27fbc181c62c29fa9`,
also failed the positive checks in `/tmp/chernobog-numeric-cfstring-after`
with matching fixture/probe/IDA/configuration hashes against its preceding
`before-03` baseline (probe SHA-256
`29555c49d798bbf0b0ad8fed97dd5e28c9c4f3a8c7305a4158b7731c9efde930`).
The callback lifecycle
diagnostic above identified the admission issue; that intermediate run is not
a passing verification.

## Final paired verification

The matched final run `/tmp/chernobog-numeric-cfstring-after-03` exited 0
using plugin SHA-256
`901d114b02156e02695782415779b40422a6b7702c1e2c46ab78b1cdefe5ca1a`
(source fingerprint `7bc4785e3333`, SDK `940`). Both admitted addresses retain
their exact signed 64-bit value through `cot_cast -> cot_ref -> cot_obj`.
Eight negative use sites remain unannotated. Initial, repeated, retargeted,
and restored stages have two precise overlays; length and missing-fact
rejections leave only the unaffected second object's overlay.

All six stages preserve monitored IDB bytes, names, and ordinary/function
comments, with zero active or saved ctree comments. Three explicit probe edits
are restored. Repeated rendered-line collections are identical. The paired
input and probe hashes above match, along with IDA executable SHA-256
`387d681d6fb4f4c1c485a60025cae3f0affa6f5ea1efce3b1809639cb1aaeb28`
and configuration SHA-256
`12f3627209554e0b63207480d17b0f2ee57d860ad6fb5e0fcc5d4edde7d6c115`.
Runner artifact-integrity checks passed in both runs.

The separate Aldaz integration pair used the displayed-pseudocode API while
retaining all eleven original literal assertions and adding the same eleven
checks after a second uncached decompilation. The matched runs
`/tmp/chernobog-numeric-cfstring-aldaz-before-ui-03` and
`/tmp/chernobog-numeric-cfstring-aldaz-after-ui-03` exited 5 and 0 respectively,
using the same baseline/final plugins listed above. Shared hashes were:

- Input: `8d3b411b17805d0f39150f9afe03e1f2b82f6e161ffde37191abc04d96bc1fa8`.
- Probe: `8f851569078bd957f2a5e8d6ab8c683e0dfb632200f2b9ab74dc6b86815aa016`.
- IDA executable: `5f75ebbf4ff6424ebdec1c5d72b1e9d669d04e25b4d5f7b2aec35ad4fea1c7fa`.
- Configuration: `8bdbb84bae77b5186f445c81647c4c249e8e95f6b2856a4d527af8a15f0bba98`.

Both Aldaz runner records report artifact integrity. An independent diagnostic
in `/tmp/chernobog-numeric-cfstring-aldaz-rendered-diagnostic-03` also exited 0:
seven use sites preserve exact object address, type, and expression address,
with protected casts and seven corresponding line overlays. Descriptor bytes
remain unchanged; the previously missing four strings are not AST `cot_str`
replacements. Its probe SHA-256 is
`607992f197d117536c13807c919ab212432b02ee33d204ba324d5c8758f9a8da`.
These are correctness comparisons; their single-run timings establish no
performance change.

The final integration CTest run passed all 10 tests in 8.28 s; retained log:
`/tmp/chernobog-cfstring-catalog-final-ctest.log`. The address decoder's 20
additional golden cases in [core_tests.cpp](core_tests.cpp), comprising six
accepted and fourteen rejected instruction sequences, also passed with
AddressSanitizer and UndefinedBehaviorSanitizer. The independently assembled
[native instruction oracle](aarch64_address_origin.s) supplies instruction-word
provenance. These checks accompany the live results above; the plugin artifact
remained `901d114b…` after the test-target rebuild.
