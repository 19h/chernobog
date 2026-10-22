# ARM64e primitive support

Chernobog retains pointer-authentication value operations in microcode, rather
than treating every PAC/AUT instruction as an arithmetic identity. Native
instruction bytes remain unchanged. This is an address and decompilation model;
it does not implement a cryptographic PAC engine.

| Family | Handling |
| --- | --- |
| PACIA/PACIB/PACDA/PACDB and zero-modifier forms | Explicit 64-bit signing intrinsics and opaque signed-pointer provenance |
| AUTIA/AUTIB/AUTDA/AUTDB and zero-modifier forms | Explicit authentication intrinsics; matching sign/auth chains recover the raw address origin |
| XPACI/XPACD | Explicit stripping intrinsics; recover an origin only from the matching instruction/data signing domain |
| PACIA1716/PACIB1716/AUTIA1716/AUTIB1716 | Preserve X17 and X16 value dependencies |
| PACGA | Explicit keyed-value intrinsic; its result is not replaced with its input or a guessed signature |
| LDRAA/LDRAB | Authenticate the base, add the signed byte offset, read 64 bits, then perform optional writeback |
| BRAA/BRAB/BRAAZ/BRABZ/BLRAA/BLRAB/BLRAAZ/BLRABZ | Preserve key/modifier dependencies and a branch-authentication guard; retain native call/link setup |
| RETAA/RETAB and conventional LR hints | Retain the native frame/return generator; recognize balanced protected identity wrappers |
| BTI | Retain native handling; call-identity analysis accepts call-compatible landing pads and rejects BTI J |

The decoder distinguishes SP, XZR and a zero modifier. Authenticated-load
offsets range from -4096 B to 4088 B in multiples of 8 B. Writeback overlap with
the destination register is constrained unpredictable and is declined by the
custom generator.

## Proof and effects

Signing outputs are opaque values, not raw integers. The bounded target
resolver tracks their input, key, modifier and native signing site. It admits
matching sign/auth and sign/strip chains within a linear native interval of at
most 256 B. Calls, control transfers, unrecognized system operations and
exception-generating instructions interrupt the key-stability check. Mismatched
keys, changed modifiers, wrong pointer domains and generic PAC values do not
produce exact targets. Recovered origins must enumerate to mapped readable or
executable addresses (or external symbols); arbitrary integers are declined
because signing can overwrite their high bits.

An IDB relocation may expose an address origin without the runtime PAC field.
For combined authenticated branches and loads, the resolver may enumerate the
mapped origins on normal completion. This result is explicitly guarded by the
retained authentication operation; it does not prove that authentication passes.
Standalone AUT and XPAC receive no arbitrary mask or address-width assumption.

The branch-address intrinsic includes the combined instruction's failure
boundary. This differs from standalone AUT, which can produce a poisoned value
instead of immediately trapping. Replacing a computed transfer preserves
observable target evaluation as a separate statement. A nested rewrite is
declined if moving that evaluation could reorder another call. Conditional
lowering is declined when copying the predicate would duplicate an effect.
Scalar table folding never removes nested calls.

Signing, authentication and stripping intrinsics have empty memory effects;
their architectural guards remain non-pure and observable. Authenticated-load
intrinsics retain conservative memory visibility. A single proven callee's
existing prototype can be supplied before native ABI analysis, allowing typed
arguments and returns without replacing an already-built argument vector.

Authenticated-load reads remain observable even when the destination is XZR or
the result is unused. Writeback follows the read, and the authenticated base is
not written back for the offset-only form. Temporary IR operands preserve the
architectural target register of authenticated branches and calls.

The ARM64 ABI helpers use IDA's processor-module register identifiers for X0;
these identifiers are not the five-bit architectural register encoding. The
hybrid driver initializes X29 as its frame-pointer register. A W0 self-move is
not a 64-bit pointer identity because it clears the upper 32 bits.

## Assumptions and falsification probes

| Assumption or boundary | Impact | Probe |
| --- | --- | --- |
| IDB bytes and permissions describe the immutable tables | High | The finite-dispatch probe changes one table byte and then its permissions; each revokes projection |
| Sign/auth inputs share a stable key and modifier | High | The primitive fixture includes wrong-key, changed-modifier, wrong-domain and intervening-call cases; each remains indirect |
| A recovered signing input represents an address origin | High | A high-bit integer sign/auth round trip followed by arithmetic remains indirect |
| Protected identity calls enter through the ordinary call ABI with canonical LR | High | Balanced key-A/key-B return wrappers pass; unpaired authentication, wrong return keys, BTI J and non-LR returns are rejected |
| IDA frame/SP metadata describes a projected continuation | High | The finite-target cache revalidates the recorded metadata before reuse |
| Projected functions retain their original request identity | Medium | The finite-dispatch probe decompiles, caches and reopens the same projected function |
| Runtime signatures, key values, feature configuration and authentication outcomes | High | Unknown; no hardware authentication or exception-state emulation is claimed |

The existing expression limits remain in force. Decode and emission use
constant space and constant work per primitive. A provenance interval scans at
most 63 intervening instructions. Target-effect preservation scans at most
32768 nested instructions and declines when that bound is exceeded.

## Verification

```sh
python3 tests/build_arm64e_primitives_fixture.py /tmp/arm64e/fixture
```

Run `tests/ida_arm64e_primitives_probe.py` with `tests/run_ida_smoke.py`, an
explicit plugin artifact, and `CHERNOBOG_ARM64E_SDK_BRIDGE` pointing to the built
`chernobog_arm64e_sdk_bridge` module. The probe checks value intrinsics,
authenticated targets, negative provenance cases, load writeback ordering,
identity contracts, retained effects, unchanged bytes and function ownership.
The fixture contains no bytes from an external program.

Primary architecture and ABI references:

- [LLVM pointer-authentication instruction mapping](https://llvm.org/docs/PointerAuth.html#aarch64-support)
- [Clang pointer-authentication semantics and arm64e ABI](https://clang.llvm.org/docs/PointerAuthentication.html)
- [Arm AAPCS64 register and frame-pointer definitions](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
- [Arm LDRAA/LDRAB instruction specification](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85)
