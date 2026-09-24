# Supplied macOS hello-world fixture

Static inspection on 2026-09-21, Chernobog revision
`7a6ba45`. Input directory: `vmp-macos-x86_64`.
The user attributes `foo_x86_vmp` to the supplied `vmp`
source tree. Compiler/protector commands, protection settings, random seed,
and source-to-protector build attestation are unknown. No executable was run
and no existing IDA database was opened or modified during this inspection.

A later [bounded process comparison](VMP_SUPPLIED_SAMPLES.md) uses the same
original/protected file hashes and records three matching no-argument exits and
output byte streams. The static observations below retain the scope of the
2026-09-21 inspection.

## Observations

`foo.c` calls `printf("Hello World")` from `main`. The adjacent `foo_x86`
is a Mach-O x86-64 executable whose 22-byte `_main` loads that literal,
calls the `_printf` stub, and returns zero. At that static-inspection date, this
was a candidate original/protected pair whose behavior had not been compared.

| Property | `foo_x86` | `foo_x86_vmp` |
|---|---|---|
| File length, bytes | 12,456 | 2,618,368 |
| `_main` symbol address | `0x100001440` | `0x100001440` |
| Bytes at segment-relative original main location | Native function | 22 zero bytes |
| `__text` section type / file offset | Regular / `0x1440` | `S_ZEROFILL` / 0 |
| `__cstring` section type / file offset | C strings / `0x145c` | `S_ZEROFILL` / 0 |
| Exact ASCII `Hello World` occurrence | File offset `0x145c` | Absent |
| `LC_MAIN` entry address | `0x100001440` | `0x100001436` |

Addresses are preferred unslid virtual addresses, not observed runtime addresses.
The protected entry contains `e9 05 00 00 00`, a direct jump to
`0x100001440`. Its `__mod_init_func` pointer is `0x10000143b`; that address
contains `e9 75 32 29 00`, a direct jump to `0x1002946b5` in `.dlC1`.
The termination pointer is `0x1001c2a05`. These are static pointer and
instruction observations, not an executed startup trace.

The added `.dlC1` segment has initial read/execute permissions, virtual
address `0x10014d000`, file offset `0x4000`, and 2,588,672 file-backed bytes.
It has no sections. `.dlC0` reserves 1,351,680 virtual bytes with zero
file-backed bytes and initial read permission. The contents of these regions
have not been classified as application code, loader code, VM handlers, or data.

The source supports a packing interpretation: `MacArchitecture` serialization
sets packed sections' physical offsets to zero and flags to `S_ZEROFILL` in
`core/macfile.cc` (`vmp/core/macfile.cc:6075`).
The local format definitions identify that section type and define `LC_MAIN`
offset semantics in `core/mach-o.h` (`vmp/core/mach-o.h:914`).
This establishes evidence consistent with the tree's packing path; it does
not establish whether the application function was also mutated or virtualized.

Size growth is exactly `2,618,368 - 12,456 = 2,605,912 bytes`.
The dimensionless ratio is `2,618,368 / 12,456 = 210.209377…`, or approximately
210.21 times. It is not a virtualization-coverage or complexity metric.

## Consequences for Chernobog

1. **High impact: diagnose missing runtime code before recovery scoring.**
   Preserve the distinction between an original symbol, file-backed initialized
   code, and code available only after startup. An unresolved original function
   here is not evidence of an MBA or flag-analysis failure. Show section type,
   backing state, entry, and initializer provenance with the diagnostic.
2. **High impact: separate packed-input and transformation benchmarks.**
   Admit this sample as a packed-startup fixture with unknown mutation/VM
   settings. The source review's transformation matrix still needs recorded
   configurations and independently validated code visibility. Packing recovery
   remains outside the implementation scope defined by that review.
3. **Medium impact: include executable segments without sections in analysis
   inventory.** `.dlC1` demonstrates why section names and `_main` alone cannot
   delimit potentially relevant executable regions. Segment inventory does not
   authorize decoding every byte as code or bypassing function boundaries.
4. **Medium impact: expose startup dependencies in visualization.** Show the
   initializer pointer, its direct jump, and the entry-to-original-main jump
   as separate facts. A later runtime snapshot would need its own byte hashes,
   initialization state, relocation context, and generation before existing
   evidence consumers could use it. Chernobog's current execution contract is
   explicitly per-function; see [RAX_HYBRID.md](../RAX_HYBRID.md).

## Assumptions and falsification probes

| ID | Assumption / dependent result | Probe |
|---|---|---|
| F1 | User-provided source attribution; vendor-specific interpretation | Rebuild the protector from the recorded tree and compare build provenance; a mismatch defeats exact build attribution. |
| F2 | Adjacent `foo_x86` is the protected program's original; paired scoring | Record protection input hash and compare outputs and exit status under a controlled execution environment. Until then, equivalence is unknown. |
| F3 | File bytes and preferred addresses describe static input; all addresses above | Verify hashes and load commands; apply actual relocation context before comparing runtime addresses. |
| F4 | Packed startup explains the absent original bytes; diagnostic proposal | Compare independently obtained post-initialization bytes and initialization events. Absence of reconstruction defeats the predicted application-code availability. |

Unconventional scope expansion is bounded to input diagnosis, region inventory,
and evidence presentation. Loader emulation, unpacking, and full VM lifting were
not performed. No recovery rate, false-edge rate, runtime behavior, or latency
claim follows from these static measurements.

## Provenance and reproduction

SHA-256 values:

```text
foo.c           b014a52b7fcd6c015a040b451c450bfdc35d8e1d9198e0f17d3f18f217be198a
foo_x86         443b0a464d7de68c5a26a3e31a92e694356ccd1eef3127d522309ac672ecc7c7
foo_x86_vmp     c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5
vmprotect_con   3fe722d21d5c8d9661f12b3b04f5863c4d9b93557692c1318dbf8f1c45c23568
core/macfile.cc dbb12f7ccb34000734f552e8f917612674df04ba15f1d0923a6afd61c199d7e6
core/mach-o.h   b862f92f9cd595b08009e0b794d5a5b5d9b180adfbcd35e510556aaa99792b6d
```

Reproduce the structural observations with `xcrun otool -l`, imported libraries
with `xcrun otool -L`, symbols with `xcrun nm -n`, and original disassembly
with `xcrun otool -tvV`. Check exact bytes using Python `Path.read_bytes()`:
protected offsets `0x1436:0x143b`, `0x143b:0x1440`, `0x1440:0x1456`,
initializer pointer `0x27c0a0:0x27c0a8`, and termination pointer
`0x27c0a8:0x27c0b0`. Pointers are little-endian unsigned 64-bit values;
`E9` displacement is signed little-endian 32-bit and relative to the next
instruction. For example, `0x10000143b + 5 + 0x293275 = 0x1002946b5`.
Exact substring scanning and hashing require O(N) time for N file bytes;
the read-all inspection uses O(N) space. Integer byte counts have no rounding
error; only the displayed size ratio is rounded.

Quality audit: technical scope requires no normative judgment; F1–F4 distinguish
assumptions from observations; measurements and calculations have reproducible
inputs; static/runtime and packing/virtualization distinctions are explicit;
source and artifact provenance are recorded; scope expansion is bounded.
This audit applies to this inspection, not completion of the implementation ledger.
