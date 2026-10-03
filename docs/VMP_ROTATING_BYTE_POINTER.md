# Executed byte-pointer source for rotate/add/XOR recovery

This checkpoint tests the one-byte branch of the bounded source-pointer
adapter described in `VMP_ROTATING_POINTER_STREAM.md`. A separate x86-64 Mach-O
fixture assembles an exact `LEA` image-source initializer followed by one
byte load and pointer increment per iteration. The fixture's process exits
zero only when both nine-byte outputs equal `VMP byte\0`. The prior plugin
has no byte-pointer annotation; the pointer-stream plugin publishes one
transient `8-bit units, key=0xA17E395B, units=9` UTF-8 candidate.

A second routine has the same loop and plaintext but loads its initial source
pointer from a writable global with `MOV`. Its pointer could change before
entry, so neither plugin publishes an annotation for it. IDA shows
`*result++` with one `cot_postinc` and one `cot_ptr` in both routines.
The positive and negative ctree text and selected expression inventories are
identical between prior/current runs. The initializer instructions are
separately decoded as `LEA` and `MOV` by the IDA probe. Exact binary, source,
plugin, runner and capture hashes are in
[`VMP_ROTATING_BYTE_POINTER_EVIDENCE.json`](VMP_ROTATING_BYTE_POINTER_EVIDENCE.json).

| x86-64 fixture | Prior plugin | Pointer-stream plugin |
|---|---:|---:|
| 2 routines, 18 checks | 14/18; the four positive annotation/restoration checks fail | 18/18 |
| Direct immutable-image pointer | No annotation | Exact 9-unit byte annotation |
| Loaded writable-global pointer | No annotation | No annotation |

The current run also checks source-byte, source-permission and native-code
revocation and exact restoration. It leaves native function bytes unchanged
and saves no user comments. The independent native process checks the two
decrypted outputs. Reproduce the bounded evidence:

```sh
clang -arch x86_64 -isysroot "$(xcrun --sdk macosx --show-sdk-path)" \
  -O1 -fno-unroll-loops -fno-vectorize -fno-slp-vectorize \
  tests/vmp_native/byte_pointer_stream.c -o build/vmp-byte-pointer-stream
python3 -B tests/verify_rotating_byte_pointer.py
```

The assembler fixture fixes the machine-code shape for this case. It is
independent native code, not a VMP-generated binary. The test adds coverage
for the adapter's existing one-byte path; it does not establish a protected
byte-string recovery rate. The paired verifier checks pinned artifacts and
fixed counts in `O(B+C)` time and `O(H+C)` peak memory for total non-capture
hashed bytes `B`, total parsed capture bytes `C`, and largest individually
hashed artifact `H`, excluding native process startup and JSON parser
internals. The program performs nine one-byte source reads per routine.
With the recorded linker, rebuilding to the specified output path reproduced
the pinned SHA-256. Building to a different output name changed only the
Mach-O `LC_UUID` bytes. Omitting `LC_UUID` produced byte-identical builds but
dyld rejected execution, so the executable evidence retains that load command.
Cross-toolchain reproducibility is unknown.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| B1 | The assembled `LEA` names the immutable nine-byte image object, while the `MOV` obtains a writable pointer value. The positive/negative distinction depends on this. | Decode both first instructions in IDA, compare their ctree pointer shapes, mutate the global pointer before entry, and require the loaded-global case to remain unresolved. |
| B2 | The final ctree represents the executed loop and its one-byte pointer advance. The annotation depends on this. | Require one `cot_postinc`, a dereference and identical paired ctree shapes; execute both loops and compare all nine output bytes with the independent literal oracle. |
| B3 | The source object and native function bytes are the same at display time. The transient annotation depends on this. | Change one source or code byte, or grant source write permission; require revocation and exact restoration in the same database. |
| B4 | The prior/current plugin pair and exact output-path binary are the pinned artifacts. The measured gain depends on these identities. | Rehash both copied plugins against `VMP_ROTATING_POINTER_STREAM_EVIDENCE.json`; rebuild the binary to the recorded path and rehash binary, probe, manifests and captures. A changed toolchain or output path requires a new paired run. |

## Bounded scope and quality gates

| Impact | Result or limit |
|---|---|
| High | A writable global pointer can name the same source on one run without proving its value at every entry; the adapter abstains. |
| Medium | The exact byte-pointer shape exercises the one-byte branch previously evidenced only through indexed byte loads. |
| Low | Nine units and one generated x86-64 image do not measure wider loop, architecture or protected-corpus coverage. |

QG1: no normative judgment is required. QG2: B1–B4 include falsification
probes. QG3: the stated byte-pointer, global-pointer, revocation and native
oracle cases are checked. QG4: byte counts and verifier complexity use
explicit units. QG5: a process output check, current ctree observation and
proof of source immutability remain distinct claims. QG6: the local primary
assembler source, exact binary and paired IDA artifacts are hash-pinned.
QG7: adjacent dynamic-pointer and protected-corpus limits are explicit.
