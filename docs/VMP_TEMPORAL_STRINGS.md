# Use-time string evidence and allocation lifetimes

The driver now retains bytes at their uses, so erasure and heap-address reuse
do not overwrite the evidence for an earlier use. Cross-run consensus matches
the use and allocation origin instead of the physical heap address. Production
IDA displays the two fixture plaintexts at their respective `strlen` arguments
and removes those annotations when consumed data becomes stale.

This implements a bounded slice of review requirements 3a/3b. The supplied
protected hello-world executable was not executed or recovered by this change.
Protected-binary coverage, native byte-loop string aggregation, broader
architecture coverage, indirect-call display, and requirement 3c transform
recognition remain incomplete. Source and artifact hashes, complete production
probe records, and validation outcomes are in
[VMP_TEMPORAL_STRINGS_EVIDENCE.json](VMP_TEMPORAL_STRINGS_EVIDENCE.json).

**Source basis and implementation**

`vmp/runtime/string_manager.cc:139–183` allocates a byte buffer, decrypts into
it, exposes its pointer, and zeros/deletes it on release. Its observed SHA-256 is
`ea4ec11e0317a6508c2d14c4032e368259c98b1955072987171c7306718e3c4d`.
The test fixtures exercise that lifetime shape using an independent constant-XOR
transform. They are not emitted VMP code and do not validate the source's
rotating-key transform.

| Component | Contract |
|---|---|
| `src/hybrid/temporal_memory.hpp` | Run-local bounded first-fit allocator and immutable use snapshots; 16-byte storage alignment, requested-size bounds, distinct allocation IDs and reuse generations |
| `src/hybrid/emu_driver.cpp` | Records modeled arguments from the buffers actually consumed, before copy writes; records directly executed scalar reads from hook values; integrates allocate/callocate/free/object summaries |
| `src/hybrid/evidence.cpp` | Validates lifetime witnesses and matches semantic uses across every scheduled run; keeps conflicting duplicates as vetoes |
| `src/hybrid/z3_bridge.cpp` | Requires current function and consumed-image identity; the print-only path separately admits a finished owned prototype-refinement lease |
| `src/plugin/idc_api.cpp` | Exposes use-string count/value, model kind, argument/use occurrence, allocation origin, offset, and observation counts; exposes capture/lifetime counters |
| `src/deobf/handlers/ctree_string_decrypt.cpp` | Maps an observed modeled use to an exact ctree call EA, direct target and argument; appends transient print text without changing the AST or saved comments |

A heap witness includes the run/seed, allocation ID, physical generation,
address, requested size, allocation/release event sequences, allocating
callsite/callee, per-origin allocation occurrence, use site/callee, argument,
per-site use occurrence, object offset, and producer/model kind. Its retained
bytes describe that use, not the final object contents. Image identity uses an
image address. Stack identity is a selected-function frame and entry-SP offset;
it does not assert recovery of a C lexical object.

Allocation attempts and zero-byte modeled calls count toward their respective
occurrence sequences even when they produce no allocation/snapshot. This avoids
aligning a later successful operation with an earlier operation in another run.
Physical generations guard a witness within its run; they are intentionally
excluded from cross-run correspondence. The allocation site, callee, occurrence,
requested size and offset remain part of that correspondence.

Free of NULL succeeds in the explicit model. Invalid/interior/double free and
modeled accesses outside live allocation bounds stop with an environment-model
failure. Zero-size, oversized, overflowing and out-of-space allocation requests
return zero. Allocation-ledger exhaustion stops modeling rather than inventing
an untracked object. These are execution-model choices, not a claim that every
native allocator has these behaviors.

`temporal_capture_complete` is separate from the existing model-free
`consumed_context_complete` contract. Modeled calls may produce use witnesses;
they do not acquire universal-proof eligibility. Every scheduled run must have
complete temporal capture. An absent, failed, unavailable or truncated run is
not dropped to manufacture consensus. Invalid/unterminated UTF-8 and conflicting
or missing per-use observations reject that use. Agreement concerns the exact
NUL-terminated UTF-8 prefix; bytes after its terminator are not part of the
literal. No Unicode normalization is applied.

**Bounds and algorithm**

All counts below are per run, excluding the already-existing execution trace.

| Bound | Value and consequence |
|---|---|
| Allocation attempts A | At most 4,096; includes failed requests |
| Use attempts U | At most 4,096; includes zero-byte modeled uses |
| Snapshot size B | At most 4,096 bytes, including any NUL terminator |
| Total retained snapshot bytes | At most `min(config.max_runtime_bytes, 1,048,576)` bytes |
| Direct executed read | Complete only for little-endian hook values of at most 8 bytes; wider/big-endian observations retain an incomplete status |
| Print annotation | At most 64 lines, two use descriptions per line, and 128 UTF-8 payload bytes per description; displayed prefixes end on scalar boundaries |

The snapshot byte allowance is separate from final-write capture. Exceeding
capture bounds marks incomplete evidence while preserving bounded execution.
The transient annotation explicitly labels model provenance and each dynamic
use occurrence. It does not replace an argument or assign a universal value to
the heap pointer. Omitted same-line uses are marked in the text; unmatched calls
and native reads receive no annotation.

```text
on modeled allocation attempt:
    count occurrence; choose first free fitting block or append bounded storage
    create allocation ID + storage generation + requested bounds
on read use:
    count occurrence; identify frame/image/live allocation
    retain only actual original read bytes, within snapshot and global budgets
on release:
    close exactly the live base-pointer allocation at this sequence
on projection:
    reject an incomplete scheduled-run corpus
    validate each use against its own allocation interval
    group by semantic use and allocation origin; reject missing/conflicting runs
    publish only agreeing admissible terminated UTF-8 prefixes
on ctree print:
    validate original function bytes, consumed bytes and admitted entry profile
    annotate only exact call-site/target/argument matches
```

First-fit allocation costs O(A) per attempt and O(A²) in the worst case for a
run. Address/lifetime lookup and release cost O(log A) using the ordered block
vector. A capture costs O(log A + log U + B); retained storage is O(A + U + T),
where T is the globally capped byte count. Consensus costs
O(A log A + U(log A + log U + B)); normalization can additionally compare B-byte
duplicate payloads during sorting. These bounds exclude backend execution and
the bounded call-model reads. For K runs, the per-run storage allowance scales
with K; no claim of constant whole-session memory follows.

**Executed validation**

| Evidence | Observed result |
|---|---|
| `tests/hybrid_tests.cpp::test_temporal_heap_uses` | Three concrete x64 cases use padding sizes 16, 32 and 64 bytes with seeds `0x93`, `0x94`, `0x95`; both strings survive erase/free and generation reuse despite different heap addresses |
| Same backend fixture | RMW read snapshots contain pre-write ciphertext; final heap bytes are zero; overlapping `memmove` captures its source before the destination write; invalid free/use stops even with string recording disabled |
| `tests/evidence_tests.cpp::temporal_memory_regressions` | Missing/conflicting/invalid observations, lifetime boundaries, physical generation differences, failed/zero-byte occurrence counting, allocation/use/byte caps, wide-value incompleteness and heap-boundary crossings are checked |
| `tests/vmp_native/temporal_strings.S` | Native x64 executable returns exit status 0 after checking both native `strlen` results sum to 14; executed through the host's x64 translation on arm64 |
| `tests/ida_temporal_string_smoke.py` | 22 checks pass: four-run publication, two correct modeled plaintexts, initial/repeated ctree display, no saved/saveable comments or changed function bytes, key/code/profile invalidation, and exact restoration |
| CTest | All 12 configured suites pass in 8.39 s wall time; this is validation latency, not a before/after performance benchmark |

The final IDA run is `build/vmp-temporal-ordered-reviewed`: runner exit 0, expected
PASS found, no internal-error marker, and artifact-integrity checks pass. The
plugin hash is
`2628214c8532356610e7d03a5769c2eca11113657031bacfef76ad96f0ba4260`.

An intermediate print probe correctly rejected initial display after Hex-Rays
refined an initially unknown prototype. The implemented fix permits only the
finished owned profile refinement while retaining original-byte/context checks.
The intermediate failure is retained in the evidence manifest; it is not counted
as successful validation. A separate overflow-classification regression found
during development was corrected; the existing three ABI controls pass.

**Assumption register and falsification probes**

| ID | Assumption / dependent conclusion | Stress test or falsification probe |
|---|---|---|
| T1 | The explicit allocation and library summaries define the modeled runs; all modeled-use values depend on them. | Compare with native behaviors, vary allocation outcomes and sizes, and reject invalid lifetime accesses. Native address reuse is not inferred from the model. |
| T2 | Hook scalar values represent original reads; directly executed snapshots depend on this. | Executed RMW ciphertext control; larger/big-endian values abstain. Broader architecture-specific hook validation remains. |
| T3 | Selected-function context plus source/occurrence identifies the correspondence being compared. | Vary actual addresses/generations, insert failed allocations or zero-byte uses, and reject missing/conflicting runs. Nested native callee execution remains outside the driver contract. |
| T4 | Function/consumed bytes and the admitted entry profile still match at publication/printing. | Patch the key or code, edit the post-seal profile, refresh cached pseudocode, and require removal. Restoring identical bytes can revalidate exact evidence. |
| T5 | The supplied VMP source motivates the lifetime problem; VMP-specific coverage depends on actual protected output. | Run a paired, provenance-recorded protected corpus. These independent fixtures cannot satisfy that coverage claim. |

**Bounded additional findings and quality gates**

High impact: post-retirement memory rereads can mislabel the written half of an
RMW instruction as the value consumed; the driver now uses the original hook
datum. Medium impact: failed allocations and zero-byte calls can shift semantic
occurrences without generating bytes; their occurrences are retained. Medium
impact: prototype refinement can invalidate otherwise-current print evidence;
the display lease is tested separately from strict IDC/proof freshness.

QG1: no normative premise. QG2: T1–T5 and explicit probes above. QG3: the stated
temporal slice is integrated from capture through display; the ledger retains
unfinished review requirements. QG4: byte/count bounds and validation seconds
are explicit; address arithmetic is checked. QG5: negative controls and scoped
abstentions are recorded. QG6: local source, test, SDK and binary hashes identify
the primary evidence. QG7: additional findings are bounded and impact-labeled.
These gates apply to this checkpoint, not to completion of the full objective.

Reproduction uses only relative files and externally supplied tool locations:

```sh
cmake --build build --target chernobog chernobog_hybrid_tests chernobog_evidence_tests -j 4
ctest --test-dir build --output-on-failure
clang -arch x86_64 -isysroot "$(xcrun --sdk macosx --show-sdk-path)" tests/vmp_native/temporal_strings.S -o build/vmp-temporal-strings
build/vmp-temporal-strings
python3 tests/run_ida_smoke.py build/vmp-temporal-strings tests/ida_temporal_string_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax --output-dir build/vmp-temporal-reproduction
```
