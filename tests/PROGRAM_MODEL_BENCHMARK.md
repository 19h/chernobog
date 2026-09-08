# Program-image identity traversal

The function-identity hash now locates the initial segment with one binary
search, then advances a cursor across the chunk. The version-3 byte stream and
persisted identity format are unchanged. This removes repeated prefix scans at
unmapped gaps.

For one chunk, let S be the image segment count, K the number of segments
traversed, and B the mapped bytes hashed. Traversal takes O(log S + K + B) time
and O(1) additional space. Previously a chunk crossing all S segments with gaps
could take O(S² + B) time. Multiple chunks each perform their own initial search.

## Assumption register

- A1: Segments have positive sizes, are sorted by start, and do not overlap.
  `hybrid_snapshot_function` filters nonpositive sizes and sorts IDA segments.
  The public model header now documents the invariant. The randomized oracle
  exercises gaps, adjacency, empty images, and queries starting within segments.
  Overlapping or unsorted manually constructed images violate this contract;
  the optimization does not add validation for them. Complexity and equivalence
  claims depend on A1.
- A2: A fragmented synthetic image isolates traversal cost. This is tested with
  increasing segment counts and identical pre/post hash values. Its relevance
  to an actual workload is unknown until its function chunks and segment layout
  are measured. No whole-plugin speedup is inferred.
- A3: Timing variability can be described by repeated batch measurements on this
  host. Reported ranges are observed minima/maxima, not confidence intervals.
  Shared-host scheduling and CPU frequency can change the measurements.

## Reproduction

From the repository root, using Apple Clang 21.0.0 on arm64 macOS:

```sh
git show 3abf0eb:src/hybrid/program_model_core.cpp > /tmp/chernobog-model-baseline.cpp
c++ -O2 -std=c++17 -DCHERNOBOG_LEGACY_MODEL -Isrc -Isrc/hybrid tests/program_model_tests.cpp /tmp/chernobog-model-baseline.cpp -o /tmp/chernobog-model-before
c++ -O2 -std=c++17 -Isrc tests/program_model_tests.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-model-after
/tmp/chernobog-model-before --benchmark
/tmp/chernobog-model-after --benchmark
```

Repeat the last two commands three times. Each measurement averages 20 hashes.
Each image has S one-byte loaded segments separated by one-byte holes, and the
function chunk spans the image plus its leading and trailing holes. Fixture
construction and the randomized regression suite are outside the timed region.

Observed 2026-09-08, three alternating baseline/modified batches:

| Segments | Baseline seconds/hash, min–max | Modified seconds/hash, min–max | Median ratio |
|---:|---:|---:|---:|
| 1,000 | 0.000191–0.000204 | 0.0000113–0.0000120 | 16.9× |
| 4,000 | 0.00331–0.00340 | 0.0000431–0.0000454 | 78.2× |
| 16,000 | 0.0625–0.0628 | 0.000164–0.000172 | 372× |

Ratio = median baseline time / median modified time; seconds cancel.
For 16,000 segments: 0.0625842 s / 0.000168269 s = 371.929..., rounded to 372.
All three fixture hashes agreed exactly between implementations.

## Verification and bounded scope

The independent serializer in `program_model_tests.cpp` checks 2,000 deterministic
randomized images, both before and after rebasing. It covers initialized masks,
truncated manual byte buffers, multiple/out-of-order function chunks, empty and
reversed chunks, and a maximal unmapped range ending at UINT64_MAX, including a
mapped final byte. It passes against both the baseline and modified code.

The modified suite also passes AddressSanitizer and UndefinedBehaviorSanitizer:

```sh
c++ -O1 -g -std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wconversion -Wshadow -Isrc tests/program_model_tests.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-model-sanitized
/tmp/chernobog-model-sanitized
```

The complete native Release plugin build and all five CTest targets passed.
The linker reports that the local libida targets macOS 15.0 while the project
sets 13.3; this run does not establish compatibility with macOS 13.3.
Live-IDB performance and behavior were not measured in this change.

- Medium impact opportunity: measure snapshot byte copying and whole-image
  content hashing separately; they may dominate ordinary, densely mapped images.
- Medium impact limitation: the FNV identity remains a noncryptographic 64-bit
  hash. This change preserves its existing collision properties.
- Low impact opportunity: the new model regression executable links neither
  IDA nor rax and can be compiled directly without configuring the plugin.

Quality review: equivalence is supported within A1 by the independent oracle,
unchanged benchmark hashes, and sanitizers; timings are scoped to A2/A3 and
reported in seconds. These results establish this optimization only, not
completion of the broader capability-expansion objective.

## Whole-image zero-run hashing

`hybrid_program_content_hash` now scans eight-byte words and combines contiguous
zero words algebraically. Both initialized masks and data bytes remain in the
serialized identity; a zero mask is never used to infer data contents.

For the existing recurrence h' = (h XOR b) × P modulo 2^64, b = 0 gives
h' = h × P. Thus N zero bytes give h' = h × P^N modulo 2^64. For W complete
zero words, exponentiation by squaring computes (P^8)^W. Trailing bytes use the
original recurrence. Unsigned 64-bit arithmetic supplies the required modular
reduction. The format, order, and hash values are unchanged.

Algorithm: scan words; hash a nonzero word bytewise; count a zero-word run and
multiply by its power using exponentiation by squaring; hash any final bytes.
For B input bytes and zero runs of lengths W_i words, the bound is
O(B + sum(log(W_i + 1))) = O(B) time and O(1) auxiliary space. The scan remains
linear; only the serial arithmetic dependency is shortened.

Additional assumptions and falsification probes:

- A4: Each optimized word is actually zero, independently of host endianness or
  loaded-mask state. `memcpy` reads only complete words. Tests cover every length
  from 0 to 257, every possible single-nonzero position, random zero/nonzero
  mixtures, and power-of-two run boundaries through 1,048,576 bytes. Native
  arm64 and x86-64 executables pass against the independent bytewise serializer;
  the latter ran through the host's translation support. No big-endian runtime
  was available; endian independence follows from using words only for a zero
  comparison, with nonzero bytes processed in their original order.
- A5: Zero runs materially occur in the selected image. The benchmark includes
  zero, random, alternating 4,096-byte zero/random pages, and random bytes at
  every eighth position. The final pattern falsifies the inference that a high
  fraction of zero bytes alone guarantees a speedup. End-to-end impact remains
  unknown without a representative live-IDB profile.

Use the same baseline revision and compiler commands above, with
`--content-benchmark` instead of `--benchmark`. Each fixture contains 8,388,608
data bytes and 1,048,576 mask bytes. The zero fixture has a zero mask; other
fixtures use 0xff masks. There are 20 hashes per timed batch and three alternating
baseline/modified batches. Construction, reference verification, and regression
checks are excluded from the timed region. These measurements compare against
the bytewise content hash at revision `3abf0eb`; they do not compare against the
intermediate eight-byte implementation in `e31f3ed`.

| Data pattern | Baseline seconds/hash, min–max | Modified seconds/hash, min–max | Median ratio |
|---|---:|---:|---:|
| All zero | 0.00906–0.00943 | 0.000301–0.000307 | 30.5× |
| Random | 0.00921–0.00956 | 0.00941–0.00949 | 0.997× |
| Alternating zero/random pages | 0.00908–0.00939 | 0.00537–0.00549 | 1.72× |
| Random byte at every eighth position | 0.00915–0.00947 | 0.00931–0.00948 | 1.01× |

Zero-case ratio: 0.0091998 s / 0.000301994 s = 30.4636..., rounded to 30.5.
Random-case median time increased about 0.3%; the observed batch ranges overlap.
These measurements do not establish a statistically significant difference for
the random or every-eighth-position fixtures. All fixture identities match the
baseline exactly. Medium impact opportunity: BSS-heavy snapshots can benefit;
medium impact limitation: scanning/copying remains linear in the image size.

The expanded regression suite passes the complete native Release build and all
five CTest targets (1.73 s total in this run), plus standalone AddressSanitizer,
UndefinedBehaviorSanitizer, and x86-64 execution. The tests independently check
program metadata, masks, bytes, and rebase behavior in addition to the earlier
function identity tests. They do not establish live-IDB performance or complete
the broader capability-expansion objective.

## Bounded initialized-byte views

`SegImage::loaded_view` and `ProgramImage::loaded_view` return a non-owning
pointer/length pair for initialized bytes, bounded by the caller's maximum,
the segment's declared end, the physical byte-vector extent, and the first
unset or absent loaded-mask bit. Empty views have a null pointer. Views stop at
segment boundaries even when the next segment is adjacent.

Static instruction decoding and SMIR analysis now consume these views directly.
This removes the instruction-byte heap allocation/copy from each nonempty SMIR
analysis and the separate stack copy in static decoding. Effect-vector
allocation remains. No elapsed-time speedup is claimed for this change.

Assumption register and probes:

- A6: The snapshot remains alive and its segment vectors do not change while a
  view is consumed. The header documents this lifetime contract. Both consumers
  call synchronous decoder/analyzer APIs while holding the const image; the
  SMIR test backend verifies the exact original pointer across effect retries.
- A7: The caller's maximum already respects the current function chunk. Static
  decoding retains its existing chunk-window calculation; SMIR additionally
  caps input at 16 bytes. Tests check a smaller caller limit and the 16-byte
  cap, with truncated backing storage and unset mask bits independently.
- A8: ProgramImage segment lookup retains the sorted/nonoverlapping invariant
  A1. SegImage views themselves do not require any image ordering. Tests cover
  empty images and stopping at adjacent segment boundaries.

Algorithm: bound the requested interval by actual storage, inspect up to eight
loaded bits per mask byte, stop at the first missing bit, and return the original
storage pointer. For N bytes returned, time is O(1 + ceil(N/8)) and auxiliary
space is O(1); at most seven trailing bits are inspected individually. The view
never constructs an end address by adding the requested maximum, so maximum
size_t requests and addresses near UINT64_MAX remain bounded by subtraction.

The model tests compare against an independent bytewise bounds oracle for all
256 middle-mask values, every start position around a 24-byte segment, request
lengths 0–32, truncated masks/buffers, maximum size_t, and the address-space end.
SMIR integration tests cover a 33-effect retry, pointer identity, empty backing
storage, unloaded bytes, and caller/instruction limits. Native full build and
five CTest targets pass; standalone view/model tests also pass AddressSanitizer,
UndefinedBehaviorSanitizer, and x86-64 execution.

Medium impact: partially populated manually built snapshots now have explicitly
bounded decoder input. Low impact opportunity: other immutable snapshot readers
can adopt the same view contract where their semantics also stop at unloaded
bytes. Medium impact limitation: views cannot outlive or survive mutation of
their backing storage. Live-IDB performance was not measured.

`CHERNOBOG_LEGACY_MODEL` in the baseline reproduction command excludes only the
new view tests, because revision 3abf0eb predates this API. Hash reference tests
and benchmarks remain enabled for both implementations.
