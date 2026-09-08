# Evidence identity capture

Function-chunk and consumed-context identities now share a segment traversal.
A binary search locates the first candidate segment; subsequent segments are
visited in order. Unmapped bytes remain zero with clear loaded bits. Initialized
runs are copied in bulk, with the destination bitmap filled using its own bit
alignment. Mixed loaded/unloaded groups are processed one bitmap byte at a time.

This removes per-byte segment searches and duplicate capture implementations.
Backing-buffer and bitmap extents are checked before reading. A declared loaded
byte without backing storage is represented as unavailable in the identity.

## Assumption register

- E1: Segments are sorted, nonoverlapping, and have positive sizes. This is the
  ProgramImage contract. Tests use contiguous and gapped segments and independently
  locate the source segment for every output byte.
- E2: The image is immutable during synchronous capture. Borrowed byte views have
  the lifetime documented in `program_model.hpp`; the capture immediately copies
  their contents into owned identity vectors.
- E3: Identity output must preserve exact range length, zeros at unloaded bytes,
  and loaded bits relative to the requested range rather than the source segment.
  The reference oracle checks both output vectors, every source/destination bit
  alignment, all 256 mixed-mask patterns, and overlapping context-read merging.
- E4: Requested identities fit available memory. Dense output still requires
  N + ceil(N/8) bytes for N range bytes, including unmapped holes. Sizes beyond
  vector capacity are rejected before narrowing; allocation failures remain
  possible. This change does not introduce a sparse identity format.

For S image segments, K intersected segments, and N output bytes, the traversal
uses O(log S + K + N) time and O(1) auxiliary state beyond the O(N) owned output.
Previously segment lookup was repeated N times, giving O(N log S) lookup work.
Dense initialization remains O(N) even when all source bytes are unmapped.

## Verification and reproduction

`tests/evidence_tests.cpp` exercises the production evidence builder, rather
than a separately exported test-only capture function. It checks function and
consumed-context identity bytes and bitmaps against a linear, bytewise reference:
all 256 masks at 16 range alignments, 1,000 randomized multi-segment snapshots,
truncated backing buffers, absent bitmap storage, empty/reversed function chunks,
empty images, and ranges ending at UINT64_MAX.

Standalone builds require the pinned rax C header but do not link IDA or rax:

```sh
c++ -O2 -std=c++17 -Wall -Wextra -Wconversion -Wshadow -Isrc -Ivendor/rax/capi/include tests/evidence_tests.cpp src/hybrid/evidence.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-evidence-after
/tmp/chernobog-evidence-after --benchmark
```

For the bytewise baseline:

```sh
git show e31f3ed:src/hybrid/evidence.cpp > /tmp/chernobog-evidence-baseline.cpp
c++ -O2 -std=c++17 -DCHERNOBOG_LEGACY_EVIDENCE -Isrc -Isrc/hybrid -Ivendor/rax/capi/include tests/evidence_tests.cpp /tmp/chernobog-evidence-baseline.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-evidence-before
/tmp/chernobog-evidence-before --benchmark
```

The baseline macro excludes truncated backing-buffer fixtures and the later
UTF-8 runtime-consensus regressions, which are outside that implementation's
capabilities. All well-formed identity-capture reference cases remain enabled.
Each timed batch captures a function identity ten times over 8,388,608
mapped bytes, using one or 256 segments. The latter have eight-byte gaps. Masks
are all loaded (0xff), all unloaded (0x00), or alternating bits (0x55). Identity
allocation and destruction are timed; fixture generation and regressions are not.

Medium impact opportunity: repeated evidence refreshes can reduce range-copy
work without changing freshness identity semantics. Medium impact limitation:
large address-space holes still consume dense output memory. Live-IDB latency
and whole-plugin throughput require separate measurements.

## Measurements

On 2026-09-08, Apple Clang 21.0.0, arm64 macOS, `-O2`, three alternating
baseline/modified batches (ten captures each) gave:

| Segments | Loaded pattern | Baseline s/capture, min–max | Modified s/capture, min–max | Median ratio |
|---:|---|---:|---:|---:|
| 1 | All loaded | 0.0175–0.0177 | 0.00187–0.00200 | 9.27× |
| 1 | All unloaded | 0.0171–0.0172 | 0.00174–0.00176 | 9.86× |
| 1 | Alternating bits | 0.0172–0.0173 | 0.00391–0.00467 | 4.21× |
| 256 | All loaded | 0.0762–0.0773 | 0.00190–0.00195 | 39.9× |
| 256 | All unloaded | 0.0761–0.0763 | 0.00173–0.00177 | 43.1× |
| 256 | Alternating bits | 0.0760–0.0764 | 0.00423–0.00439 | 17.4× |

Ratios divide median baseline seconds by median modified seconds. For example,
0.076198 s / 0.00176785 s = 43.102..., rounded to 43.1. These are observed
batch ranges, not confidence intervals. E5: the synthetic layouts isolate
capture cost; workload representativeness and live-IDB latency remain unknown.
The modified path was also checked on the alternating-bit case to test whether
fragmentation defeats the bulk-copy benefit. No local compilation was launched
during these final timing batches; other host scheduling and frequency effects
were not controlled. Earlier exploratory timings taken during concurrent builds
are excluded from this table.

Validation completed: the full native Release plugin build and all six CTest
entries passed (3.06 s for this run). Standalone evidence tests passed on arm64
and x86-64, and under AddressSanitizer plus UndefinedBehaviorSanitizer:

```sh
c++ -O1 -g -std=c++17 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Wconversion -Wshadow -Isrc -Ivendor/rax/capi/include tests/evidence_tests.cpp src/hybrid/evidence.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-evidence-sanitized
/tmp/chernobog-evidence-sanitized
c++ -arch x86_64 -O2 -std=c++17 -Wall -Wextra -Wconversion -Wshadow -Isrc -Ivendor/rax/capi/include tests/evidence_tests.cpp src/hybrid/evidence.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-evidence-x86_64
/tmp/chernobog-evidence-x86_64
```

The local libida deployment-target warning remains: it targets macOS 15.0 while
the project targets 13.3. Successful linking here does not establish macOS 13.3
compatibility. The x86-64 executable ran through host translation support; these
results do not establish native Windows/Linux or big-endian runtime behavior.
