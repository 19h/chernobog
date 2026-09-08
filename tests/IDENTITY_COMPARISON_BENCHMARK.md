# Evidence identity comparison

`hybrid_compare_identity_bytes` skips equal 64-byte blocks and fully unloaded
blocks. Remaining equal-mask eight-byte groups use a masked word comparison;
only potentially significant differences enter the bytewise diagnostic path.
Byte-vector size errors precede bitmap size errors. The first differing address
still determines the diagnostic, with loaded-state differences taking precedence
over payload differences at that address. Unloaded payload and trailing bitmap
padding remain irrelevant.

## Assumption register and falsification probes

- C1: Input vectors remain immutable throughout a call. Concurrent mutation is
  outside the existing API contract. The implementation retains no input pointer.
- C2: Only loaded payload bytes participate. Tests enumerate all 256 bitmap
  patterns, alter unloaded bytes independently, and compare every diagnostic
  field against an independent bytewise oracle.
- C3: Block skipping preserves the earliest significant difference. Tests cover
  lengths 0–193, every mismatch position, competing payload/state mismatches,
  reversed state changes, short masks, padding bits, and 10,000 randomized inputs
  of up to 4,096 bytes. These are regression evidence, not a formal proof.
- C4: Native byte order must not affect equality. Words and expanded masks are
  loaded with `memcpy` in the same byte order. arm64 and translated x86-64 tests
  pass; actual big-endian execution remains untested.
- C5: Synthetic comparison time predicts only this operation. Whole-IDB latency,
  production identity-size distributions, and cache residency are unknown.
  Representative end-to-end profiling would falsify a broader speedup inference.

Results below depend on C1–C5. Storage requirements are checked before reading;
the required mask size is `N / 8 + (N % 8 != 0)`, avoiding addition overflow.
The algorithm has O(N) worst-case time, O(1) auxiliary space, and a fixed
2,048-byte lookup table. No allocation or hashing is added to comparison.

## Reproduction and provenance

Primary implementation and measurements are local to this repository:
`src/hybrid/evidence.cpp` and `tests/evidence_tests.cpp`. The baseline comparator
is the bytewise implementation in commit `e31f3ed`. Measurement used a source
copy made immediately before this comparator change, preserving earlier capture
and UTF-8 changes; those functions are outside the timed region. The following
baseline command reproduces the same comparator from the committed source:

```sh
git show e31f3ed:src/hybrid/evidence.cpp > /tmp/chernobog-compare-baseline.cpp
c++ -O2 -std=c++17 -DCHERNOBOG_LEGACY_EVIDENCE -Isrc -Isrc/hybrid -Ivendor/rax/capi/include tests/evidence_tests.cpp /tmp/chernobog-compare-baseline.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-compare-before
c++ -O2 -std=c++17 -Wall -Wextra -Wconversion -Wshadow -Isrc -Ivendor/rax/capi/include tests/evidence_tests.cpp src/hybrid/evidence.cpp src/hybrid/program_model_core.cpp -o /tmp/chernobog-compare-after
/tmp/chernobog-compare-before --compare-benchmark
/tmp/chernobog-compare-after --compare-benchmark
```

The legacy macro excludes only capture fixtures with truncated backing storage
and UTF-8 consensus regressions unsupported by that baseline. Comparator tests
remain enabled. Fixture construction and oracle checks are outside timing.
Each batch runs 1,000,000 comparisons for short inputs and the first-byte case,
or 20 for the remaining cases. A volatile diagnostic sink retains results.

## Measurements

2026-09-08, Apple Clang 21.0.0, arm64 macOS, `-O2`: three alternating baseline
and modified batches. Large fixtures contain 8,388,608 payload bytes (8 MiB).
Mixed masks are `0x55`. Times are seconds per comparison; ranges are observed
batch minima and maxima, not confidence intervals. Host frequency and scheduling
were uncontrolled. Discarded exploratory versions are excluded.

| Payload / case | Baseline median s (min–max) | Modified median s (min–max) | Median ratio |
|---|---:|---:|---:|
| 32 bytes, loaded equal | 1.88e-8 (1.87e-8–1.89e-8) | 5.23e-9 (5.20e-9–5.39e-9) | 3.60× |
| 256 bytes, loaded equal | 1.51e-7 (1.49e-7–1.54e-7) | 5.75e-9 (5.62e-9–5.76e-9) | 26.2× |
| 8 MiB, loaded equal | 0.00447 (0.00444–0.00448) | 0.000173 (0.000173–0.000175) | 25.9× |
| 8 MiB, unloaded equal | 0.00398 (0.00389–0.00406) | 0.0000497 (0.0000478–0.0000510) | 80.1× |
| 8 MiB, mixed equal | 0.00429 (0.00427–0.00439) | 0.000179 (0.000174–0.000180) | 24.0× |
| 8 MiB, mixed with differing unloaded bytes | 0.00423 (0.00422–0.00451) | 0.00102 (0.00101–0.00105) | 4.14× |
| 8 MiB, first byte differs | 1.54e-9 (1.52e-9–1.61e-9) | 3.63e-9 (3.62e-9–3.65e-9) | 0.424× |
| 8 MiB, last byte differs | 0.00449 (0.00448–0.00453) | 0.000177 (0.000169–0.000179) | 25.4× |
| 8 MiB, last loaded state differs | 0.00457 (0.00456–0.00459) | 0.000179 (0.000164–0.000181) | 25.6× |

Ratios use unrounded median baseline time divided by modified time. For example,
0.00446898 s / 0.000172642 s = 25.8858…, rounded to 25.9×. First-byte mismatch
cost increases by (3.63333 − 1.53975) × 10⁻⁹ s = 2.09 ns. Consequently, this
change does not accelerate every comparison distribution.

## Validation and bounded implications

The full native plugin build and all six CTest entries passed (1.77 s total).
Standalone evidence tests passed under AddressSanitizer/UndefinedBehaviorSanitizer
and in an x86-64 build executed through host translation. The existing local
libida macOS 15.0 versus project 13.3 deployment-target warning persists;
compatibility with macOS 13.3 is not established by this build.

The pristine live IDA UTF-8 smoke test also passed with the rebuilt plugin:
repeated uncached decompilations retain the recovered literal, changing a consumed
global key removes the stale literal, database bytes remain unchanged, and named
or commented ranges retain their metadata. The fixture and procedure are in
`tests/RUNTIME_UTF8.md`. This run used `/tmp/chernobog-compare-smoke/ida.log`,
fixture SHA-256 `394dc8bdd2845d7ed35cd493f8ca1d3c7deea3ed0b3c4ac412596560e479782b`,
and plugin SHA-256 `6bc6117f8c97cd95522f584bbae4e43cca024ae13f80f86f61a966daa4d05e28`.
It establishes this fixture's integration behavior, not corpus-wide coverage.

- Medium impact opportunity: repeated freshness validation of long unchanged
  identities can spend less time comparing bytes; C5 limits extrapolation.
- Low impact tradeoff: early mismatches perform additional bounded block work,
  measured above, and the table adds 2 KiB of static storage.
- Medium impact limitation: identity storage and capture remain dense. This
  comparator does not reduce memory use for sparse address ranges.

Quality-gate review: the change requires no normative premise; assumptions and
probes are explicit; comparator semantics and diagnostic fields have oracle
coverage; timing units and ratios are reproducible; known regression and platform
limits are disclosed; provenance is the production source and executable tests;
scope expansion is bounded above. Broader plugin performance remains unproven.
