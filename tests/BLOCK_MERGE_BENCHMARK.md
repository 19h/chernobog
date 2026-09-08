# Split-block detector: equivalent bounded traversal

`block_merge_handler_t::detect_split_blocks` previously calculated the longest
candidate chain starting from every candidate block, allocating a function-sized
visited bitmap for each start. Its caller needs only the decision that more than
30% of blocks qualify and a chain contains at least four distinct candidates.
The implementation now tests that decision directly: reject the ratio first,
then visit at most four candidate nodes per start. Instruction counting stops
at the third instruction because only counts of at most two qualify.

Candidate eligibility, successor/predecessor restrictions, short-cycle behavior,
bad stack-pointer rejection, and the strict ratio threshold are unchanged.
For V blocks, the detector now uses O(V) time and O(V) candidate storage, with
O(1) per-walk state. Previously dense chains/cycles required O(V²) work and
repeated O(V)-sized allocations; instruction counting also traversed full blocks.

## Assumption register and falsification probes

- B1: The CFG remains immutable during synchronous detection. Counted SDK shims
  model pure block queries; the native build checks actual SDK integration.
- B2: The consumer needs only the existing Boolean decision. The fourth node
  was counted before its successor was examined in the old algorithm, so a
  four-node prefix suffices even when that last edge is malformed. Tests retain
  that detail rather than tightening eligibility.
- B3: Cycles shorter than four must not qualify. A fixed four-entry visited
  array rejects repeats; one-, two-, three-, and four-node cycles are explicit
  probes. All functional graph topologies and candidate masks through five
  nodes are enumerated, with 100,000 seeded randomized larger/invalid graphs.
- B4: Only counts 0, 1, 2, and greater than 2 affect classification. Long-block
  tests verify the capped count and operation reduction. `count_insns` has no
  other production caller.
- B5: Instrumented algorithm timings do not measure Hex-Rays/decompilation
  latency. The shim includes query/link counters; host caches, scheduling, and
  frequency are uncontrolled. Native workload impact remains unknown.

## Verification and reproduction

The suite compiles production `block_merge.cpp` against a counted interface and
the frozen old algorithm in `block_merge_reference.cpp`. All 359,397 graph cases
matched the reference, including null/malformed edges, joins, noncandidates,
the 0.30 boundary, dense/sparse chains, and long instruction lists. ASan/UBSan
passed. Compiling the actual previous production source against the same suite
produced zero semantic mismatches and 209,928 operation-bound failures: the
oracle matches that source, while the new work bounds distinguish it.

```sh
python3 tests/run_block_merge_tests.py --cxx /usr/bin/clang++
python3 tests/run_block_merge_tests.py --sanitize
python3 tests/run_block_merge_tests.py --benchmark > /tmp/block-merge.csv
git show e31f3ed:src/deobf/handlers/block_merge.cpp > /tmp/block-merge-old.cpp
python3 tests/run_block_merge_tests.py --source /tmp/block-merge-old.cpp
```

The final command is expected to fail the new operation bounds. On UNIX with
Python and Clang/GCC, CMake also registers the suite as `chernobog.block_merge`.

## Measurements

2026-09-08, Apple Clang 21.0.0, native arm64 macOS, `-O2`: seven samples per case,
alternating reference/modified call order. Fixture creation and equivalence
checks are excluded from timing. Dense chain/cycle, sparse chain, and long-block
cases use one call per sample; short cycles use ten, and small negatives 10,000.
The following per-call times divide each sample by its repetition count.
Ranges are observed minima/maxima, not confidence intervals.

| Fixture | Old median (range), s | New median (range), s | Median ratio |
|---|---:|---:|---:|
| 4,096-node chain | 0.0161 (0.0160–0.0162) | 7.58e-6 (7.33e-6–9.46e-6) | 2.13e3× |
| 4,096-node cycle | 0.0390 (0.0389–0.0393) | 7.83e-6 (7.42e-6–8.38e-6) | 4.98e3× |
| 1,000 candidates / 4,096 nodes | 9.36e-4 (9.22e-4–9.57e-4) | 4.67e-6 (4.58e-6–4.83e-6) | 201× |
| Disjoint three-node cycles / 4,096 nodes | 1.06e-4 (1.02e-4–1.08e-4) | 4.00e-5 (3.88e-5–4.05e-5) | 2.66× |
| 512 blocks, 4,096 instructions each | 6.76e-4 (6.67e-4–1.18e-3) | 1.83e-6 (1.04e-6–4.08e-6) | 369× |
| 16-node negative | 2.77e-8 (2.74e-8–2.86e-8) | 2.10e-8 (2.05e-8–2.19e-8) | 1.32× |

For the dense chain, 16,123,792 ns / 7,584 ns = 2,126.027…,
rounded to 2.13 × 10³. Counted block queries fall from 16,777,216 to 4,102;
on the large cycle they fall from 33,558,528 to 4,102. Long-block instruction-link
reads fall from 2,097,152 to 1,024. These operation counts provide evidence
independent of clock noise. The final raw CSV is
`/tmp/chernobog-block-merge-final.csv`; earlier exploratory timings are excluded.
No local builds or other test processes were launched during the final samples.

Medium impact opportunity: repeated split-block detection on large CFGs can
avoid quadratic query/allocation work. Low impact limitation: candidate storage
is still proportional to V. High impact boundary: this change preserves detector
decisions; it does not establish that every merge decision is semantically valid
or that every obfuscation scheme is supported.

Provenance is production source, the independently compiled frozen oracle,
executable tests, and raw counter/timing records. Assumptions, equivalence probes,
complexity, units, observed variability, and scope limits are explicit.
