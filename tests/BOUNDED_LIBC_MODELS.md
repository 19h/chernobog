# Bounded byte-search runtime models

Chernobog recognizes `memchr` and `strnlen` import summaries, including the
existing decorated-symbol forms. This permits exploration to continue through
two common bounded byte operations using the normal target ABI adapters.
The enum additions preserve existing summary identifiers.

`memchr` searches for the first byte equal to its integer argument converted to
`unsigned char`, returning its guest address or zero. `strnlen` returns the first
NUL byte's offset, or the supplied bound when there is no NUL within it. Both
stop as soon as the result is known and do not prevalidate an unused tail.
Lengths count bytes, including when the input encodes Unicode.

The requested bound is capped at 1,048,576 bytes (1 MiB), consistent with the
existing bounded memory models. A larger bound fails before any source read,
even if a match could occur early. Zero-bound calls return zero without reading
source memory. This is the operational summary convention, not a claim that
every C call with an invalid pointer has defined language-level behavior.
Failures retain the existing environment-model/permission failure classification.

## Assumption register

- M1: Named call targets denote the modeled functions, with arguments supplied
  by the selected ABI. Tests execute guest instructions through real rax using
  AAPCS64, SysV x86-64, and Windows x86-64 argument layouts. Host Windows and
  other guest-architecture integration require separate validation.
- M2: The requested bound is within the model cap and each consumed byte is
  readable. Tests probe zero/exact/over-cap bounds, missing terminators, unsigned
  conversion, address limits, permission failures, and an unmapped unused tail.
- M3: Only bytes consumed through the first match/NUL or exhausted bound may
  contribute dependencies. Tests check reported ranges and guest-observed
  results, including successfully read prefixes before a later failure. Scope
  transitions split records: permissive reads through engine page padding must
  not discard image dependencies before or after that padding. Adjacent image
  segments remain one contiguous image scope. Scope classification is reused
  until a segment or scratch-region boundary.
- M4: External models supply exploratory semantics. Their existing provenance
  flags remain set; these results do not become unconditional native proofs.
  The live probe changes a consumed search value and verifies that stale
  recovered text disappears.

For N visited bytes, the scan makes N backend byte reads and uses O(1) auxiliary
memory: an eight-byte preview plus counters. It visits at most
min(bound, first-match offset + 1) bytes on a successful match. With S image
segments and K crossed scope boundaries, host metadata work is O(N + K log S)
in permissive mode and O(N log S) with per-byte strict-permission checks,
in addition to backend read cost. Recorded output ranges use their existing
bounded event storage. No host-libc scan over guest pointers is performed.

## Primary provenance

The byte-search semantics are specified in the
[WG14 C11 draft N1570, §7.24.5.1](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1570.pdf).
Bounded length and maximum accessed bytes are specified by the
[OpenGroup POSIX strlen/strnlen page, 2016 edition](https://pubs.opengroup.org/onlinepubs/9699919799.2016edition/functions/strlen.html).
The latter was verified from the retrieval tool's cached primary page; direct
origin access intermittently returned HTTP 403. The 1 MiB cap, failure behavior,
and provenance rules are Chernobog model policy, not requirements of those
standards.

## Live reproduction

```sh
cc -O1 -fno-builtin tests/runtime_strings/bounded_search_fixture.c -o /tmp/chernobog-bounded-search-fixture
python3 tests/run_ida_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax --verbose --output-dir /tmp/chernobog-bounded-search-run /tmp/chernobog-bounded-search-fixture tests/ida_bounded_search_smoke.py
```

The fixture calls `strnlen` on three nonterminated bytes and searches for integer
0x180 in a three-byte buffer containing 0x80. Both exact results gate decoding
of `bounded search OK`. The probe requires that literal in two uncached ctrees,
then changes the searched byte to select an early return and requires removal
of the old literal. IDB output bytes must remain unchanged throughout.

Medium impact capability: bounded byte operations no longer stop otherwise
modeled exploration. Medium impact limitation: long scans still perform one
backend read per byte, and bounds above 1 MiB remain unsupported. High impact
constraint: external-call provenance must remain attached to derived evidence.

## Verification results

The full native plugin build and all nine CTest entries passed on 2026-09-08
(7.53 s total for this run). The hybrid suite includes 90 new real-rax runtime
cases, 30 per ABI layout; 24 cover scope transitions and partial failures.
An initial permissive-padding fixture reproduced zero image dependencies before
the scope correction. Current assertions require the exact consumed image
ranges across padding, adjacent image segments, and later failures.

The live smoke failed against the pre-feature plugin: exploration stopped at
the first unsupported bounded call, with zero summarized calls and no recovered
literal. With the completed implementation, two calls per run are summarized
(eight across four runs), and both positive ctrees contain the expected literal.
Changing the search value selects the early return, removes the old literal,
and leaves IDB output bytes unchanged. The existing Aldaz probe also passes its
11 literal and repeated-decompilation byte-stability assertions.

Artifacts:

- Baseline run: `/tmp/chernobog-bounded-search-before`; plugin SHA-256
  `2880bea68c13e2887b687dccd729c0668d6d15ef76da682a6a042e5607cfa1ad`.
- Completed run: `/tmp/chernobog-bounded-search-final`; plugin SHA-256
  `5e595e591de1ad3dd0f6012e4ce63b4bbaa0cc2ac2e758c235b0161cb6db3e28`,
  source fingerprint `dac1293b6fb0`, IDA SDK 9.40.
- Fixture SHA-256:
  `f388681de06cf09c7c9a6bfbd99ff923eec26787ecea300312e74704289c0152`.
- Aldaz regression: `/tmp/chernobog-libc-indexed-aldaz`.

These runs verify behavior, not a libc-model performance improvement. The local
libida macOS 15.0 versus project 13.3 deployment-target warning remains; native
Windows/Linux host integration is unverified. Quality review covers explicit
assumptions/probes, target-byte units, standard/model-policy separation, failure
and dependency edges, reproducible validation, and bounded capability claims.
