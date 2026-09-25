# Completed heap strings before an incomplete spatial suffix

Review requirements 3a and 3b require exact use-time bytes without assigning
meaning to unobserved allocation contents. The prior allocation-wide read
projector suppressed every candidate when any later spatial component lacked
an observed NUL. A completed string ending in NUL remains independently
witnessed when the next observed address is separated by a real gap. The
projector now retains complete components before the first incomplete spatial
component and excludes that component and every later address. It does not
infer a string start after an incomplete component.

## Admission and bounds

All reads still require matching data events, one live allocation generation,
complete temporal/data capture, no duplicate observed byte, no unknown effect
or lifetime boundary, and cross-run agreement on use, source-site shape and
value. A NUL followed by an adjacent observed byte remains ambiguous. A gap
after NUL closes a complete component. A gap after a non-NUL byte ends the
admissible prefix; earlier complete components may survive, while later
components do not. A duplicate in the ignored suffix still invalidates its
allocation-wide group. A write overlapping an admitted component vetoes that
component under the existing bounded write check.

```text
sort exact observed bytes by allocation address
scan until the first gap after a non-NUL byte
collect only NUL-terminated components closed before that gap
if the final component lacks NUL, exclude it
assign original read fragments to each completed component
reject crossing fragments, duplicate bytes, effects or write overlap
publish only semantic keys, spatial read shapes and values found in every run
```

For `N` observed bytes and `P` read fragments, the scan and assignment cost
`O(N + P log N)` time and `O(N + P)` space after the existing ordered-byte
map construction. `N` is capped by the 4,096-byte snapshot limit, and each
write scan retains the existing 256-visit cap. These are observed read
strings; the excluded suffix and the allocation's final state have no
inferred value.

## Controlled observations

The x86-64 and arm64 Mach-O fixtures each allocate 32 bytes. They decode
`secret!\0` at offsets 0–7 and `second!\0` at 16–23, read byte `Z` at
offset 30, then read and hash the two strings through two instruction sites
under two input-dependent orders. The extra read occurs first in execution,
but last in spatial order. The function erases all 32 bytes with volatile
stores before freeing the allocation. Both unmodified process binaries exit
0; corrupting the expected second-string hash makes both exit 1.

| Architecture | Complete returned runs | Previous: strings / stream rows / ctree uses | Current: strings / stream rows / ctree uses |
|---|---:|---:|---:|
| x86-64 | 4 | 0 / 0 / 0 | 2 / 8 / 2 |
| arm64 | 6 | 0 / 0 / 0 | 2 / 12 / 2 |

The four fresh IDA 9.4 SP1 profiles use identical binary and probe bytes
within each previous/current pair. The bounded event view shows the exact
offset-30 `Z` read before the string reads in run zero. Every current
candidate has eight original fragments and four or six eligible observations.
The current profiles pass 10/10 checks, including no final image strings, no
saved use comments, unchanged function bytes and consumed-key
revocation/restoration. The previous plugin passes the six unaffected checks
and fails only the four candidate/display checks. Portable controls preserve
the first string when an incomplete component lies between it and the second,
reject a later string when the first component lacks NUL, and reject duplicate
suffix observations. Existing stack-hash, scalar, multisite, permuted-read
and same-object-write IDA probes pass 10/10, 9/9, 10/10, 9/9 and 9/9 checks.
The evidence executable reports 470 interleaved checks, and all 21 CTest
suites pass with four parallel jobs. Exact identities and raw-report hashes
are in `VMP_COMPLETED_READ_PREFIX_EVIDENCE.json`.

Reproduce the current x86-64 profile with:

```sh
xcrun --sdk macosx clang -O2 -arch x86_64 \
  -DNATIVE_DISJOINT_TRAILING_READ=1 \
  tests/vmp_native/native_disjoint_strings.c -o build/vmp-spatial-tail-x64
python3 tests/run_ida_smoke.py build/vmp-spatial-tail-x64 \
  tests/ida_disjoint_string_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_TRAILING_READ=1 \
  --output-dir build/vmp-spatial-tail-reproduction
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| P1 | An observed NUL and a later address gap close a complete earlier component. Prefix admission depends on this. | Adjacent byte after NUL rejects; an incomplete first component admits no later string. A missing read falsely reported as complete would falsify the inference. |
| P2 | Exact allocation identity and read/data events bind each fragment to its component. Both values depend on this. | Same-allocation offset-30 read appears in the bounded event view; duplicate suffix observations and crossing fragments reject. |
| P3 | Temporal capture includes relevant writes and effects. Candidate safety depends on this. | Every run reports complete capture; overlapping writes and unknown effects retain abstention. A falsely complete trace remains an external integrity risk. |
| P4 | The process hash oracle tests the decoded strings independently of the projector. Native behavior depends on this. | Both positive binaries exit 0; both wrong-second-hash binaries exit 1. |
| P5 | The decompiler display belongs to current evidence and the consumed key. The two annotations depend on this. | A key edit revokes both, restoration recovers both, no comments are saved, and isolated runner integrity fields remain true. |

**High impact:** unrelated high-offset reads no longer erase earlier complete
heap strings. **Medium impact:** strings after an incomplete spatial component
still abstain; identifying an independently proved later start is a separate
opportunity. **Low impact:** the scan stops at the first incomplete component
and remains within existing caps. VMP-emitted coverage, other architectures,
cross-thread effects and full protected-path recovery remain unknown.

QG1: no normative premise. QG2: P1–P5 have falsification probes. QG3:
portable, native-process, matched production and regression checks cover this
scoped change; the full review remains open. QG4: byte offsets, caps, counts
and complexity are explicit. QG5: first-incomplete, duplicate, adjacent-NUL,
write-overlap and unknown-effect cases retain abstention. QG6: source,
binary, plugin, IDA and raw-report hashes are recorded. QG7: adjacent
opportunity and limits are bounded above.
