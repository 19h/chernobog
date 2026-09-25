# Corroborated single-read heap strings

Review requirements 3a and 3b require use-time bytes with explicit provenance.
The general use-site projector previously admitted a NUL-terminated executed
read from its snapshot alone. It did not require the corresponding memory event
or a complete data trace. The native read projector already validates exact
read/data pairs, but only published streams containing multiple reads. Executed
single reads now pass through that validator. Modeled argument snapshots remain
on their separate path.

## Admission and cost

An executed read requires an exact snapshot and, for heap reads, a live
allocation generation. It also requires a matching read event at the next
sequence, with the same instruction site, address, scope, size and
little-endian value, and a complete unfiltered data trace in every eligible
run. A single read containing a valid NUL-terminated UTF-8 prefix
may then enter cross-run semantic-use consensus. The original read is retained
as its sole fragment. A missing, changed or unavailable data event abstains.
One exact read does not imply an unobserved prefix, allocation final value or
equivalence of different input paths.

For `U` executed uses of at most `B = 8` bytes each, the additional terminator
scan and decoding cost `O(U B)` time. The existing cap is `U <= 4,096` uses per
run and 1,048,576 retained snapshot bytes per run. The ordinary consensus
indexes and native grouping retain their prior bounds.

## Matched observations

The x86-64 and arm64 Mach-O fixtures each decode `secret!\0` and `second!\0`
into one 32-byte heap object, make one volatile eight-byte read per string,
consume the loaded bytes in a hash, erase the allocation with 32 volatile byte
stores and free it. Both positive binaries exit 0; corrupting the expected
second hash makes both exit 1. The portable regression constructs two complete
runs with matching read/data records and then changes both snapshots without
changing either data event; the forged value is rejected. Missing data and an
unavailable data trace also reject.

| Architecture | Returned runs | Previous plugin: candidates / annotations / verified rows / checks | Revised plugin: candidates / annotations / verified rows / checks |
|---|---:|---:|---:|
| x86-64 | 4 | 2 / 2 / 0 / 9 of 10 | 2 / 2 / 8 / 10 of 10 |
| arm64 | 6 | 2 / 2 / 0 / 9 of 10 | 2 / 2 / 12 / 10 of 10 |

Each matched previous/current pair uses identical binary, probe and IDA bytes.
The prior plugin already displayed both strings; this change adds independently
checked read/data provenance and the corresponding evidence rows. The bounded
event view exposes both eight-byte reads per run on x86-64 and the first on
arm64. Its 1,024-row event cap omits the later arm64 read events, while the
separate bounded read-stream table retains both candidates per run. Every
visible read has an exact matching data event. Both current profiles preserve
the two transient annotations, saved-comment absence, function bytes and
key-edit revocation/restoration. The prior plugin fails only the verified-row
check. Existing disjoint multi-read x86-64 and arm64 profiles still pass 10/10
checks each; all 21 CTest suites pass with four parallel jobs. Exact identities
and raw-report hashes are in `VMP_SINGLE_READ_CORROBORATION_EVIDENCE.json`.

Reproduce a current x86-64 profile with a fresh output directory:

```sh
xcrun --sdk macosx clang -O2 -arch x86_64 \
  -DNATIVE_DISJOINT_SINGLE_READ=1 \
  tests/vmp_native/native_disjoint_strings.c -o build/vmp-single-read-x64
python3 tests/run_ida_smoke.py build/vmp-single-read-x64 \
  tests/ida_disjoint_string_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_SINGLE_READ=1 \
  --output-dir build/vmp-single-read-reproduction
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | A validated read/data pair describes the same executed use. Both corroborated values depend on this. | Change snapshot bytes, remove the data event or disable data observation; each rejects. Fresh IDA shows matching visible read/data pairs. |
| R2 | Complete temporal and data capture covers the reported use. Candidate publication depends on this. | Incomplete memory observation rejects in the portable case; production profiles report complete returned runs and no temporal truncation. A falsely complete external trace remains unknown. |
| R3 | The source hash oracle detects a changed second string. Native behavior depends on this. | Positive x86-64/arm64 binaries exit 0; both wrong-second-hash binaries exit 1. |
| R4 | Matched IDA profiles differ in plugin bytes for attribution. The row gain depends on this. | Compare input, probe and IDA hashes in each previous/current pair; each previous plugin has zero verified rows. |
| R5 | The display is tied to current evidence and a current key. Both annotations depend on this. | Key mutation revokes both annotations; restoration recovers them, without saved comments or function-byte changes. |

**High impact:** executed single-read text can no longer be published solely
from uncorroborated snapshots. **Medium impact:** exact single-read provenance
is visible in the read-stream table without changing the measured literal
count. **Low impact:** the bounded event view omits some arm64 raw rows; the
separate candidate table and exact validator are not derived from that view.
Protected-sample coverage, other memory scopes, incomplete external traces,
cross-thread effects and full review completion remain unknown.

QG1: no normative premise. QG2: R1–R5 include falsification probes. QG3:
portable red/green, native-process, matched IDA and multi-read regression
checks cover this scoped change; the full review remains open. QG4: byte sizes,
run counts, caps and complexity are explicit. QG5: missing or contradictory
data and unavailable observation abstain. QG6: source, fixture, plugin, IDA
and raw-report hashes identify the primary evidence. QG7: event-view and
protected-sample limits are bounded above.
