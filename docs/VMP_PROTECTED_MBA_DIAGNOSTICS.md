# Protected SDK shapes and bounded MBA rejection diagnostics

This checkpoint adds status/width/reason diagnostics to the existing typed
instance verifier and measures the complete generated x86-64/i386 protector
matrix at four SDK maturities. It advances review 4a/4b and validation row V.
The full review remains in progress. No new identity, reaching-definition
propagation, native ownership policy, or VM lifting is implemented here.

## Production diagnostic contract

`chernobog_rule_stats()` retains its existing four instance outcome counters
and adds:

| Field | Representation and meaning |
|---|---|
| `instance_rejection_reasons` | JSON string containing `{status,width_bits,reason,count}` records for completed disproved, unsupported, or unknown attempts |
| `instance_unrecorded_rejections` | Rejections whose distinct reason exceeds the retention budget |

At most 32 distinct `(status, width, reason)` keys and 256 bytes per
reason are retained. A repeated retained key continues accumulating after the
distinct-key budget fills. Every dropped reason still increments its outcome
counter. Snapshots and resets hold one mutex across the counters and histogram.
An attempt completing after a reset belongs to the new diagnostic interval,
irrespective of when it started. The solver and translator run outside that
mutex; their proof eligibility, result, timeout and resource limits are unchanged.

These are process-local completion diagnostics. They are neither persistent
proof receipts nor an attribution to a unique instruction or rule. Repeated
microcode generation can count the same expression again. Registry
`successful_matches` counts a structural match before the typed proof; it
does not count accepted replacements. A successful match can subsequently
produce an unsupported instance result.

Recording takes O(K·L) worst-case string comparison work with K ≤ 32 and
L ≤ 256 bytes. Retained reason payload is at most 8,192 bytes, plus bounded
container/key overhead. Snapshot work is O(K·L); reset clears that retained
state. This is not a function-wide solver or latency bound.

## Frozen generation and provenance

The former local `build/vmp-corpus-release` archives are absent. Fresh,
separately named corpora were generated with the unchanged corpus producer.
Historical reports and source hashes were preserved. The console and SDK
binary hashes match the historical protector artifacts; six of eight shared
reference-source hashes differ from the earlier paired-corpus checkpoint
(`VMP_PAIRED_CORPUS_EVIDENCE.json`). Source-to-console
build attestation remains **unknown**. Current reference hashes, including the
ELF emitter, are recorded separately in the evidence JSON.

Each architecture has an original and nine protected binaries:
mutation, virtualization and combined modes with protector seeds 0, 1 and
`0xc0ffee`. Each requested build repeats byte-identically. Three input seeds
exercise 560 behavior records per binary. Both full corpora pass 30 native
process observations and 16,800 integer-oracle records each: 60 observations
and 33,600 records total. The producer's reserved protector/input seed
partitions are retained; the subsequent diagnostic inspection includes those
seeds. They are not represented as permanently sequestered data after this
inspection. The finite arithmetic seed below is not a held-out seed.

The x86-64 Mach-O executable runs through host translation; ELF32 runs through
the pinned QEMU 9.2.0 image. Physical x86 execution equivalence is unknown.
The producer compares its declared result/flag/memory/stack outputs; this
does not establish every fault, flag, input or execution-mode behavior.

## SDK capture profile and access workaround

All five supplied sample files have mode `0755` and were read completely.
Filesystem access no longer prevents analysis. Generated corpora remain
distinct from those supplied samples.

An initial native-analysis-enabled entry-only matrix completed 39 processes
but one i386 virtualization case exceeded its 120 s wall-clock cap. A separate
diagnostic process remained in initial `auto_wait()` until explicitly stopped
after 188.082 s. A 2 s stack sample includes native proof revalidation and
register/dataflow recomputation inside IDA database callbacks. The complete
cause and a production latency fix are **unknown**; increasing a limit is not
presented as that fix.

The MBA matrix explicitly sets `CHERNOBOG_IDA_ANALYSIS=0` in both profiles.
That disables native analysis and dependent early lowering while retaining
the Chernobog MBA handler in the enabled profile. This configuration lets the
isolated case complete and makes the diagnostic capture reproducible. Native
recovery behavior under the default configuration is outside this matrix.
To apply the same temporary configuration to a process launched from a shell:

```sh
export CHERNOBOG_IDA_ANALYSIS=0
```

IDA's bundled gooMBA plugin also loads. Its binary/configuration, x86 decompiler,
processor module, IDA libraries and executable are pinned before and after each
matrix. The disabled profile is the recorded IDA/plugin environment with
Chernobog transformations disabled; it is not a claim about bare Hex-Rays.

Each matrix has 40 isolated processes: 20 byte-identical binaries × disabled
and enabled Chernobog profiles. Both original selected entries are captured
at GENERATED, PREOPTIMIZED, LOCOPT and GLBOPT1. For a decoded direct entry
jump, the probe also inspects its one-hop target. It captures that target only
when it already has an exact function owner. It creates no function or region.
The driver independently checks entry bytes against the file-backed text
section and computes the relative jump target from the encoded displacement.

Capture limits are 64 native chunks, 262,144 native bytes per selected owner,
256 blocks per stage, 8,192 instruction nodes per process, depth 64,
524,288 retained diagnostic-text bytes, 1,024 text bytes per node, and a
4,194,304-byte JSON report. UTF-8 truncation retains complete code points.
The per-process wall-clock cap is 300 s. Refusals and quota outcomes remain
explicit; a passed measurement is not a successful deobfuscation verdict.

## Observed shapes and limits

| Population, per profile | Observed result |
|---|---|
| 40 selected entry owners | All captured; every protected entry owner contains the five-byte jump stub |
| 18 x86-64 protected direct targets | Ownerless; no body microcode fabricated |
| 18 i386 protected direct targets | 17 exact owners; mutation seed 1's branch target lies inside another owner and is not captured |
| 228 SDK stage attempts | 227 captures; the reserved-seed i386 virtualization branch body refuses GLBOPT1 with `MERR_BADCALL` (−12: call arguments not determined) in both profiles |
| 227 paired captured stages | 224 recorded shapes equal; three changed stages |
| Enabled typed outcomes | Four verified attempts, two unsupported attempts, zero disproved/unknown attempts |

The verified attempts occur in seed-0 i386 virtualization and combined
transform bodies. Two isolated LOCOPT value changes are:

```text
neg.4(add.4(x, 0x106cb8a8)) -> sub.4(neg.4(x), 0x106cb8a8)
bnot.4(sub.4(x, 1))        -> neg.4(x)
```

For M = 2³², both equalities hold modulo M:
`−(x+c) ≡ −x−c` and `M−1−((x−1) mod M) ≡ −x`.
They use existing identities. The third changed capture is the virtualization
expression retained inside a later GLBOPT1 call tree; it is not a third unique
recovered identity. Instance counts include earlier optimization work performed
inside generation of a later maturity.

Two proposals in the reserved-seed i386 combined transform body's GLBOPT1
generation are rejected with width 32 and reason
`unsupported instruction opcode or effects`. The original remains in place.
This aggregate per-generation reason does not identify which proposal EA or
which effect/operator triggered the refusal. The two structural matches cannot
be reported as two accepted rewrites.

The measured misses are therefore ownership availability, an SDK refusal and
unsupported typed proof shapes. Remaining recognition, reaching-definition,
aliasing, conversion-order and identity coverage within unavailable or
unproposed bodies is **unknown**. Zero proposals at an entry stub does not
establish canonicalization success or absence of an MBA identity. Literal,
edge and whole-function recovery accuracy are not measured here.

## Verification

The production catalog test collects 69 actual initial results: 9 verified,
9 disproved, 50 unsupported and 1 resource-exhausted unknown. It checks exact
per-status counts and retained reason counts, duplicate-key exclusion,
32-key exhaustion with 17 unrecorded rejections, reset, and one subsequent
disproved result. All 108 catalog rules verify; the deliberately false catalog
rule rejects. All 21 CTest suites pass.

The current capture driver rejects 432 actual-report corruptions; the prior
plugin's legacy-reason profile rejects 392. The independent auditor compares
all 152 selected native rows and 456 stages across the two complete matrices:
454 captured stages and both SDK refusals retain identical recorded trees,
ownership, native chunk hashes and the six preexisting statistics. New
telemetry changes no measured proof outcome or captured SDK shape.

Current measured runner durations range from 0.986326500 s to 14.768611209 s;
the largest platform-reported `wait4` peak-resident value is 205,684,736 bytes.
These include startup and capture under two concurrent jobs. They establish
neither isolated SDK latency, deterministic timing nor a whole-system memory
bound. The SDK refusal name comes from the pinned `hexrays.hpp` enum.

The two isolated 32-bit LOCOPT expressions also pass 65,547 independent Python
integer comparisons each: 11 boundary inputs and 65,536 pseudorandom inputs,
131,094 total. Two deliberately corrupted proposals fail that oracle. Three
profile/population corruptions reject in the cross-plugin comparison. The
auditor neither calls Z3 nor reuses the production translator. Its scalar
register/constant language does not interpret the entire protected body,
flags, memory aliases or fault behavior.

Reproduction, using the recorded corpora and configured tool paths:

```sh
python3 -B tests/run_protected_mba_corpus.py \
  --corpus-report build/vmp-mba-corpus-x64/corpus.json \
  --corpus-report build/vmp-mba-corpus-i386/corpus.json \
  --ida "$TASK_IDA" --plugin "$TASK_PLUGIN" --output-dir "$TASK_CAPTURE"
```

Use the archived prior plugin with `--legacy-reasons` in a separate output
directory. Compare the two full reports:

```sh
python3 -B tests/verify_protected_mba_capture.py \
  "$TASK_PRIOR_REPORT" "$TASK_CURRENT_REPORT" --output "$TASK_COMPARISON"
ctest --test-dir build --output-on-failure -j 20
```

## Assumptions and falsification probes

| ID | Assumption / dependent result | Stress test |
|---|---|---|
| P1 | The frozen protector binary/settings generate this population; all protected observations depend on it | Pin console/SDK/inputs, repeat every protected build, compare every native record; source-build equivalence remains unknown |
| P2 | The recorded SDK environment/profile describes these captures | Pin loaded relevant IDA components, reject changed profile/entry/native bytes/target/maturity, preserve refusals and ownership boundaries |
| P3 | The reason histogram represents completed attempts in one diagnostic interval | Compare independently collected result multisets and each status count; exhaust 32 keys, reset, reject lost-rejection accounting |
| P4 | The two isolated trees describe ordinary 32-bit scalar values | Require matching destinations, exact widths/arity and register/constant leaves; independent arithmetic checks and wrong-proposal controls |
| P5 | Equal recorded trees establish preservation of this measured pipeline only | Compare every prior/current stage and outcome; do not infer omitted frame-owner identities, ISA flags, memory effects, faults or full protected recovery |

High impact: pure entry-stub captures conceal inaccessible relocated bodies.
High impact: repeated proof revalidation during native autoanalysis warrants a
separate bounded performance investigation; the temporary profile loses native
analysis coverage. Medium impact: structural matches can inflate a reported
recovery count unless acceptance outcomes are retained. Low impact: bounded
diagnostic loss remains measurable without changing verifier decisions.

QG1: technical scope only. QG2: P1–P5 include falsification probes. QG3: the
bounded diagnostic feature and full requested capture population are covered;
the original review remains in progress. QG4: byte/bit limits and integer counts
are exact; elapsed nanoseconds and platform `wait4` memory accounting remain
separate from semantic accuracy. QG5: unsupported owners, SDK refusals and
unmeasured effects are explicit. QG6: primary sources/artifacts are pinned in
[VMP_PROTECTED_MBA_DIAGNOSTICS_EVIDENCE.json](VMP_PROTECTED_MBA_DIAGNOSTICS_EVIDENCE.json).
QG7: adjacent opportunities and their limits are bounded above.
