# Paired protected temporal-string measurements

The native read-stream implementation recovers and displays both literals from
the original fixture, but recovers neither from any of nine protected variants.
All 36 protected function explorations stop after one instruction at the entry
jump into ownerless code, before any allocation. This identifies region admission
as the first measured prerequisite for this fixture; it does not measure string
recognition after entry into the transformed body.

The accepted run is `build/vmp-protected-strings-release/strings.json`.
[VMP_PROTECTED_STRINGS_EVIDENCE.json](VMP_PROTECTED_STRINGS_EVIDENCE.json) binds
the runner, primary source, binaries, plugin, probes and test log by SHA-256.
This adds a benchmark to review rows 0b, 3a, 3b and V. It does not change production
execution boundaries or complete the review.

**Assumption register**

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| S1 | The supplied protector is relevant to the source tree. Vendor-specific extrapolation depends on this; source-to-build attestation remains **unknown**. | Hash the console, SDK and relevant source independently. Record the actual transformed binaries and all project options. |
| S2 | The independent fixture exercises byte consumption followed by erasure and release. Literal-value expectations depend on this. | Its unprotected comparator checks both packed return values byte for byte. Corrupt each comparator immediate separately and require exit 1, never a crash. Verify the entire 67-byte comparator remains unchanged in every protected image. |
| S3 | Seed instrumentation controls these generated outputs. Same-input repeatability depends on this. | Independently check seed 1 versus 17 and injected override 17; require the callback and every srand application to attest the requested seed. Repeat all nine generations and compare complete file hashes. |
| S4 | Published candidates have fresh, complete scheduled temporal evidence. Reported literal yield depends on this. | Reject unavailable/stale publication, omitted runs, incomplete execution or memory capture, and incomplete consensus. Negative metric controls exercise each case. |
| S5 | Process execution provides a separate behavior observation from Chernobog. Cross-engine comparison depends on this. | Run each binary three times with loader injection removed. The host is arm64; x86-64 execution uses host translation, not independent x86 hardware. Translation implementation/version and ISA-wide correctness are **unknown**. |

**Corpus and oracle [S1–S3, S5]**

`tests/run_vmp_strings.py` compiles
`tests/vmp_native/native_read_strings.S` as x86-64 Mach-O with legacy relocations
and header padding accepted by this serializer. Only `_native_read_strings` is
selected for protection; `_main` remains the independent byte comparator.
The selected entry-to-main span must change and remain file backed. Both expected
plaintext values must be absent from every complete binary image.

The function decrypts `secret!` and `second!`, consumes each as eight individual
byte reads including the terminating NUL, zeroes each 16-byte allocation and
releases it. Chernobog's allocation model reuses addresses; reuse by the native
allocator is not asserted. This is an independent workload protected by the
console, not a claim that it invokes the source tree's `VirtualString` routine.
That routine remains primary motivation: `vmp/runtime/string_manager.cc`.

The matrix uses mutation, virtualization and combined protection at seeds 0, 1
and 12648430 (`0xC0FFEE`). The final seed was reserved before these measurements;
no recognizer was changed in this benchmark changeset. Every artifact is
generated twice with equal whole-file hashes. Project, VM and procedure options
are zero; packing is disabled. Implicit license-dependent flags remain unknown.
There is one fixed input workload, not a randomized input corpus.

All 30 process executions return zero, validating two values each. Both negative
comparators return exactly 1. These are 60 repeated literal comparisons across
10 binaries, not 60 distinct inputs or exhaustive equivalence proofs.

**Production results [S4]**

| Variant family | Binaries | Scheduled / returned analysis runs | Distinct expected values recovered | Displayed annotations | First stop |
|---|---:|---:|---:|---:|---|
| Original | 1 | 4 / 4 | 2 / 2 | 2 | Return sentinel |
| Mutation | 3 | 12 / 0 | 0 / 6 | 0 | Entry jump to ownerless code |
| Virtualization | 3 | 12 / 0 | 0 / 6 | 0 | Entry jump to ownerless code |
| Combined | 3 | 12 / 0 | 0 / 6 | 0 | Entry jump to ownerless code |

Each original run executes 171 instructions and records two allocation lifetimes.
Each protected run executes one instruction and records zero allocation lifetimes.
The probe records the boundary source/target, decoded stop bytes, inferred owner,
run identities, temporal completeness, omissions and candidate provenance. It
does not create instructions, extend functions, or repair ownership to obtain
a successful benchmark result.

Literal-value recall is `distinct expected values observed / 2` per binary.
Duplicate candidate instances cannot inflate it. Literal-value precision is
`expected-value instances / all candidate instances`: 2/2 for the original and
undefined for the protected variants, which publish no candidates. No unexpected
literal values were published. These metrics do not establish semantic-use/site
correspondence for an arbitrary transformed workload; a value match alone is
insufficient for that stronger claim. The protected stop is an explicit
abstention, not a proven absence of plaintext.

Measured process elapsed time spans 0.0235–0.256 s for the native executions and
3.01–6.30 s for the isolated IDA runner processes. Reported peak resident sizes
span 3,391,488–14,422,016 bytes and 199,180,288–233,684,992 bytes respectively.
Elapsed time includes launch and 20 ms polling overhead; IDA runner wait4 memory
accounting includes waited-for children. These descriptive ranges are not
algorithm latency, throughput, confidence intervals or a speedup claim. Raw
integer nanoseconds and bytes are retained for reproducibility.

**Reproduction and measurement controls**

```sh
python3 -B tests/run_vmp_strings.py \
  --protector "$VMP_CONSOLE" --source-tree "$VMP_SOURCE" \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/vmp-protected-strings-new
ctest --test-dir build --output-on-failure
```

The output directory must be new. Console/license banners and host exception
messages are excluded from public reports. Logical filenames identify artifacts.
`tests/ida_protected_strings_probe.py` measures ordinary function exploration,
the existing use-string API and transient ctree display. It is deliberately
separate from the original-only positive regression probe.

`tests/vmp_corpus_tests.py` passes 19 test methods, including duplicate recall,
unexpected/empty precision, incomplete/stale consensus and missing/conflicting
seed-marker controls. All 20 CTest suites pass (11.23 s in this run).
No production code changed, so the plugin identity is the preceding native
read-stream implementation.

With R scheduled runs and C candidates, summary computation takes O(R + C)
expected time and O(C + K) space, where K is the number of distinct stop reasons;
this excludes the recorded view and execution. The probe admits at most 128
candidates, and refuses an omitted run inventory. Matrix execution has fixed
18 protection processes, 30 native positive processes, two native negative
processes and 10 IDA processes, excluding build and seed controls. Each child has
a timeout and a 2 MiB output cap. These bounds do not describe general symbolic
execution complexity.

**Bounded implications and quality gates**

- **High:** entry ownership currently dominates this protected-string workload.
  The next execution improvement needs explicit region bounds and environment
  summaries for allocation/use/release; the separate native-region trace cannot
  yet substitute for ordinary temporal evidence.
- **Medium:** a byte-correct protected native result can coexist with zero
  analysis yield. Keep behavior correctness, recovery and abstentions separate.
- **Low:** fixed input and host translation limit extrapolation. Wider
  architectures, interleaved reads and actual protected `VirtualString` callers
  remain unmeasured by this corpus.

QG1: technical results only. QG2: S1–S5 and falsification probes registered.
QG3: this benchmark changeset has native, production and metric controls; the
full implementation ledger remains incomplete. QG4: exact counts/byte units,
undefined precision and timing scope are explicit. QG5: entry-boundary stops
are preserved and not counted as recovery. QG6: primary fixture/source and all
accepted observations are hash bound. QG7: adjacent implications and limits are
bounded above. The broader goal remains active.
