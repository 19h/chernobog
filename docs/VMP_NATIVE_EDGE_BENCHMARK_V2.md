# Current native edge and destination-cover benchmark

Review row V now has a separately frozen current-source scorer. The historical
`score_native_edge_benchmark.py` and earlier evidence remain unchanged. Version
2 reviews 62 named PUSH/RET sites in the current assembly: 44 fixed targets,
three input-dependent target pairs and 15 concrete-only cases. Its oracle is
`tests/vmp_native/edge_oracle_v2.json`, bound by a literal SHA-256 in the new
scorer. Changing reviewed assembly, native drivers, probes or shared parsing
code requires a new contract review and pins [E1–E3].

This checkpoint adds measurement and provenance checks. The native analyzer
and target-cover implementation are unchanged. The full review remains in
progress, including protected-mode recovery rates, literal accuracy, solver
rejection reasons and the remaining production gaps.

## Independent oracle and execution [E1, E2]

The oracle names labels independently of plugin targets. `llvm-nm` resolves
them in each exact binary. Capstone independently decodes each root's bounded
file-backed text range and requires exactly one adjacent natural-width PUSH
and near RET. The RET is the edge source. Owned records must identify that RET
and preceding PUSH; ownerless records must identify the same decoded pair.
The scorer checks the target routines' literal 7/8 returns and the stack-word
destinations' 4/8-byte stack adjustments. The byte-overwrite target pair must
share all address bits above the low byte. Thus neither the expected target
nor the expected source EA is taken from the plugin result.

The existing native dataflow driver executes all selected transfer families
over inputs 0–255, along with its other result/flag/memory controls. The owned
binary passes 37,630 x86-64 and 36,350 i386 checks. The new optional
`--edge-oracle-driver` builds the exact ownerless IDA input with
`ownerless_edge_main.c`: it executes the full dataflow driver followed by the
existing ownerless driver. Both result records are required. This strengthens
the earlier ownerless driver, which executed only a subset of the selected
transfer families.

The ownerless primary binaries pass the same 37,630/36,350 dataflow checks and
4,606 additional ownerless checks each. Both deliberate ownerless corruptions
retain their expected nonzero exits and distinct failed cases; the full
dataflow oracle must pass first in each corrupted binary. These are exact-file
process results. The address oracle remains the reviewed source plus decoded
labels and target shapes; an instruction-level entered-edge trace is not
claimed. x86-64 execution is translated macOS execution on the arm64 host;
i386 uses the pinned QEMU 9.2.0 Linux image. Physical x86 equivalence remains
unknown.

## Scoring contract [E2–E4]

The 47 eligible sites contribute 44 + 3·2 = 50 distinct source/target oracle
edges per architecture and analysis path. A fixed site contributes a correct
edge only for an exact current scalar proof. Owned proof targets must equal
the captured IDB user code xrefs. Ownerless proofs remain unpublished and
require a converged, untruncated root with unchanged IDB inventory. A unique
unconditional target at a dynamic site is false even if it is one of the two
oracle destinations: the API supplies no input predicate for that edge.

Destination covers have a separate metric. A complete cover is exact when its
members equal the oracle target set. Omitting a reachable oracle member while
claiming completeness is unsound. Additional members form a sound but
imprecise superset. An incomplete cover establishes no complete-set claim.
Sorted unique members, declared count, width, completeness/status, unknown
inputs, current validation and supporting code bytes are checked. A scalar
proof also requires a consistent singleton cover. Complete covers must retain
the independently decoded PUSH/RET support. Cover equality does not establish
an input predicate or authorize publication of every member as a unique edge.

The 15 concrete-only sites are excluded from both eligible denominators.
Their native target depends on the driver's initial writable bytes, disjoint
object/stack layout or callback argument, which the static root does not
receive. Their reported scalar match, mismatch or abstention is retained
separately.

The architectural string-memory oracle assumes matching DS/ES bases for the
i386 positives under its flat execution model. The static API receives no
segment-base contract. Its conservative i386 segment abstentions count as
missed positive oracle cases; no unsupported segment hypothesis is supplied
to the analyzer to inflate recovery. Normal completion, unchanged code and
nonconcurrent ordinary memory bound the target oracle. Fault equivalence and
whole-program reachability are outside this score [E3].

| Architecture/path | Correct / oracle edges | False edges | Unresolved eligible sites | Exact complete covers / eligible sites | Incomplete covers | Concrete-only abstentions |
|---|---:|---:|---:|---:|---:|---:|
| x86-64 owned | 42/50 | 0 | 5/47 | 45/47 | 2 | 15/15 |
| x86-64 ownerless | 42/50 | 0 | 5/47 | 45/47 | 2 | 15/15 |
| i386 owned | 33/50 | 0 | 14/47 | 36/47 | 11 | 15/15 |
| i386 ownerless | 33/50 | 0 | 14/47 | 36/47 | 11 | 15/15 |

The exact edge fractions are 84% and 66%. All three dynamic sites in every
path have exact two-member complete covers, while their scalar edge remains
unresolved. Complete covers have zero missing or extra oracle members and
zero unsound or imprecise sets. Across the four rows, the scorer checks 248
site captures and reports 150 correct unique edges out of 200 oracle edges,
162 exact covers out of 188 eligible sites, 38 scalar abstentions and zero
false unique edges. These are repeated architecture/path observations, not
248 distinct fixture designs.

The two fixed x86-64 misses are `df_rep_stos_disjoint_target` and
`df_rep_movs_disjoint_target`: the masked input count can be zero or one but
the current abstraction clears the needed memory fact. i386 retains those
two plus nine string-memory/load sites whose admitted local memory proof is
absent. Their raw `incomplete_source` reasons are preserved. They are measured
abstentions, not repaired features. Historical 34/48-edge denominators and
their hashes are retained in their own documents; they are not rewritten by
this score.

## Corruption and attribution controls [E4]

Each architecture/path has 15 mutations of actual captures: wrong fixed or
unconditional dynamic targets, a missing complete-cover member, an imprecise
superset, duplicate members, unknown inputs under completeness, contradictory
status, wrong source site, missing/duplicate records, an unresolved record
with a target, wrong supporting bytes, wrong width, and two ownership-specific
freshness/publication or inventory/publication controls. False edges and
unsound covers must be classified as such; well-formed imprecision remains
separate; malformed or stale inputs must reject.

Seven outer-report mutations additionally require the specific rejection
for source/capture/plugin/binary attribution, duplicate architecture, accepted
corrupted native execution and a failed full dataflow result. All 60 capture
controls and seven attribution controls pass. The full probes retain
453/386 owned and 1,730/1,680 ownerless assertions. Input reports, exact binary
and corruption-binary hashes, probe and shared source hashes, IDA/plugin
identity, Capstone binding/library, `llvm-nm` and measured artifacts remain
stable throughout scoring. Raw per-site rows and controls are retained in
the ignored score, with committed identities in
`VMP_NATIVE_EDGE_BENCHMARK_V2_EVIDENCE.json`.

## Cost, resources and reproduction [E5]

For G global labels and M selected roots, root-bound lookup in this implementation
costs O(M·G) time, plus O(M·L) independent decoding with L≤512 bytes per root.
Cover checks cost O(M·K·log K + P) time, where K≤8 members in the production
domain and P is the retained supporting byte payload. Input parsing and
hashing cost O(A) time and space for artifact bytes A; retained score/control
state is O(M·(K+L)+P). These bounds describe the scorer, not native fixed-point
analysis, IDA or plugin latency.

The score records each outer wrapper's elapsed nanoseconds divided by
10^9 ns/s and peak resident bytes. This wait4 accounting includes launcher
work and is not isolated IDA accounting. Runs may overlap; summing them is
not total wall-clock task time. No speedup is inferred.

```sh
python3 -B tests/run_native_dataflow.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/edge-v2-owned-reproduction \
  --linux32-image chernobog-vmp-linux32:qemu9.2
python3 -B tests/run_ownerless_dataflow.py --edge-oracle-driver \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/edge-v2-ownerless-reproduction \
  --linux32-image chernobog-vmp-linux32:qemu9.2
python3 -B tests/score_native_edge_benchmark_v2.py \
  --owned-report build/edge-v2-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/edge-v2-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$CHERNOBOG_LLVM_NM" --output-dir build/edge-v2-score-reproduction
```

All output directories must be new and repository-relative. Primary provenance
is the pinned assembly/drivers, exact binary labels/bytes, native outputs,
actual IDA records/xref inventories and independently decoded sites. The
Capstone executable binding/library and tool versions are pinned.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress/falsification probe | Bound |
|---|---|---|---|
| E1 | Named labels and reviewed source encode the oracle; edge/source denominator | Literal contract hash, all source pins, independent labels and byte decoding, duplicate/absent/collapsed labels, literal returns and byte-target layout | 62 fixed designs; a source edit requires a new review |
| E2 | Exact native binaries implement the process oracle; target/effect controls | Full dataflow driver in owned and ownerless inputs, both ownerless result records, two corrupted native expectations, input 0/nonzero | Entered-edge trace and physical x86 equivalence unknown |
| E3 | Flat normal-completion model and excluded initial-state cases match the stated domain; interpretation of misses | Explicit segment-base limitation, source-dependent aliases and callbacks, retain all abstentions and 15 excluded cases | i386 segment and variable-count gaps remain; no fault or whole-program claim |
| E4 | Current reports identify exact proofs/covers and actual publications; four scored rows | 60 capture mutations, seven attributed rejection controls, source/artifact/tool stability and read-only ownerless inventory | Complete sets remain distinct from scalar edges; zero false results is limited to selected sites |
| E5 | Wrapper measurements retain their original accounting scope; resource claims | Pin raw measurements; convert nanoseconds exactly; do not sum overlapping runs as task time | Isolated IDA/plugin latency, memory and speedup unknown |

## Bounded scope expansion and quality gates

- High impact: the complete-set oracle detects missing reachable members even
  when scalar target abstention is preserved.
- High impact: executing the full native driver in the ownerless input closes
  a selected-fixture native-evidence gap in the earlier runner.
- Medium impact: independent source EAs and supporting bytes detect misplaced
  transfer records and stale evidence beyond target-value comparison.
- Medium impact: current fixed misses give concrete next analysis work for
  masked repeat counts and missing i386 segment information.
- Low impact: zero selected false edges or unsound covers does not bound a
  protected-binary or whole-IDB error rate.

QG1 passes for this technical scope. QG2 passes with E1–E5 and their probes.
QG3 passes for the current native benchmark checkpoint; review row V and the
full objective remain incomplete. QG4 passes with integer site/member/edge
counts and explicit byte/second accounting. QG5 passes with unsupported
segment information, concrete-only exclusions, dynamic predicates and native
trace limitations explicit. QG6 passes with pinned primary sources and measured
artifacts. QG7 passes with the bounded expansions above.
