# Typed integer flag expressions and independent replay

This checkpoint advances review rows 4a/4b. Production instance verification
now translates integer `cfadd`, `ofadd`, `seto` and `setp`. Constant proposals
run through the predicate registry and typed admission before mutation, in both
the bounded MBA traversal and dedicated predicate handler. Symbolic flags do
not generate speculative 0/1 proposals. The complete review remains in progress.

## Contracts

Inputs have equal widths of 1, 2, 4 or 8 bytes; results have exactly one byte.
For w input bits, unsigned inputs u/v and signed interpretation s, results are:

| Opcode | Byte value, always 0 or 1 |
|---|---|
| `cfadd` | u + v is at least 2^w |
| `ofadd` | s(u) + s(v) is outside [-2^(w-1), 2^(w-1)-1] |
| `seto` | s(u) - s(v) is outside the same signed interval |
| `setp` | The low byte of u - v has an even population count |

Production uses wrapping bitvectors and sign/parity bits. Independent symbolic
analysis uses widened arithmetic; integer replay uses signed intervals and
population counts. The [primary SDK declarations](https://cpp.docs.hex-rays.com/hexrays_8hpp_source.html)
identify these operations and floating/integer SETP modes. The pinned local
header and actual compiled CMP/SUB/SETcc observations establish the tested
domain; the public page is not a version pin.

Floating instructions, unsupported effects/widths, undefined values, changed
explicit reads, distinct value numbers and frame owners retain existing
rejection contracts. Shift carry remains unsupported. UNKNOWN/UNSUPPORTED
cannot authorize mutation. Equivalence concerns normal-completion values;
faults, concurrent/volatile observations and whole architectural state remain
outside the contract.

## Original instruction metadata

Transient inputs now retain original `root_iprops`; synthetic AST-only captures
record null. Replay accepts historical five-field and new six-field records.
Independent primitive analysis adds four flags, ten integer comparisons, sign
extraction and logical NOT. These require explicit zero root properties,
correct arity and typed input/result widths. Missing/nonzero properties abstain.
Metadata participates in proof cache keys and witness replay. Historical
evidence is unchanged; floating unordered SETP is never inferred to be parity.

## Executed evidence

The fixture executes ADD/SUB with SETC/SETO/SETP, a separate CMP/SETP function,
and four constant parity/overflow return controls. It runs as an x86-64 process
on arm64 macOS. Translation is inferred from those architectures; available
Rosetta runtime files are hashed, but their loaded mapping is unknown. Physical
x86 hardware cross-validation is not claimed.

Exactly 256 × 256 + 3 × 8 × 8 = 65,728 pairs cover exhaustive byte inputs and
eight signed/unsigned boundary values at each wider width. Four status bytes
per pair give 262,912 bytes, SHA-256
`2f6e190ef29c9d5e95ef0193a10c27f62a98f51fc9b0dc459bebadd6b8852a1a`.

| Check | Exact observed result |
|---|---|
| Production verifier vs native bytes | 262,912 verified, no mismatch |
| Independent integer/symbolic evaluation | 262,912 checks each, no mismatch |
| SDK context-free optimizer | 132,012 folded results match native bytes |
| SDK retained constant expressions | 65,172 OFADD and 65,728 SETP; no invented result |
| Matched live SDK fixture | Nine functions, 36 captures and 328,516 result/memory checks per profile |
| Actual simplification | Four parity/overflow functions become correct constants; five other GLBOPT1 trees remain equal |
| Corruption/control evidence | Wrong captured constant rejected; 509 semantic controls pass |
| Regression suites | 23 pass, zero failures; observed elapsed time 25.70 s |

Production/native comparison took 1.816484583 s, peak 22,872,064 resident bytes;
independent integer/symbolic comparison took 26.555066250 s, peak 81,641,472
bytes. These are individual process observations. Component dispatch constructs
allocation-free SDK values; actual IDA runs separately demonstrate live mutation.

## Protected matrix and remaining scope

The current matrix has 40 successful SDK processes: both architectures,
original plus nine variants, transformations enabled/disabled. It rechecks
33,600 historical native behavior records and their hashes. Baseline is the
accepted `b89d23fc` installed-module matrix; `b89d23fc` through `e2ea24bf` has
no production source difference.

All 152 native row pairs, 456 stage outcomes and 454 captured typed trees remain
equal. Catalog applications remain five. Extra transient verified admissions
replace 18 unindexed attempts on i386: mutation seed 0 adds three; virtualization
seeds 0/1 add three/six; held-out seed 12,648,430 adds six. All 108 catalog rules
certify in this run. Those admissions establish no captured-tree/recovery gain.

The semantic audit uses 325 unique proofs. Of 5,261 retained events, 4,595 refute
any constant/current same-width operand reduction and 666 abstain: 627
nonprimitive trees, six unsupported nested values/loads, 30 reserved condition
registers and three unsupported roots. It replays 8,593 SAT witnesses and 521
rejected-rule counterexamples. Capture quotas omit another 8,786 of 14,047 total
events. Native reachability and arbitrary identity completeness remain unknown.

## Reproduction and durable evidence

`VMP_INTEGER_FLAGS_EVIDENCE.json` pins sources, tools, modules and receipts.
`VMP_INTEGER_FLAGS_CAPTURE.json.gz` retains exact UTF-8 captures/reports in
`files[path].text` and native observations in `binary_files[path].base64`, each
with SHA-256. Paths are repository-relative. Restore to a separate checkout and
verify hashes before replay. Modules/protected executable bytes are not embedded.

```sh
xcrun --sdk macosx clang -arch x86_64 -O2 -Wall -Wextra -Werror \
  tests/vmp_native/flag_values_oracle.c -o build/flag-values-oracle
build/flag-values-oracle > build/flag-values-native.bin
build/chernobog_catalog_tests --native-flag-values build/flag-values-native.bin
python3 -B tests/verify_flag_values.py --native build/flag-values-native.bin \
  --fixtures build/flag-component-fixtures.json --output build/flag-values-independent.json
python3 -B tests/mba_semantic_miss_tests.py --fixtures build/flag-component-fixtures.json
python3 -B tests/verify_flag_shapes.py --before build/flag-shapes-prior-e2ea24bf-v3 \
  --after build/flag-shapes-candidate-v1 --native build/flag-values-native.bin \
  --output build/flag-shapes-paired-audit.json
python3 -B tests/verify_flag_corpus.py \
  --baseline build/predicate-matrix-installed-b89d23fc-v3/protected_mba_analysis.json \
  --current build/flag-matrix-candidate-v1/protected_mba_analysis.json \
  --output build/flag-matrix-paired-audit.json
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/flag-matrix-candidate-v1/protected_mba_analysis.json \
  --output build/flag-matrix-semantic-audit.json
```

The component binary requires the SDK loader environment used by CTest. Z3
engine/package versions are 4.16.0/4.16.0.0. Fresh SDK captures use
`run_ida_smoke.py`, pinned IDA/module paths, `ida_flag_shapes_probe.py` and
`CHERNOBOG_IDA_ANALYSIS=0`. The protected matrix keeps native analysis enabled.
Exact manifests record those distinct profiles.

## Assumptions, bounded expansion and quality gates

| ID | Assumption / dependent conclusion | Falsification probe |
|---|---|---|
| F1 | Pinned SDK integer flags match observed x86 process semantics; typed results depend on this. | Exhaustive byte/wider-boundary native, integer, symbolic and SDK comparisons; nonzero-right CMP, float and width controls. Other SDKs/hardware remain unknown. |
| F2 | Stable normal-completion snapshots define equivalence. | Distinct versions/owners/read occurrences; reject effects and missing original metadata. Fault/concurrency behavior remains outside the contract. |
| F3 | Live callers retain destination/ownership. | Matched SDK/native bytes, rejected wrong constants, unchanged protected native rows and typed admission gates. |
| F4 | Matched hashes/profiles attribute observations. | Verify source/tool/input/archive pins and process outcomes; compare baseline and preserve historical evidence. |

Bounded opportunities: **medium**, constant flag gaps gain typed live admission;
**medium**, original instruction metadata improves semantic abstention; **low**,
durable captures preserve replay. General CFG/aliases, shift carry, floating
unordered semantics, whole-state faults and full recovery remain open.

For fixed scalar widths, each flag translation uses O(1) terms/work; parity
examines eight bits. Joint translation retains 512-visit/depth-64 bounds.
Witness replay is O(B) in snapshot bytes. Solver queries have separate budgets;
no polynomial SMT complexity claim is made. Counts/arithmetic are exact.

QG1: technical scope. QG2: F1–F4/probes. QG3: checkpoint integration, metadata,
independent semantics, controls and corpus covered; full review remains open.
QG4: exact bit/byte equations, counts and SI units. QG5: unsupported domains,
omissions and UNKNOWN explicit. QG6: pinned primary SDK/native/solver evidence.
QG7: bounded adjacent opportunities and exclusions recorded.
