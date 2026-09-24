# Source-annotated native transfer edge benchmark

Review row V requires correctly recovered edges over oracle edges, false edges,
unresolved candidates and bounded resource measurements. The paired VMP corpus
artifacts and protector source tree used in earlier reports are absent from this
workspace. This checkpoint scores **46 source-annotated transfer sites** in the
existing executable x86-64 and i386 native fixtures. It measures the selected
native recognizer, not VMP-protected recovery or whole-binary CFG accuracy.
This is the historical checkpoint at commit
`0b91fc548e915461790da1d7146cab812df65fcb`; its frozen source and
scorer must be checked out at that revision to reproduce its 26/34 result.
The later count-transfer result is in `VMP_REP_MOVS_COUNT.md`.

`tests/score_native_edge_benchmark.py` freezes the reviewed assembly and C
execution-driver hashes. Its oracle names target labels independently of plugin
results. It resolves those labels with `llvm-nm` in each exact binary, checks
binary/probe/IDA/plugin/report identities, and requires one current transfer
record per selected function. For owned functions it also compares the fact's
target with actual IDB user code xrefs from that transfer site. For ownerless
roots it requires a converged, unpublished result and unchanged IDB inventory.
Missing, duplicate, contradictory or changed inputs reject rather than
entering a denominator.

| Oracle class | Sites | Oracle source/target edges | Scoring rule |
|---|---:|---:|---|
| Fixed target for all admitted inputs | 28 | 28 | Count an exact published/proved target; otherwise unresolved or false. |
| Two targets selected by input | 3 | 6 | One unconditional target cannot prove a conditional edge; any such publication is false. |
| Concrete execution contract only | 15 | Excluded | Report separately: entry-supplied aliases, initial writable bytes, or a caller-supplied callback do not establish an unconditional static target. |

The native driver executes the fixed and dynamic fixtures over inputs 0–255.
Its x86-64 process runs under macOS translation on this arm64 host; i386 runs
through pinned QEMU user-mode translation. The C driver checks the returned
values, while the assembly labels establish the address-level oracle. For
the three dynamic cases the two labeled targets have distinct process returns.
The manual label contract is constrained to the exact pinned source hashes;
changing either source file requires a new oracle review.

| Architecture and analysis path | Correct / oracle edges | False edges | Unresolved eligible sites | Concrete-only abstentions |
|---|---:|---:|---:|---:|
| x86-64 owned | 26 / 34 | 0 | 5 / 31 | 15 / 15 |
| x86-64 ownerless | 26 / 34 | 0 | 5 / 31 | 15 / 15 |
| i386 owned | 26 / 34 | 0 | 5 / 31 | 15 / 15 |
| i386 ownerless | 26 / 34 | 0 | 5 / 31 | 15 / 15 |

The exact fraction is 26/34 = 13/17, or 76.5% to three significant figures.
The eight missing oracle edges consist of two fixed targets and six edges at
three input-dependent sites. The two fixed misses are
`df_stack_top_overwrite` and `df_rep_movs_count_unknown`. These abstentions
identify specific next production gaps. The dynamic misses are
`df_stack_top_dynamic`, `df_memory_conflicting_byte`, and
`df_memory_conflicting_store`; an unconditional edge would be unsound there.
The 15 excluded sites remain unresolved in each path. Zero false edges means
zero false published/proved targets **at these selected sites**; it is not a
binary-wide false-positive estimate. The ownerless path returns read-only
facts and publishes no user edges.

The owned fixture runner passed 20,990 native checks and 269 IDA assertions
per architecture. The ownerless runner passed 4,094 native checks and 1,042
IDA assertions per architecture, including its corrupted native-oracle
rejection. The scorer's seven additional in-memory controls cover wrong fixed
targets, unconditional dynamic targets, unresolved facts, and missing,
duplicate or contradictory records. All 21 CTest suites pass. Source, tool,
binary and report SHA-256 values are in
`VMP_NATIVE_EDGE_BENCHMARK_EVIDENCE.json`; the ignored raw score retains each
site, target and classification.

The outer `wait4` wrapper observations were 5.67/10.90 s for x86-64
owned/ownerless and 6.02/7.12 s for i386 owned/ownerless. Corresponding peak
resident bytes were 178,077,696/190,431,232 and 143,654,912/155,222,016.
These measure the Python launcher process including startup, not isolated IDA
or plugin work; no speedup or plugin-memory claim follows. Times in seconds
equal integer nanoseconds divided by 10^9 ns/s.

Reproduce from the hash-matched reports and binaries with a fresh output
directory and the local `llvm-nm` executable:

```sh
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/vmp-native-edge-owned-xrefs/dataflow_analysis.json \
  --ownerless-report build/vmp-string-io-ownerless-installed/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/native-edge-score-reproduction
```

With B total bytes hashed across inputs, F = 46 selected sites, and S symbol
lines per binary, scoring takes O(B + F + S) time and O(B + F + S) host space
under the current read-whole-file hashing. The external `llvm-nm` and native
analysis costs are separate. Counts and edges are dimensionless; sizes are
bytes and timing is seconds or nanoseconds as labeled.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| E1 | The pinned assembly labels describe the expected transfer targets. The 34-edge denominator depends on this manual oracle. | Rehash both source files; resolve every named label in each binary independently with `llvm-nm`; reject duplicate, absent or collapsed labels. Re-review the manifest after any source edit. |
| E2 | The native driver reaches the recorded sites for its inputs. Its 256-input result checks support the selected execution contract. | Require all native checks and the deliberately corrupted ownerless oracle rejection. An instruction-level trace would strengthen dynamic-edge coverage; exact entered-site coverage is not claimed here. |
| E3 | The three dynamic fixtures require input-dependent targets. The six missed edges and false-edge rule depend on this. | Verify distinct target labels and distinct return values for both C-driver branches. A future predicate-scoped result would need a different scoring rule. |
| E4 | Static roots do not inherit the concrete driver's alias, callback or initial writable-state contract. Exclusion of 15 sites depends on this. | Add explicit input and memory-state contracts to the analysis API, then reclassify these sites; until then keep their oracle edges outside the denominator. |
| E5 | The selected reports and binaries correspond to the same installed plugin and IDA version. All four scored rows depend on this. | Rehash source, binaries, raw inspections and outer manifests; reject IDA/plugin mismatch or changed ownerless inventory. Require owned proof targets to equal observed user xrefs. |
| E6 | `wait4` measurements describe the wrapper child, not isolated IDA resource use. The reported resource bounds depend on this scope. | Instrument IDA directly before claiming plugin latency or peak memory. Compare only same-scope wrapper runs. |

- **High impact:** the first source-annotated edge denominator exposes two
  fixed-target implementation gaps and three conditional-target gaps.
- **Medium impact:** separating concrete-only cases prevents the static score
  from claiming the driver's alias and initial-state assumptions.
- **Low impact:** zero observed false edges at these sites does not bound
  protected-binary or whole-IDB false-edge rates.

QG1: technical scope. QG2: E1–E6 include falsification probes. QG3: this
native transfer score covers the stated selected sites; review row V remains
incomplete for VMP protection modes, literal accuracy, solver rejection
reasons and broader fixtures. QG4: edge arithmetic, units and cost are
explicit. QG5: dynamic and concrete-only cases are separated from fixed
proofs. QG6: pinned primary assembly, executable controls, IDA reports and
artifact hashes support the bounded claims. QG7: broader recovery and
resource limits remain explicit.
