# Native prefix decoder precheck

`NativeAnalysisEngine::Impl::redundant_rep_prefix()` previously decoded a loaded
address before checking whether its first byte was `F2` or `F3`. That byte
condition was already mandatory in `prefix_candidate_is_semantically_eligible()`.
The change tests it before the recursive decode. Remaining prefix admission,
instruction-equivalence checks, and database mutations are unchanged.

The engine observes `processor_t::ev_ana_insn`, which also occurs when Hex-Rays
decodes native instructions for register-access queries. The recursion flag
prevents indefinite recursion but previously allowed one additional raw decode
and event traversal at every ordinary opcode. The new precheck eliminates that
additional decode for first bytes other than `F2` and `F3`. It adds no cache or
invalidation policy.

## Reproduction and observed controls

```sh
xcrun clang -arch x86_64 -g0 tests/native_prefix/fixture.S \
  -o /tmp/native_prefix_fixture
python3 tests/run_ida_smoke.py \
  /tmp/native_prefix_fixture tests/ida_native_prefix_gate_smoke.py \
  --ida /path/to/idat --plugin /path/to/chernobog.dylib --verbose \
  --output-dir /tmp/chernobog-native-prefix-validation
```

The [fixture](native_prefix/fixture.S) supplies eleven instruction byte
sequences. Its native `main` returns zero; the string-operation controls are
decoded rather than executed. The [probe](ida_native_prefix_gate_smoke.py)
performs 32 explicit `decode_insn` calls per sequence. Its IDP observer is active
only during those calls and always returns zero. It records analysis callbacks
by address, instruction size/type/features/operands and prefix metadata, and
unchanged raw bytes.

The old artifact
`5c492fddf152e5ed642a49af8e27d76172eb2514365f35f6b435673d39e1663b`
passed in `/tmp/chernobog-native-prefix-before-2`:

| Control | Explicit calls | Old callbacks | New callbacks |
|---|---:|---:|---:|
| Ordinary ADD | 32 | 64 | 32 |
| Ordinary NOP | 32 | 64 | 32 |
| Redundant F3 ADD | 32 | 96 | 96 |
| Redundant F2 ADD | 32 | 96 | 96 |
| PAUSE | 32 | 64 | 64 |
| F3 RET | 32 | 64 | 64 |
| REP MOVSB | 32 | 64 | 64 |
| REPNE CMPSB | 32 | 64 | 64 |
| F2 mandatory SSE prefix | 32 | 64 | 64 |
| F3 plus REX prefix train | 32 | 64 | 64 |
| F3 plus operand-size prefix train | 32 | 64 | 64 |

This is 352 explicit decoder calls. Accepted redundant prefixes retain the
engine's one-byte NOP representation; all negative prefix controls retain their
full native instruction lengths. The matched new artifact
`06477f4c8caea6432b5500e8a8e93e7813219c3d7b2083606f6c88585b601833`
passed in `/tmp/chernobog-native-prefix-after-2`. All instruction records,
including `auxpref`, `segpref`, `insnpref`, flags, and operands, and every raw
byte record are identical across the pair. Ordinary controls decrease from
two to one analysis event per explicit decode; the nine F2/F3 controls retain
their original event counts and address distributions.

The [offline comparison](verify_native_prefix_gate_pair.py) passes for these
runs and enforces the ordinary event reduction and unchanged prefix controls:

```sh
python3 tests/verify_native_prefix_gate_pair.py \
  /tmp/chernobog-native-prefix-before-2 /tmp/chernobog-native-prefix-after-2
```

Output is saved in `/tmp/chernobog-native-prefix-pair.txt`. Both runs have
identical input, probe, IDA executable, controlled environment, and PASS
assertion hashes; every artifact-integrity check passes. The controlled
environment SHA-256 is
`b1256521b6d90be3a772eaba3cc9473b6ff7f0d173e2ce2e8b32b1347b0cf8c7`;
the IDA executable SHA-256 is
`387d681d6fb4f4c1c485a60025cae3f0affa6f5ea1efce3b1809639cb1aaeb28`.
The plugin artifacts also contain changes outside the native prefix handler;
the focused probe performs no decompilation, and the only native prefix source
change is this necessary-condition precheck.

Frozen raw executable SHA-256:
`89e2887898083d926e645e0edaae7748ce4bc766fc833e84bef88f54cbb8f71a`.
Frozen probe SHA-256:
`f80611f31f9af3946075018ab186aa2d5b3ca20adfd3ff86533a7efada052367`.
Fixture assembly SHA-256:
`ad2202daedd036c4f9bf41a68ea7e54a8eb1bee58ec92511cce1727cfaf8cde7`.

## Assumptions and falsification probes

- P1: The gate reads stable bytes during a synchronous decode. The probe
  requires unchanged raw bytes before and after every repeated control.
- P2: A first byte other than `F2` or `F3` cannot pass the existing downstream
  eligibility test. This follows directly from its first-byte predicate; the
  ordinary ADD and NOP controls test the shortened path.
- P3: The precheck preserves prefix admission. Redundant F2/F3 operations are
  positive controls; PAUSE, RET, strings, mandatory SSE prefixes, and prefix
  trains are negative controls. Instruction records must match across builds.
- P4: Observer counts measure actual analysis events during explicit decode
  calls, including recursive calls. The observer returns zero and does not
  alter the processor result. Run attribution requires identical raw input,
  probe, IDA executable, and controlled environment.
- P5: Event counts are operation counts, not elapsed-time estimates. The
  controls are an intentionally balanced fixture and do not establish the
  frequency of ordinary instructions in a real query workload.

Medium-impact opportunity: the early rejection removes redundant decoding from
read-only register-access queries as well as normal autoanalysis. Low-impact
scope limit: actual F2/F3 candidates retain the previous number of proof
decodes. Per invocation the new work is one byte read and two comparisons,
with `O(1)` time and space; the avoided decoder cost is SDK-dependent.

## Diagnostic provenance and limits

A single 3 s process sample of the root-owned larger-corpus run is saved at
`/tmp/chernobog-guarded-dispatch-fast/regression_audit_sample.txt`. All 2100
main-thread samples occurred in Hex-Rays global call analysis; 2089 were under
call-register-argument discovery. A dominant subtree containing 803 samples
passed through the native analysis event hook, including redundant-prefix
probing and another native decode. No recurrent-switch solver stack was
sampled in that interval. The sample occurred after that run's proof deadline
and does not measure the preceding solver work.

The raw corpus `.text` section contains 2176 F2/F3-valued bytes among 193817
bytes. This byte density includes instruction operands and data; it is not an
instruction-head distribution or dynamic query frequency and does not support
a whole-program speedup estimate. The source predicate and focused event
counts provide the relevant evidence for the avoided operation.

QG1: descriptive technical change. QG2: assumptions P1–P5 have explicit probes
or limits. QG3: ordinary and accepted/rejected prefix paths are covered.
QG4: byte and event counts and the sampling interval are explicit. QG5: static
density, sample location, and dynamic operation counts are distinguished.
QG6: local source, raw controls, IDP records, and run hashes supply provenance.
QG7: the operation reduction and remaining candidate cost are bounded. The matched
operation-count and instruction-semantics validation passes for all eleven
controls; no whole-program elapsed-time claim follows.
