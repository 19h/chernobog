# Exact local SCAS comparison flags

Review row 2a requires flag facts to reflect architectural instruction effects.
Intel's [SCAS instruction reference](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf)
defines the comparison as AL/AX/EAX/RAX minus the memory element at ES:[DI],
with status flags set from that subtraction. Intel's
[64-bit segment-base rule](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-1-manual.pdf)
sets both DS and ES bases to zero in long mode. A plain long-mode `SCAS` now
reads a locally established writable element at an exact natural-address-size
DI address and applies the shared finite-width comparison transfer. The
decoded operands must identify DI and the matching accumulator slice. In
i386, a local DS store does not establish the value at ES:[DI], so these
comparison flags remain unknown. The transfer invalidates DI because its
post-instruction address depends on DF. It preserves the accumulator, count,
stack and retained memory because plain `SCAS` does not write them. A missing
local byte, address-size override, unsupported operand shape or repeat prefix
leaves the six modeled comparison flags unknown. Repeated `SCAS` also
invalidates the count; zero iterations can leave the prior flags unchanged.

The independent assembly fixture executes byte comparisons with CF false and
true and ZF true, a word comparison with CF true, a doubleword comparison with
ZF true, and an x86-64 quadword comparison with ZF true. The earlier
`df_scas_flags_changed` byte case supplies the CF-false result. An initial
`.data` byte without a local write remains unknown to analysis even though the
native process returns CF true. A `REPE SCASB` fixture alternates its count
between zero and one, yielding different native CF results while remaining
unresolved statically. This tests the repeat zero-iteration ambiguity rather
than assuming the final comparison always ran.

| Architecture | Prior/current proved SCAS conditions per path | Owned native checks | Prior/current owned IDA assertions | Ownerless native checks | Ownerless IDA assertions |
|---|---:|---:|---:|---:|---:|
| x86-64 | 0 / 6 | 23,294 | 285 / 297 | 4,094 | 1,150 |
| i386 | 0 / 0 | 23,038 | 284 / 284 | 4,094 | 1,140 |

All counts are per architecture and per owned or ownerless path as applicable.
The native totals are `89 × 256 + 2 × 255 = 23,294` for x86-64 and
`88 × 256 + 2 × 255 = 23,038` for i386. Each ownerless runner rejects its
deliberately corrupted oracle. The prior plugin is the signed build from the
`REP STOS`/`REP LODS` checkpoint; the current plugin differs in the `SCAS`
state transfer. Prior/current runs use identical source-annotated fixtures,
probes, executable binaries and IDA bytes. The expectation-only
`CHERNOBOG_SCAS_BASELINE=1` setting distinguishes prior assertions. Only the
six x86-64 positive condition outcomes change. The two negative controls and
all i386 SCAS conditions remain unresolved. The frozen native
transfer oracle remains 30/36 correct edges, zero false edges and three
unresolved eligible sites for both plugins, architectures and analysis paths.
All 21 CTest suites pass. No protected-binary flag-recovery rate follows from
these native fixtures.

Reproduce with fresh output directories and hash-matched tools:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/scas-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/scas-ownerless-reproduction
python3 -B tests/score_native_edge_benchmark.py \
  --owned-report build/scas-owned-reproduction/dataflow_analysis.json \
  --ownerless-report build/scas-ownerless-reproduction/ownerless_dataflow_analysis.json \
  --nm "$LLVM_NM" --output-dir build/scas-score-reproduction
```

The prior controls add `--scas-baseline` to each runner and use the prior
signed plugin. `VMP_SCAS_LOCAL_FLAGS_EVIDENCE.json` records exact source,
tool, binary and report SHA-256 values and per-run wrapper measurements.
Elapsed nanoseconds and peak resident bytes measure the outer `wait4`
launcher, including IDA startup; they do not isolate plugin latency or peak
memory. Each local memory read checks W/8 bytes, where W is 8, 16, 32 or 64
bits. With B at most 128 retained bytes in an ordered map, the lookup work is
O((W/8) log B) time and O(1) additional space. IDA segment lookup and CFG
iteration are outside that bound. A byte is 8 bits; time and resident size are
reported in nanoseconds and bytes.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | The decoder's implicit DI memory operand and accumulator slice match the instruction's element width and the Intel subtraction order. The proved CF/ZF values depend on this. | Inspect decoded operands on x86-64/i386; execute smaller and larger accumulator comparisons, equal comparisons and all admitted widths. Reverse the operands as a mutation and require the CF-true case to fail. |
| C2 | In 64-bit mode, Intel specifies zero bases for DS and ES. The local-read proof depends on this and on a natural address size. | Test a 32-bit database, where ES identity is unknown, and require abstention despite matching native results. Add explicit segment identity before admitting an i386 local comparison. |
| C3 | Initial writable bytes are unknown and a repeated scan may execute zero times. The negative outcomes depend on these barriers. | Require the initial-byte fixture to remain unresolved; execute repeat counts zero and one with different CF outputs and require no static fact. |
| C4 | The only production semantic difference in the matched runs is the new SCAS transfer. Attribution of six long-mode gains depends on this. | Compare fixture, probe, binary and IDA hashes; compare all captured condition outcomes and the 36-edge transfer oracle. |
| C5 | Wrapper `wait4` scope includes launch and IDA startup. The resource observations depend on this scope. | Instrument IDA and plugin separately before making plugin-specific performance claims. |

- **High impact:** exact local scan comparisons add six x86-64 proven
  conditions across owned and ownerless analysis.
- **Medium impact:** the i386 fixtures execute the same comparisons but remain
  unresolved because ES may address different memory from DS.
- **Low impact:** the transfer-edge denominator is unchanged, and protected
  effectiveness remains unknown.

QG1: technical scope. QG2: C1–C5 include falsification probes. QG3: all four
admitted long-mode widths, i386 abstention, both analysis paths,
negative controls and matched comparison are covered; the full review remains
in progress. QG4: check arithmetic, units and complexity are explicit. QG5:
repeat, initial memory and i386 segment ambiguity remain outside proved facts. QG6:
Intel's primary manuals and hash-linked native/IDA reports support
the bounded claims. QG7: segment modeling and protected coverage are bounded
above.
