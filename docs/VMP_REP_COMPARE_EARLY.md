# First-comparison termination of REPE/REPNE SCAS and CMPS

Review rows 1b, 2a and V require exact repeated-comparison effects to survive
the native abstract transfer. The [Intel REP specification](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
decrements the address-size count after each comparison and tests the new ZF
to decide whether `REPE` or `REPNE` continues. For an initial exact count
`c >= 2`, a first comparison with ZF = 0 under `REPE`, or ZF = 1 under
`REPNE`, completes exactly one iteration. The final count is `c - 1`;
CF, PF, AF, ZF, SF and OF are the flags of that comparison. The prior ZF
cannot establish termination.

The new abstract helper computes first-comparison flags with the existing
subtraction transfer, then checks the resulting ZF. The production IDA
transfer admits the helper only for decoded implicit `SCAS` or `CMPS`
operands with natural address size, no segment override, supported element
width and an exact count. In x86-64, exact retained local bytes can establish
the first comparison; an identical `CMPS` source and destination address
also establishes equality. When the continuation condition fails, the
transfer retains `RCX = c - 1` and all six computed status flags. It still
invalidates the modified index registers. An unknown first comparison or a
comparison that would continue the repeat remains unresolved. The i386
transfer abstains on comparison flags because the source and destination
segment bases need not agree. Zero-count and one-count behavior remains as
specified in `VMP_REP_COMPARE_LOCAL.md`.

Two new byte comparison fixtures each start at count two. Equal first bytes
stop `REPNE CMPS`; unequal first bytes stop `REPE SCAS`. Each uses the
remaining count to form an indirect `PUSH; RET` target. The executable
oracle returns 7 for each fixture over 256 inputs on both architectures.
Component tests exercise element widths 8, 16, 32 and 64 bits and counts
2, 3 and `UINT64_MAX`, plus continuation, unknown operands, stale prior ZF,
zero/one counts and an invalid width. The full CTest run passes 23/23 suites.

| Architecture and analysis | Native executable checks | IDA checks | Correct oracle edges | Exact covers | False edges |
|---|---:|---:|---:|---:|---:|
| x86-64 owned | 38,142 | 489 | 46/52 | 49/49 | 0 |
| x86-64 ownerless | 38,142 | 1,860 | 46/52 | 49/49 | 0 |
| i386 owned | 36,862 | 418 | 33/52 | 36/49 | 0 |
| i386 ownerless | 36,862 | 1,810 | 33/52 | 36/49 | 0 |

The ownerless driver separately executes 4,606 native checks per
architecture and rejects two corrupted oracles per architecture. The
independent 52-edge scorer decodes all 64 selected `PUSH; RET` roots in
each run. It classifies both new edges and covers as exact on x86-64 and
unresolved on i386. The x86-64 correct-edge fraction is 88.5%; the i386
fraction is 63.5%, rounded to three significant figures. The edge
denominator counts distinct oracle targets; the 49-site cover denominator
counts eligible source sites.

A same-binary IDA delta uses identical fixture bytes, probe script and IDA
executable with the prior and current signed plugins. Both new target sites
change from `candidate`, no edge and unknown target to `native-proof` with
one exact user edge to `df_memory_target`. Two existing one-count target
controls remain identical. Seven attribution controls and explicit
mutations pass. This matched delta establishes the two new x86-64 target
gains without treating earlier 50-edge scores as an interchangeable
baseline. On the supplied `samples/foo_x86_vmp`, one selected root still
has 75 nodes, 77 edges and three unresolved facts; eight IDA checks pass
and its database inventory remains unchanged. A gain on that protected
root is not observed.

`VMP_REP_COMPARE_EARLY_CAPTURE.json.gz` contains the fixture binaries,
raw IDA inspections, runner manifests, score, matched delta and protected
inspection. `VMP_REP_COMPARE_EARLY_EVIDENCE.json` pins their SHA-256 values,
the IDA executable, both plugins, the oracle delta, scorer and verifier.
Verify the archive without the original build directories:

```sh
python3 -B tests/verify_rep_compare_early_archive.py \
  --archive docs/VMP_REP_COMPARE_EARLY_CAPTURE.json.gz \
  --evidence docs/VMP_REP_COMPARE_EARLY_EVIDENCE.json
```

For one abstract step, retained local memory has `B <= 128` bytes and an
element has `W` in {8, 16, 32, 64} bits. At most `2W/8` bytes are looked
up in an ordered map, giving `O((W/8) log B)` time and `O(1)` extra space
after decode. The helper never unrolls `c` iterations. This bound excludes
IDA address queries, CFG traversal and process startup.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| E1 | `REPE` continues only after ZF = 1 and `REPNE` only after ZF = 0. Count and flag proofs depend on the first post-comparison ZF. | Vary both prefixes, equal/unequal first bytes and prior ZF; require continuation cases to abstain. Compare count-two native executions. |
| E2 | IDA's count width, prefixes and implicit operands identify a supported string comparison. Production admission depends on this decode. | Inspect both modes; introduce address-size or segment overrides and mismatched operands and require abstention. |
| E3 | Long-mode DS and ES bases are zero; exact local bytes represent the first read. The x86-64 flag and target gains depend on this. | Use equal-address and unequal local-byte cases; require i386 to abstain on flags. Change or invalidate retained bytes and require proof loss. |
| E4 | The analyzed transfer describes normal completion without a fault or concurrent/device-memory change. Exact count and flags depend on that execution scope. | Fault the first access or alter memory externally; require an exceptional or concurrent model before extending the claim. |
| E5 | Source-annotated executable results and matched input/tool identities isolate the plugin delta. The 52-edge classification depends on this. | Check hashes and all 64 decoded roots per run, reject corrupted ownerless oracles, mutate attribution and compare the two unchanged controls. |
| E6 | The selected protected root represents only its inspected static region. Its unchanged result depends on that root and database state. | Repeat the exact inspection and compare inventory; inspect other roots and runtime-entered bytes before extending the result. |

- **High impact:** two first-comparison count-derived target edges are proved
  in x86-64 owned and ownerless analysis.
- **Medium impact:** i386 segment ambiguity and comparisons that continue
  beyond the first iteration keep count and flags unresolved.
- **Low impact:** the selected supplied protected root remains unchanged;
  broader protected recovery is unknown.

QG1: technical scope. QG2: E1–E6 identify assumptions and falsification
probes. QG3: both prefixes, both instruction families, both architectures,
both ownership modes, an executable oracle and a protected root are covered.
QG4: count arithmetic, widths, percentages and complexity are explicit.
QG5: continuation, segment and exceptional execution limits are explicit.
QG6: Intel's primary architectural specification and hash-linked executable
and IDA reports support the bounded claims. QG7: broader repeat behavior
and protected effectiveness remain bounded unknowns. The full review
implementation remains in progress.
