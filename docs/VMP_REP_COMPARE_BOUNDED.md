# Bounded multi-iteration REPE/REPNE comparison replay

Review rows 1b, 2a and V require native target and flag facts only when
the repeated comparison's effects are exact. The
[Intel REP specification](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
tests the address-size count before an iteration and the comparison's new
ZF afterward. A known count `c` can therefore finish after `k` comparisons
with remaining count `c - k` when the kth ZF fails the prefix's continuation
condition, or with count zero after all `c` comparisons. The flags are those
of the final executed comparison.

The portable transfer now replays up to 128 first-use comparisons. It reads
each operand at its iteration, computes the six status flags with the
existing subtraction transfer, and checks the new ZF before continuing.
The last iteration may have unknown operands: count exhaustion still proves
zero count, while its flags become unknown. An unknown earlier ZF, missing
address, invalid range or iteration beyond the bound causes abstention.
For unknown direction flag (DF), both forward and backward completions must
yield the same remaining count; only their common flag bits survive. First
comparison early stops remain available even when the initial count exceeds
the replay bound.

The production IDA transfer admits only natural-address-size x86-64
`REPE`/`REPNE SCAS` and `CMPS` with matching decoded implicit operands, no
segment override and a known count. Each iterated memory address is checked
for arithmetic overflow and an IDA readable range; `SCAS` local bytes
additionally require a writable range. The transfer reads only retained
local byte definitions, or proves a same-address `CMPS` comparison equal.
It does not change retained memory. It invalidates the modified index
registers and publishes the exact final count and common flags only when
the bounded replay completes. Static i386 comparison effects still abstain
because DS and ES bases may differ.

Four new count-three fixtures form indirect `PUSH; RET` targets from the
remaining count. `REPE CMPS` at the same source and destination address
exhausts the count. `REPNE CMPS` and forward `REPE SCAS` stop after their
second comparisons. A backward `REPE SCAS` fixture sets DF, stops after its
second comparison, then clears DF before return. Each native executable
returns 7 for all 256 inputs on both architectures. Component cases cover
all four element widths, both prefixes, count exhaustion, unknown final
flags, divergent DF paths, missing bytes, the 128-iteration limit and a
first stop with `UINT64_MAX` initial count.

| Architecture and analysis | Native executable checks | IDA checks | Correct oracle edges | Exact covers | False edges |
|---|---:|---:|---:|---:|---:|
| x86-64 owned | 39,166 | 501 | 50/56 | 53/53 | 0 |
| x86-64 ownerless | 39,166 | 1,900 | 50/56 | 53/53 | 0 |
| i386 owned | 37,886 | 430 | 33/56 | 36/53 | 0 |
| i386 ownerless | 37,886 | 1,850 | 33/56 | 36/53 | 0 |

The ownerless driver separately passes 4,606 native checks and rejects two
corrupt oracles per architecture. The independent scorer decodes all 68
selected `PUSH; RET` roots in each of four runs: 272 scored cases. The
x86-64 correct-edge fraction is 89.3%; i386 is 58.9%, rounded to three
significant figures. The 56-edge denominator counts distinct oracle
targets, whereas the 53-site denominator counts eligible source sites.
The four new edges and covers are exact on x86-64 and unresolved in static
i386 analysis.

A same-binary prior/current IDA comparison uses identical fixture bytes,
probe and IDA executable. All four new sites change from `candidate`, no
edge and unknown target to `native-proof` with one exact user edge to
`df_memory_target`. Two preceding first-comparison target controls remain
identical. The independent scorer checks seven attribution controls and
negative mutations. A matched protected inspection of one selected root
in `samples/foo_x86_vmp` has byte-identical prior/current facts: 75 nodes,
77 edges and three unresolved facts. Both eight-check inspections preserve
their IDB inventories. No protected gain is observed at that root.

`VMP_REP_COMPARE_BOUNDED_CAPTURE.json.gz` contains fixture binaries, raw
owned and ownerless IDA inspections, runner manifests, scores, matched
deltas and protected inspections. Its evidence JSON pins SHA-256 values for
the archive, tools, scripts and exact plugin pair. Offline verification:

```sh
python3 -B tests/verify_rep_compare_bounded_archive.py \
  --archive docs/VMP_REP_COMPARE_BOUNDED_CAPTURE.json.gz \
  --evidence docs/VMP_REP_COMPARE_BOUNDED_EVIDENCE.json
```

For one abstract transfer, the local byte map has `B <= 128` entries and
element width `W` in {8, 16, 32, 64} bits. At most two DF paths each replay
`min(c, 128)` comparisons and read at most `2W/8` bytes per comparison.
Map lookup time is `O(min(c, 128) (W/8) log(B + 1))` and extra working memory is
`O(1)`, excluding IDA range queries, CFG traversal and retained evidence.
Addresses crossing arithmetic bounds abstain; the transfer does not model
address wraparound.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| B1 | `REPE` continues after ZF = 1, `REPNE` after ZF = 0, and each completed comparison decrements count once. All remaining-count and final-flag claims depend on this. | Execute both prefixes with first-stop, second-stop and count-exhaustion cases; vary the prior flags and compare the native result. |
| B2 | Retained local bytes represent values at their comparison uses and `CMPS`/`SCAS` do not write them. Later-iteration claims depend on this. | Change the second byte, omit its local definition or add a potentially aliasing write before the string instruction; require changed proof or abstention. |
| B3 | The decoded DF fact represents the compared address progression. Backward and unknown-DF results depend on this. | Execute a backward `STD` fixture; force forward/backward paths to yield different counts in the portable test and require abstention. |
| B4 | Long-mode DS/ES bases are zero; i386 bases are not established by this abstract state. x86-64 gains and i386 abstentions depend on this. | Compare the same address and separate local bytes in x86-64; inspect both i386 modes and require unresolved comparison-derived targets. |
| B5 | Native executable checks and matched source, fixture, IDA and plugin identities isolate four new gains. The 56-edge score depends on this. | Pin hashes, decode all 68 roots per run, reject corrupted ownerless oracles, mutate scorer attribution and compare unchanged controls. |
| B6 | The selected protected root represents only one inspected static region. Its unchanged result depends on that scope. | Compare matched raw inspections and IDB inventories; inspect other roots and runtime-entered bytes before generalizing. |
| B7 | The 128-iteration cap and no-wrap address rule bound analysis. No claim covers longer continuing runs or wrapped indexes. | Test 129 continuing comparisons for abstention and `UINT64_MAX` count with an immediate stop for bounded termination. |

- **High impact:** four additional exact native target edges are recovered
  in x86-64 owned and ownerless analysis.
- **Medium impact:** unknown earlier comparisons, i386 segment bases,
  arithmetic wraparound and continuing runs beyond 128 iterations remain
  unresolved.
- **Low impact:** the selected supplied protected root remains unchanged;
  effectiveness on other protected paths is unknown.

QG1: technical scope. QG2: B1–B7 give assumptions and falsification probes.
QG3: both prefixes and instruction families, forward and backward direction,
both architectures and ownership modes, executable and independent edge
oracles, and a protected root are covered. QG4: count arithmetic, units,
fractions and complexity are explicit. QG5: segment, memory, direction,
range and bound limits are explicit. QG6: the Intel architectural primary
source and hash-linked process/IDA reports support the bounded claims.
QG7: wider repeat and protected recovery remain bounded unknowns. The full
review implementation remains in progress.
