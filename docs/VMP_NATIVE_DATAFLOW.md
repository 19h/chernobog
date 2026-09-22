# Bounded native facts across branches and loops

Native flag and register recovery now propagates facts across an owned x86
function's direct control-flow graph. The previous implementation replayed only
a contiguous single-entry prefix. It missed equal register definitions on both
arms of a diamond, carry preserved through a loop, and equal stack values before
a joined POP. The same register analysis also supplies exact PUSH/RET targets.

The new independent x64 and i386 fixtures each establish five condition facts
and one register-derived transfer. Disagreeing register, flag, stack and target
inputs remain unresolved. The archived prior plugin misses all six new facts on
the identical x64 binary; its unresolved stack-transfer candidate is not counted
as a recovered edge. This advances review rows 1b, 2a and 2b. It does not establish
new protected-corpus recovery or complete those rows.

## Analysis contract

`bounded_dataflow.h` implements a synchronous must-analysis. An absent output
means a node has not been reached by the analysis; `State{}` means unknown
architectural input. These states remain distinct: initializing every loop
output as unknown would suppress invariants supplied by an actual entry.

At each join, a register or flag bit remains known only if every incoming state
knows it with the same value. Stack facts describe a suffix above otherwise
unknown bytes; joins align suffixes at the current stack top and retain only
equal values. Unsupported effects retain the existing state invalidation rules.
Calls invalidate tracked state, and internal call targets receive unknown entry
state. No initial writable-memory value becomes a constant.

The IDA adapter inventories the entire existing owned function within the
configured instruction bound. It reconstructs both successors of direct Jcc
instructions from decoded bytes, even if earlier native analysis suppressed an
IDB edge. Direct JMP preserves state. External, call, far or incompatible incoming
references contribute unknown state. Missing direct successors, unsupported
transfers, mixed modes, inventory overflow and nonconvergence prevent graph
admission; the preexisting local prefix analysis remains available in those cases.
Indirect or far targets and return destinations are not guessed.

All graph rounds must converge before any input state is returned. Back-edge
disagreement may remove an initially plausible fact. No edge is pruned using a
provisional state, and no condition is assumed merely because one path was
observed. Unreached cycles cannot manufacture facts. The result remains a local
normal-completion analysis under current ownership and entry metadata, not a
whole-program reachability or exception proof.

Every admitted graph instruction is retained as a proof dependency, including
definitions outside the old linear prefix. Native proof inspection recomputes
the condition or target and preserves the existing byte, mode, permission,
ownership, annotation and edge-ownership contracts. The implementation does not
merge functions or replace the original stack-writing PUSH/RET instructions.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Probe or explicit limit |
|---|---|---|
| D1 | Current owned code and recorded external entries define the analysis region. | Both architectural Jcc successors are rebuilt independently of pruned xrefs. Adding an external join entry removes the condition fact in both architectures; removing it permits recomputation. Ownerless protected code remains outside this admission. |
| D2 | The existing typed transfer model is sound for ordinary normal-completion x86 semantics. | Existing arithmetic/condition tests and 12,288 independent x86/x64 microcode effect comparisons pass, with 192 read-fault controls. Full fault-path propagation and new instruction families are not claimed. |
| D3 | Join and fixed-point results conservatively cover all represented predecessors. | 65,536 partial-bit input pairs are compared with independently enumerated concrete-set unions. Diamonds, invariant/changing loops, external inputs, unreached cycles, invalid indexes and exhausted budgets are tested. |
| D4 | Equal stack suffix values refer to the current architectural stack top. | Joined PUSH/POP fixtures execute in both widths; unequal values remain unknown. Existing stack/alias/register-target production controls remain passing. Arbitrary memory alias propagation is not introduced. |
| D5 | Retained dependencies and recomputation identify the current conclusion. | Changing one diamond predecessor removes consensus; exact restoration recomputes it. Existing native evidence probes validate byte changes, owned metadata, freshness and observation/publication separation. Broader lifecycle coverage remains open. |

## Bounds and complexity

```text
inventory owned instructions within min(configured depth, 64)
reconstruct architectural direct successors and unknown external entries
initialize outputs as not yet reached
repeat, at most 128 rounds:
    join all available predecessor outputs and any unknown entry input
    apply the typed instruction transfer without pruning graph edges
    if all outputs are unchanged: return the joined input states
reject the graph if the round limit expires
```

The adapter caps incoming-reference inspection at 256 records per instruction.
Register state has 16 known-bit words and six abstract flags; stack suffixes are
capped at 64 machine words. The default configured depth is unchanged. The new
fixture matrix explicitly selects depth 64 for both flag and register analysis.

For N nodes, E edges, S retained stack words and K rounds, propagation costs
O(K (N + E) (16 + S)) time and O(N (16 + S) + E) space. The generic solver
also bounds predecessor-vector length by its node limit. Adapter inventory and
reference lookup cost O((N + X) log N), excluding IDA's internal lookup costs;
X is capped by 256N. These are algorithmic bounds, not measured speedups.

## Validation

All 20 CTest suites pass in 11.25 s. The accepted production evidence includes:

| Validation | Result |
|---|---|
| New x64 fixture | 2,558 independent native result checks; 25 production checks |
| New i386 fixture | 2,558 independent QEMU process-result checks; 25 production checks |
| Existing flag corpus, depths 8 and 64 | 33 + 33 condition/edge checks |
| Existing stack/get-PC native evidence | 35 + 17 checks |
| Existing condition microcode consumers | 12,288 effect comparisons and 192 fault controls across both architectures |
| Protected condition matrix | 40 matched runs; zero lowering events; unchanged comparable IR/pseudocode |

The new ordinary fixtures test both branches with inputs 0 through 255, and
loop outcomes with counts 1 through 255. The expected results are computed by a
separate C process oracle. The fixture's two differing PUSH/RET destinations
return different values, independently checking that both paths exist. Static
production probes require a fresh `native-proof`, an actual edge, a
`register-definition` basis and retained stack effects for the equal-target case;
the differing-target case must remain an unresolved candidate.

The host is arm64. x64 runs use the host's x86-64 execution support; i386 uses
the previously pinned Linux/QEMU image. This is not hardware-only differential
coverage. The new inspection processes took 11.766381041 s (x64) and
8.631554625 s (i386), with observed peak resident sizes 190,676,992 and
158,187,520 bytes respectively. These single process-accounting observations
include startup and analysis, and establish neither a speedup nor an
architecture ranking.

The protected measurements retain the previously observed two i386 final
decompilation failures with SDK code -12. A successful entry-stub decompilation
does not imply recovery of its ownerless protected body. The default-depth
protected matrix therefore establishes regression behavior, not effectiveness
of graph analysis on admitted protected regions.

An intermediate adapter wrongly treated every IDA basic-block end as a control
transfer, suppressing ordinary predecessor instructions before a join. The
failing capture is retained; the corrected adapter checks architectural transfer
forms instead. The first i386 attempt stopped because the local container
service was absent; the accepted run followed restoration of that service.
The first legacy stack-fixture build omitted its required non-PIE linker flag;
the corrected build and production probes pass. None of those failed attempts
is counted as accepted coverage.

Reproduce with a new output directory:

```sh
python3 -B tests/run_native_dataflow.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --linux32-image "$PINNED_LINUX32_IMAGE" \
  --output-dir build/native-dataflow-new
```

Omitting the image runs only x64. Hashes of the implementation, fixtures,
runtime artifacts, accepted reports and retained failures are recorded in
[VMP_NATIVE_DATAFLOW_EVIDENCE.json](VMP_NATIVE_DATAFLOW_EVIDENCE.json).

## Bounded findings and quality gates

- **High:** must-analysis across joins recovers facts unavailable to a linear
  prefix while retaining disagreements as unknown.
- **High:** protected region ownership remains a separate prerequisite. This
  change supplies neither ownerless-region admission nor whole-function recovery.
- **Medium:** the whole-owned-function inventory cap excludes larger functions
  even when a smaller predecessor region might suffice. More scalable region
  selection, richer memory reasoning and path constraints remain open.

QG1: technical analysis scope. QG2: D1–D5 and probes. QG3: joins, loops, both
native consumers, both architectures and regression coverage; full review open.
QG4: finite concretizations, widths, counts, time/byte units and bounds explicit.
QG5: predecessor disagreement, entry changes, nonconvergence and unsupported
graphs retain uncertainty. QG6: hash-bound source, baseline and independent
native/IR artifacts. QG7: remaining region, memory and lifecycle limits stated.
