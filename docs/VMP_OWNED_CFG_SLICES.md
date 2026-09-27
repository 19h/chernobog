# Bounded predecessor slices in owned native functions

This checkpoint advances review rows 1b, 2a, 2b and V. Owned native analysis
now separates complete function inventory from the local state-transfer budget.
Large supported functions can supply exact joined register, flag and local
memory facts without solving their entire bodies. Full protected recovery,
general topology completeness and review completion remain in progress.

## Production contract

Previously `flow_before` admitted a function only when every decoded head fit
inside `min(depth, 64)`. With default flag depth 8, even a short joined region
inside a longer function caused whole-graph rejection. A contiguous prefix
cannot cross that join and therefore could not recover the demonstrated facts.

The new path first inventories at most 4,096 code heads in the current function.
It rejects overflow before decoding instructions. It decodes admitted heads
and checks mode, owner, instruction shape and incoming references. Unsupported
control-flow shapes reject during decoding. Both architectural successors of
each supported direct Jcc are reconstructed from bytes, including successors
absent from IDA references. All original owner, external-entry, interior-entry,
call-continuation and complete-successor guards still apply. Unsupported or
incomplete inventories use the existing bounded contiguous-prefix fallback.

From the complete graph, `backward_flow_slice` selects the query and its nearest
predecessors in deterministic breadth-first order, up to `min(depth, 64)` preceding
nodes plus the separately reserved query node.
It restores the original node order for solving. Each predecessor outside the
selected set contributes an unknown entry at its selected destination.
An omitted edge is never interpreted as unreachable. Original unknown entries
remain unknown. An incomplete loop entry therefore cannot borrow an invariant
from an establishing instruction outside the slice.

```text
heads := complete current owned code-head inventory, cap 4096
if overflow: fall back
code, graph := decode and audit complete inventory
if unsupported or incomplete: fall back
selected := backward breadth-first predecessors, cap min(depth, 64), plus query
for selected node:
    retain selected predecessors
    add unknown input for each omitted predecessor
solve selected graph to fixed point, cap 128 rounds
retry eligible joins with the existing at-most-eight-alternative domain
refine only universally decided branches from converged unfiltered inputs
return query fact with complete original inventory support
```

The transfer and optional refinement solvers retain their existing semantics.
No provisional iteration is published. Cut entries survive branch refinement;
removing an edge does not introduce a new implicit entry. Overflow of correlated
alternatives joins every represented state conservatively.

Freshness support includes every inventoried instruction except the query,
which the consumer records separately. Instructions outside the transfer slice
still constrain topology admission and remain byte/owner dependencies. Internal
support is not truncated to the display's 64 dependency rows. The 4,096-head
positive control has 4,096 dependencies and 4,032 explicitly omitted display
rows. No graph, decoded-instruction or proof-result cache is added.

The flag default remains 8 preceding nodes. Register setting zero retains its
existing effective depth 64 in the transfer classifier. The query has a
separately reserved node, preserving the preceding-instruction horizon of the
existing contiguous-prefix scan. The prefix cap, modeled ISA effects, writable-memory
admission and normal-completion interpretation remain those documented in the
prior native checkpoints. This change does not establish hardware-fault,
concurrency, segment-base or dynamic-heap equivalence.

## Bounds and complexity

Let `M <= 4096` be inventoried heads, `E <= 2 M` reconstructed architectural
edges, `N <= 1 + min(depth, 64) <= 65` selected nodes and `E_s` selected edges. Each
instruction retains the existing 256-reference guard, including interior-byte
entry auditing, and the same separate incoming-reference guard.

Counting rejects after observing head 4,097, before processor decoding or
instruction-object allocation. For an admitted inventory, map-based decoding
and graph construction cost `O((M + E) log M + X)`, where `X` is the bounded
reference-audit work. Slice construction costs `O(M + E + N log N)` time and
`O(M + N + E_s)` temporary space. The existing synchronous solver costs
`O(K (N + E_s) S)` time and `O(N S)` state space, with `K <= 128` and state cost
`S` under the existing register, stack, memory and alternative bounds.
Complete decoded inventory, graph and retained proof support use `O(M + E)`
additional space, excluding the fixed-size architecture records and SDK costs.

Inventory is rebuilt for each query. Per-function aggregate cost can therefore
remain proportional to query count times inventory size. The single-run timing
measurements below expose that cost; they do not establish constant-time queries,
a general speedup or a complete latency solution.

## Matched production controls

Ten independent routines contain large prefixes, diamonds, loops, bounded
memory stores and PUSH/RET transfers. Four functions produce exact SETcc facts:
equal values at a join, equal carry flags at a join, a carry-preserving loop,
and an exact 4,096-head inventory. A register source and a locally stored memory
source produce two exact transfer targets and actual owned destination edges.

The immediately preceding installed plugin from `b65415a8` proves none of these
six facts on the identical x86-64 and i386 binaries at the default profile:
flag depth 8 and register setting zero, with effective register depth 64.
The corrected plugin proves all six per architecture and retains the legacy
straight-line fact. Each corrected capture passes 59 assertions; each matched
predecessor capture passes 35. The depth-1 control passes 34 assertions, and the
first-candidate budget counterfactual passes 56. The existing production
dataflow regression separately uses configured flag and register depths 64.

A separate routine establishes carry exactly eight preceding instructions
before SETcc. The immediately preceding plugin proves it at default depth 8.
The first slice candidate loses it because its query consumes one node of that
budget. The corrected candidate reserves the query separately and retains this
existing fact on both architectures. The matched first-candidate control
explicitly records that loss; it is not accepted as the final behavior.

Three conditions remain unresolved: disagreeing joined values, a carry definition
outside the bounded slice, and an exact 4,097-head inventory. At depth 1, all six
positive cases and the legacy fact remain unresolved. Native bytes are
unchanged after all inspections and mutation restorations.

Adding an external entry at the joined comparison revokes its exact value.
Removing that entry recomputes a new publication. Changing one establishing
constant from 42 to 41 removes consensus, and restoration recovers it. Replacing
a NOP outside the transfer slice with CLC recomputes the guarded publication
while retaining the later exact value; restoring the NOP preserves that value.
This last control checks complete support rather than only selected transfers.

## Independent oracles and protected matrix

The portable oracle covers all `2^10 = 1024` five-node acyclic topologies,
16 transfer layouts and budgets 1 through 5:
`1024 × 16 × 5 = 81,920` comparisons. A separate concrete Boolean-set evaluator
computes every original query completion. Every admitted slice fact agrees with
every original completion. Loop cuts, zero budget, foreign query and even an
unselected malformed predecessor receive separate controls. The existing
finite-width arithmetic, flag, join and alternative controls also pass.

The independently assembled x86-64 process and i386 QEMU process each pass
11,264 result/final-cell checks, or 22,528 across architectures. Each executes
1,024 deterministic/corner/seeded inputs with seed `0x713ec0a5`; loop counts
are bounded to 1 through 32. The x86-64 process uses macOS translation on the
arm64 host. The ELF32 compiler, loader, libc and QEMU bytes are pinned.
Independent physical x86 execution is unknown. These finite cases do not prove
all machine states or hardware exceptions.

The existing production dataflow regression passes 37,630 x86-64 and 36,350
i386 native checks, with 479 and 412 IDA assertions respectively. All 22 CTest
suites pass. The final full protector matrix passes 40 processes, including
20 with the native engine enabled, and rejects 602 corrupted captures.
Compared with the preceding AST checkpoint matrix, all 152 native rows,
456 SDK stage outcomes, 454 typed captures and 456 complete matching diagnostics
are unchanged. Two SDK refusals remain. The 14,065 attempts and five existing
verified applications are retained, with no disproved, unsupported or unknown
instance attempt in this population. No protected recovery gain is established.

## Admission-cost counterfactual

The first slice candidate passes the complete protected matrix but records
177,578,693,209 ns on its slowest i386 reserved-seed virtualization profile.
A same-process sample attributes substantial work to repeated owned-inventory
decoding. Its plugin, source snapshot, matrix and sample remain pinned as trial
evidence. Head counting before decoding and early unsupported-shape rejection
reduce the intermediate candidate's corresponding observation to
51,254,380,292 ns. After reserving the query separately, the final candidate
records 51,259,757,375 ns on that profile; its maximum recorded peak resident
size is 203,177,984 bytes. All compared native rows, typed SDK captures and
matching diagnostics remain unchanged between these candidates.

The preceding checkpoint's maximum was 26,913,515,041 ns. The broader inventory
therefore retains a measured cost above that earlier run. These are single-run
runner observations with startup and scheduling included, not general latency
estimates. Further inventory reuse with complete invalidation would require its
own lifecycle evidence. The first probe also rejected a redundant SDK
`set_func_end` request during setup; accepted captures avoid that redundant
request. That setup failure is not counted as a production result.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| A1 | The current SDK's owned item inventory and decoded direct successors describe the admitted graph. All graph facts depend on this. | Exact 4096/4097 head counts, owner/mode guards, byte-derived branch successors and complete matched captures; broader incomplete topology remains unresolved. |
| A2 | Each cut predecessor contributes arbitrary modeled input. Slice soundness depends on this. | 81,920 independent concrete-set comparisons, loop-entry cuts, disagreeing predecessors and the outside-budget definition control. |
| A3 | Existing state transfer and join semantics remain applicable under the smaller graph. Native value conclusions depend on them. | Native x86-64/i386 oracles, existing regression, all 22 CTest suites and preserved protected typed captures. Unmodeled effects and faults retain prior limits. |
| A4 | Complete inventory support participates in byte/owner freshness despite display quotas. Publication claims depend on it. | Dependency counts/omissions, external entry, constant mutation, and an excluded NOP mutation with publication replacement and restoration. |
| A5 | Pinned artifacts and explicit profiles bind comparisons. Attribution and timing depend on them. | Same-binary predecessor controls, fresh disposable IDBs, immutable runner receipts and report/source hashes. Multi-run latency and larger populations remain unknown. |

## Bounded opportunities and remaining work

- **High impact:** bounded local joins now work inside admitted functions through
  4,096 heads. The measured fixture gain is eight conditions and four transfer
  targets across architectures; complete protected ownership remains open.
- **Medium impact:** repeated full inventories retain a measured latency cost.
  Reuse requires explicit code/item/chunk/context invalidation and separate
  lifecycle measurements; it is not inferred from hash equality or this result.
- **Medium impact:** slice cuts can remove useful correlations and loop
  definitions. Unknown input preserves uncertainty; larger state budgets and
  inventories remain explicit future scope.
- **Low impact:** the proof display exposes only 64 dependency rows. Its explicit
  omitted count identifies the larger internal support.

Dynamic heap identity, more general region ownership, ISA effects, fault
contracts, protected recovery metrics and the full review remain in progress.

## Reproduction and primary provenance

```sh
cmake --build build -j 20
ctest --test-dir build --output-on-failure --parallel 8
xcrun clang -arch x86_64 -O2 tests/vmp_native/cfg_slices.S tests/vmp_native/cfg_slices_main.c -o build/cfg-slices-x86_64
build/cfg-slices-x86_64
python3 -B tests/run_ida_smoke.py build/cfg-slices-x86_64 tests/ida_cfg_slices_probe.py --ida "$CHERNOBOG_IDAT" --plugin build/cfg-slice-complete-candidate.dylib --output-dir build/cfg-slices-reproduction
python3 -B tests/run_native_dataflow.py --ida "$CHERNOBOG_IDAT" --plugin build/cfg-slice-complete-candidate.dylib --linux32-image sha256:91a6e07bec9b5ef76ccee2f076aa419b5e79a93e15c69de67017e0b8a3a38bc2 --output-dir build/cfg-slice-dataflow-reproduction
python3 -B tests/run_protected_mba_corpus.py --corpus-report build/vmp-mba-corpus-x64/corpus.json --corpus-report build/vmp-mba-corpus-i386/corpus.json --ida "$CHERNOBOG_IDAT" --plugin build/cfg-slice-complete-candidate.dylib --output-dir build/cfg-slice-protected-reproduction --native-analysis
```

Primary provenance is the production graph, slice and transfer code; native
assembly and C oracle; independently computed Boolean sets; actual IDA captures;
and SDK item, function and reference definitions. The evidence JSON pins these
sources, exact preceding/candidate modules, runtime components and reports.
Historical evidence hashes remain unchanged.

QG1: no normative content required. QG2: A1-A5 register dependencies and probes.
QG3: this changeset's larger-owned-function admission and preservation contracts
are covered; the full review remains open. QG4: counts, head limits, bytes and
nanoseconds are exact and reproducible. QG5: cuts, unsupported graphs, SDK refusals,
display quotas and the measured latency cost are explicit. QG6: primary source
and artifact hashes are recorded. QG7: bounded reuse, correlation and inspection
opportunities are stated. These gates apply to this changeset.
