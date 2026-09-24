# Exact full-word stack-top stores before PUSH/RET

This is the historical 28/34 checkpoint. The later
`VMP_STRING_REPEAT_COUNT.md` expands the native oracle to 36 edges and records
the current 30/36 result. The hashes and measurements below remain tied to
this earlier revision.

Review rows 1a and 1b require exact stack-mediated transfer targets with
unchanged stack effects. The bounded x86 state now models `MOV [SP], register`
when the decoded destination is exactly a natural-address-size, full machine
word at the current SP with no displacement, index or segment override. It
replaces the tracked top word with the source register's known bits. The
following `PUSH [SP]; RET` can therefore use the overwritten word as a
`stack-definition` target. The instruction sequence and its architectural
memory/stack operations remain intact. Other memory writes keep the existing
stack invalidation; the writable-memory map is invalidated or updated under
its separate address rules.

The independent native driver checks `df_stack_top_overwrite` on each of 256
inputs and returns 8 from the overwritten destination. Its two distinct
destination labels are resolved from the exact binary by `llvm-nm`. The
matched prior-transfer plugin and current plugin use identical x86-64 and
i386 binaries, IDA executable, probes and runner sources. The only production
source change is this exact stack store. The baseline expectation flag changes
the IDA environment hash without changing fixture bytes.

| Architecture and path | Prior correct / oracle edges | Current correct / oracle edges | Current false edges | Current unresolved eligible sites |
|---|---:|---:|---:|---:|
| x86-64 owned | 27/34 | 28/34 | 0 | 3/31 |
| x86-64 ownerless | 27/34 | 28/34 | 0 | 3/31 |
| i386 owned | 27/34 | 28/34 | 0 | 3/31 |
| i386 ownerless | 27/34 | 28/34 | 0 | 3/31 |

The current exact fraction is 28/34 = 14/17 = 82.4% to three significant
figures. All 28 fixed targets are recovered. The three remaining eligible
sites each have two input-dependent oracle edges; a single unconditional
target would be unsound. The 15 concrete-driver-only sites remain excluded
and unresolved. At all selected owned sites, reported proof targets equal
actual IDB user code xrefs. Ownerless inspection remains read-only.

The owned runner passes 20,990 native checks and 272 IDA assertions per
architecture. The ownerless runner passes 4,094 native checks, rejects its
deliberately corrupted result and passes 1,060 IDA assertions per
architecture. Both probes mutate the full-word `MOV` to a byte-width store,
require an unresolved target without a new publication, restore the original
byte, and require the original result. This is a conservative partial-write
control: partial-word values are not modeled. All other 45 selected-site
outcomes remain unchanged under the matched plugins. All 21 CTest suites
pass. Exact source, tool, binary, report and resource hashes are in
`VMP_STACK_TOP_STORES_EVIDENCE.json`.

Reproduce with fresh output directories by running `run_native_dataflow.py`
and `run_ownerless_dataflow.py` with the same `--ida`, `--plugin` and
`--linux32-image chernobog-vmp-linux32:test` arguments shown in
`VMP_MOVS_FLAGS.md`, then score their reports with
`score_native_edge_benchmark.py`. The prior-transfer control uses
`--stack-store-baseline` and a rebuilt plugin with this one state update
reverted; the evidence records its signed hash. The ignored raw score retains
all 46 site classifications. Wrapper elapsed time in nanoseconds and peak
resident size in bytes measure the launcher including IDA startup. They do
not isolate plugin latency or memory.

With at most S = 64 retained stack words and B = 128 retained writable bytes,
the exact store replaces one stack word in O(1) time and O(1) extra space.
Memory invalidation costs O(B) in the worst case. These bounds exclude CFG
iteration and IDA startup; edge counts are dimensionless.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| T1 | A full-width natural-address-size write to exact `[SP]` replaces the current top word on normal completion. The new target proof depends on this. | Check x86-64/i386 instruction bytes and native return values; mutate the opcode to a byte store and require abstention, then restore and re-prove. Test 16-bit, segment-override and exceptional execution separately before expanding the rule. |
| T2 | The source register value is established before the write and the stack suffix corresponds to the current SP. Exact target attribution depends on this. | Compare matched prior/current plugin facts on the same binaries, require no proof for the input-dependent stack target, and invalidate on intervening non-exact writes. |
| T3 | The frozen assembly labels define the 34-edge selected oracle. The 28/34 score depends on this. | Rehash source, resolve every selected label with `llvm-nm`, reject missing/duplicate records, and compare owned user xrefs with proofs. |
| T4 | `wait4` observes the launcher, including IDA startup. Resource values depend on this scope. | Instrument IDA and the plugin separately before inferring plugin performance. |

- **High impact:** exact stack-top stores supply a native edge that the prior
  memory-write barrier discarded.
- **Medium impact:** partial, displaced and segment-overridden stack writes
  remain conservative abstentions until byte-addressed stack effects are
  modeled.
- **Low impact:** the selected native false-edge count does not estimate
  whole-binary or protected-mode error rates.

QG1: technical scope. QG2: T1–T4 have falsification probes. QG3: this exact
stack-store change and its selected benchmark result are covered; the full
review remains incomplete. QG4: edge arithmetic, units and complexity are
explicit. QG5: partial writes and dynamic targets remain unresolved. QG6:
exact source, native execution, IDA facts, user xrefs and hashes support the
bounded claims. QG7: wider stack and protected scopes remain explicit.
