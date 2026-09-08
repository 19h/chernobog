# Guarded recurrent-switch regression

The fixture exercises an encoded eight-case dispatcher with a separate unsigned
self-loop guard. All seven recurrent case edges return to the decoder. The
eighth case returns a checksum. This topology gives the classifier a complete
native switch, eight distinct case targets, seven distinct returning frontiers,
and three selector arithmetic transformations.

For unsigned 32-bit arithmetic, define

```text
decode(s) = ((s XOR 0x9E3779B9) + 0x13579BDF) XOR 0x2468ACE0
encode(i) = ((i XOR 0x2468ACE0) - 0x13579BDF) XOR 0x9E3779B9
```

Addition and subtraction wrap modulo 2^32. Therefore `decode(encode(i)) = i`.
Each decoder entry first checks `selector > 8` and loops to itself when true.
The native table range check, `selector > 7`, follows it. IDA incorporates the
second check into the switch's default edge while retaining the first check as
an explicit conditional branch at `MMAT_LOCOPT`.

The ordinary case sequence is 0 through 7. Its return value is
`sum(2^i, i=0..7) = 2^8 - 1 = 255`. The register-effect variant increments a
dispatcher register on every entry and adds it in each case, so its return is
`sum(i, i=1..8) = 8 * 9 / 2 = 36`. These are exact integer calculations. The restored-selector variant adds 1
for argument 0 or 2 for argument 1, yielding 256 and 257. Its decoder uses R10d
in place of the first XOR constant. The corrupted variant changes that key
from `0x9E3779B9` to `0x9E3779B9 XOR 15 = 0x9E3779B6`. Substitution into the decoder maps `encode(4)` to 9.

| Function | Native scenario | Required observation |
|---|---|---|
| `rg_positive` | Private encoded state, eight successive visits | Return 255 |
| `rg_late_guard` | Case 3 writes `encode(9)` | Guard loops after four cases |
| `rg_unknown_guard` | Case 3 copies its argument into state | `encode(4)` returns 255; `encode(8)` reaches the table default and loops; `encode(9)` reaches the explicit guard and loops |
| `rg_global_effect` | Every dispatcher entry increments a global counter | Return 255; counter exactly 8 |
| `rg_escaped_state` | State address is stored globally; case 3 writes through the alias | Return 255 |
| `rg_recurrence_register` | Case 0 changes a register consulted by case 1 | Return 255; entry value 0 is not a recurrent invariant |
| `rg_middle_entry` | Case 3 jumps past the decoder with selector register still 3 | Repeats case 3 |
| `rg_register_effect` | Dispatcher updates a register consumed by the cases | Return 36 |
| `rg_entry_cycle` | Entry loop increments a register until it reaches argument `n`; dispatcher loops if register > 1 | `n=1` returns 255; `n=2` loops |
| `rg_restored_selector` | Decoder key in R10d is saved to R9d, overwritten with 1 or 2, consumed in the checksum, and restored across a branch and merge | Argument 0 returns 256; argument 1 returns 257 |
| `rg_corrupted_restore` | The restored decoder key is XORed with 15 | Both arguments reach decoded state 9 and loop |

The [native harness](recurrent_guard/fixture.c) executes all sixteen scenarios.
Each of the seven nonreturning observations runs in a child process with an
alarm of 1 s and must terminate from `SIGALRM`. The assembly also exposes why
these paths recur: decoded state 9 remains unchanged in the guard, state 8 repeatedly takes the table default, selector 3
remains unchanged on the middle entry, or the entry-loop register remains 2.
The alarm observation alone is not a universal nontermination proof.

## Reproduction

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin \
  tests/recurrent_guard/fixture.c tests/recurrent_guard/fixture.S \
  -o /tmp/recurrent_guard_fixture
/tmp/recurrent_guard_fixture
python3 tests/run_ida_smoke.py \
  /tmp/recurrent_guard_fixture tests/ida_recurrent_guard_smoke.py \
  --ida /path/to/idat --plugin /path/to/chernobog.dylib --verbose \
  --output-dir /tmp/chernobog-recurrent-guard-validation
python3 tests/verify_recurrent_guard_pair.py \
  /tmp/chernobog-recurrent-guard-before /tmp/chernobog-recurrent-guard-after
```

The [IDA probe](ida_recurrent_guard_smoke.py) records every basic block,
instruction address, opcode, instruction rendering, predecessor, and successor
at `MMAT_LOCOPT` and `MMAT_GLBOPT3`. It also records final pseudocode and calls
the SDK's microcode verifier. Local assembly labels supply function-relative
32-bit site offsets without creating additional native function starts.

Instruction-address records include nested instructions and the original address
returned by `mba_t::map_fict_ea`. Every known fictional-address mapping must resolve
to an original native instruction within the function's original chunks. The
comparison also requires those mapped native addresses to occur in the initial
LOCOPT microcode. Before any microcode generation or decompilation, the probe
snapshots every native byte in all eleven functions; it compares the same ranges
after all decompilations. The output records the exact bytes and their SHA-256
identities, so this check detects IDB byte changes as well as file changes.

The probe independently interprets the final microcode for the sixteen native
scenarios. Register and memory storage use separate little-endian byte maps;
overlapping register widths share bytes. Unsupported operations and reads of
uninitialized bytes fail. The interpreter checks return values and the exact
global-effect counter. It records its complete basic-block trace, capped at
256 block executions per input. Reaching the cap is reported as a bounded
nonreturn observation, not a proof for every possible input.

Let `B <= 256` be block executions, `I` the maximum number of instructions and
nested expression nodes per block, `W <= 8` the operand width in bytes, and `S`
the number of touched storage bytes. Interpreter time is `O(B * I * W)` and
storage is `O(S + B)` including the recorded trace. Switch tables have eight
explicit cases and one default edge in this fixture. These are operation
bounds; no decompilation speedup is inferred.

## Assumptions and falsification probes

- G1: The native target is little-endian x86-64 macOS with 64-bit pointers.
  Native compilation and execution establish the reference on that target.
  Other architectures and ABIs are untested by this fixture.
- G2: State arithmetic has 32-bit modular semantics. The assembler uses
  32-bit loads, stores, XOR, and addition. Native and microcode results test
  the decoder through eight successive states and the invalid states 8 and 9.
- G3: Removing dispatcher control preserves every observable dispatcher
  operation. Global-counter and live-register variants falsify an edge rewrite
  that drops or duplicates those updates, even when the state sequence remains
  correct. A retained dispatcher also satisfies these semantic checks.
- G4: Entry facts are not automatically recurrent facts. The changed-register
  variant tests that distinction; the unknown-state and entry-cycle variants
  test independent sources of uncertainty. The saved/overwritten/restored selector-register pair
  distinguishes a pathwise identity from a syntactic no-write condition. The
  actual LOCOPT graph retains the save, both overwrites, and the restore in
  separate blocks. A classifier rejection establishes
  conservative retention, not execution of a later proof gate.
- G5: A native entry into the middle of the dispatcher may observe stale
  registers. `rg_middle_entry` exercises this path explicitly. Its behavior
  differs from replaying the whole decoder at that entry.
- G6: These observations cover sixteen concrete inputs and the recorded CFGs.
  The interpreter has a fixed instruction subset and execution bound. It does
  not use the plugin's symbolic executor or solver; unsupported semantics fail
  instead of receiving an assumed value.
- G7: Artifact attribution requires equal raw input, probe, IDA executable,
  and controlled environment across the comparison. The smoke runner records
  SHA-256 identities before and after execution and rejects missing PASS output.
- G8: Instruction copies may require distinct microcode addresses while retaining
  their original native-address association. The nested-instruction visitor and
  offline comparison check every known fictional mapping against native code
  heads and initial LOCOPT instructions. At least one mapping must survive in
  GLBOPT3 to establish that this comparison exercises the mechanism. Original
  native function chunks must retain identical bytes throughout the probe.

High-impact boundary: a guard proved false on initial entry can become true on
a later state. High-impact boundary: dispatcher register or memory updates can
remain observable after selector recovery. High-impact boundary: copied
instruction addresses can collide during local-variable allocation despite a
successful CFG verification. Medium-impact coverage limitation:
the middle-entry and entry-cycle variants can be rejected by the classifier
before reaching recurrent-transition proof logic. Low-impact limitation: the
bounded interpreter measures behavior and trace shape, not runtime latency.

## Frozen fixture and upstream baseline

On 2026-09-08, native execution passed all sixteen scenarios. SHA-256 identities:

| Artifact | SHA-256 |
|---|---|
| Native executable | `b770005f5c375018d282815dd23d0219a405ea346feb22cb19c6b118cea7862a` |
| `fixture.S` | `f46ed64d934a25e45b8f8c1ae0cda23a7467e030b5757f606670a3f6e814f642` |
| `fixture.c` | `48f9fb5e2dc0e548d008a3ea1ed76c2702bf93ef4f56eb58f72797dd3f7e6352` |
| IDA probe | `3eab48aaad00db038742a3dd667b859b78c9a8397c9ac0a6294c5eb9369e66b8` |

The upstream artifact `e1333736fc6e1cc5c9b8853731b14c9691f77a02f5e5fcfa4f9f3a38ad0b432e`
passed the semantic probe in `/tmp/chernobog-recurrent-guard-address-upstream-before`.
It recognized the positive recurrent switch with score 100 and rejected it
because the dispatcher chain was not linear. Positive microcode retained one
switch: 14 blocks at LOCOPT and 12 at GLBOPT3. All sixteen reference checks
passed, including counter 8 and result 36. The two restored-register functions retain
their save/overwrite/restore instructions at LOCOPT and are recognized as
recurrent dispatchers. This baseline is built from clean upstream commit
`b3b5b03`.

## Matched verification

The modified artifact
`4cc611242a0844b0d622e92791ab1d627b79772b3180b56fd98ed8fb9c1f9100`
passed all sixteen scenarios in
`/tmp/chernobog-recurrent-guard-address-after`. Both runs have identical
raw input, frozen probe, IDA executable, controlled environment, and PASS
assertion identities. Every runner artifact-integrity check passed. The
controlled environment SHA-256 is
`b1256521b6d90be3a772eaba3cc9473b6ff7f0d173e2ce2e8b32b1347b0cf8c7`;
the IDA executable SHA-256 is
`387d681d6fb4f4c1c485a60025cae3f0affa6f5ea1efce3b1809639cb1aaeb28`.

An earlier artifact (`06477f4c…`) passed the sixteen-scenario comparison but
reported Hex-Rays `INTERR 50342` during local-variable processing on the separate
larger corpus. The final artifact allocates distinct SDK fictional addresses
for copied instructions, including nested instructions, while mapping them to
their original native addresses. This fixture retains eight such mappings in
the global-effect function at GLBOPT3; every mapping resolves to an original
native instruction present at LOCOPT. No other fictional mappings survive final
optimization. All 1,956 native bytes across the eleven functions are unchanged,
and their recorded snapshots match the upstream run exactly. The separate final
larger-corpus run completed three uncached decompilations with this artifact in
`/tmp/chernobog-guarded-dispatch-fict-ea`; that run used its own corpus probe and
is separate from this matched fixture comparison.

| Function | Upstream GLBOPT3 blocks / switches | Modified GLBOPT3 blocks / switches | Concrete result |
|---|---:|---:|---|
| Positive | 12 / 1 | 3 / 0 | 255 |
| Global effect | 12 / 1 | 3 / 0 | 255; exactly eight global updates |
| Register effect | 12 / 1 | 3 / 0 | 36 |
| Restored selector | 15 / 1 | 6 / 0 | 256 and 257 |
| Late guard | 12 / 1 | 12 / 1 | Bounded nonreturn |
| Unknown guard | 12 / 1 | 12 / 1 | 255; two bounded nonreturns |
| Escaped state | 12 / 1 | 12 / 1 | 255 |
| Changed recurrence register | 14 / 1 | 14 / 1 | 255 |
| Middle entry | 14 / 1 | 14 / 1 | Bounded nonreturn |
| Entry cycle | 15 / 1 | 15 / 1 | 255; bounded nonreturn |
| Corrupted restore | 15 / 1 | 15 / 1 | Two bounded nonreturns |

All seven negative functions have identical recorded LOCOPT and GLBOPT3
microcode, including instructions and CFG edges, and identical interpreter
traces across the pair. The restored-selector log records a proved recurrence
identity for `r10d.4`; the corrupted restore proves no complete transition
mapping and remains unchanged. The late and unknown guards resolve six of
seven transition paths and retain the dispatcher. The changed-register case
resolves seven of eight paths and remains unchanged. Escaped state fails the
private-storage gate. Middle entry and entry cycle fail classification before
these proof gates.

The [offline comparison](verify_recurrent_guard_pair.py) asserts these sixteen
semantic observations, four positive dispatcher removals, exact negative
microcode/trace retention, native-byte preservation, source-address mappings,
and matched run identities. It passes for the
reported pair; its upstream-versus-upstream negative control fails because
the positive dispatchers were not removed. Temporary copies with a missing
LOCOPT source mapping or a failed native-byte integrity flag also fail the
comparison. The full comparison output is
`/tmp/chernobog-recurrent-guard-address-pair.txt`.

The test also identified an optimizer-progress issue during implementation.
An intermediate artifact rewrote the positive reachable path correctly but
left an unreachable dispatcher cycle with edges into live cases. A temporary
diagnostic interpreted the rewritten LOCOPT path as 255. Replacing only the
BFS-proved unreachable blocks with one-way exit branches, without deleting
blocks or invoking another optimizer, allowed normal global optimization to
finish. The final artifact performs this retirement transactionally and
completes the full probe. The diagnostic used separate scripts and is not part
of the matched semantic comparison. Concurrent builds and corpus probes ran
during verification, so elapsed times do not support a speedup claim.

## Provenance and quality gates

Fixture semantics come from [the assembly](recurrent_guard/fixture.S), the
native executable's self-checks, and the probe's recorded microcode. Operand
representations were checked against the installed IDA 9.4 IDAPython
`ida_hexrays.py` declarations for `mop_t`, `mop_addr_t`, `stkvar_ref_t`,
`mcases_t`, and `reg2mreg`. The installed SDK's
`include/hexrays.hpp` declarations for `mba_t::alloc_fict_ea` and
`mba_t::map_fict_ea` explicitly document instruction-copy collisions and the
reverse native-address mapping. No external performance or general soundness claim
is made from these results.

QG1: descriptive technical content. QG2: assumptions G1–G8 have explicit
falsification cases or scope limits. QG3: positive, later/unknown guard,
observable effects, alias, recurrence register, middle entry, entry cycle,
restored selector register, and corrupted restore
are covered. QG4: widths, modular arithmetic, integer results, and bounds are
explicit. QG5: bounded loop observations and classifier-level rejections are
distinguished from stronger proofs. QG6: native, microcode, and artifact
identities provide reproducible provenance. QG7: impact-labeled boundaries and
coverage limits are stated. The matched comparison passes all stated checks;
its scope remains the recorded sixteen inputs and fixture topologies.
