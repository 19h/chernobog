# Typed predicate constants in the live MBA traversal

Review rows 4a/4b require typed proposals to pass instance verification before
mutation. The existing predicate registry was compiled but had no caller outside
its own source file. It now runs in the bounded bottom-up MBA traversal and
admits constants only after a typed instance proof.

## Observed missing shape

A separately compiled x86-64 function compares these distinct expressions:

```text
setz.1(xdu.4(bnot.1(low.1(x))), bnot.4(xdu.4(low.1(x))))
```

The first operand has zero upper 24 bits; the second has one upper 24 bits.
Equality is false for every 32-bit input. The prior plugin retains a comparison
under output extension at GLBOPT1. The current traversal produces one `mov #0`,
with two typed admissions across the SDK/ctree requests. This is a predicate
recognition gap involving width conversion. The two NOT expressions remain
semantically distinct.

The first three native fixtures already reduce under the prior SDK/plugin
pipeline. Their final trees remain unchanged. A signed byte predicate remains
input-dependent. An intervening full-width memory write retains distinct old/new
values and its write. Protected recovery gain remains unmeasured.

## Admission and contract

Matching rules and the older general translator supply proposals of 0 or 1.
A thread-local `RuleVerifier` checks the untouched typed tree against a borrowed
numeric MOV tree. VERIFIED admits; SAT, unsupported input and UNKNOWN retain
the original instruction. The numeric payload is stack-owned for the synchronous
query, requiring no SDK allocation or recursive operand copy.

The caller retains destination, width, EA and instruction properties, marks
block lists dirty and reports changes through the optimizer callback. Existing
collection limits remain 256 nodes/depth 64 before mutation. Predicate hit counts
describe proposals; instance counters describe admission. Catalog counters retain
catalog scope, and the 108-rule catalog remains unchanged.

The instance translator adds logical NOT, sign extraction and ten integer
comparisons. Comparisons require equal scalar input widths of 1, 2, 4 or 8 bytes
and a one-byte result. Signed inputs retain their declared interpretation.
Logical NOT emits 0 or 1 at its declared scalar result width. Arithmetic keeps
its existing result-width checks; explicit extension/extraction remains visible.
Implicit conversions reject.

Snapshot identities retain value numbers, exact widths and frame owners.
Overlapping registers without identical identities remain independent in this
production verifier, which can reject valid alias-based proposals. No reaching
definition or cross-instruction memory equality is inferred. Explicit loads
retain independent occurrences, branches, addresses, widths and source EAs;
a constant cannot remove their reads. Float, undefined, aggregate, barrier,
persistent, assertion and unsupported effect inputs reject. Carry, overflow
and parity primitives remain outside the added translation model.

These are normal-completion scalar value proofs. Fault equivalence, concurrent
memory, MMIO and volatile-access elision remain outside the snapshot contract.
Destination equivalence depends on the caller preserving it. Arbitrary native
instruction deletion is not certified by this value proof.

## Evidence

Six independent native functions use inline x86-64 assembly in
`tests/vmp_native/predicate_shapes_oracle.c`. Both plugin profiles use identical
executable, capture-script and IDA bytes. The actual prior installed module and
candidate have separate SHA-256 pins. All 24 SDK captures per profile and native
byte checks pass.

The native oracle checks five scalar functions on 256 byte values plus three
32-bit corners and checks 65,536 memory-write input pairs:

```text
5 × (256 + 3) + 256 × 256 = 66,831 checks
```

A separate integer interpreter checks result and a four-byte memory cell on
66,831 cases for each GLBOPT1 profile: 133,662 total. A changed folded constant
is rejected. All five unrelated final trees remain equal. The native wrapper
takes 29,157,792 ns and peaks at 3,407,872 resident bytes.

263 added predicate component results yield 453 initial typed-instance results:
119 verified, 99 disproved, 233 unsupported and two UNKNOWN. Controls cover
scalar widths, signed/unsigned comparisons, wrong constants, distinct value
numbers/owners, unequal widths, sign-bit corners, logical result widths, removed
explicit reads, properties and unmodeled flags. A real resource limit of one
returns UNKNOWN for an equivalent carry predicate; it never becomes admission.
Diagnostic quota/reset controls also pass.

All 23 CTest suites pass after a complete rebuild. Their wrapper takes
21,628,514,792 ns and peaks at 120,733,696 bytes. Prior/current SDK wrappers
take 3,113,378,917 / 3,093,253,667 ns and peak at
178,569,216 / 186,941,440 bytes. These single-run process measurements include
launch and surrounding work; plugin-only costs and repeatability errors are
unknown. Query timeout remains 250 ms. Translation/simplification and whole
function time/memory bounds are unknown.

The build directory disappeared between validation commands; cause unknown.
Earlier untracked matrix/receipt files became unavailable. Historical recorded
hashes are preserved. This checkpoint rebuilds current tests and regenerates
paired native controls; at that checkpoint a new complete protected matrix
remained outstanding. The subsequent paired refresh is recorded in
`VMP_TYPED_PREDICATES_CORPUS.md` and its evidence/capture archives.
The evidence JSON archives all twelve GLBOPT1 function snapshots, operand
properties/value numbers, ABI and a canonical snapshot digest. Integer replay
survives subsequent build cleanup:

```sh
python3 -B tests/verify_predicate_shapes.py \
  --archive docs/VMP_TYPED_PREDICATES_EVIDENCE.json \
  --output build/predicate-archive-reproduction.json
```

For fresh captures, compile the oracle with the pinned compiler using
`clang -arch x86_64 -O2 -g`, execute it, run `tests/run_ida_smoke.py` with
`tests/ida_predicate_shapes_probe.py` once per pinned plugin, then pass the fresh
directories to `tests/verify_predicate_shapes.py --before ... --after ...
--output ...`. Evidence pins sources, compiler, SDK header, Z3 source revision,
modules and measured receipts.

For D translated visits, expected identity-map work and retained terms are
O(D). Collection uses O(N log N) set work and O(N) space; repeated subtree
queries can sum to O(N²) visits. Joint translation remains bounded to 512 visits
and depth 64. SMT search has separate costs and a per-query timeout, without
a polynomial solver or whole-function complexity claim.

## Assumption register and bounded expansion

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| P1 | Pinned SDK predicates follow declared-width integer contracts; admissions depend on this. | Check sign-bit, byte-result, conversion and float controls against SDK/native results. |
| P2 | Stable snapshots and normal completion define the domain; value equivalence depends on this. | Distinguish owners/versions, reject removed explicit reads/effects and preserve alias-write captures; leave faults/concurrency unknown. |
| P3 | The caller preserves destination and current ownership; mutation depends on this. | Capture actual SDK stages, check native bytes and exact new MOV/result, retain traversal/translation limits. |
| P4 | Matched bytes identify the observed change; attribution depends on this. | Verify input/script/IDA/module pins, compare all final trees, reject a corrupted constant and replay archived snapshots. |

Bounded opportunities: **medium**, dormant rules now have typed live admission;
**medium**, mixed-width comparisons expose a simplification miss; **low**,
committed snapshots retain replay after cache removal. Wider protected coverage,
predicate fault contracts, general aliases/definitions and full review remain.

QG1: technical scope. QG2: P1–P4/probes. QG3: live integration, actual missing
shape, typed admission, negative and paired controls. QG4: exact counts, widths,
SI process units and complexity scope. QG5: UNKNOWN, effects and unavailable
historical raw artifacts are explicit. QG6: primary SDK/Z3 sources and actual
native/SDK observations are hash-linked. QG7: bounded expansion and remaining
full-review work are explicit.
