# Finite indirect targets

The indirect-transfer resolver evaluates the transfer's own operand and its
reaching definitions. It can prove constants hidden behind correlated byte
lookups and recover a Boolean-indexed pair of targets without selecting a
runtime outcome.

The evaluator enumerates every assignment in an admitted finite domain. It does
not substitute the initial IDB values of writable globals. Repeated values use
the same expression node or Hex-Rays value number; unrelated mutable reads stay
independent. Pure byte arithmetic may be replaced by an unconstrained byte,
which overapproximates its possible values. A missing table row, mutable table,
unsupported operation, or exhausted bound prevents a proof.

A wide value masked into the low byte retains its zero extension while using
at most 256 assignments. Repeated comparisons with the same operand snapshots
share one Boolean input, including copies nested in different expression nodes.
Already bounded byte arithmetic retains that Boolean relationship; only an
unbounded arithmetic byte is widened to all 256 values. A constant-time
conservative domain-size estimate controls this choice and can overcount shared
inputs, which loses precision rather than inventing equalities.
Different mutable snapshots remain independent. Exact same-block stack stores
can supply a later value; partial writes and unknown operations interrupt that
search. The ARM path stops at indirect stores and real calls, checking every
nested call before an authentication intrinsic can preserve a stack snapshot.
AMD64 can also follow a unique predecessor and cross effects whose SDK may-def
list excludes the queried slot, as detailed in the AMD64 adapter document below.

| Boundary | Limit or behavior |
| --- | --- |
| Expression graph | 4,096 nodes |
| Exhaustive domain | 256 assignments |
| Evaluation work | 2,000,000 node evaluations |
| Register definitions | Same block or a unique predecessor chain; stop at joins, cycles, partial definitions, or call clobbers |
| Definition scanning | 32,768 instructions; 8,192 indexed instructions |
| Scalar table folding | 32 candidates and a 20 ms pass budget |
| Nested value traversal | 4,096 instructions per folding pass, including stack stores and call arguments |
| Memory | Exact reads from readable, non-writable segments |
| Calls | Existing executable entries or named external symbols; retain the call-site ABI |
| Known callee types | Supply a proven single target's existing type before native argument/return collection; no type is invented |
| Call scanning | Top-level and nested instructions; at most 32,768 instructions and 256 calls |

For `N` expression nodes and `A` admitted assignments, one enumeration uses
at most `A * N` node evaluations. Ordered-map lookups add
`O(log(N + R))` overhead per lookup, and storage is `O(N + R + A)`, where
`R` is the number of distinct table reads. All limits fail closed. Folding
carries its original table-byte dependencies into later target proofs so a
folded base does not conceal the evidence needed to invalidate a cached result.

## Conditional control flow and frames

Two-target results retain their false/true mapping. Existing switch case edges
identify destinations even after optimization shifts their first instruction.
The pass emits native comparison branches. A predicate that reads memory is
copied into a temporary at the transfer, before the retained authentication
guard, and the branch tests that copy. If neither destination is the
physical fallthrough, a synthetic block provides it using an SDK fictional
address and a valid address interval. The SDK renumbers block and case
references, and the next pass rebuilds the resolver's block index.

Small, automatically named ARM64 fragments that consume the caller's state can
be included in a per-decompilation range view. Existing IDB function ownership
is retained. Admission requires a frame/SP use or a transfer that consumes an
incoming X19-X28 value before defining it. The scan covers at most 32 logical
instructions of up to 16 B each, including IDA's constant-building macros.
Conventional LR-signing prologues, negative SP accesses, frame-pointer/SP
redefinitions before a witness, calls, user prototypes and incoming call
references prevent admission. This register criterion assumes the ordinary
AArch64 call ABI; explicit custom prototypes are excluded.

All destinations must be covered before a conditional projection retains any
fragments. Initial switch and single-target edges are installed before
optimization, preserving the registers and memory passed to them. Their stack
deltas are translated to the incoming frame, and the omitted frame-pointer
setup is represented explicitly in microcode. The frame interpretation relies
on IDA's frame and stack-point metadata.

The temporary snippet range view is restored to the function request when the
ctree is final, so projected functions can be cached and reopened normally.

Code bytes, table bytes, memory permissions, function ranges, and frame metadata
are checked before a cached view is reused. A stale proof removes only the
resolver's own edges and comment and causes a fresh analysis. User-owned edges
are retained. An unknown predicate remains a runtime choice; recovering both
successors does not prove either successor individually reachable.

Table folding visits pure value expressions inside stack stores and call
arguments without replacing their enclosing calls. A universally constant
target argument can also replace an authentication guard's table calculation;
the guard and its modifier remain. The pass queries instruction values directly,
avoiding an SDK instruction-embedding operation that is unnecessary for this
proof. Persistent instructions and assertions are retained.

These proofs do not establish arbitrary interprocedural or loop-carried state
invariants. A transfer whose target domain cannot be bounded remains indirect.
Call resolution and scalar folding use separate passes, so a resolved call can
still retain a table calculation in its authentication guard.

IDA represents `BRAA`/`BLRAA` with the same instruction types as `BR`/`BLR`.
Native encoding checks distinguish authentication. Resolving these transfers
does not validate a PAC. Direct native patching is disabled for authenticated
forms, and their bytes remain unchanged.

## Model assumptions

| Assumption | Falsification probe or boundary |
| --- | --- |
| Read-only IDB bytes describe the tables | Change any consulted byte or its segment permissions; the cached projection is rejected |
| IDA frame and stack metadata describe the inherited frame | Change the root frame size/offset or the source stack delta; the cached projection is rejected |
| An authenticated transfer passes its runtime authentication check | PAC execution is not modeled or tested; native authenticated instructions remain intact |
| The predicate may be either Boolean value | Both are enumerated; this overapproximation does not prove that each is reachable |
| A local stack store still reaches its use | Partial stores, aliasing indirect stores and real calls revoke the value; authentication intrinsics require explicit empty memory effects |
| A register-only continuation consumes caller state | A nested fixture uses X28 before defining it; an independent frame and a partially admissible target set are rejected |
| The callee's stored prototype describes its ABI | Native argument collection uses it only after an exact single-target proof; missing types retain the existing ABI |

## Verification

`chernobog.finite_domain` checks correlated lookups, Boolean target polarity,
one-row counterexamples, missing rows, mutable memory, bit widths, enumeration
bounds, and authenticated encodings.

On macOS, build the synthetic ARM64 fixture with:

```sh
python3 tests/build_finite_dispatch_fixture.py /tmp/finite-dispatch/fixture
python3 tests/build_finite_dispatch_fixture.py /tmp/nested-dispatch/fixture --nested
```

Run `tests/ida_finite_dispatch_probe.py` with `tests/run_ida_smoke.py` and an
explicit plugin artifact. The probe checks both successors, the projected
frame, unchanged native bytes and function owners, and invalidation after
changing a table byte or its segment permissions. It also captures the resulting
pseudocode, including a resolved authenticated helper call whose used return
value is nested inside another microcode instruction. The fixture contains no
bytes from an external application.

The nested fixture also checks a child dispatch preceding its parent, repeated
Boolean tests, non-fallthrough successors, a 64-bit instruction macro before
an SP value use, register-only and single-target continuations, exact guard
counts, native argument widths, real-call stack invalidation and partial-view
rejection. Both fixtures require structured conditions in final pseudocode.

ARM64e value semantics, authentication guards and pointer-origin proofs are
described in [ARM64e primitive support](arm64e-primitives.md).

AMD64 relative dispatch, address-valued proofs and outlined-register
preservation are described in [AMD64 finite dispatch](x86-finite-dispatch.md).
