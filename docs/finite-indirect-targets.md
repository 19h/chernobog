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

| Boundary | Limit or behavior |
| --- | --- |
| Expression graph | 4,096 nodes |
| Exhaustive domain | 256 assignments |
| Evaluation work | 2,000,000 node evaluations |
| Register definitions | Same block or a unique predecessor chain; stop at joins, cycles, partial definitions, or call clobbers |
| Definition scanning | 32,768 instructions; 8,192 indexed instructions |
| Scalar table folding | 32 candidates and a 20 ms pass budget |
| Memory | Exact reads from readable, non-writable segments |
| Calls | Existing executable entries or named external symbols; retain the call-site ABI |
| Call scanning | Top-level and nested instructions; at most 32,768 instructions and 256 calls |

For `N` expression nodes and `A` admitted assignments, one enumeration uses
at most `A * N` node evaluations. Ordered-map lookups add
`O(log(N + R))` overhead per lookup, and storage is `O(N + R + A)`, where
`R` is the number of distinct table reads. All limits fail closed. Folding
carries its original table-byte dependencies into later target proofs so a folded base does not conceal the
evidence needed to invalidate a cached result.

## Conditional control flow and frames

Two-target results retain their false/true mapping. The microcode pass emits a
conditional branch when an existing successor is the physical fallthrough;
otherwise it retains the explicit switch and its proven target set.

Small, automatically named ARM64 fragments that consume the caller's frame can
be included in a per-decompilation range view. Existing IDB function ownership
is retained. Initial switch edges are installed before optimization, preserving
the registers and memory passed to those fragments. Their stack deltas are
translated to the incoming frame, and the omitted frame-pointer setup is
represented explicitly in microcode. The frame interpretation relies on IDA's
frame and stack-point metadata.

Code bytes, table bytes, memory permissions, function ranges, and frame metadata
are checked before a cached view is reused. A stale proof removes only the
resolver's own edges and comment and causes a fresh analysis. User-owned edges
are retained. An unknown predicate remains a runtime choice; recovering both
successors does not prove either successor individually reachable.

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

## Verification

`chernobog.finite_domain` checks correlated lookups, Boolean target polarity,
one-row counterexamples, missing rows, mutable memory, bit widths, enumeration
bounds, and authenticated encodings.

On macOS, build the synthetic ARM64 fixture with:

```sh
python3 tests/build_finite_dispatch_fixture.py /tmp/finite-dispatch/fixture
```

Run `tests/ida_finite_dispatch_probe.py` with `tests/run_ida_smoke.py` and an
explicit plugin artifact. The probe checks both successors, the projected
frame, unchanged native bytes and function owners, and invalidation after
changing a table byte or its segment permissions. It also captures the resulting
pseudocode, including a resolved authenticated helper call whose used return
value is nested inside another microcode instruction. The fixture contains no
bytes from an external application.
