# Aliased Hikari state recovery

The microcode pipeline resolves stack aliases before threading constant
dispatcher paths. This covers state updates such as `p = &state; *p = next`,
signed comparison trees, and conditional state assignments that converge
through a shared store. It preserves the computed results of assignments on
each selected path. A runtime condition remains a runtime condition; its two
successors receive separate copies of required intermediate values.

The transformations run at local optimization, calls, and before local-variable
allocation. Late changes request a new allocation pass through the documented
preallocation callback. They modify the current microcode, not native instructions or IDB
function ownership. They work independently of the ARM64 cross-function
`CHERNOBOG_HIKARI_CFG` option.

## Contracts and limits

| Analysis | Admission condition | Rejection probe |
| --- | --- | --- |
| Stack alias | Every reachable incoming definition denotes the same frame offset and width | Conflicting joins, loop-carried rebinding, partial pointer overwrites |
| Direct stack access | Ordinary x86 data segment; access fits the local frame | Segment-relative access, out-of-frame offset, extended store |
| Call crossing | Separate may-pointer analysis finds no frame address passed to a call or stored externally | Address of the alias cell passed to a pointer-modifying callee |
| Dispatcher path | Constant evaluation determines every skipped branch; all copied assignments are nontrapping register/stack operations | Unknown condition, call, indirect access, division, cyclic path |
| Dead state assignment | No ctree observation, no remaining address in microcode, and no protected variable metadata | Address escape, volatile/user-defined/overlapping variable, observable read |

The call-crossing contract uses the decompiler's calling-convention model.
The optional `CHERNOBOG_STACK_ALIAS_OBJECTS=1` additionally assumes that a
callee accessing a passed frame object does not access unrelated frame
objects. This permits an unexposed alias cell to survive calls that receive
other local buffers. It is a static-analysis model, not a proof of a callee's
memory footprint. Leave it unset when out-of-bounds accesses or caller-frame
inspection are relevant. Passing the alias cell's own address still rejects
the refinement.

`CHERNOBOG_WRITABLE_CONST=2` is a separate existing assumption: admitted
writable scalar/array bytes represent stable initial values. Direct writes,
fixups, and disallowed references still reject admission. It does not prove
absence of indirect writes or concurrent mutation. This mode can expose
opaque predicates and constant string-decryption expressions before state
recovery. Changes to this option through `chernobog_set_option` now invalidate
the process-wide classification policy; cached decisions from a different
mode are not reused.

The stack analysis retains at most 512 facts, permits 100,000 worklist visits,
and limits instruction visits to eight million. The preliminary may-pointer
analysis allows 64 rounds under the same instruction budget. It returns no
rewrites when its fixed point cannot be established within those bounds.
Unreachable blocks contribute no facts.

Dispatcher threading permits at most 64 blocks and 32 copied instructions per
path, eight rounds, and 4,096 copied instructions per direct-threading round.
It declines arrays over 10,000 blocks and checks cancellation between work
items. Conditional bridges preserve the physical fallthrough required by
Hex-Rays. No SMT timeout or guessed state value can authorize a rewrite.

Stack analysis uses `O((R*N + W)*F)` time and `O(B*F)` space, where `N` is
instruction count, `B` block count, `R <= 64` preliminary rounds, `F <= 512`
facts per block, and `W <= 8,000,000` worklist instruction visits. This excludes
the SDK's use/def-list construction cost. Dispatcher work is bounded
by source scans plus `O(B*L*C)` path work per round, with `L <= 64` and
`C <= 32`. Copied instructions are included in subsequent round budgets.

## Validation

The synthetic fixture is public source in
[`tests/hikari_dispatch_fixture.c`](../tests/hikari_dispatch_fixture.c).
Its unsigned arithmetic, signed dispatcher constants, common transitions,
callee side effects, ambiguous aliases, escaped alias cell, partial-width
store, and loop-carried alias rebinding are checked through actual
decompilation. The probe decompiles twice without a cache, verifies native
bytes, and exports reconstructed C. The driver compiles and executes both
original and reconstructed C over ordinary and boundary inputs, comparing
results and helper-call observations.

```sh
python3 tests/test_hikari_dispatch.py \
    --ida /path/to/idat --plugin /path/to/chernobog.dylib \
    --output-dir /tmp/hikari-dispatch

python3 tests/test_hikari_dispatch.py \
    --ida /path/to/idat --plugin /path/to/chernobog.dylib \
    --stack-alias-objects --output-dir /tmp/hikari-dispatch-objects
```

The generated C test uses `-fwrapv` so signed temporary types chosen by the
decompiler retain the fixture's fixed-width wrapping arithmetic. It also
checks switching writable-data policy from disabled to enabled and back in
the same IDA process.

For an analyst-selected static Hikari session:

```python
import idc

idc.eval_idc('chernobog_set_option("writable_const", 2);')
idc.eval_idc('chernobog_set_option("stack_alias_objects", 1);')
idc.eval_idc('chernobog_set_option("auto", 1);')
idc.eval_idc('chernobog_clear_all();')
```

Use those options only with the two additional memory assumptions above.
Reopen pseudocode after clearing the cache. Function-size admission remains
independent; raising it does not strengthen a transformation's proof.
