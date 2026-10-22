# Indirect-target proofs and CFG growth

A target inferred through one predecessor is a fact about that CFG. Another
incoming edge can change the register or stack value at the jump. A target
already propagated by the decompiler has the same lifetime restriction as a
target proved by the finite evaluator.

The indirect-branch cache therefore retains a union of discovered destination
addresses and their byte/range dependencies. This union is an edge-discovery
hint, not an exhaustive target proof and not a fixed destination for every
caller. It is not exported to native dispatch recovery as a proof certificate.

```text
discover another destination
          |
          v
retain edge hint -> MERR_REDO -> regenerate native microcode
                                      |
                                      v
                     install incoming edges before propagation
                                      |
                                      v
                     test the actual native target once
                          /                     \
                 known address               default
                      |                         |
                destination block       original indirect transfer
```

Every new discovered edge requests a native-generation restart, including edges
between blocks already present in the function. Repeating global optimization
alone cannot undo earlier value propagation. The branch pass stops discovery in
that MBA once a restart is pending. Scalar table folds and call rewrites in the
discarded MBA are regenerated too.

Generation evaluates the native target into a temporary and constructs guarded
case edges, even for a singleton hint. The default retains the indirect transfer
through the same temporary. Authentication and other target-evaluation effects
remain evaluated once. A new caller can therefore select another target without
being redirected through the first caller's cached destination.

Later optimization can replace this guarded transfer with a condition or `goto`
only using a fresh proof in the current MBA. It may prune or split existing
successors, but cannot add a new native destination at that maturity.
Scalar switch refinement proves the current selector domain and tests that
selector, without re-reading a predicate from an earlier memory state.
Target expressions use the bounded finite evaluator and its
register-clobber/memory-effect rules. A separate scalar
shortcut cannot bypass those rules. These CFG-dependent results do not authorize
a native instruction patch.

Code bytes, table bytes, permissions, frame metadata and function ranges still
invalidate stale edge hints. The cache admits at most 128 functions, 32 sites per
function, 128 discovered addresses and 8,192 dependency records per site. It
retains the existing range and expression-work bounds. If discovery cannot be
recorded, the handler retains the indirect transfer rather than adding an edge
to an already optimized CFG. During an unchanged snapshot, edge discovery is
monotone and bounded by 4,096 distinct edges per function; repeated sightings do
not cause another restart.

For `E` stored edges and `B` generated blocks, installing guarded cases takes
`O(E * B)` time and `O(E + B)` auxiliary storage. This excludes the separately
bounded finite-expression evaluation and SDK regeneration work. Metadata or
byte changes begin another snapshot and are not included in that bound.

## Assumptions and falsification probes

| Assumption or boundary | Impact | Probe |
| --- | --- | --- |
| A complete current target proof covers every represented incoming state | High | Start with one predecessor, discover a second state-bearing edge, and compare both native outcomes |
| Regeneration removes values baked into the earlier MBA | High | A fixture with a shared observable store must retain both the input condition and both results across repeated decompilations |
| A discovered address can later be selected differently or not selected | High | Guard every cached case with the actual target and retain a default indirect transfer |
| Read-only byte and function metadata dependencies remain current | High | Existing changed-row, writable-table and function-range invalidation probes must continue to pass |
| Authentication is modeled at normal completion, with its guard retained | High | The authenticated join fixture checks IR behavior; plain native fixtures provide the executable outcome oracle |

An address hint does not prove individual reachability or discover every native
successor. Unknown transfers remain unknown. The high-impact scope boundary is
arbitrary interprocedural or loop-state reconstruction; the medium-impact cost
is additional native regeneration as edges are discovered. No context-specific
block cloning is implemented here.

## Regression fixtures

`tests/build_cfg_join_fixture.py` builds hand-written ARM64 and AMD64 programs.
The first caller enters a shared dispatch with state zero. Another caller uses
an opaque byte lookup to enter it with state one. The shared dispatch stores that
state and selects native results 71 and 83. The AMD64 stack variant stores the
incoming state in a frame slot. The raw-authentication variant is an analysis
fixture for relocated pointer origins, not a native PAC-validation test.

`tests/ida_cfg_join_probe.py` confirms the initial one-predecessor native CFG and
requires both outcomes and the runtime input to survive repeated decompilations.
An authenticated target which is not enumerable after the join must keep a
computed indirect fallback and a caller-dependent observable store.
The native fixtures establish the two outcome values independently of the
plugin. No fixture contains instructions copied from another program.

The public SDK contracts used here are `MERR_REDO`, `hxe_flowchart_ea`,
`hxe_microcode`, `m_jtbl`, `m_ijmp`, `mcases_t` and the block-insertion API in the
released IDA SDK's `hexrays.hpp` and `gdl.hpp`.
