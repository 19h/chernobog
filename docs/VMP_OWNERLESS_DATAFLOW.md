# Ownerless native graphs with explicit entry scope

`chernobog_native_region_facts(root_ea)` analyzes existing decoded x86/x64
instructions outside IDA function ownership. It carries register, stack and
individual flag facts across direct branches and loops, retaining both
architectural Jcc alternatives. It returns a graph, boundaries, unresolved
conditions and proved local conditions or PUSH/RET targets.

This is an explicit-root, read-only analysis. A result applies to modeled paths
entered at the selected root before leaving the admitted graph. It does not
publish ordinary native proofs, rewrite IDA references, create instructions,
assign function ownership, admit VM execution or authorize microcode lowering.
Existing function analysis and contiguous ownerless-prefix analysis remain
unchanged. This advances review rows 1b, 2a, 5 and the region-model groundwork
without completing their broader requirements.

## Admission and transfer contract

The root must be an existing loaded executable ownerless instruction head.
Admitted instructions have exact decoded item spans, at most 15 bytes each,
within one segment and execution mode. Every byte must remain ownerless.
Overlapping interpretations and code references into instruction interiors
reject the graph.

Traversal uses decoded direct targets and fallthrough, independently of outgoing
IDA references. Both Jcc successors remain in the graph even when an earlier
analysis removed a reference or proves one alternative impossible. No edge is
removed using provisional abstract states. For supported control shapes, each
syntactic successor is admitted or represented as a frontier. Unsupported control
shapes stop at a source frontier without enumerating their successors. Owned
code, missing heads, segment/mode
boundaries, returns and unsupported transfers remain visible. BSWAP with a
16-bit operand is an unsupported frontier; no behavior is invented for it.

The root starts with unknown registers, flags and stack contents. Known incoming
code references that do not match an admitted architectural edge add an unknown
entry. Independently decoded adjacent fallthrough does the same when its edge
is absent, including a predecessor already represented as a modeling frontier.
Calls are not followed into their callees: their syntactic normal-return
continuation starts with entirely unknown state.

The existing abstract state and bounded fixed-point solver supply conservative
joins. Equal facts survive diamonds and invariant loops; disagreement discards
them. Jcc/SETcc/CMOVcc records expose the known flag mask, outcome and full
instruction support, including unresolved outcomes. Register values are not
derived from dynamic witnesses or initial writable-memory contents.

Flag masks use the compact abstract encoding CF=1, PF=2, AF=4, ZF=8, SF=16 and
OF=32. These are not EFLAGS/RFLAGS bit positions. The API and Qt detail expose
this encoding explicitly.

Immediate/register PUSH followed by a structurally admitted near RET retains
the existing portable classifier's width, stack-write and stack-delta contract.
A graph register fact is used directly; failed graph analysis never silently
falls back to a linear prefix. Memory targets remain unresolved in this API.
A known target is an architectural value, not a claim that its destination is
executable or that a stack write can be removed. The pair assumes ordinary-stack
normal completion; CET shadow-stack checks and other exceptions are not modeled.
A known target does not establish that the RET will reach it.

## Why the root remains explicit

Backward traversal through existing references alone cannot establish a complete
predecessor inventory. For example, a remote conditional jump may have lost its
reference after a prior native proof. Changing that remote instruction before
reanalyzing it can make the missing edge feasible again. A local backward walk
would not necessarily include the changed source in its dependencies.

The new API therefore retains root-conditioned scope and never promotes its
results into ordinary IDB CFG publications. A complete architectural predecessor
inventory or an independently complete suppressed-edge index is still required
before such promotion. Paths leaving the graph and later reentering it are not
summarized as continuous executions.

## Inspection and freshness

The **Chernobog native region facts** action under **View → Open subviews** uses
the exact selected address. The Qt view links instruction nodes, decoded edges,
frontier reasons and scoped fact details. It displays fixed-point status,
truncation, the complete entry contract and `published: false`.

Each request rebuilds the inventory and analysis. Navigation compares the full
current result, database identity and a per-engine context identifier. It does
not rely on a hash or fabricate a publication ID. Changes affecting retained
bytes, ownership, reference audits, permissions or mode make an earlier view
stale. Restoring the exact
inputs can restore the same scoped result; recomputation replaces the displayed
snapshot. Old results remain visible while stale navigation is disabled.

`make install -j 20` now also installs the existing Python inspection companion;
previously that target copied only the native plugin. Makefile formatting is
pinned to mbake 1.4.6 with the checked-in final-newline configuration.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| O1 | The selected root and represented paths define the entry scope. All graph facts depend on this. | Both direct alternatives are reconstructed from bytes; missing outgoing references, external entries, adjacent fallthrough and conflicting joins are tested. Missing remote predecessors prohibit global publication. |
| O2 | Flat unchanged-code, normal-completion semantics apply; calls return normally if their continuation is analyzed. | Calls clear all state; BSWAP16 and unsupported transfers remain frontiers. Exceptions, devices, concurrency, exit/reentry and complete VM identity are excluded. |
| O3 | IDA itemization, modes and ownership correctly describe the inspected byte spans. | Every admitted span is checked; byte, ownership, mode, permission, interior-entry and restoration controls run against actual IDA. Inspection preserves the inventoried IDB fields listed below. |
| O4 | Concrete fixture results are independent of the abstract evaluator. | Separate C expected-result oracles execute both architectures and deliberately corrupted expectations are rejected. x64 host translation and i386 QEMU execution are reported explicitly. Negative PUSH encodings and BSWAP16 controls are not claimed as native executions. |
| O5 | A displayed result still describes its original database and graph. | Actual Qt controls test byte changes, stale direct-slot navigation, exact restoration, recomputation and timer cleanup. Identity-field negative controls reject changed context/database/root. Full-result comparison gates navigation. |

## Validation and measured effect

| Check | Result |
|---|---|
| x64 native oracle | 3,070 checks; deliberately corrupted expected result rejected |
| i386 native oracle | 3,070 checks; deliberately corrupted expected result rejected |
| Actual IDA fixture inspection | 310 assertions per architecture; 620 total |
| Read-only API calls in the fixture matrix | 60 calls preserve the checked IDB inventory and a fresh nonempty ordinary publication |
| Actual Qt inspection | 90 assertions; six retained screenshots; registered action dispatch and cleanup pass |
| Existing portable CTest suites | 21/21 pass in 9.66 s |
| Frozen protected development measurement | 36 assertions; four converged roots and one node-limit abstention |

The fixture matrix includes gap-separated equal/conflicting diamonds, invariant
and changing loops, equal/conflicting register targets, strict 64/65-node limits,
call barriers, pruned references, external/interior entries and mutation
restoration. PUSH immediate sign-extension and the BSWAP16 adjacency case are
separately labeled encoding/IDB controls, not native behavior claims.

The IDB inventory covers loaded bytes, item flags and spans, function owners,
function chunks and flags, incoming/outgoing references represented by the
probe, names, comments, and segment modes and permissions. It is not an inventory
of every possible database attribute.

The protected plan was frozen before invoking the new API. It uses existing
combined-protection seeds 0 and 1 with five explicitly recorded roots. Admitted
inventories contain 35, 12, 48 and 35 instructions; the remaining independently
enumerated 97-instruction graph is rejected at 64. Overlapping roots are not
counted as distinct recovered conditions. Across five distinct bounded
condition sites, **0/5 are proved**. All PUSH/RET records are also unresolved,
and the microcode-lowering delta is zero. Source-build attestation is unknown;
held-out semantic artifacts were not used to tune this change.

Initial failures are retained. The console probe first failed to replace an
explicit data item with code, then incorrectly compared publication identities
across its own ownership mutations. The corrected probe explicitly prepares
items and refreshes the ordinary control before each measured call. GUI
diagnostics isolated six deferred ordinary-analysis comments after fixture
setup. Completing that setup work before the baseline permits the first form
opening and subsequent actions to pass the unchanged-inventory checks.
The first flag-encoding GUI run passed 89/90 checks; its recomputed-result
screenshot scrolled the legend outside the viewport. Resetting the probe's
detail scroll position before capture passes both legend and result visibility
checks in the retained final run.
No production rule was weakened to accommodate these probes.

Source, runtime, report and retained-failure hashes are recorded in
[VMP_OWNERLESS_DATAFLOW_EVIDENCE.json](VMP_OWNERLESS_DATAFLOW_EVIDENCE.json).

## Bounds, costs and remaining requirements

Limits are 64 nodes, 128 fixed-point rounds and 256 incoming references per
instruction, including references to interior bytes. Node/reference exhaustion,
invalid overlap/interior entries and nonconvergence return diagnostics without
graph-derived facts. Normal frontiers are not whole-function completion.

For N nodes, E admitted edges, X inspected incoming references and R rounds,
inventory compatibility checks cost O((X + N)E), with additional ordered-map/set
costs O(N log N + X log 256), excluding IDA lookup costs. Bounded propagation costs
O(R(N + E)S), where S is the fixed architectural register/flag state plus at most
64 tracked stack values. Support materialization costs O(N²) in the worst case.
Retained graph/provenance storage is O(N + E + X + NS), excluding formatted
support strings, whose worst case is O(N²). No SMT solver is added by this API.

- **High:** explicit entry scope prevents a local graph from becoming an
  unsupported claim about every native entry.
- **High:** the measured protected conditions remain unresolved; availability
  of an inspector is not recovery coverage.
- **Medium:** complete predecessor discovery, ordinary fact publication,
  cross-owner propagation, protected effectiveness and microcode integration
  require further work, as does the complete database/restart lifecycle matrix.

QG1: technical scope. QG2: O1–O5 with explicit probes. QG3: the scoped inspector,
both architectures, UI and installation path are covered; the full review remains
open. QG4: exact bit/byte widths, counts and limits. QG5: conflicting joins,
entries, frontiers and exhaustion retain uncertainty. QG6: independent native
oracles, actual IDA/Qt behavior and frozen artifact hashes. QG7: publication,
protected effectiveness and remaining ownership limitations are explicit.
