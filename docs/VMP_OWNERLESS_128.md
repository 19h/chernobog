# Ownerless native-region bound on the supplied VMP initializer

`chernobog_native_region_facts(root_ea)` now admits at most 128 existing decoded
x86/x64 ownerless instruction heads. The round limit remains 128 and the
incoming-reference limit remains 256 per instruction. This is a read-only,
root-conditioned normal-completion analysis. It does not assign function
ownership, publish ordinary CFG facts, claim complete program reachability or
identify a VM handler. This checkpoint advances review rows 1b and 2a without
completing either row.

The selected root is `0x1002946b5`, the initializer target in the exact
`samples/foo_x86_vmp` binary. Its SHA-256 is
`c61935fe4f8a66a6d36e8c0027341a55b816833005dc0006dc0fdbdb342938a5`.
Three fresh IDA 9.4 SP1 processes used the same finalized probe and input.
RAX was disabled. The prior installed plugin, new built plugin and decode-off
control were selected by artifact hashes in
`VMP_OWNERLESS_128_EVIDENCE.json`.

| Profile | Direct-jump decode | Available / converged / truncated | Nodes / edges / records | Stop reason |
|---|---:|---|---:|---|
| Prior 64-node plugin | On | true / false / true | 64 / 66 / 0 | `node_limit` |
| New 128-node plugin | On | true / true / false | 75 / 77 / 3 | `complete_bounded_region` |
| New plugin | Off | false / false / false | 0 / 0 / 0 | `not_existing_code_head` |

The 128-node result retains a call target at `0x1001a9297` as
`call_target_not_followed` and an unsupported transfer at `0x10024801a` as
`unsupported_control`. The two `SETcc` records at `0x1001d6c12` and
`0x100248015`, and the branch-condition record at `0x10025d082`, all have
`status=unresolved` and `outcome=unknown`. Thus the measured increase is a
bounded graph completion and three explicit abstentions, **zero proved
protected conditions**. The term `complete_bounded_region` applies only to
the admitted normal-completion graph and its represented frontiers.

The probe hashes loaded bytes/masks, item flags/spans, function owners/chunks
and flags, outgoing references, names, comments, segment modes and permissions
before and after inspection. The decode-on prior and new runs have identical
inventories: 278 heads, 275 references, seven functions, SHA-256
`06057fc0eaf67b39521f259a547815cb931369fe0618b7be3d55b06136770e2d`.
The decode-off run has 73 heads, 64 references and two functions, with its own
unchanged before/after inventory. The inventory is bounded to 64 MiB of
segments, 1,048,576 heads, 2,097,152 references and 4,096 functions; it is
not a hash of every IDB attribute.

Independent x64 and i386 native fixtures execute 3,582 oracle checks each,
including the new exactly-128 and 129-node controls; a deliberately corrupted
expected result is rejected in both modes. Actual IDA inspection passes 332
assertions per architecture. The exactly-128 graph converges; the 129-node
graph returns `node_limit` and no partial facts. All 21 existing CTest suites
pass. Historical 64-node measurements and hashes in
`VMP_OWNERLESS_DATAFLOW.md` are retained unchanged.

The historical protected-corpus plan also records a 97-node root as exceeding
its original 64-node budget. Its inspection harness now interprets that same
frozen plan under the 128-node bound and will require exact head and condition
coverage for that root. The archived protected binaries and corpus report are
absent from this workspace, so the current result for that 97-node root is
**unknown**. The 75-node supplied-sample result above is a separate observed
measurement.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| B1 | The hashed supplied binary and selected root represent the protected initializer. The protected measurement depends on this identity. | Rehash the input; compare the independently decoded initializer target, IDA version, plugin and probe hashes. Decode-off must reject the same root as an absent code head. |
| B2 | IDA's existing decoded spans and ownerless labels describe the local graph. The 75-node result depends on those inputs. | Recompute in fresh databases; check every admitted owner and the whole checked IDB inventory before/after; alter the decode switch and require abstention. Unknown remote predecessors still prevent global publication. |
| B3 | The flat unchanged-code, normal-return model applies only up to represented frontiers. The convergence label depends on this scope. | Require visible call and unsupported-control frontiers; do not infer their successors. Dynamic unpacking, exceptions and reentry would falsify a whole-program interpretation. |
| B4 | Node-bound behavior is exact and architecture independent. The resource conclusion depends on this boundary. | Execute independent x64/i386 128-node and 129-node oracles; require an admitted fact at 128 and no partial facts at 129. |
| B5 | The archived 97-node plan's historical 64-node classification remains immutable. Any future current-limit corpus result depends on having its exact binary and report. | Retain the frozen plan field and hash; require the 97-node graph under the 128-node current limit when the hash-matched archived inputs are available. Until then its current condition yield is unknown. |

## Bounds, cost and impact

For N admitted nodes, E admitted edges, X inspected incoming references and R
rounds, the existing compatibility work is O((X + N)E), plus ordered-map/set
cost O(N log N + X log 256), excluding IDA lookup costs. Propagation is
O(R(N + E)S), where S is fixed architectural register/flag state plus at most
64 tracked stack values. Support materialization is O(N²); retained graph and
state storage is O(N + E + X + NS), excluding O(N²) formatted support strings.
Here N ≤ 128 and R ≤ 128. Counts are dimensionless; elapsed process times and
memory were not used to infer a performance gain.

- **High impact:** a real protected initializer passes the former node limit,
  making its conditional abstentions inspectable.
- **High impact:** the zero proved conditions and unsupported frontier prevent
  this local completion from being counted as protected semantic recovery.
- **Medium impact:** predecessor discovery, larger graphs, ordinary proof
  publication and supported indirect control remain open requirements. The
  archived 97-node protected result is unmeasured under the new limit.

QG1: technical scope. QG2: B1–B5 and their probes. QG3: both architectures,
protected prior/new/decode-off controls and installation are covered. QG4:
counts, limits and complexity bounds are explicit. QG5: node exhaustion and
frontiers retain uncertainty. QG6: original protected bytes, independently
executed native fixtures, actual IDA state and hashed reports are recorded.
QG7: impact and remaining boundaries are explicit. Full `VMP_REVIEW.md`
completion remains open.

Reproduce with hash-matched local IDA and plugin artifacts, using fresh output
directories:

```sh
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/ownerless-128-recheck
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_protected_region_inspect.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/protected-128-recheck \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set CHERNOBOG_PROTECTED_REGION_ROOT=0x1002946b5 \
  --set CHERNOBOG_PROTECTED_REGION_EXPECT=complete
```
