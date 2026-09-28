# Current 128-node result for the historical protected 97-head root

The frozen ownerless-corpus plan in `VMP_OWNERLESS_DATAFLOW.md` identified a
97-head post-call graph rooted at `0x1000ab676` in the x86-64 `combined-0`
artifact. Its 64-node inspection stopped at the node bound. The earlier
128-node follow-up could not inspect that exact artifact because its local
copy was absent. The regenerated `combined-0` file now has the **same SHA-256**
as the historical artifact:
`1c14af5156970789fd75a758cadb3cbda8248849acabd2106a2e5ba907fb6b74`.
The original frozen plan file remains unavailable; matching the exact binary,
root and independently decoded 97-head graph does not reconstruct that file's
recorded bytes or its historical IDA state.

A fresh IDA 9.4 SP1 database with the installed signed plugin reports
`available=true`, `converged=true`, `truncated=false` and
`reason=complete_bounded_region`. It retains 97 ownerless heads, 97 direct
edges, one return frontier and four unresolved records:

| Site | Kind | Result |
|---:|---|---|
| `0x10006e5b9` | branch condition | unknown |
| `0x10006e5fb` | CMOV condition | unknown |
| `0x10006e610` | SETcc value | unknown |
| `0x10008145f` | PUSH/RET transfer | unresolved target |

The return frontier is at `0x100081460`. The inspection leaves loaded bytes,
item boundaries and flags, ownership, outgoing references, names and comments
unchanged under the probe's bounded IDB inventory. A second independent
Capstone 5.0.7 walk reads only the exact file-backed Mach-O bytes. It matches
all 97 site addresses, instruction sizes, bytes and 97 direct edges. Its
condition-site set matches the three IDA condition records. This establishes
**zero proved conditions** in this selected region. It does not establish
whole-program reachability, VM identity, exceptional behavior or a new
microcode lowering event.

The reports and runner manifest are retained in
`VMP_PROTECTED_OWNERLESS_97_CAPTURE.json.gz`, with identities and SHA-256
values in `VMP_PROTECTED_OWNERLESS_97_EVIDENCE.json`. Verify the retained
archive without IDA. It also retains an eight-check 75-node supplied-sample
regression using the same inspection probe and installed plugin:

```sh
python3 -B tests/verify_protected_ownerless_97_archive.py \
  --archive docs/VMP_PROTECTED_OWNERLESS_97_CAPTURE.json.gz \
  --evidence docs/VMP_PROTECTED_OWNERLESS_97_EVIDENCE.json
```

Reproduce the IDA capture with the same input hash, installed plugin and a
new output directory:

```sh
python3 -B tests/run_ida_smoke.py \
  build/predicate-protected-x64-b89d23fc-v1/combined-0 \
  tests/ida_protected_region_inspect.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/ownerless-97-reproduction \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set CHERNOBOG_PROTECTED_REGION_ROOT=0x1000ab676 \
  --set CHERNOBOG_PROTECTED_REGION_EXPECT=expanded97
python3 -B tests/verify_protected_ownerless_97.py \
  --binary build/predicate-protected-x64-b89d23fc-v1/combined-0 \
  --inspection build/ownerless-97-reproduction/protected_region.json \
  --run build/ownerless-97-reproduction/run.json \
  --output build/ownerless-97-reproduction/independent_verify.json
```

## Assumption register and bounds

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| P1 | The exact regenerated file and root correspond to the historical selected case. The current-limit comparison depends on their identity. | Require the historical SHA-256 and root; reject any changed file, root or independently decoded head count. The missing original frozen plan cannot be claimed reverified. |
| P2 | The direct-successor, normal-completion traversal represents this root's static code graph. Head and edge agreement depends on that traversal model. | Decode mapped bytes independently; compare every head, size, byte sequence and direct edge; retain the return frontier. A hidden indirect or exceptional successor invalidates a complete-program reading. |
| P3 | IDA's current item and owner classifications define the queried region. Its 97-node result depends on this IDB state. | Run in a fresh database, check ownerless status and full captured inventory before/after, and compare a repeated query. |
| P4 | A local static must-fact is insufficient at all three conditions and the transfer. The zero-proof result depends on the current abstract model. | Recompute after any state-transfer change; require exact site and record comparison before claiming a new proof. |

**High impact:** the previously unmeasured exact protected root is now
admitted under the 128-node bound with independently matched heads and edges.
**Medium risk:** the original frozen plan is absent, and the result has four
unresolved facts. **Low risk:** the archived scope is one root and one input;
its zero-proof result does not quantify other protected paths.

For `N <= 128` heads and `E <= 256` represented direct successors, the
independent traversal decodes each reached head once and stores `O(N + E)`
state. The production propagation remains bounded by 128 rounds and 256
incoming references per node. Counts are dimensionless; no process-time
improvement is inferred.

QG1: technical scope. QG2: P1–P4 include falsification probes. QG3: the
historical root's current bound, abstentions, independent bytes/edges and
read-only IDB state are covered. QG4: node, edge, round and incoming bounds
are explicit. QG5: the missing original plan and normal-completion frontier
remain explicit. QG6: input, IDA, plugin, scripts and reports are pinned in
the retained archive and evidence manifest. QG7: broader protected recovery
and all remaining review rows remain in progress.
