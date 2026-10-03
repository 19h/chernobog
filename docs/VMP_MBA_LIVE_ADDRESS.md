# Live SDK address extents through AST construction and repeated binding

This closes the constructed full-matcher fixture left open in
`VMP_MBA_ADDRESS_EXTENTS.md`. It addresses review row 4a at the scope of
`mop_a` input/output access extents. The local IDA 9.4 SDK's `mop_addr_t`
declaration and `lexcompare` implementation are pinned by SHA-256
`7ced9073b5b1fe06357f51e5983e041cae0b6b0f8f69d790f443031ec05022ff`.
The fixture uses `new mop_addr_t(referent, insize, outsize)` inside a live
Hex-Rays process, so the root `minsn_t`, address payloads and AST operand
copies use SDK ownership rather than the standalone test stub.

The bridge constructs `m_sub(address(reg100, 4, 0),
address(reg100, input_size, output_size))` with 8-byte address operands and
an 8-byte destination. It calls the plugin's exported `MopKey::from_mop`,
`mops_equal_strict`, `minsn_to_ast` and `match_pattern`. The repeated-binding
pattern is `x_0 - x_0`. Three cases use right-side extents `(4, 0)`, `(8, 0)`
and `(4, 8)`, respectively. The first is an equality control; the others
differ in exactly one signed SDK extent field. Each process uses a 64-byte
`MopKey`.

Three isolated IDA processes use the same input, IDA executable, probe,
compiled bridge and explicit environment. Only the plugin binary changes:

| Plugin stage | SHA-256 | Equal case | Input extent mismatch | Output extent mismatch |
|---|---|---|---|---|
| Prior, before address-key change | `e112d00d24806f5263d817c3d8b6271bdf04c37411d45da027be86a90901708c` | Matches | **Incorrectly matches** | **Incorrectly matches** |
| Address-key stage, before later strict cache gate | `e264c7cfac50da572faf1b0b977db7d2d7e0a842790eaa6e358f1facb08a817f` | Matches | Rejects | Rejects |
| Current plugin | `b94678b6758326da50c4e796f551eb9928c1e8f6a4d2ae920470f8fb3f21ba45` | Matches | Rejects | Rejects |

The prior plugin's strict operand comparator already reports the unequal
operands, but both keys are equal. AST construction reuses the first address
leaf for the second; the copied right operand no longer matches the source,
and the repeated binding succeeds. Both later plugins retain distinct keys,
preserve both copied operands and reject with `AddressInputSize` and
`AddressOutputSize` (enum values 22 and 23). This establishes the local
matcher failure and correction for the constructed SDK-owned shape. The
three plugin stages also contain other code changes; the source and staged
plugin identities delimit the attribution. No natural unequal-extent
protected operand occurred in the 40-profile matrix.

The prior, keyed and current report SHA-256 values are, in that order,
`49d0629dea48dba142f4d7721b58aca918a1cbb9612ac3f625a5efc5cad0b9cb`,
`cfff41003c1b583a891a168be05ca2c24aaf1ca05c7a4e0bdad86dada3c28d28`
and `1a5ae325633c211b3e767aaf5030658d3182110c97166dacdec5688c561437a1`.
`VMP_MBA_LIVE_ADDRESS_EVIDENCE.json` pins those reports, process manifests,
plugin, IDA, input, bridge and source hashes. The independent verifier
checks copied plugin and probe bytes, integrity fields, matched environment,
the exact outcome transition and rejection of a mutated matcher result.
The prior process exits 1 because it detects the expected incorrect match;
both later processes exit 0. The complete reports and manifests remain in
ignored `build/` directories.

An additional three-process control begins with an **SDK-produced** `mop_a`
operand from the protected i386 `virtualization-0` matrix fixture, rather
than a wholly constructed referent. At maturity 5, the selected instruction
at `0x8073510` in the owned function at `0x806f37b` contains an address of a
`mop_S` stack variable at decompiler stack offset 140 bytes. Its 4-byte
address operand has `insize=-1`, `outsize=-1`. The bridge deep-copies that
operand twice, changes only the second copy's input or output extent from
`-1` to 4, and runs full AST construction and `x_0 - x_0` matching. A saved
SDK copy verifies that the original operand is preserved in all three runs;
the bridge does not request a database mutation.

The prior plugin reports unequal source operands but equal keys. Its second
AST copy no longer matches the changed source and the repeated binding is
incorrectly accepted in both cases. The keyed and current plugins distinguish
both keys, preserve both copied operands and reject the two bindings with
`AddressInputSize` and `AddressOutputSize`. The source function, instruction,
stack offset, referent kind, observed extents, input binary, IDA executable,
probe, bridge and explicit environment agree across the three processes.
The prior, keyed and current result SHA-256 values are
`fce02f29da9dcc82e6b3e14eef7deaeea6cf50285f16053ac0d9698b2c6e97e7`,
`956e57acd8d806941106c262a5d9c3ab82a2bd63db305779f52da0eb52010b00`
and `e4486fdc9e97bec50b8f527bbbecc12c48f6fb3f8afe946dc81e1c03b992ac3d`.
`VMP_MBA_OBSERVED_ADDRESS_EVIDENCE.json` pins the reports, run manifests,
source and binary hashes and three in-memory mutation rejections. This test
uses a real protected microcode operand as the source of a **constructed**
unequal-extent pair; it does not claim a naturally emitted unequal pair or a
protected rewrite gain.

Reproduction from the repository root:

```sh
CCACHE_DIR="$PWD/build/.ccache" c++ -std=c++17 -O2 -DNDEBUG \
  -D__EA64__=1 -D__IDP__ -D__MAC__ -mmacosx-version-min=13.3 \
  -fPIC -dynamiclib -Wl,-undefined,dynamic_lookup \
  -Isrc -I../ida-sdk/src/include tests/ida_mba_address_bridge.cpp \
  -o build/ida_mba_address_bridge.dylib
python3 -B tests/verify_mba_live_address.py \
  --prior build/mba-live-address-prior-v1 \
  --keyed build/mba-live-address-key-v1 \
  --current build/mba-live-address-v2 \
  --bridge build/ida_mba_address_bridge.dylib \
  --evidence docs/VMP_MBA_LIVE_ADDRESS_EVIDENCE.json \
  --output build/mba-live-address-verified.json
CCACHE_DIR="$PWD/build/.ccache" c++ -std=c++17 -O2 -DNDEBUG \
  -D__EA64__=1 -D__IDP__ -D__MAC__ -mmacosx-version-min=13.3 \
  -fPIC -dynamiclib -Wl,-undefined,dynamic_lookup \
  -Isrc -I../ida-sdk/src/include \
  tests/ida_mba_observed_address_bridge.cpp \
  -o build/ida_mba_observed_address_bridge.dylib
python3 -B tests/verify_mba_observed_address.py \
  --prior build/mba-observed-address-prior-v3 \
  --keyed build/mba-observed-address-key-v3 \
  --current build/mba-observed-address-v4 \
  --bridge build/ida_mba_observed_address_bridge.dylib \
  --evidence docs/VMP_MBA_OBSERVED_ADDRESS_EVIDENCE.json \
  --output build/mba-observed-address-verified.json
```

For a fresh IDA repeat, use `tests/run_ida_smoke.py` with
`tests/ida_mba_address_probe.py`, `build/flag-values-oracle`, the IDA 9.4
`idat` executable and `CHERNOBOG_MBA_ADDRESS_BRIDGE` set to the compiled
bridge. The prior, keyed and current plugin paths are
`build/mba-address-live-i386-v1/idauser/plugins/chernobog.dylib`,
`build/mba-address-key-matrix-native-v1/x86_64/original-on/idauser/plugins/chernobog.dylib`
and `build/local-plugins/chernobog.dylib`. Give each run a new output
directory. The prior process is expected to return 1; pass the three new
directories to the verifier without `--evidence` because the exact
process-manifest hashes are specific to the recorded runs.

| Source | SHA-256 |
|---|---|
| `tests/ida_mba_address_bridge.cpp` | `698b37057712625b77a8411a1aa0a3e89a8cdbc58d8d71dd30842bf280404a49` |
| `tests/ida_mba_address_probe.py` | `1e3b4ef0f73fa4a6f3025ac656eeea6a28d337d95129320be07e2c24cf17f969` |
| `tests/verify_mba_live_address.py` | `b1b07f6bbac01cb22c3badf34c25b8ebb93bb8a046595ba9f5de0efe47ee9568` |
| `tests/ida_mba_observed_address_bridge.cpp` | `4c70a3681ed6abf026375fed99a63ca4634417d3f138b64c93148f28af600278` |
| `tests/ida_mba_observed_address_probe.py` | `71833b56cdc83457a244eddbbf3350256e3ae07577210ca8e1e15996cbf912d7` |
| `tests/verify_mba_observed_address.py` | `ad2b6b9a3f3166e3b2f52a2da7fe1f9d0403be72d93c706d920d59523edb9868` |

For `n=3` constant-size cases per process, fixture construction and key
checks use `O(n)` time and space outside SDK copying. The AST builder retains
its 1,024-visit, 64-depth and 4,096-byte text limits. Strict comparison is
bounded by 512 operand visits and 64 recursive levels per binding. For total
retained artifact bytes `B`, the verifier reads `O(B)` time and memory,
excluding JSON-library overhead. These bounds do not measure production
matcher throughput or protected-corpus recovery.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| L1 | SDK-owned `mop_addr_t` copies preserve referent and extent fields. The full matcher claim depends on this copy contract. | Compare both copied AST operands with the source under the strict comparator; mutate one extent and require a mismatch. |
| L2 | The three runs differ only in plugin bytes for this fixture. The staged transition depends on the runner's copied identities. | Compare binary, IDA, probe, bridge and explicit environment hashes; verify each copied plugin and probe. Re-run in fresh isolated processes. |
| L3 | A repeated `x_0` binding must compare both source address operands. The incorrect prior acceptance claim depends on this pattern shape. | Require the equal control to match, both unequal controls to reject after the change, and a mutated acceptance result to fail verification. |
| L4 | Constructed extents represent the targeted SDK contract but do not establish natural protected occurrence. The corpus conclusion depends on this separation. | Capture a protected microcode pair with unequal extents and repeat the same comparison; the measured 40-profile matrix contains only `-1/-1` extents. |
| L5 | The selected protected `mop_a` object remains alive during the bridge call and its `mop_S` payload is copied by the SDK. The source-derived test depends on this object identity. | Pin the source function, instruction, maturity, referent kind, stack offset and original extents across all three runs; mutate a source identity field in the verifier and require rejection. |

| Impact | Result or remaining risk |
|---|---|
| High | The prior full matcher incorrectly accepts both constructed unequal-extent repeated bindings; the keyed and current plugins reject both. |
| Medium | SDK ownership and copied operand identities are tested in live IDA processes. |
| Medium | A protected SDK-produced stack address reproduces the same failure after a single copied-extent mutation. |
| Medium | Natural occurrence and protected rewrite gains remain unknown. |

QG1: technical claims only. QG2: L1–L5 have falsification probes. QG3:
equal, input-mismatch and output-mismatch cases traverse key construction,
full AST construction and repeated matching in three plugin stages, then a
protected SDK-produced operand repeats both mismatch cases. QG4:
operand widths, extent values, visit bounds and verifier complexity are
explicit. QG5: staged plugin differences and natural-occurrence limits are
identified. QG6: local primary SDK, source, plugin and isolated-process
artifacts are pinned by hashes. QG7: no protected effectiveness or throughput
claim follows from this fixture. The complete review remains in progress.
