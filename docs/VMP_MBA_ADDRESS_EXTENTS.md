# Strict address-operand extent comparison and versioned capture

Review row 4a requires a repeated matcher binding to retain the metadata of
the actual microcode operand. The local IDA 9.4 SDK defines `mop_a` as an
address of a `mop_l`, `mop_v`, `mop_S` or `mop_r` operand. Its `mop_addr_t`
also carries `insize` and `outsize`, the numbers of bytes of the pointed
operand that can be read and written. Its `lexcompare` compares the referent,
then `insize`, then `outsize`; the strict matcher now retains the same
distinction. The SDK header SHA-256 is
`7ced9073b5b1fe06357f51e5983e041cae0b6b0f8f69d790f443031ec05022ff`.

The prior strict comparator compared the referenced operand but skipped both
extent fields. It could therefore accept two address operands with identical
referents and different access contracts as one repeated binding. The
comparator now checks `insize` and `outsize` before recursing into the
referent. A mismatch yields `address_input_size` or `address_output_size`
with both signed SDK values preserved as hexadecimal 64-bit diagnostic
fields. Equal extents and equal referents still compare equal. The change
does not establish pointer values, frame bases, aliasing or call effects.

The AST builder's `MopKey` previously omitted both extents. Its local
deduplication context could therefore reuse one address leaf for another
with the same referent but a different access contract before the strict
matcher examined them. The key now packs the exact 32-bit `insize` and
`outsize` representations into its existing 64-bit metadata field. Key
equality checks that field even under a forced hash collision, and nested
instruction hashes inherit the distinction. The key remains 64 bytes.
The component suite passes 1,284 operand-identity checks, including equal
extents, differing input and output extents, `NOSIZE`, a changed referent,
context separation and nested hashes. A deterministic nested-key collision
is checked below. A later live SDK-owned full matcher fixture checks unequal
extents through AST construction and repeated binding; see
`VMP_MBA_LIVE_ADDRESS.md`.

The capture encoder now labels matcher inputs `schema: 2` and serializes a
non-null `mop_a` payload as `[referent, insize, outsize]`. The independent
reader requires both extents for schema 2. It accepts the older five-field
referent payload only when the input has no schema marker, preserving the
source-pinned historical corpus. A schema 2 record with missing, malformed
or out-of-range extents is rejected; removing the schema marker from an
otherwise unchanged schema 2 record is also rejected. The catalog pattern
schema remains 1 because its pattern tree has no captured SDK address
operand.

Direct C++ strict-comparison controls exercise differing input extents,
differing output extents and equal extents. The C++ encoder and independent
Python replay agree on the generated address equality fixtures. Three
mutation controls reject missing extents, an out-of-range input extent and a
schema downgrade. The focused `chernobog.mba_catalog` and
`chernobog.mba_match_replay` suites pass 2/2. A full build and the four-job
CTest suite pass 23/23 on the final tree. The historical
14,047-event audit and its independent delta pass with the new reader:
13,717 refuted, 325 unsupported, five existing catalog applications, zero
unrecorded events. The 48 historical address-of events remain unsupported
because their old capture lacks extents and frame-base state. No protected
recovery or occurrence-rate gain is claimed.

An address-rich synthetic boundary control places two `mop_a` operands in
each consecutive predecessor and anchor. The referent is `mop_v`; both
extent fields use the signed 32-bit maximum to stress the serializer. At 45
predecessors the complete schema 2 record is 8,053 bytes. At 46, it retains
an 8,052-byte record with `prefix_status: byte_limit`, within the 8,192-byte
cap. The independent reader accepts that bounded record and rejects an
out-of-range extent mutation within its retained prefix. This checks capture
integrity at the byte frontier; it does not measure how often real IDA
operands approach the cap.

The standalone fixture harness can compare borrowed SDK address descriptors
directly. Passing such a synthetic descriptor through the full matcher
aborted inside SDK operand ownership handling, so that fixture was removed.
The direct comparator test and independent serialized replay cover differing
extents. Two fresh isolated IDA processes on the i386
`virtualization-0-on` sample captured 1,693 matcher events each, with 1,138
retained samples and zero omissions. The current serializer's schema 2
validated for every retained sample. In each process, 12 samples at one
`corpus_transform:direct_target` maturity-5 source contain `mop_a` in the
candidate root, representing 24 weighted events and 28 weighted address
occurrences. All 28 observed address extents are `insize=-1`,
`outsize=-1`. This verifies live capture of SDK-produced address operands
through the matcher path but provides no live unequal-extent comparison or
protected recovery gain. The first and second report SHA-256 values are
`ac6025aed7f3f5195353eb1ff3386b0a54c893d8560d2cba0666060b6f59153b`
and `bd249579164783e06d058199599eed9a3453d3f07736562dec5b8dfee6a133c6`.
The associated plugin SHA-256 is
`e112d00d24806f5263d817c3d8b6271bdf04c37411d45da027be86a90901708c`.
Those two processes certified only 90 of 108 MBA rules because 18 timed out;
their event counts cannot be compared as an unchanged-catalog effectiveness
measure. A later isolated run with bounded proof retries certified 108 of 108
and reproduced the same 1,693 events, 1,138 samples, 24 address-bearing
weighted events and `-1/-1` extents. Its report SHA-256 is
`e09062e42a279e46e5fe994bcbded7fe1953aa835a0ce53ead3a8a20f513a12f`;
the timeout change is documented in `VMP_MBA_RUNTIME_CERTIFICATION.md`.

A fresh isolated IDA process with the address-key change used the same
protected i386 input, probe, capture limit, IDA binary and explicit environment
as the 108/108 certified prior run. The plugin SHA-256 is
`e264c7cfac50da572faf1b0b977db7d2d7e0a842790eaa6e358f1facb08a817f`;
its report SHA-256 is
`882b52dcd31a57049b64a2e95c49f4191936c1159d67d7c0558f4f1ad0b02b3b`.
An independent verifier parses all 1,138 retained schema 2 inputs and checks
exact equality of the complete prior/current IDA reports after removing only
per-stage elapsed nanoseconds. The shared normalized SHA-256 is
`dcf22f2f5f98d0537ee067a7993a35ce2f06ab2636f04acfecadf4d15571acf5`.
Both runs have 1,693 matcher events, zero unrecorded events, 24 weighted
address-bearing events and 28 weighted address occurrences; every observed
extent remains `-1/-1`. A live-derived out-of-range extent and an altered
event count are rejected. `VMP_MBA_ADDRESS_KEY_EVIDENCE.json` records the
run, report, tool and normalized hashes. These equal reports bound the
selected-corpus observation; they do not demonstrate an unequal-extent
protected rewrite.

A wider matched native-analysis profile repeated the historical 40-process
x86-64/i386 matrix: ten original/protected binaries per architecture, each
with transformations disabled and enabled, the same IDA executable, binary
hashes, probe script and explicit environment. The corpus runner verified
all 40 process manifests, 40 SDK reports and their pinned artifacts. A
separate matrix-delta verifier then checked every current retained matcher
input with the independent schema 2 reader, checked every live address
extent, and compared all reports with their historical counterparts. Only
`generation_elapsed_ns` and the schema 2 marker/extent encoding were removed
for the comparison. The latter projection was admitted only for observed
`insize=-1, outsize=-1` operands. All 40 projected reports, all 40 per-run
count records and the 76 paired-result records agree exactly. The common
normalized report digest is
`96d114fb2b864193f9ec62ecc6aa5c164e76ae74e5c3a02203a47756f1f307cd`.

| Matched matrix measure | Current result |
|---|---:|
| SDK process profiles | 40 |
| Matcher events | 14,047 |
| Retained, complete schema 2 inputs | 9,729 |
| Unrecorded events | 0 |
| Address-bearing samples / weighted events | 98 / 149 |
| Address operands / weighted occurrences | 235 / 361 |
| Successful catalog applications | 5 |

All 235 retained address operands have both extents equal to `-1`; a mutated
live input with `insize=0` is rejected by the matrix verifier. The historical
and current aggregate SHA-256 values are
`b2a56f35acaf3983203b993fb33a1eab858167163b77d4e3dc94554677412cba`
and `8d80d9f7a3183eb5da5b66fc200cc2a7280cb322250c68d78593270f2391fff9`.
`VMP_MBA_ADDRESS_MATRIX_EVIDENCE.json` pins these values and the verifier
source. The historical plugin differs from the current plugin in more than
the address-key change, so equal matrix outcomes are a bounded regression
observation, not causal evidence for that key change. This corpus also has
no unequal-extent live address operand. A constructed SDK-owned
repeated-binding fixture is covered separately in `VMP_MBA_LIVE_ADDRESS.md`;
that document also copies one protected SDK-produced stack address and changes
one extent in each of two test cases. Natural unequal-extent protected
operands remain unobserved. Both complete
report directories are ignored local build artifacts; the tracked evidence
contains their hashes and derived values.

The compact key also had a distinct collision mode: its nested-instruction
hash includes destination size, value number and properties but omits the
destination register identifier. Two constructed `mop_d` operands with
identical opcode, sources and EA but different destination registers
therefore have equal `MopKey` values while the strict comparator rejects
them. Previously `mop_to_ast_internal` reused the first cached AST on the
key match alone. It now calls `AstBuilderContext::get_exact`, which compares
the cached AST's copied SDK operand with the current operand before reuse.
The component control reproduces the deterministic collision, accepts the
equal source and rejects the unequal source through the gate. A second
nine-check control runs both candidates through full `minsn_to_ast`
construction. Its bounded standalone SDK stub deep-copies only one nested
instruction whose three children are allocation-free operands, tracks each
owned copy and checks ownership before freeing. The returned AST has two
distinct children with destination registers 102 and 103; both copied
operands compare equal to their respective inputs, and all copied nested
instructions are released after AST destruction. A collision can leave the
later AST uncached in the current one-slot map; this changes deduplication
efficiency, not operand identity. The 1,024-visit AST budget remains in
force.

A paired live IDA 9.4 control constructs the same nested operands using
SDK-owned `minsn_t` objects inside the IDA process and calls the plugin's
exported `MopKey::from_mop`, `mops_equal_strict` and `minsn_to_ast` functions.
The key is 64 bytes and equal for both operands; strict equality rejects
them. With the prior plugin, full AST construction returns status 6,
`ast_collision_merge`. With the fixed plugin, 11 AST visits return distinct
children whose copied operands compare equal to their respective inputs and
whose destination registers remain 102 and 103. The two isolated processes
used the same input, IDA executable, probe, bridge and explicit environment;
the plugin binaries differed. The prior and current result SHA-256 values are
`e3ff9390827fe3a8a15d6308b4374a4fcaf2870912f3752d0038239281162e51`
and `d8452cfc87205da503ed19865e5cc6ff8f308980f3efa87099760b1237efcc3d`.
`VMP_MBA_LIVE_COLLISION_EVIDENCE.json` pins both process manifests, inputs,
executables, source and bridge hashes. An altered destination is rejected by
the independent verifier. The fixture proves this constructed SDK-owned
collision path; whether protected microcode naturally presents it is unknown.

The rebuilt plugin's native-analysis-enabled 40-profile matrix was compared
with the preceding schema 2 matrix on the same binaries, IDA executable,
probe and explicit environment. All 40 full SDK reports agree after removing
only `generation_elapsed_ns`; every paired result and per-run count agrees.
The current plugin SHA-256 is
`b94678b6758326da50c4e796f551eb9928c1e8f6a4d2ae920470f8fb3f21ba45`,
the new aggregate SHA-256 is
`3dbaf050cc0dea70768a99ba7cf9f2615d48b608dae7bc716c960ef6ac30769d`,
and the common normalized-report digest is
`3a4ffcd23f348ec0081db46bee6c10be808cfe22e7618ea4065c971f8fd6a8e6`.
The 9,729 complete inputs contain 14,047 matcher events with zero
unrecorded events and five successful catalog applications. A mutated
report event count is rejected. `VMP_MBA_CACHE_GATE_EVIDENCE.json` pins the
two aggregate hashes, tool identities and verifier source. These equal
results bound regression on this corpus; they do not demonstrate the
collision occurring in protected IDA microcode or a protected recovery gain.

Reproduction from the repository root:

```sh
cmake --build build --target chernobog_catalog_tests -j 20
ctest --test-dir build -R 'mba_catalog|mba_match_replay' --output-on-failure
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --capture-tar docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz \
  --source-revision 5756071e69c4626db2419bc0e45531bf21f5f2a2 \
  --output build/mba-address-legacy-audit.json
python3 -B tests/verify_mba_bounded_delta.py \
  --prior docs/VMP_MBA_SHIFT_AUDIT.json.gz \
  --current build/mba-address-legacy-audit.json \
  --controls build/mba-unary-controls.json \
  --capture-tar docs/VMP_MBA_COMPLETE_CAPTURE.tar.gz \
  --output build/mba-address-legacy-delta.json
python3 -B tests/verify_mba_address_key_delta.py \
  --prior build/mba-rule-timeout-final/protected_mba.json \
  --current build/mba-address-key-fresh-v1/protected_mba.json \
  --prior-run build/mba-rule-timeout-final/run.json \
  --current-run build/mba-address-key-fresh-v1/run.json \
  --evidence docs/VMP_MBA_ADDRESS_KEY_EVIDENCE.json \
  --output build/mba-address-key-delta-verified.json
python3 -B tests/run_protected_mba_corpus.py \
  --corpus-report build/predicate-protected-x64-b89d23fc-v1/corpus.json \
  --corpus-report build/predicate-protected-i386-b89d23fc-v1/corpus.json \
  --ida '/Applications/IDA Professional 9.4.app/Contents/MacOS/idat' \
  --plugin build/local-plugins/chernobog.dylib \
  --output-dir build/mba-address-key-matrix-native-v1 \
  --matcher-inputs --input-limit 1024 --native-analysis \
  --workers 2 --timeout 300
python3 -B tests/verify_mba_address_matrix_delta.py \
  --prior build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --current build/mba-address-key-matrix-native-v1/protected_mba_analysis.json \
  --evidence docs/VMP_MBA_ADDRESS_MATRIX_EVIDENCE.json \
  --output build/mba-address-matrix-delta-verified.json
python3 -B tests/run_protected_mba_corpus.py \
  --corpus-report build/predicate-protected-x64-b89d23fc-v1/corpus.json \
  --corpus-report build/predicate-protected-i386-b89d23fc-v1/corpus.json \
  --ida '/Applications/IDA Professional 9.4.app/Contents/MacOS/idat' \
  --plugin build/local-plugins/chernobog.dylib \
  --output-dir build/mba-strict-cache-matrix-v1 \
  --matcher-inputs --input-limit 1024 --native-analysis \
  --workers 2 --timeout 300
python3 -B tests/verify_mba_cache_gate_delta.py \
  --prior build/mba-address-key-matrix-native-v1/protected_mba_analysis.json \
  --current build/mba-strict-cache-matrix-v1/protected_mba_analysis.json \
  --evidence docs/VMP_MBA_CACHE_GATE_EVIDENCE.json \
  --output build/mba-cache-gate-delta-verified.json
CCACHE_DIR="$PWD/build/.ccache" c++ -std=c++17 -O2 -DNDEBUG \
  -D__EA64__=1 -D__IDP__ -D__MAC__ -mmacosx-version-min=13.3 \
  -fPIC -dynamiclib -Wl,-undefined,dynamic_lookup \
  -Isrc -I../ida-sdk/src/include tests/ida_mba_collision_bridge.cpp \
  -o build/ida_mba_collision_bridge.dylib
python3 -B tests/verify_mba_live_collision.py \
  --prior build/mba-live-collision-prior-v1 \
  --current build/mba-live-collision-v2 \
  --bridge build/ida_mba_collision_bridge.dylib \
  --evidence docs/VMP_MBA_LIVE_COLLISION_EVIDENCE.json \
  --output build/mba-live-collision-verified.json
```

The corpus runner requires a new output directory. For a fresh repeat, choose
a new directory name and pass its aggregate to the verifier without
`--evidence`; the pinned evidence refers to the recorded run above.
The paired live control can likewise be repeated with two fresh output
directories and `--evidence` omitted from its verifier. Its prior command
returns process status 1 because the fixture detects the expected merge:

```sh
python3 -B tests/run_ida_smoke.py build/flag-values-oracle \
  tests/ida_mba_collision_probe.py \
  --ida '/Applications/IDA Professional 9.4.app/Contents/MacOS/idat' \
  --plugin build/mba-address-key-matrix-native-v1/x86_64/original-on/idauser/plugins/chernobog.dylib \
  --set "CHERNOBOG_MBA_COLLISION_BRIDGE=$PWD/build/ida_mba_collision_bridge.dylib" \
  --expect-log '\[chernobog\]\[mba-collision\] FAIL' \
  --output-dir build/mba-live-collision-prior-repeat || test $? -eq 1
python3 -B tests/run_ida_smoke.py build/flag-values-oracle \
  tests/ida_mba_collision_probe.py \
  --ida '/Applications/IDA Professional 9.4.app/Contents/MacOS/idat' \
  --plugin build/local-plugins/chernobog.dylib \
  --set "CHERNOBOG_MBA_COLLISION_BRIDGE=$PWD/build/ida_mba_collision_bridge.dylib" \
  --expect-log '\[chernobog\]\[mba-collision\] PASS' \
  --output-dir build/mba-live-collision-current-repeat
python3 -B tests/verify_mba_live_collision.py \
  --prior build/mba-live-collision-prior-repeat \
  --current build/mba-live-collision-current-repeat \
  --bridge build/ida_mba_collision_bridge.dylib \
  --output build/mba-live-collision-repeat-verified.json
```

The changed source and control SHA-256 values, in the same order as the
following list, are:

| File | SHA-256 |
|---|---|
| `src/deobf/analysis/ast.h` | `1f57dd69fc3e5cd5806c4276b9da5a9d847acae2ae713fa2b80bde720af1f392` |
| `src/deobf/analysis/ast.cpp` | `bc1bb1d2badaec033c86f9e3f4f609ad61f4bf128981b27262bc1a8d38021aca` |
| `src/deobf/analysis/ast_builder.h` | `a996f6d883043837729ee283ef8e54a85ea89df74b3550d130739278879e8dbf` |
| `src/deobf/analysis/ast_builder.cpp` | `4fcf1eb26ae12ca84421b527c3d530a5091dce0a4fe327697e60403622f477a6` |
| `src/deobf/analysis/match_capture.h` | `ed59d0f8ea9de0071965ccadfc4126c491b3c9d47a289439899ab5d086bc1068` |
| `src/deobf/analysis/match_capture.cpp` | `2d15328bd676f1eb8e6d2cf00f44b52edea6632ab88cd06e2897969fdc56094e` |
| `tests/catalog_tests.cpp` | `62edf5338b51d2d9185b535eb58e4547ed2b79af4badbbc5640bf5ceb3219039` |
| `tests/mba_match_replay.py` | `90d84d79cd54fc93d975198089938be9a2a5026b828675a933c68460d031f05a` |
| `tests/mba_match_replay_tests.py` | `291bda4dfcdbc195a96217cc9fa275c3ff5301963c69a165d7cd1bd8b13099f9` |
| `tests/mba_matching_diagnostics.py` | `f59ecc06fdeadc2f8898839539cfb559733143ca82053e7292071cd9c262b51e` |
| `tests/verify_mba_address_key_delta.py` | `e1bcd724f48a5ec32ab7d23bc7a2c73921bb3da506ae4d4e0b1aa5172d12c2a3` |
| `tests/verify_mba_address_matrix_delta.py` | `d16aef68da68e2b790d60dea8a13240586ce195327030e0532d458afb4626a31` |
| `tests/verify_mba_cache_gate_delta.py` | `3cffea343fd75882f9cfa8b29a65c839128e45fb8541e9af311a5467732d6181` |
| `tests/ida_mba_collision_bridge.cpp` | `78b7b9edbcecd0535156ed2f272b73d18014f0914041b0c4acc3a846b1bb29bb` |
| `tests/ida_mba_collision_probe.py` | `fea05e87ac5480b0f5509d8cf5f0e520222e606cfe4c5dc22160b064b0008c40` |
| `tests/verify_mba_live_collision.py` | `e6cefd1eec568720113ea252420df7f128e52ae382b1d271ab866d826b79ee24` |
| `tests/ida_mba_address_bridge.cpp` | `698b37057712625b77a8411a1aa0a3e89a8cdbc58d8d71dd30842bf280404a49` |
| `tests/ida_mba_address_probe.py` | `1e3b4ef0f73fa4a6f3025ac656eeea6a28d337d95129320be07e2c24cf17f969` |
| `tests/verify_mba_live_address.py` | `b1b07f6bbac01cb22c3badf34c25b8ebb93bb8a046595ba9f5de0efe47ee9568` |
| `tests/ida_mba_observed_address_bridge.cpp` | `4c70a3681ed6abf026375fed99a63ca4634417d3f138b64c93148f28af600278` |
| `tests/ida_mba_observed_address_probe.py` | `71833b56cdc83457a244eddbbf3350256e3ae07577210ca8e1e15996cbf912d7` |
| `tests/verify_mba_observed_address.py` | `ad2b6b9a3f3166e3b2f52a2da7fe1f9d0403be72d93c706d920d59523edb9868` |

The two additional extent comparisons use `O(1)` time and space per address
operand, beyond the existing bounded recursive referent comparison. Packing
both fields into the AST key also uses `O(1)` time and no additional key
storage. Encoding
two signed 32-bit fields adds at most 22 decimal bytes plus delimiters per
address operand; the existing 8,192-byte input limit and 512-visit/64-depth
budgets still apply.
For report byte count `B` and `S` retained input samples of at most 8,192
bytes each, the independent delta verifier uses `O(B + S * 8,192)` time and
`O(B)` retained memory, excluding JSON-library overhead. This is not a
protected matcher throughput measurement. The pinned full IDA reports and
run manifests reside in ignored `build/` directories; the tracked evidence
JSON contains their hashes and derived counts, not their complete bytes.
The strict cache check costs at most 512 operand visits and 64 recursive
levels for one candidate lookup, beyond key lookup. Across the 1,024-visit
AST admission limit its comparison work is bounded by `O(1,024 × 512)`
operand visits with `O(64)` comparison stack space, excluding AST storage.
The protected matrix does not measure a throughput difference.
The 40-profile verifier scans each report once. For total captured report
bytes `T`, it uses `O(T)` time and `O(M + A)` memory, where `M` is the
largest paired report and `A` is the aggregate-manifest size, excluding
JSON-library overhead. Its performance is a verifier cost, not a matcher
throughput result.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| A1 | SDK `insize`/`outsize` are part of the address operand's access contract. Strict-equality tightening depends on this interpretation. | Recheck the hashed SDK declaration and test identical referents with differing input and output extents. |
| A2 | AST construction preserves unequal address extents and the C++ matcher uses the strict comparator for repeated bindings. Rejection of a repeated binding with differing extents depends on both stages. | Force key-hash collisions and query the AST context with unequal input/output extents; paired live SDK-owned full matcher fixtures check a constructed referent and a copied protected stack-address source. Search protected captures for natural unequal extents; the observed protected operands all have `-1/-1` extents. |
| A3 | New encoder and independent reader agree on `[referent, insize, outsize]`. New capture claims depend on this shape. | Compare generated C++ equality fixtures with independent replay; mutate each extent and remove the schema marker. |
| A4 | Historical inputs without a schema marker use the older referent-only shape. Legacy audit continuity depends on this separation. | Rerun the 14,047-event source-pinned audit and delta; reject a schema 2 payload with missing extents. |
| A5 | Added fields fit the bounded capture or produce an explicit byte-limit status. Capture completeness depends on that bound. | The synthetic 45/46-predecessor boundary has a complete 8,053-byte record followed by an 8,052-byte record marked `byte_limit`; the independent reader validates it and rejects a corrupt extent. Recheck on live address-rich inputs for frequency. |
| A6 | The historical and current 40-profile matrices refer to the same protected inputs and SDK environment. The regression comparison depends on this identity. | Compare all binary, IDA, probe and environment hashes from each paired run manifest; verify all 160 report and run-artifact hashes, 9,729 current inputs, 40 projected report equalities and a mutated live extent. A fresh matrix with an unequal-extent operand would falsify the observed `-1/-1` restriction. |
| A7 | A cached AST retains a faithful copied operand during local AST construction. The strict reuse gate depends on that copy. | The direct and bounded-stub controls check the gate and ownership. The paired live IDA fixture constructs SDK-owned recursive operands and verifies the prior merge and current distinct copied children. Search protected captures for a natural occurrence; the matched protected reports do not contain this constructed collision. |

| Impact | Result or remaining risk |
|---|---|
| High | AST deduplication and strict comparison now distinguish different address access extents. |
| Medium | New inputs retain the metadata needed to audit that distinction; historical input identity is preserved. |
| Medium | A constructed live SDK-owned unequal-extent matcher fixture rejects both mismatches; natural protected occurrence and effectiveness remain unknown. |
| Medium | Forty matched profiles reproduce the historical captured outcomes after schema projection; this bounds regression risk for the measured corpus. |
| High | Strict cache reuse blocks a deterministic nested-key collision from merging unequal operand snapshots. |
| Medium | A paired live SDK fixture confirms the constructed collision path; natural protected occurrence remains unknown. |
| Medium | The one-slot cache may deduplicate fewer repeated operands after a collision; measured throughput impact is unknown. |
| Low | Extra fields may cause a previously near-limit input to reach the existing byte cap. |

QG1: descriptive technical scope. QG2: A1–A7 include falsification probes.
QG3: AST key/context, comparator, diagnostics, capture, near-limit independent replay, and
legacy audit paths, deterministic cache collision and matched 40-profile
matrices are covered. QG4: field widths,
byte cap and complexity are explicit.
QG5: natural protected unequal extents, collision occurrence and protected
effectiveness remain unknown.
QG6: the local primary SDK header, source hashes, executed controls and
same-input protected report comparison pin the claims. QG7: the capture cap,
unarchived full IDA reports and unmeasured protected paths bound the scope.
