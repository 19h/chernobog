# Bounded writable-memory sources for native PUSH/RET transfers

Review row 1b requires a memory-source target only when its address and value
are established at the transfer. The x86-64/i386 analyzer now retains at most
16 complete words written by full-width `MOV` instructions to exact addresses
in mapped writable segments. Initial writable image bytes are unknown. At a
full-width `PUSH memory; RET`, owned analysis can publish an edge with a distinct
`memory-definition` proof; explicit-root ownerless analysis can report the same
must-fact without publishing an IDB edge. The original memory read, stack write
and RET remain intact. This uses normal-completion x86 semantics as specified
by the [Intel instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

The state computes an address from a direct operand or individually known base
and index registers. A known write overlapping a retained word removes that
word; a write with an unknown address removes all retained words. Calls,
unknown instruction effects and stack operations also remove the map. A CFG
join keeps a word only when every admitted predecessor establishes the same
complete value at the same address. The candidate remains unresolved when any
required address, write, value or path is unknown. Segment overrides, 16-bit
addressing, dynamic allocation identity, asynchronous mutation, exceptional
control flow and unmodeled segment bases are outside this proof.

## Executed and production controls

The source-emitted fixture executes each of these forms for 256 inputs on
x86-64 and i386:

| Shape | Process result | Owned IDA | Ownerless IDA |
|---|---:|---|---|
| Register-addressed full-word store, then `PUSH [register]; RET` | 7 | Exact edge | Proved target |
| Direct global store, then direct global `PUSH; RET` | 7 | Exact edge | Proved target |
| Writable global has an initial pointer but no local store | 7 | Candidate | Unresolved |
| Both branch arms store the same pointer | 7 | Exact edge | Proved target |
| A disjoint store follows the pointer store | 7 | Exact edge | Proved target |
| A byte write overlaps the stored pointer, while preserving its runtime byte | 7 | Candidate | Unresolved |
| An entry-supplied address receives a disjoint runtime write but may alias statically | 7 | Candidate | Unresolved |
| Branch arms store distinct target pointers | 7 or 8 | Candidate | Unresolved |

The complete owned harness passes **7,422 executed native checks and 108 IDA
assertions per architecture**. The ownerless harness passes its **4,094
existing native checks and 512 IDA assertions per architecture**, including
the eight separately linked assembly prefixes; its native oracle does not
execute the new eight functions. A deliberately corrupted ownerless oracle is
rejected. The two positive direct/register forms, equal-path join and disjoint
write each have an actual owned user edge, correct 32- or 64-bit width, a
zero-byte net SP delta and retained stack write. The four negative forms have
no newly published edge.

In an isolated owned IDA database, changing the defining `MOV` opcode from
store to load revokes the proof and user edge. Restoring the original byte
recomputes the exact proof with a new publication identity. Four matched
prior/new comparisons use the **same binary, probe and IDA version** per
architecture and ownership mode; only the plugin differs. The prior plugin
misses the four exact targets in each mode. All 21 CTest suites pass. On the
exact supplied `samples/foo_x86_vmp` initializer, the built plugin still
reports 75 nodes, 77 edges and three unresolved flag/branch facts, with
unchanged IDB inventory. This root establishes no gain for this memory shape.

Exact source, binaries, tools, reports and CTest hashes are in
`VMP_WRITABLE_MEMORY_TRANSFERS_EVIDENCE.json`. The owned and ownerless fixture
harnesses can be rerun with fresh output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-memory-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-memory-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| M1 | Flat normal user-mode addressing and full-width near PUSH/RET define the modeled execution domain. Address and target claims depend on it. | Execute both x86 widths; require direct and register-addressed forms to reach the intended target. Segment overrides and 16-bit address forms remain unproved. |
| M2 | A mapped writable word becomes known only after a represented local store on every admitted path. Exact-target claims depend on this. | The initialized but unstored writable slot stays unresolved; equal branch stores prove, while distinct branch stores do not. |
| M3 | Known ranges do not alias when disjoint; unknown writes may alias every retained word. The retained target depends on this. | Require the disjoint store to retain the proof, overlapping byte write and unknown-address store to revoke it, and source-byte removal/restoration to revoke/recompute an owned edge. |
| M4 | The bounded owned graph or explicit ownerless root captures the represented predecessors. Static consensus depends on this scope. | Require both architectural joins, read-only ownerless inventory, and existing external-entry controls. Other graph shapes or exceptional entries require new controls. |
| M5 | Prior/new reports are paired on unchanged input and analysis conditions. Feature attribution depends on this. | Compare each pair's input, probe and IDA hashes; require the plugin hash to differ and the prior plugin to miss the four exact targets. |
| M6 | The protected initializer is the same selected root, not a binary-wide benchmark. Its unchanged result depends on the exact sample hash and traversal. | Check sample, plugin and report hashes; compare nodes, edges, records and before/after IDB inventory. Runtime-unpacked paths remain unmeasured. |

With N nodes, E edges, S retained stack words, M retained writable words and K
rounds, the bounded graph analysis costs O(K(N + E)(16 + S + M log M)) time
and O(N(16 + S + M) + E) space, excluding IDA queries. Owned analysis caps
N at 64 and K at 128; explicit-root ownerless analysis caps N and K at 128.
Both cap M at 16, S at 64 and incoming references at 256 per node. Stack
offsets are bytes, pointer widths are bits and 8 bits = 1 byte exactly.

- **High impact:** a locally established writable target can now supply a
  native edge while preserving the original transfer effects.
- **Medium impact:** overlapping and unknown-alias writes, conflicting paths
  and initial writable bytes remain unresolved under the bounded model.
- **Low impact:** the supplied protected initializer has no measured change;
  dynamic heap identity and runtime mutation require separate evidence.

QG1: no normative premise. QG2: M1–M6 include falsification probes. QG3:
classifier, address/value analysis, owned publication, ownerless inspection,
both widths, native results, abstentions and byte invalidation cover this
local-store shape; the full review remains open. QG4: widths, bytes, counts
and complexity are explicit. QG5: initial data, aliasing, joins and
publication freshness retain uncertainty when unproved. QG6: Intel's primary
instruction reference and hash-matched local oracles support the claims.
QG7: protected scope and unmodeled dynamic memory are bounded explicitly.
