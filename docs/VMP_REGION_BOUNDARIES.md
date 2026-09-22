# Native region-boundary audit

Chernobog now exposes a bounded, read-only native topology audit in the
`boundary_audit` object returned by `chernobog_vm_regions` and the related
summary/observation inspection APIs. It identifies where traversal encounters
ownerless code, a foreign function, a shared function tail, a missing code
head, a mode/permission boundary, or an unmodeled transfer. It does not admit
a VM execution region or change IDA ownership.

The paired corpus gives a concrete distinction [B1–B3]: twelve x64
virtualization/combined entries reach an unmodeled call after the entry jump
and one push instruction; all eighteen i386 protected entries immediately
reach another IDA function. Extending only ownerless function tails would
therefore leave both call semantics and cross-function region identity
unresolved.

## Implementation and contract

The portable implementation is [boundary.cpp](../src/vm/boundary.cpp), with
its plain-data interface in [boundary.hpp](../src/vm/boundary.hpp). The
production adapter is [ida_regions.cpp](../src/vm/ida_regions.cpp).

The adapter verifies a current, loaded executable code item, its complete
instruction span, byte ownership, mode, and current native bytes. Shared
function tails are explicit stops, including when the selected root is the
tail's primary owner. Unsupported prefixes stop traversal. The core rejects
invalid spans, missing byte encodings, projection-address mismatches, and
overlapping decoded instructions.

Direct targets come from decoded near operands, not arbitrary IDB xrefs.
Conditional branches retain both native alternatives; linear instructions
contribute their physical fallthrough. Consequently, this audit can retain a
decoded edge whose IDB xref has been removed. It does not evaluate branch
conditions or assert that either alternative is dynamically feasible.

Calls stop with `call_requires_summary`, even when their immediate target is
known: neither entering the callee nor returning to the next instruction is
assumed. Indirect jumps stop with `unresolved_indirect`. Native RET stops with
`unresolved_return`, because it may implement a stack-mediated dispatch.
Known IDB jump references on a RET do not change that classification.
Other unsupported control transfers stop explicitly.

Existing incoming code references **to instruction heads** are inventoried
separately. An incoming source outside the accepted native graph is reported
as `external_code_entry`; a source inside it without a matching decoded edge
is `unverified_internal_xref`. References to the selected entry have a
separate count. These are database observations. Absence of such references
does not prove isolation: dynamic entries, references into instruction
interiors, and implicit exception/control transfers are outside this census.

The output retains rejected nodes, native bytes, owners, edge origins,
frontier reasons, and explicit quota flags. A retained edge can terminate at
a rejected node; `decoded_heads` counts only accepted nodes. `available`
means the selected root is an inspectable x86 function, not that the graph is
closed or executable. `execution_admitted` is always false. Results are
ephemeral observations in the outer response's database/function scope;
they are not ownership receipts or reusable execution publications.

The prior contiguous recognizer also now caps its incoming-reference scan
at 64 records. Exhaustion marks truncation and prevents treating that path
as single-entry. Existing candidate recognition and its xref-based reachability
remain distinct from the new decoded-topology audit.

## Algorithm and bounds [B2, B4]

```text
queue := selected function entry
while queue is nonempty and scheduled-head quota permits:
    read one current instruction and bounded incoming head references
    retain its bytes, ownership and any rejection
    reject invalid, foreign, shared, overlapping or incompatible spans
    enqueue only decoded direct targets and native fallthrough alternatives
    record calls, indirect transfers and RETs as unresolved frontiers
compare incoming head references with accepted nodes and decoded edges
return observations with quota flags; execution_admitted := false
```

Hard ceilings are 1,024 scheduled heads, 64 incoming records per head and
8,192 incoming records globally. Caller-supplied limits can reduce these
ceilings. Zero limits, exact limits, cycles and a reader that overproduces
incoming records have explicit controls. A decoder span contains at most
15 bytes. At most two native edges are retained per accepted head.

For H scheduled heads and I retained incoming references, ordered sets/maps
give O((H + I) log(H + 1)) core time and O(H + I) space. IDA database-index
lookup and decoder internals are excluded from this complexity statement.
The adapter examines at most 15 instruction bytes and up to the allotted
incoming records plus one exhaustion witness per requested head. It does
not scan all possible dynamic targets. Exceptions, calls and return effects
require additional models before any execution admission.

## Measurements

The runner [run_vmp_boundaries.py](../tests/run_vmp_boundaries.py) verifies
the existing paired corpus, input, plugin, IDA and harness identities. It
starts ten isolated IDA processes per architecture: original plus mutation,
virtualization and combined variants for seeds 0, 1 and 12,648,430. The normal
native analysis runs first; RAX execution remains disabled. Each process
audits `corpus_transform` and `corpus_branch`.

Counts below sum entry-specific observations across artifacts. They are
neither unique whole-program instruction counts nor recovery rates.

| Observation | x86-64 Mach-O | i386 ELF |
|---|---:|---:|
| Binary/process measurements | 10 | 10 |
| Selected-entry audits | 20 | 20 |
| Accepted native heads | 141 | 38 |
| Accepted ownerless heads | 106 | 0 |
| Retained native edges | 125 | 37 |
| Unresolved call frontiers | 12 | 0 |
| Unresolved RET frontiers | 8 | 2 |
| Foreign-function frontiers | 0 | 18 |
| Corpus audits reaching either quota | 0 | 0 |

In x64, the six mutation entries contribute 88 accepted heads, 82 ownerless,
and six unresolved RETs. The six virtualization and six combined entries
each have three accepted instructions: entry JMP, PUSH, CALL. Their call
targets are retained but not traversed. The two original functions contribute
17 accepted heads and two RETs. In i386, each protected root contributes one
accepted entry instruction before the foreign-function stop; the originals
contribute the remaining 20 accepted heads and two RETs.

These narrower counts do not contradict the earlier condition census in
`VMP_CONDITION_CORPUS.md`. That census followed existing non-call IDB xrefs
and inspected encountered owners. This audit uses decoded native edges and
stops before crossing ownership or unmodeled calls. Its frontier counts do
not establish complete native or virtual control-flow coverage. No protected
code is executed by this measurement, and no decompilation benefit is claimed.

The supplied hello-world remains the separate packed-startup fixture
described in `VMP_HELLO_FIXTURE.md`; this matrix does not reclassify or unpack
it. Exact source-to-protector build attestation remains unknown [B1].

## Validation and provenance

All **79 portable boundary controls** pass. Live controls in each architecture's
original-artifact process cover ownerless code, RET xrefs, side entries,
spurious internal xrefs, foreign functions, shared tails, ownership restoration,
missing direct xrefs, calls, indirect transfers, traps, prefixes, missing code,
permissions, mode changes and both quotas. The complete matrix passes
**474 production checks**: 237 per architecture, including repeated inspection,
retained-byte/count validation, and preservation of an independently selected
native inventory before the first and second inspections. Constructed mutation
controls operate only on disposable IDBs and are excluded from corpus counts.

All **19 CTest suites** pass; the suite log is
`build/vmp-boundary-ctest.log` (11.32 s for this execution). The two architecture
matrices ran concurrently, with serial launches within each matrix. Summed
runner durations were 31.799457626 s and 48.793006791 s; maximum reported peak
resident sizes were 212,910,080 bytes and 162,709,504 bytes. These include
process startup and fixture controls, and do not measure isolated audit cost,
speedup, or statistical performance.

Primary capture reports are:

- `build/vmp-boundary-corpus-x64/boundaries_analysis.json`
- `build/vmp-boundary-corpus-x86/boundaries_analysis.json`

`VMP_REGION_BOUNDARIES_EVIDENCE.json` records source, SDK, executable and
artifact hashes. SDK provenance is the installed `intel.hpp` conditional
branch classifier, `funcs.hpp` tail ownership/reference-count definitions,
`xref.hpp` code-reference iteration, and `ua.hpp` instruction/operand model.
No commercial-version coverage is inferred from these local sources.

Reproduction uses fresh output directories:

```sh
python3 -B tests/run_vmp_boundaries.py \
  --corpus-report build/vmp-corpus-release/corpus.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/boundary-reproduction-x64

python3 -B tests/run_vmp_boundaries.py \
  --corpus-report build/vmp-elf32-release/corpus.json \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/boundary-reproduction-x86
```

## Assumption register and falsification probes

| ID | Assumption / dependent result | Stress test or falsification probe |
|---|---|---|
| B1 | Archived paired artifacts identify the measured source/configuration family | Corpus and binary hashes are checked before/after all runs. A mismatch rejects attribution. Exact protector source-build attestation remains unknown |
| B2 | Current IDA decoding, ownership, item boundaries and incoming head references describe the observed native database | Missing xrefs, spurious xrefs, foreign/shared ownership, mode and permission mutations exercise the adapter. Dynamic and instruction-interior entries remain outside scope |
| B3 | The audit remains observational and requires separate call/return/VM-state proofs | First/repeated native inventories must be preserved; RET-xref and call controls must stop. Every capture must retain `execution_admitted=false` |
| B4 | The adapter honors bounded reads and the core retains bounded evidence | Zero/exact/reduced/hard-cap tests and an overproducing reader test truncation. SDK-internal lookup complexity remains outside the portable bound |
| B5 | These recorded processes establish this corpus checkpoint | Source/plugin/input identities must remain stable. One process per artifact provides no statistical timing or broader-version generalization guarantee |

## Bounded scope expansion and quality gates

- **High impact:** x64 VM-entry calls need return-address/stack and context
  summaries before traversal can advance. A known callee address is insufficient.
- **High impact:** i386 needs a logical region model spanning existing function
  identities. Erasing those owners would discard evidence and still leave
  execution publication, freshness and rollback requirements unresolved.
- **Medium impact:** IDB xrefs and native decoded alternatives can disagree.
  Keeping both exposes stale metadata without turning it into control-flow proof.
- **Medium impact:** head-reference isolation cannot establish instruction-interior
  or dynamic isolation; any future ownership-admission gate needs those additional
  exclusions or an explicit narrower contract.

QG1 requires no normative content. QG2 is the assumption register above.
QG3 covers this bounded audit implementation and measurements; the complete
review objective remains open in `VMP_IMPLEMENTATION.md`. QG4 is supported
by explicit counts, units, quotas and reproducible reports. QG5 includes the
negative/edge controls and explicitly separates decoded alternatives from
feasible execution and topology from ownership. QG6 uses hashed local primary
sources and captures. QG7 is the bounded expansion above. These gates do not
assert that unresolved VM ownership, handler semantics or lifecycle work is
complete.
