# Partial-width writable-memory sources for native PUSH/RET

Review row 1b asks for an exact memory target only when both address and value
are established at the transfer. The x86-64/i386 analyzer now retains up to
128 individually known bytes written by local `MOV` instructions to exact
addresses in mapped readable/writable segments. Stores of 8, 16, 32 or 64
bits update their addressed bytes. A full-width `PUSH memory; RET` can publish
an owned `memory-definition` edge, or expose an ownerless must-fact, only when
all four or eight pointer bytes are known and agree across all admitted paths.
The original memory read, stack write and return effects remain. Instruction
semantics follow the [Intel 64 and IA-32 instruction set reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

Initial writable image bytes are unknown. A local write with an unknown value
removes only its addressed bytes; an unknown address clears the entire retained
map. Calls, stack operations and unknown effects keep their previous
conservative invalidation. A join retains a byte only when every admitted
predecessor has the same known value at that address. The byte map evicts its
lowest address when its 128-byte limit would be exceeded; eviction loses
precision and cannot establish a target. A 32-bit range crossing `UINT32_MAX`
is rejected rather than wrapped.

## Executed and production controls

The source-emitted fixture executes 256 inputs per architecture. Its five new
shapes extend the eight full-word controls in
`VMP_WRITABLE_MEMORY_TRANSFERS.md`:

| New shape | Native process result | Owned IDA | Ownerless IDA |
|---|---:|---|---|
| Pointer assembled by two 16-bit stores on i386 or two 32-bit stores on x86-64 | 7 | Exact edge | Proved target |
| Full-word store followed by a known byte overwrite preserving that byte | 7 | Exact edge | Proved target |
| Unknown byte self-write followed by a known repair | 7 | Exact edge | Proved target |
| Only the low byte is written to a preinitialized writable pointer | 7 | Candidate | Unresolved |
| Branch-dependent low-byte write selects between two aligned targets | 7 or 8 | Candidate | Unresolved |

The complete owned harness passes **8,702 native checks and 128 IDA
assertions per architecture**. The ownerless harness passes **4,094 existing
native checks and 562 IDA assertions per architecture**; its native oracle
does not execute the five newly linked functions. A deliberately corrupted
ownerless oracle is rejected. Across all writable-memory controls, seven
shapes have an exact target and six remain unresolved in each architecture and
analysis mode. Every positive owned control has a user edge, correct 32- or
64-bit target width, zero-byte net SP delta and retained stack write. The six
negative controls publish no new edge.

Four matched prior/new IDA comparisons use the same binary, probe and IDA
bytes per architecture and mode. The previous full-word plugin misses only
the three newly admitted positive shapes: six failed assertions in each owned
run, and three in each ownerless run. The current plugin has zero probe errors.
All 21 CTest suites pass. On the exact supplied `samples/foo_x86_vmp`
initializer, the current plugin reports 75 nodes, 77 edges and three
unresolved flag/branch facts; the before/after IDB inventory is identical.
This selected protected root contains no measured gain from the new byte map.

Exact source, fixture, tool, plugin and raw-report SHA-256 values are in
`VMP_PARTIAL_WRITABLE_MEMORY_EVIDENCE.json`. The fixture harnesses can be
repeated with new output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/partial-memory-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/partial-memory-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| P1 | Normal-completion flat x86 addressing and little-endian 32-/64-bit near transfers define the modeled domain. All target values depend on this. | Execute both widths; compare assembled pointers with native target results. Segment overrides, 16-bit addresses and exceptions remain unproved. |
| P2 | A byte becomes known only through a represented local store on every admitted path. Exact target claims depend on complete byte coverage. | Two partial stores prove a target; one low-byte store with an initialized remainder remains unresolved. |
| P3 | Exact addressed writes replace only overlapping bytes; unknown-address writes can alias every retained byte. Preserved/invalidated target claims depend on this. | Known byte overwrite and repair prove; the earlier unknown-alias and overlapping-unknown controls remain unresolved. |
| P4 | A bytewise must-join discards conflicting values and keeps equal predecessor values. Path-sensitive claims depend on the admitted graph. | Distinct low bytes at a branch remain unresolved; the prior equal-full-word branch case remains proved. External entries and incomplete graphs abstain under the existing bounds. |
| P5 | The four prior/new comparisons change only plugin bytes. Feature attribution depends on this. | Require equal binary, probe and IDA SHA-256 per pair; prior misses exactly three positive shapes, while new runs pass. |
| P6 | The selected supplied initializer is a bounded static control, not a binary-wide benchmark. The unchanged result depends on its exact hash and selected root. | Compare the exact sample and probe hashes, 75-node/77-edge inventory, three records and before/after IDB digest. Runtime-unpacked paths remain unmeasured. |

For N admitted nodes, E edges, S retained stack words, B retained writable
bytes and K rounds, analysis is bounded by
O(K(N + E)(16 + S + B log B)) time and O(N(16 + S + B) + E) space,
excluding IDA queries. The owned graph caps N at 64; the explicit-root
ownerless graph caps N at 128. Both cap K at 128, S at 64, B at 128 and
incoming references at 256 per node. Pointer widths are bits, offsets and
stack deltas are bytes, and 8 bits = 1 byte exactly.

- **High impact:** bytewise assembly proves three locally defined targets that
  the previous plugin left unresolved.
- **Medium impact:** incomplete bytes, unknown aliases and conflicting path
  bytes still prevent target publication.
- **Low impact:** the selected protected initializer has no measured change;
  heap identity and runtime mutation require separate evidence.

QG1: no normative premise. QG2: P1–P6 include falsification probes. QG3:
partial stores, known overwrite/repair, incomplete and conflicting bytes,
owned publication, ownerless inspection, both widths and prior/new attribution
cover this bounded change; the full review remains open. QG4: widths, counts,
units and complexity are explicit. QG5: initial data, aliases, joins and graph
frontiers retain uncertainty when unproved. QG6: Intel's primary instruction
reference and hash-matched local oracles support the claims. QG7: the protected
scope and unmodeled dynamic memory are bounded explicitly.
