# i386 PUSHA/POPA writable-memory alias control

The bytewise writable-memory state introduced in
`VMP_PARTIAL_WRITABLE_MEMORY.md` clears retained bytes on i386 `PUSHA` and
`POPA`. Each instruction performs stack memory accesses through ESP; an exact
global slot address does not establish that those writes are disjoint from the
slot without an independently proved stack address. The normal-completion
stack effects follow the [Intel 64 and IA-32 instruction set reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

The new `df_memory_stack_round_trip` fixture writes a target pointer to a
writable global, executes `PUSHA; POPA` on i386 or `PUSH RAX; POP RAX` on
x86-64, then uses a **direct global** `PUSH memory; RET` source. The direct
source keeps the address known after `POPA` clears register facts. The native
process reaches target 7 for each of 256 inputs on both architectures. Static
owned analysis retains an unresolved transfer with no user edge; explicit-root
ownerless analysis returns an unresolved target without modifying the IDB.
The existing x86-64 stack operations already invalidated writable facts; this
control also checks that behavior.

The complete owned harness passes **8,958 native checks and 132 IDA assertions
per architecture**. The ownerless harness passes **4,094 existing native
checks and 572 IDA assertions per architecture**, including a rejected
corrupted oracle; its native oracle does not execute the new function. Four
same-binary/probe/IDA comparisons against the plugin built before the
`PUSHA`/`POPA` invalidation show zero prior errors on x86-64. On i386, the
earlier plugin publishes the unsupported target and user edge (two owned
assertion failures) and reports a proved ownerless target (one failure). The
installed current plugin passes all corresponding assertions. This is a
must-analysis scope correction, not a claim that the earlier target is wrong
for the observed process execution.

The first 20-way CTest invocation had one `vm_push_handlers` failure outside
these files; an isolated rerun passed, as did a complete 21/21 run with four
workers. The cause of the first failure is **unknown**. Exact source, fixture,
plugin, tool and report hashes are in `VMP_STACK_ALIAS_INVALIDATION_EVIDENCE.json`.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| A1 | Stack writes may alias a writable global when ESP is not proved disjoint. Static abstention depends on this conservative alias model. | Store a pointer, execute `PUSHA; POPA`, then read the slot directly. Require native target 7 and an unresolved static target; a proof would require an exact disjoint stack-address witness. |
| A2 | The direct global operand remains identifiable after register facts are cleared. The i386 regression depends on this isolation. | Require the emitted i386 `PUSH` source to carry the slot's absolute address and the matched prior plugin to publish an edge at that same transfer. |
| A3 | Earlier/current IDA comparisons differ in plugin bytes under fixed fixture, probe and IDA bytes. Regression attribution depends on this pair. | Compare all three SHA-256 fields per architecture and mode; require prior i386 proof, current i386 abstention, and unchanged x86-64 outcomes. |
| A4 | The native process path has a stack disjoint from the global slot in the observed runs. Native result 7 depends on this host/runtime state. | Reexecute all 256 inputs under both recorded runtimes; vary or prove stack placement before generalizing beyond these runs. |

The fixture adds one constant-size function call per input, so its native
oracle adds 256 checks and O(256) time with O(1) fixture storage per process.
The abstract byte-map invalidation clears at most B = 128 retained bytes in
O(B) time and O(1) auxiliary space. Existing graph caps remain 64 owned or
128 ownerless nodes, 128 rounds and 256 incoming references per node. ESP
offsets and stack effects are bytes; `PUSHA` writes eight 32-bit stack words
and `POPA` reads eight, discarding the saved ESP word. Each moves ESP by
8 × 4 bytes = 32 bytes in opposite directions.

- **High impact:** the i386 analyzer no longer publishes a target after an
  unproved stack/global alias.
- **Medium impact:** the fixture separates target-address knowledge from
  pointer-value knowledge and retains native behavior as an independent check.
- **Low impact:** the observed 20-way CTest failure has unknown cause and no
  observed effect on the repeated four-worker result.

QG1: no normative premise. QG2: A1–A4 include falsification probes. QG3:
both widths, native oracle, owned edge, ownerless fact and matched earlier
plugin are checked. QG4: counts, bytes and complexity are explicit. QG5:
native observed success is separated from static must-proof; the CTest anomaly
is recorded. QG6: Intel's primary reference and hash-matched local reports
support the claims. QG7: unproved stack placement and broader control-flow
shapes remain outside this bounded control.
