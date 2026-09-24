# Local writable-memory MOV loads

Review row 1b requires a register-sourced transfer target to have an exact
reaching value. The bounded x86-64/i386 must-analysis now reads the bytes of a
scalar `MOV register, memory` from its local writable-memory map when the
pre-instruction address is exact, mapped, readable and writable, the operand
widths agree, and every source byte was established by a preceding local
store. It writes the resulting value through the existing 8-/16-/32-/64-bit
register-slice rules. A 32-bit register destination in long mode therefore
uses the existing architectural upper-half zeroing. The tracked `[SP]` word
retains its separate stack rule, and a destination in the SP register is
excluded. The source map and flags are unchanged by the load. This is the
normal-completion scalar behavior specified by Intel's
[MOV instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

The new read also completes an existing byte read-then-write case: after a
known pointer store, `MOV byte register, [slot]` and `MOV [slot], byte register`
retain that byte, so the later `PUSH [slot]; RET` has an exact target. Earlier
evidence correctly recorded this case as unresolved under the earlier model;
its historical result is unchanged. Initial writable image bytes, incomplete
source words, unknown addresses and possibly aliased writes remain unknown.
Segment overrides, 16-bit addressing, faults, concurrent writes and device
memory are outside this local proof. No replacement bytes or instruction
semantics are published in the IDB; only the subsequent owned transfer can
receive an exact edge.

## Executed and production controls

The source-emitted fixture executes four new functions for 256 inputs on each
architecture. Its independent process result is 7 for every call. The static
expectations distinguish known local bytes from runtime-only values:

| Shape | Owned IDA | Ownerless IDA |
|---|---|---|
| Full local pointer store, full-width register load, `PUSH register; RET` | Exact register-definition edge | Proved target |
| Full store, changed low register byte, byte load restoring it, `PUSH register; RET` | Exact register-definition edge | Proved target |
| Full store, byte load then same-byte store, `PUSH memory; RET` | Exact memory-definition edge | Proved target |
| Initial writable pointer loaded into a register | Candidate without edge | Unresolved |
| Local pointer store, unknown-alias write, register load | Candidate without edge | Unresolved |

The complete owned harness passes **11,262 native checks and 162 IDA
assertions per architecture**. The ownerless harness passes its **4,094
existing native checks and 662 read-only IDA assertions per architecture**;
its native oracle does not execute the new functions. Its deliberately
corrupted oracle is rejected. Four matched previous/current IDA pairs use the
same fixture, probe and IDA bytes; only plugin bytes differ. The previous
plugin misses the three newly proved targets with six failed owned assertions
and three failed ownerless assertions per architecture. The current plugin has
zero probe errors. All 21 CTest suites pass.

On the exact supplied `samples/foo_x86_vmp` initializer, the current built
plugin still reports 75 nodes, 77 edges and three unresolved flag/branch
facts. Before and after IDB inventories are identical. No gain is measured at
that selected static root. Exact source, fixture, tool, plugin and raw-report
hashes are in `VMP_WRITABLE_LOADS_EVIDENCE.json`. Reproduce the harnesses with
fresh output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-loads-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-loads-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| L1 | Decoded scalar `MOV register, memory` transfers the source-width bytes to a matching register slice under normal completion. Both register targets depend on this. | Execute full-width and byte-load targets on x86-64 and i386, including an intervening change to the low register byte. Reject mismatched widths and unsupported destinations. |
| L2 | Only locally written bytes at an exact mapped writable address enter the load value. All three new exact targets depend on this. | Require a store before each positive load and an unresolved target when the same native pointer comes only from initial writable image bytes. |
| L3 | An unproved memory write may alias the retained slot. The alias rejection depends on clearing those facts. | Write to an entry-supplied disjoint pointer after the local store; native execution reaches 7, while static inspection must keep the register target unresolved. |
| L4 | The prior/current pairs differ only in plugin bytes. Feature attribution depends on this. | Compare input, probe and IDA SHA-256 for all four pairs and require the three target failures on the prior plugin and zero errors on the new plugin. |
| L5 | The protected initializer is one selected static region, not a full protected-program benchmark. Its unchanged result depends on the exact root and input. | Rehash the sample; require 75 nodes, 77 edges, three unresolved records and identical before/after IDB inventories. Runtime-entered code remains unmeasured. |

For W loaded bytes, W ∈ {1, 2, 4, 8}, and B ≤ 128 retained writable bytes,
map lookup costs O(W log(B + 1)) time and O(1) additional space, excluding IDA
queries and copied graph states. The existing graph bound remains
O(K(N + E)(16 + S + B log B)) time and O(N(16 + S + B) + E) space, with at most
N = 64 owned or 128 ownerless nodes, K = 128 rounds, S = 64 stack words, and
256 incoming references per node. Widths are bits, addresses and stack offsets
are bytes, and 8 bits = 1 byte.

- **High impact:** locally written pointer bytes can reach a register and then
  an exact native transfer.
- **Medium impact:** a known byte read and same-byte write now preserves a
  memory-source target; initial and possibly aliased bytes remain unresolved.
- **Low impact:** the selected supplied protected initializer shows no measured
  change, and dynamic heap identity remains open.

QG1: no normative premise. QG2: L1–L5 include falsification probes. QG3:
full/partial loads, value propagation, negative controls, owned publication,
ownerless inspection and matched attribution cover this local operation; the
full review remains open. QG4: units, counts and complexity are explicit.
QG5: known local bytes, initial bytes and possibly aliased bytes remain
distinct. QG6: Intel's primary instruction reference and hash-matched local
oracles support the claims. QG7: the static-root and execution-model limits
are explicit.
