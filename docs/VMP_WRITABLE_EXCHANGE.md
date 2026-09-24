# Local register/memory XCHG target facts

Review row 1b requires a memory-source target only after its address and value
are established at the transfer. The bounded x86-64/i386 must-analysis now
models a register/memory `XCHG` at an exact mapped readable/writable address.
It reads the old memory bytes and register slice from the **pre-exchange**
state, invalidates the addressed bytes, writes the old memory value to the
register, and writes the old register value to memory. Byte widths of 8, 16,
32 and 64 bits use the existing partial-register and byte-map rules. Other
retained bytes survive an exact, disjoint exchange. This follows Intel's
[XCHG instruction reference](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf)
under the stated normal-completion, single-threaded memory model.

An exchange with an unknown source register removes the addressed memory
bytes; an unknown address leaves the exchange unproved and conservatively
invalidates retained writable facts. A missing old memory byte leaves the
register result unknown. Initial writable image bytes remain unknown. Stack
top exchanges continue through their separate tracked-stack model. Segment
overrides, 16-bit addresses, faults, concurrent writes and device memory are
outside this local proof. The analyzer publishes no replacement bytes or
changed instruction semantics in the IDB; it can publish an exact owned edge
only at the subsequent proved transfer.

## Executed and production controls

The source-emitted fixture executes each shape for 256 inputs on x86-64 and
i386. Its five new functions extend the preceding writable-memory controls:

| Shape | Native result | Owned IDA | Ownerless IDA |
|---|---:|---|---|
| Full-width exchange stores a known register pointer into an initially unknown slot, then `PUSH memory; RET` | 7 | Exact memory-definition edge | Proved target |
| Prior full pointer, then a 16-bit i386 or 32-bit x86-64 exchange of its low part | 7 | Exact memory-definition edge | Proved target |
| Prior full pointer, then an 8-bit exchange of its low byte | 7 | Exact memory-definition edge | Proved target |
| Exchange loads a locally written pointer into a register, then `PUSH register; RET` | 7 | Exact register-definition edge | Proved target |
| Unknown entry-supplied pointer replaces a locally written slot through exchange | 7 for the supplied input | Candidate; no new edge | Unresolved |

The complete owned harness passes **10,238 native checks and 150 IDA
assertions per architecture**. The ownerless harness passes its **4,094
existing native checks and 622 read-only IDA assertions per architecture**;
its native oracle does not execute the new exchange functions. Its deliberately
corrupted oracle is rejected. The negative control supplies a concrete target
pointer at runtime, but the static state correctly retains uncertainty about
the entry value.

Four matched previous/current IDA comparisons use the same binary, probe and
IDA bytes per architecture and ownership mode. Only plugin bytes differ. The
previous plugin misses the four new exact targets: eight failed owned
assertions and four failed ownerless assertions per architecture. The current
plugin has zero probe errors. All 21 CTest suites pass. On the exact supplied
`samples/foo_x86_vmp` initializer, the built plugin still reports 75 nodes,
77 edges and three unresolved flag/branch facts, with unchanged before/after
IDB inventory. No gain is measured at that selected root.

Exact source, fixture, tool, plugin and raw-report hashes are in
`VMP_WRITABLE_EXCHANGE_EVIDENCE.json`. Rerun the two harnesses with fresh output
directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-exchange-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/writable-exchange-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| X1 | A decoded scalar register/memory XCHG swaps equal-width operands at its pre-instruction address under normal completion. The new target facts depend on this. | Execute both modes, full and partial widths; verify the store and old-memory-to-register target paths against independent process results. Width mismatch, unsupported address modes and segment overrides abstain. |
| X2 | Only locally represented bytes at an exact mapped writable address can be used as old memory facts. Register-load proof depends on this. | Store the pointer before exchange and require the loaded register target. The initially unknown slot is used only to prove its subsequent write, never its old value. |
| X3 | A known register source replaces only addressed bytes; an unknown source cannot retain their previous values. Memory-target proof depends on this. | Require full, low-part and one-byte positive cases; require the entry-supplied source to leave `PUSH memory; RET` unresolved. Earlier unknown-alias and stack-alias controls continue to abstain. |
| X4 | Prior/current results differ only by plugin under fixed fixture, probe and IDA bytes. Feature attribution depends on this. | Compare all three SHA-256 fields in four pairs; require exactly the four newly admitted targets to fail on the prior plugin and all current assertions to pass. |
| X5 | The supplied initializer is a selected static root, not a full protected-program benchmark. Its unchanged result depends on exact input and traversal. | Recheck the sample hash, 75 nodes, 77 edges, three records and before/after IDB digest. Runtime-entered code remains unmeasured by this control. |

For W exchange bytes, W ∈ {1, 2, 4, 8}, and B ≤ 128 retained writable bytes,
the local map read, invalidation and write cost O(W log(B + 1)) time and O(1)
additional space, excluding copied states and IDA queries. The existing graph
bound remains O(K(N + E)(16 + S + B log B)) time and
O(N(16 + S + B) + E) space, with at most N = 64 owned or 128 ownerless nodes,
K = 128 rounds, S = 64 stack words and 256 incoming references per node.
Widths are bits, addresses and stack offsets are bytes, and 8 bits = 1 byte.

- **High impact:** a local exchange can now supply both memory and register
  targets for native `PUSH; RET` recovery.
- **Medium impact:** unknown sources, addresses and initial bytes remain
  unresolved under the same alias policy.
- **Low impact:** the selected protected initializer shows no measured change;
  other operations and runtime memory identity remain open.

QG1: no normative premise. QG2: X1–X5 include falsification probes. QG3:
pre-exchange operands, all scalar widths, target effects, negative controls,
owned publication, ownerless inspection and matched attribution cover this
local operation; the full review remains open. QG4: units, counts and
complexity are explicit. QG5: old and new values, partial bytes and unknown
aliases remain distinct. QG6: Intel's primary instruction reference and
hash-matched local oracles support the claims. QG7: protected-root scope and
concurrency/exception limits are explicit.
