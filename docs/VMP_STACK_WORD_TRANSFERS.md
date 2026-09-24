# Exact stack-word source for native PUSH/RET transfers

Review rows 1a and 1b require exact targets for stack-mediated transfers while
retaining their native stack effects. A `PUSH [SP]; RET` pair can read a word
established by a preceding local `PUSH`. The x86 adapter now admits that target
only when a bounded must-analysis proves the complete word at the current
stack top. The portable classifier gives it a distinct `stack_definition`
proof kind, bound to a full-width, no-displacement, no-index stack read.
Unlike an immutable-image target, the proof depends on prior instruction bytes
and on the absence of an intervening modeled write. The original memory read,
new stack write and RET remain in place. Intel specifies that a memory PUSH
computes an ESP-based source address before decrementing ESP
([Intel instruction reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)).

The adapter uses the existing x86-64/i386 dataflow state, which retains at
most 64 stack words as bit-precise known/value masks. An owned-function graph
or contiguous single-entry prefix supplies the word and code dependencies.
The explicit-root ownerless inspector uses the same transfer and reports its
proof without publishing an IDB edge. An unknown initial word, explicit
intervening memory write, conflicting branch definitions, unsupported width,
segment override or non-stack addressing cannot supply a `stack_definition`
proof.
Normal completion and no asynchronous external stack mutation are explicit
limits; this is not general writable-memory target recovery.

## Paired validation

The source-emitted fixture has three executed functions per architecture:

| Shape | Executed result | Owned IDA | Ownerless IDA |
|---|---:|---|---|
| Prior `PUSH` establishes target; `PUSH [SP]; RET` | 7 | Exact `stack-definition` edge | Proved target |
| An explicit store overwrites the prior stack word | 8 | Unresolved candidate | Unresolved candidate |
| Two branches push distinct target words | 7 for input 0, 8 otherwise | Unresolved candidate | Unresolved candidate |

Each executed function is checked for 256 inputs. The complete owned native
oracle passes 5,374 checks per architecture; the complete ownerless harness
passes its 4,094 existing native checks and rejects a deliberately corrupted
expected result. The new three functions are executed by the owned harness,
and the ownerless harness inspects their separately linked assembly prefixes.
The built plugin passes 74 owned and 432 ownerless IDA assertions per
architecture. The previously installed plugin is tested against the **same
binary and probe per architecture**: it does not publish the new exact edge,
and its ownerless report leaves the target unresolved. Its candidate provenance
also lacks the stack-source distinction. The enabled result retains the
native stack-write width and zero net SP delta for the final pair.

The owned probe changes the establishing register `PUSH` byte to `NOP` in an
isolated IDA database. The exact proof and user edge disappear. Restoring the
byte recomputes the proof with a new publication identity. The ownerless probe
checks a read-only IDB inventory around each inspection. All 21 CTest suites
pass. On the exact supplied `samples/foo_x86_vmp` initializer, the built
plugin still completes 75 nodes and 77 edges, retaining two unresolved SETcc
values and one unresolved branch condition, with unchanged IDB inventory.
That protected root establishes no recovery gain for this transfer.

Exact source, binary, plugin, IDA, report and CTest hashes are recorded in
`VMP_STACK_WORD_TRANSFERS_EVIDENCE.json`. Reproduce the two fixture harnesses
with new output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/stack-word-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/stack-word-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| W1 | In normal 32-bit/64-bit execution, `PUSH [SP]` reads the pre-decrement stack top. The recovered target depends on this ordering. | Check Intel's instruction contract and the two independently executed architectures; a different order would miss or fault in the positive fixture. 16-bit and exceptional behavior are excluded. |
| W2 | A tracked stack suffix represents words established on every admitted path, without an asynchronous external writer. Exact local proofs depend on this. | An explicit overwrite must revoke the value; two different branch words must remain unknown; removal/restoration of the establishing instruction must revoke/recompute the owned edge. Thread, signal and device mutation are not modeled. |
| W3 | The classifier and adapters identify only a full-width `[SP]` operand without displacement, index or segment override. Proof-kind soundness depends on this. | Portable wrong-shape/missing-dependency checks reject; both production architectures prove the exact fixture, while overwrite and conflicting-branch controls remain candidates. |
| W4 | Prior/new probes are paired on the same fixture and analysis conditions. Red/green attribution depends on identity. | Compare input, probe and IDA hashes per pair; assert only the plugin hash differs. Re-run both architectures and both ownership modes. |
| W5 | The supplied VMP initializer is the same hash-matched 75-node root. Its negative-effect conclusion applies only there. | Compare exact input hash, nodes, edges, records and before/after inventory. Other roots and runtime-unpacked paths remain unmeasured. |

The classifier's new validation is O(1) time and space. For N graph nodes, E
edges, S retained stack words and K rounds, the existing owned dataflow costs
O(K(N + E)(16 + S)) time and O(N(16 + S) + E) space, with N ≤ 64, K ≤ 128 and
S ≤ 64. Ownerless inspection caps N and K at 128 and incoming references at
256 per node. The added stack-word read itself is O(1). Stack deltas and
offsets are in bytes; widths are in bits, with 8 bits/byte and no rounding.

- **High impact:** an exact mutable stack source can now produce a native
  transfer edge without replacing the memory access or RET.
- **Medium impact:** explicit writes and conflicting paths remain candidates,
  limiting false target publication under the modeled local state.
- **Low impact:** the supplied protected initializer has no measured gain from
  this source shape; broader writable-memory and asynchronous cases remain.

QG1: no normative premise. QG2: W1–W5 include falsification probes. QG3:
portable classifier, owned publication, ownerless inspection, two widths,
native execution, negative controls and proof invalidation cover this shape;
the full review remains open. QG4: widths, bytes, counts and complexity are
explicit. QG5: source alias, overwrite, disagreement, lifecycle and protected
limits retain uncertainty. QG6: Intel's primary instruction reference and
hash-matched local oracles support the claims. QG7: general writable memory
and external mutation remain explicit boundaries.
