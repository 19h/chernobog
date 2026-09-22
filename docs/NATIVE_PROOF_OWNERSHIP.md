# Native proof ownership and database lifecycle

This implements part of VMP review requirements 1b and 2b. It does not establish
completion of the [full implementation ledger](VMP_IMPLEMENTATION.md).

## Storage and recovery contract

The native engine distinguishes proof conclusions from metadata ownership.
Dependency bytes, permissions, bitness, and function ownership remain in memory
for the current engine session. A bounded receipt records only the source and
annotation site, owned outgoing edges, and the exact owned comment line.
Receipts are stored in the database netnode
`$ chernobog.native_proof_ownership.v1`.

On reopening, the engine removes matching owned artifacts and queues the source
and annotation site for recomputation. A receipt is never accepted as a proof
of the current branch outcome or transfer target. User comments and preexisting
user edges remain outside its ownership. An external user-edge reassertion
observed by the active callback transfers that edge out of plugin ownership.

The codec uses explicit little-endian integers, schema magic `NPR` and version
1, at most eight edges, and at most 512 comment bytes. Embedded NUL, CR, and LF
are rejected in owned comment lines. The maximum encoded record is exactly
`4 + 8 + 8 + 1 + 8 × 10 + 2 + 512 = 615 bytes`. At the 4,096-record limit,
maximum receipt payload is `4,096 × 615 = 2,519,040 bytes`, excluding database
index overhead. Invalid schema, bounds, or ownership metadata disable new
publication and preserve the malformed record for diagnosis. Failed receipt
writes revoke the newly owned artifacts and disable further publication instead
of creating an unbounded retry/reanalysis loop.

Addresses are stored as IDA node identities through `ea2node` and recovered
through `node2ea`. Before an active segment move, live proofs are revoked while
their old addresses still identify their metadata. Reanalysis sources follow
the move notifications. Closing the database retains the saved receipts;
unloading the engine while the database remains open revokes its live records.

Undo/redo can restore both metadata and its receipts. The engine suspends its
mutation callbacks during replay, discards the obsolete in-memory ledger when
replay ends, and defers receipt recovery to an ordinary subsequent analysis or
database interaction. It must not delete references or comments from inside
the `ev_ending_undo` notification: a live test demonstrated that doing so can
produce IDA's `Bad event detected during undo` diagnostic even when the probe
and process report success. The smoke runner now treats this diagnostic and
internal-error diagnostics as failures independently of PASS markers.

Primary implementation references are
[`native_engine.cpp`](../src/ida_analysis/native_engine.cpp),
[`proof_receipt.hpp`](../src/ida_analysis/proof_receipt.hpp), and the supplied
IDA SDK's `include/netnode.hpp`, `include/nalt.hpp`, and `include/idp.hpp`.
The SDK documents netnode persistence, address-to-node mapping, and move/undo
notification timing. Observed undo behavior is an integration-test finding,
not an inferred guarantee about every SDK release.

## Validation contract

The portable core test covers exact round-trip values, integer byte order,
every truncation of a representative receipt, trailing data, unknown schema,
oversized edge counts, invalid user bits, maximum-size records, oversized
comments, and embedded line terminators/NULs.

`ida_native_ownership_smoke.py` uses separate IDA processes for writing a
checkpoint and reading it. It checks ownership recovery, recomputation,
synchronous revocation after support changes, user annotation/edge preservation,
SETcc/CMOV annotation revocation without instruction-byte changes, fast rebasing,
explicit netnode-moving rebasing, reopening both rebased checkpoints, and
undo/redo of predicate support. `ida_stack_ownership_smoke.py` separately checks
saved/reopened immutable-pointer transfer ownership and target replacement.

The original in-session lifecycle and native semantics probes remain necessary
regression controls. A save/reopen test does not substitute for byte/permission
invalidation checks or for architectural instruction-semantics tests.

## Verified checkpoint

Final plugin SHA-256:
`07e78b299efac8730bae95a770456e73717a4cb34cec5109e7af220566b4c658`.
The [evidence manifest](NATIVE_PROOF_OWNERSHIP_EVIDENCE.json) records source,
input, script, plugin, IDA executable, configuration, structured-report, and
redacted-log hashes. All eleven final IDA runs used this exact plugin artifact,
passed their assertions, retained artifact integrity, and had no detected
internal-error diagnostic.

| Final check | Observed result |
|---|---|
| In-session flag ownership | 11 assertions pass, including retention of one user-added copy of an identical comment line |
| In-session stack ownership | 10 assertions pass, including preservation of an independent listener's extra edge created during the plugin callback |
| Reopened Jcc/SETcc/CMOV facts | 16 assertions pass |
| Jcc undo/redo plus reopened value facts | 23 assertions pass; no undo bad-event diagnostic |
| Reopened immutable-pointer transfer | 6 assertions pass |
| Ordinary and explicit-netnode rebases | 21 assertions pass in each process |
| Reopen each rebased checkpoint | 16 assertions pass in each process |
| Native regression fixtures | 33 flag cases and 12 stack cases pass |
| Final CTest suite | 12/12 pass in 8.11 s, including the bounded receipt codec and 12 runner tests |

These are repeated controls across eleven processes, not 185 independent
semantic proofs. No latency or corpus-coverage estimate is inferred from them.

The earlier undo run in `build/vmp-ownership-flags-undo-4` is invalid despite its
PASS marker because its log contains the kernel diagnostic discussed above.
The reviewed build defers recovery and the final undo run has no such diagnostic.
An earlier full CTest run had three Z3 assertion failures; its isolated rerun
retained one failure. The host was then heavily loaded, but the Boolean proof
helper did not expose the failure reason, so timeout attribution remains an
inference. The final full run passed with the original 100 ms / 1,000 ms proof
deadlines unchanged. Both failed logs remain identified in the evidence
manifest; they are not counted as successful verification.

## Reproduction

Reproduction uses the existing smoke runner with local executable and plugin
configuration in `CHERNOBOG_IDAT` and `CHERNOBOG_PLUGIN`:

```sh
python3 tests/run_ida_smoke.py build/vmp-lifecycle-flags tests/ida_native_ownership_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --output-dir build/ownership-write --set CHERNOBOG_TEST_OWNERSHIP_STAGE=write
python3 tests/run_ida_smoke.py build/ownership-write/ownership.i64 tests/ida_native_ownership_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --output-dir build/ownership-read --set CHERNOBOG_TEST_OWNERSHIP_STAGE=read --allow-database
```

Use stages `rebase`, `rebase_nodes`, and `undo` with the saved checkpoint in
separate output directories. The rebase stages save `ownership_rebased.i64`;
open those checkpoints with stages `read_rebased` and `read_moved_nodes`.
For the stack probe, use the stack fixture, the stack script, and its
`stack_ownership.i64` checkpoint. Build the fixture executables from the
assembly sources using the commands in [VMP_NATIVE.md](../tests/VMP_NATIVE.md).
Output directories must be new or empty; the runner retains input, script,
plugin, executable, and configuration hashes with each result.

## Assumption register and remaining scope

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| P1 | The active IDA kernel preserves receipt records with the corresponding database snapshot. Save/reopen and undo ownership depend on this. | Separate-process reload, undo/redo, malformed/truncated codec controls, and final log audit. Power-loss recovery and arbitrary database corruption are not established. |
| P2 | User-edge reassertions occur while the ownership callback is active. Ownership transfer depends on observing the event. | Reassert an owned edge before saving, reopen, invalidate its proof, and require the user edge to survive. Reassertions while the plugin is absent cannot be attributed from identical edge bytes alone. |
| P3 | Address mapping and move callbacks match the tested SDK behavior. Relocation support depends on this. | Test both ordinary and explicit-netnode rebasing, save each result, and reopen it. Moves made while the plugin is absent and all individual segment-move variants remain unverified. |
| P4 | The supported local proof dependencies capture the claim being published. Proof soundness depends on this. | Byte, permission, alternate-entry, pointer-write-reference, and partial-register controls. Cross-block proofs and the complete function-tail lifecycle remain separate work. |

Additional bounded observations:

- **High impact:** a PASS marker and zero process status can coexist with an
  IDA internal diagnostic; validation must inspect both structured assertions
  and process/kernel diagnostics.
- **High impact:** historical metadata without ownership receipts cannot be
  safely claimed as plugin-owned merely from its comment prefix. Migration of
  such databases remains unresolved.
- **Medium impact:** receipts provide a persistent starting point for future
  evidence visualization, but contain no executable proof and cannot authorize
  simplification without recomputation.

For F receipts, E owned edges per receipt, C owned-comment bytes, L bytes in the
complete current annotation, and X existing outgoing references at a site,
cleanup costs O(F·(E·X + L)), excluding IDA's storage and reanalysis costs. Codec
time/space is O(E + C). E, C, and F have the bounds above; X and L are
database-dependent. Whole-corpus latency remains unknown.

Quality gates apply to these explicitly bounded claims. Universal lifecycle
coverage, plugin-absent edits, legacy migration, power-loss recovery, and the
complete VMP objective have not been established.
