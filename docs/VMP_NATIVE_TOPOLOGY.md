# Native proof revocation after topology changes

An external fallthrough into an owned function tail can invalidate a flag or
register fact without changing any instruction bytes. Native proof publication
now revokes the affected owned comments and edges when that entry is added.
Revalidation also recomputes the current recognizer and verifies coverage of its
supporting instructions and immutable data. Inspection and publication use the
same conclusion check.

The previous plugin reproduced the defect in IDA: an adjacent instruction
outside the function acquired an ordinary `fl_F` edge into a discontiguous tail.
The inspector rejected the old SETB and JB conclusions, but their publications,
owned comments and branch edge survived immediately and after autoanalysis.
Removing the function tail also left owned metadata behind. The baseline fails
10 of the new probe's 53 assertions; all original 25 assertions pass.

## Publication contract

New contiguous flow is exempt from invalidation only for a condition or stack
transfer proof whose code dependencies already contain both endpoints, and only
when the source has an ordinary adjacent architectural successor. Calls,
returns and unconditional or indirect jumps do not use that exemption. This
retains ordinary processor emulation of successors already represented by the
bounded graph or checked prefix. The external predecessor in the regression is
absent from the proof and cannot use the exemption.

Save and autoanalysis revalidation rerun the existing recognizers, in addition
to checking bytes, ownership, mode and permissions. A conclusion with newly
introduced supporting instructions or immutable data is rejected even if its
value happens to match. An emulated condition that becomes unknown removes its
previous publication without queuing the same unknown query again.

Function-boundary and deletion notifications revoke proofs before ownership
changes. Function addition/update, tail append/delete and tail-owner changes
trigger revalidation after the update. Both the earlier SDK notification names
and the SDK 9.4 forms are handled at compile time. Conservative pre-change
revocation applies to all retained native proofs; subsequent analysis may
publish independently recomputed conclusions. Persisted receipts continue to
authorize cleanup, not reuse of a saved conclusion.

Only the plugin's recorded comment lines and owned edges are removed. Other
comment lines and externally reasserted user edges retain their existing
ownership rules. This change does not repair unrelated legacy annotations or
establish whole-program reachability.

## Assumptions and falsification probes

| ID | Assumption and dependent result | Probe or limit |
|---|---|---|
| T1 | IDA reports the relevant entry and ownership mutations through the hooked notifications. | Actual plain adjacent `fl_F`, immediate and post-analysis metadata checks, tail removal and reattachment pass in x64 and i386. Other SDK versions and every metadata mutation are not established by those runs. |
| T2 | Existing bounded x86 recognizers remain valid under their stated normal-completion contracts. | All 20 CTest suites and 5,116 independent native process-result checks pass. Instruction semantics and protected region admission are unchanged. |
| T3 | Recorded ownership distinguishes plugin metadata from independent annotations and edges. | Exact owned-line removal, unrelated-line retention, save/reopen, undo, both tested rebase modes and independent-edge controls pass. Legacy metadata without valid receipts remains outside this attribution. |
| T4 | Current support must cover every dependency used to rederive the conclusion. | Code-support inclusion and exact immutable-data dependencies are checked. The adjacent-entry and tail tests retain unchanged fixture bytes throughout. The full topology mutation matrix remains open. |

## Validation and reproduction

| Check | Result |
|---|---|
| Prior plugin, x64 fixture | 53 assertions; 10 expected failures reproducing stale publication/metadata |
| Corrected plugin, x64 | 53 production assertions and 2,558 independent native result checks pass |
| Corrected plugin, i386 | 53 production assertions and 2,558 independent QEMU result checks pass |
| Existing native lifecycle and get-PC probes | 11 + 10 + 53 assertions pass |
| Saved/reopened flag and stack ownership, undo and rebases | 95 assertions across seven processes pass |
| Portable CTest suites | 20/20 pass in 5.99 s |

All ten regression processes retain matching input, script, plugin and IDA
artifacts and report no detected internal-error diagnostic. These are scoped
integration controls, not independent proofs of every notification ordering.
The arm64 host executes x64 through host translation; i386 uses the pinned
Linux/QEMU image documented by the existing dataflow runner.

The baseline, accepted captures, source hashes and runtime hashes are recorded
in [VMP_NATIVE_TOPOLOGY_EVIDENCE.json](VMP_NATIVE_TOPOLOGY_EVIDENCE.json).
Historical evidence manifests remain unchanged. Reproduce with a new directory:

```sh
python3 -B tests/run_native_dataflow.py \
  --ida "$IDA_CONSOLE" --plugin "$CHERNOBOG_PLUGIN" \
  --linux32-image "$PINNED_LINUX32_IMAGE" \
  --output-dir build/native-topology-new
```

## Bounds and quality gates

Publication remains capped at 4,096 native proofs. For P proofs, D stored
dependencies per proof, S rederived code dependencies, B bytes per dependency
(at most 16), and recognizer cost A, full revalidation costs
O(P (DB + A + SD)) time, plus immutable-data coverage comparisons. Code/data
coverage scans retain bounded existing vectors; no execution history is added.
SDK-internal lookup and metadata-mutation costs are not included in that bound.

- **High:** a stale inspector row is insufficient revocation when an owned edge
  or comment still affects downstream analysis. Both are now checked directly.
- **Medium:** conservative pre-change revocation can recompute unaffected
  proofs. The regression processes pass, but large-database latency is unknown.
- **Medium:** function ownership, unsupported regions and legacy metadata remain
  separate limitations of review rows 1b, 2a/2b and 5.

QG1: technical scope. QG2: T1–T4 and explicit probes. QG3: the reproduced
publication defect and ownership regression matrix are covered; the full review
remains incomplete. QG4: architectural widths, counts, byte bounds and elapsed
time are explicit. QG5: unknown outcomes revoke prior publications; independent
metadata is preserved. QG6: primary implementation, SDK declarations and
hash-bound captured evidence. QG7: latency and remaining lifecycle scope stated.
