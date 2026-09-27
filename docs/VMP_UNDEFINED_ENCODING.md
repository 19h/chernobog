# Encoding boundary for undefined-result certificates

This checkpoint hardens the closed dependence slices introduced in commit
`3e65b2bd8c2dfd20bd23d96c2c7a7e3fb37126df`. Review rows 3a, 3b, 6a and V remain
in progress. The historical captures, proofs and source hashes in
`VMP_UNDEFINED_RESULTS_CAPTURE.json.gz` are unchanged.

## Admission contract

The instruction-effect inventory consumes at most two SDK operands and models
scalar legacy encodings. Previously, its prefix filter did not explicitly
exclude every newer encoding family, and operands after Op2 were not counted.
An unrepresented form could therefore inherit the represented mnemonic's
destination or flag effects. The new gate counts all non-void SDK operands,
including gaps, before effect construction. Three or more operands reject.

The portable gate accepts only 32-bit or 64-bit mode and 1 through 15 encoded
bytes. It skips operand-size overrides and, in 64-bit mode, REX prefixes;
prefix-only input rejects. Leading bytes 62, C4, C5 and D5 reject, as do address,
LOCK, REP and segment prefixes. An 8F encoding requires a following byte whose
low five bits are less than eight, distinguishing the represented POP form from
unrepresented map selectors. The existing instruction and effect whitelist
still applies after this gate. Passing this gate alone does not certify an
instruction or an undefined-result slice.

These byte predicates are conservative implementation boundaries. Some rejected
forms may be valid instructions; their dependence semantics are unrepresented.
The architectural observation contract remains the one documented in
`VMP_UNDEFINED_RESULTS.md` and its cited
[Intel instruction reference](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf).

## Verification and replay

The hybrid suite passes with 23 encoding cases: three retained legacy forms and
20 rejected cases, including an extra operand, unsupported prefixes, an 8F map
selector, empty and prefix-only input, oversized input and unsupported mode.
Its existing undefined-result, partial-write, interruption and quota controls
also pass. The added tests introduce no compiler warning; the existing shadow
warning at the earlier VM-lifting test remains.

`tests/verify_native_undefined_encoding.py` checks the historical archive's
compressed and canonical SHA-256 values, verifies every capture against its
recorded hash, decodes each certificate step with Capstone 5.0.7, and submits
its bytes and decoded operand count to the compiled production gate. All 232
instruction occurrences across 26 distinct certificates remain admitted. This
checks encoding coverage; the archived independent symbolic dependence proofs
retain their original scope and source versions. Capstone operand counts are
an independent inventory; the production decoder separately counts SDK operands.

Fresh SDK-linked trace and string probes for mutation seed 1 pass. All four
entry seeds complete in 344 instructions, including one explicit abstract
step each. The trace capture is byte-identical to the historical mutation-1
capture. Completed string inspection retains both `secret!` and `second!` with
four witnesses each. No new recovery-coverage metric is inferred from this
two-probe checkpoint.

Replay from the checkout on macOS:

```sh
uv run --no-project --with capstone==5.0.7 python tests/verify_native_undefined_encoding.py --archive docs/VMP_UNDEFINED_RESULTS_CAPTURE.json.gz --output build/undefined-encoding-replay.json
```

`VMP_UNDEFINED_ENCODING_EVIDENCE.json` records the new source pins, replay and
SDK receipts. `VMP_UNDEFINED_ENCODING_CAPTURE.json.gz` retains their exact text
artifacts and source snapshots in a canonical JSON container with gzip mtime 0.
Each `files` entry contains its SHA-256 and UTF-8 text. Compiled plugin binaries
are identified by hash and are not included in this container.

## Assumption register and bounds

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| E1 | The existing effects apply only to the represented legacy forms and at most two SDK operands. Certificate admission depends on this. | Reject additional operands and every excluded prefix family before constructing effects; retained legacy and 8F controls pass. |
| E2 | Archived bytes and Capstone's operand inventory describe the historical certificate occurrences. Replay coverage depends on this. | Compressed/canonical archive hashes, per-capture hashes, exact single-instruction decoding and 232 compiled gate decisions. |
| E3 | The SDK-linked plugin and pinned input describe the fresh mutation-1 observations. Concrete results depend on this. | Isolated runner receipts pin plugin, input, IDA and probe sources; four return-register oracles, allocation/release and string checks pass. |
| E4 | The normal flat execution contract and historical dependence proof inventory remain applicable. Continuation claims depend on this. | Existing undefined-result and interruption controls pass; unsupported forms retain their boundary. Other environment equivalence remains unknown. |

For B <= 15 encoded bytes and the fixed SDK operand-array length O, admission
cost is O(B + O) time and O(1) extra space. Replay retains S = 232 cases and
performs O(S) decoding and gate calls, excluding archive decompression and
compilation. No solver is added to production admission.

Bounded scope: **high impact** prevents unrepresented destination or flag
effects from closing a dependence certificate; **medium impact** preserves
all historical certificate encodings; **high remaining impact** interpreter
environment effects and full virtualization recovery remain open. This gate
provides no additional instruction-effect inventory or VM recovery.

Quality gates: QG1 requires no normative content; QG2 records E1-E4 and probes;
QG3 covers the encoding boundary while retaining the full review scope; QG4
records counts, bit widths, byte bounds and complexity; QG5 retains unsupported
forms and conservative rejection; QG6 pins source and capture provenance;
QG7 records impacts and remaining work. This checkpoint does not complete the
review.
