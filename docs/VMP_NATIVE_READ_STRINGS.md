# Strings assembled from observed native reads

Chernobog now recovers bounded UTF-8 strings from successive native scalar reads,
including byte-at-a-time loops over buffers later erased and released. The
derived result retains every original read witness. Exact pointer/index
expressions receive transient pseudocode annotations, and the evidence workspace
has a separate **Read streams** table linked to run and sequence intervals.

This advances review requirements 3a, 3b and 5. The native fixture is independently
written x64 Mach-O code, not protector output. Protected-corpus coverage,
indirect-call annotations, noncontiguous/interleaved read algorithms and broader
architecture validation remain incomplete. The complete review goal stays open.

## Derivation contract

`hybrid_consensus_native_read_strings` in `src/hybrid/native_read_strings.cpp`
derives streams from immutable `UseSnapshot`, `DataAcc`, `ExecEdge` and
`AllocationLifetime` records. It does not reread backend memory, change the
execution trace, or insert a synthetic aggregate into the raw memory ledger.

Every scheduled run must have completed temporal capture and available,
unfiltered, untruncated memory observations. Duplicate run identities, use
sequences, data sequences or allocation IDs reject derived consensus. Unknown
run identities and oversized projection inputs also reject it; a per-stream
byte limit interrupts the affected stream. The existing
model-free `data_trace_complete` contract remains unchanged: malloc/free and
other environment summaries still prevent model-free proof eligibility.
Temporal streams can use the separate completed-model contract, with calls and
lifetime changes acting as barriers.

Each constituent read must:

- belong to the evidence's selected-function context;
- be an exact directly executed read with no modeled argument/callee identity;
- contain 1–8 complete little-endian hook bytes;
- match the next sequence's data record in source, address, width, scope and
  value; the driver records a use immediately before its corresponding data
  event;
- satisfy its own live allocation witness, or retain image-address/relative
  frame identity as appropriate.

Streams grow only through consecutive increasing addresses. Between adjacent
members there may be control-only loop instructions, but no other memory
access, call/unknown transfer, modeled use, allocation or release event.
Heap reads must retain the same allocation ID and generation. Stack offsets
must advance consistently within the selected frame. Image adjacency describes
observed addresses, not a recovered lexical object. Any failed check interrupts
the stream. A NUL in a member closes it; at least two read records are required
for an aggregate. Single-read literals retain their existing projection.

Across runs, correspondence includes the first use's semantic key and the full
ordered sequence of source-instruction addresses and read widths. Physical heap
addresses and generations remain run-local witnesses. Agreement requires the
same admissible NUL-terminated UTF-8 prefix in every scheduled run. Minimum
length counts Unicode scalars; maximum length counts payload bytes. No Unicode
normalization occurs. Bytes after a terminator are not part of the literal.

The candidate's producer is `executed-read-stream`. `read_fragments` contains one
ordered vector of original snapshots per agreeing run. Its synthesized `use`
summarizes the interval; it is not represented as a single architectural load.
The IDC use-string result now exposes `first_sequence`, `last_sequence`,
`read_count` and `observed_bytes`, in addition to existing lifetime and consensus
metadata. Sequences delimit use events; the last matching data event is at
`last_sequence + 1`.

## Display and bounds

Pseudocode annotations require current evidence and an exact ctree source EA.
Native reads match pointer or indexed-memory expressions. If Hex-Rays eliminated
that expression, no nearby line is substituted. Annotations describe an observed
read or read stream; they do not replace the expression, change the AST, save a
comment, or assign a universal literal to an address. Existing direct modeled-call
annotations keep their target and argument checks. Display is capped at 64 lines,
two descriptions per line, and 128 payload bytes per description, ending on a
UTF-8 scalar boundary.

| Resource | Limit |
|---|---:|
| Original use records indexed per run | 4,096 |
| Original allocation records indexed per run | 4,096 |
| Data records indexed per run | 65,536 |
| Derived stream bytes | 4,096 including observed terminator/tail |
| Retained aggregate payload allowance per run | 1,048,576 bytes |
| Dedicated stream-table witnesses | 128 |
| Fragment references shown per table witness | 16 |
| Byte preview per table witness | 64 bytes |
| General event timeline | Existing 1,024 records |

The raw-use and scalar-width caps also bound the available bytes to
`4096 * 8 = 32768` bytes per run. Aggregates consume disjoint read sequences;
copied witness metadata is additional storage. Limits apply per run except the
session-view table limits. Total capture storage scales with the number of runs.

For R runs, U uses, D data events, A allocations and E edges per run, indexing
and ordering cost `O(R * (U log U + D log D + A log A + E log B))`, where B is
the bounded barrier-set size. Matching adds `O(R * U * (log D + log A + log B))`.
For C derived candidates and at most K fragments per candidate, cross-run
grouping adds at most `O(R C K log(R C))` comparisons plus payload decoding.
Storage is linear in indexed records, retained payloads and fragment witnesses,
before view quotas. These bounds exclude backend execution and decompilation.

A production test demonstrated why the stream table needs a separate allowance:
the general timeline omitted 240 events, including the second use's completed
stream records. The dedicated table retains all eight witnesses (two uses in
four runs). Selecting one filters the retained timeline by run/seed and its
sequence interval. It does not reconstruct omitted generic events. Fragment
and table omissions remain explicit. The detail pane leads with observed UTF-8
bytes, read count, source, interval and assumptions. Freshness still gates source
navigation; historical evidence remains inspectable.

## Validation and primary evidence

`tests/vmp_native/native_read_strings.S` independently allocates, decrypts,
reads, erases and releases two buffers. Each native loop packs its consumed
bytes into registers. The native caller re-encrypts both packed values and
compares all 64 bits against their original ciphertext constants. The executable
returns zero under the host's x64 translation on arm64. Neither `secret!` nor
`second!` occurs as plaintext in the binary. This is an exact byte comparison,
not a length-only or hash oracle.

Production IDA checks recover those two values from eight scalar reads each,
with four agreeing runs per use. They verify allocation provenance, exact
pseudocode display, repeated rendering, unchanged function bytes and AST,
absence of saved/saveable comments, consumed-key and code invalidation,
prototype/profile freshness, and exact restoration. The companion's interval
filter is exercised in the console probe; the GUI probe additionally creates
the actual Qt table, selects a stream, checks linked events and details, verifies
stale-navigation rejection/restoration, and closes its polling timer. A rendered
workspace artifact is retained for visual inspection.

The accepted console probe passes 24 checks, the actual GUI probe passes 29,
and the unchanged modeled-string probe passes 22: 75 production checks in
total. All 20 CTest suites pass in 15.99 s. That duration includes overlapping
production work and is validation latency, not an isolated performance result.
The native fixture was compiled with Clang 23.0.0git revision
`b51054818b78dc395cd4d33f17cfb6e98a36a76d` and macOS SDK 27.0. The accepted
artifact roots use the prefix `build/vmp-native-read-strings-release-` with
`console`, `gui` and `modeled` suffixes. The GUI image
`build/vmp-native-read-strings-release-gui/native_read_streams.png` was inspected:
both uses and all eight witnesses are visible, and the selected stream's
plaintext, source, interval and assumptions lead the detail pane.

Portable regressions validate cross-address heap correspondence, separate reuse
generations, image/frame identities, UTF-8 scalars split across 1/2/4-byte reads,
scalar-count versus byte-count limits, reordered storage with preserved event
order, and local versus corpus-wide rejection. Corrupted bytes, mismatched
memory records, foreign context, invalid lifetimes, changed source shapes,
missing termination, interposed reads/writes/calls, and duplicate records reject
the affected scope. A 4,096-read stream is retained; a 4,097-use input rejects.
The dedicated table retains 128 of 130 witnesses and reports two omissions.
It also retains a long stream after the generic timeline truncates, reporting
4,080 omitted fragment references out of 4,096.

The initial production failure came from requiring model-free data completeness
for a fixture that intentionally uses allocation/release models. The correction
uses the existing temporal-model contract plus lossless recorded memory order;
it does not change model-free proof admission. The later timeline failure is
retained separately from accepted evidence. Neither failure is counted as a
passing run.

Source, native-oracle, runtime, console, GUI, modeled-regression and test hashes
are recorded in `VMP_NATIVE_READ_STRINGS_EVIDENCE.json`. The motivating local VMP
source is `runtime/string_manager.cc`, whose allocate/decrypt/use/erase/release
behavior was verified in `VMP_TEMPORAL_STRINGS.md`. This fixture's constant-XOR
transform does not establish coverage of VMP's rotating-key transform.

## Assumptions and bounded findings

| ID | Assumption / dependent result | Falsification probe and status |
|---|---|---|
| S1 | Hook bytes and total event order describe the original reads. All derived strings depend on this. | Exact data-event joins, earlier RMW controls, byte/sequence corruption and the independent native byte oracle. Retained for the tested x64 capture. |
| S2 | Completed environment summaries and allocation witnesses define each run. | Invalid lifetime, release barrier, missing/filtered data and modeled-call regression tests. Retained model contract, not native allocator equivalence. |
| S3 | The first semantic use and complete read-site/width sequence identify cross-run correspondence. | Vary heap addresses/generations; change a site, occurrence or context; require rejection. Retained as a bounded observation relation. |
| S4 | Byte/function/profile freshness permits an annotation at its exact ctree EA. | Key/code/profile edits, rendering and Qt navigation invalidation/restoration. Retained under the existing freshness lease. |
| S5 | A passing native fixture predicts protected-corpus recovery. | Not assumed. Actual protected string fixtures and wider execution paths remain required. |

**High:** Concatenating read bytes across a write or lifetime boundary could
invent a value that never existed at one stable use. This implementation treats
every intervening memory access conservatively; interleaved algorithms abstain.
**Medium:** General timeline truncation can hide a complete derived result;
the separate table preserves bounded access to its witnesses. **Medium:** A
finished modeled execution and model-free proof eligibility are distinct
contracts. These observations remain explicitly dependent on the temporal model.

Quality gates apply to this integrated capture-to-display checkpoint. They do
not establish completion of the full review or universal string recovery.
