# Heap read streams across exact stack writes

Review requirements 3a and 3b require a use-time string to survive unrelated
effects without losing temporal safeguards. A hash accumulator stored on the
stack after every heap byte read previously broke the entire read stream.
The projector now indexes exact 1–8-byte stack-scope writes alongside bounded
heap writes. A heap stream may cross such a write only when its interval is
outside the witnessed allocation. Image and stack strings retain their write
barrier. Unknown, wide, overflowing or scope-mismatched writes remain barriers.

## Scope and algorithm

The execution hook labels a write as `STACK` only when its full address range
lies in the mapped stack range after image and heap classification. A
heap-labeled write wholly inside the allocation is checked against the
completed observed string span; a partial overlap rejects. A stack-labeled
write overlapping the allocation is inconsistent and rejects that object's
stream. Writes outside the candidate's allocation do not establish any byte
value; all string bytes still come from exact matching read events.

```text
index exact writes of width 1..8 bytes with HEAP or STACK scope
keep every other write as a global barrier
for each extension of a heap read stream:
    inspect at most 256 indexed writes since its previous read
    reject overflow, partial allocation overlap or STACK/heap overlap
for each completed stream:
    inspect at most 256 indexed writes from first through last read
    reject any write intersecting its complete observed byte span
require all scheduled runs to agree on semantic use, read shape and bytes
```

For `W` indexed writes, each extension and completed check costs
`O(log W + min(W, 257))` time and `O(1)` additional working space. The map
uses `O(W)` space within the existing 65,536-data-record run limit. The 257th
visit causes abstention. Accesses crossing the heap/stack mapping boundary
have `OTHER` scope and remain a global barrier.

## Controlled observations

The fixture in `tests/vmp_native/native_disjoint_strings.c`, compiled with
`NATIVE_DISJOINT_STACK_HASH=1`, stores its 64-bit hash accumulator on the
stack after every byte read. The x86-64 and arm64 Mach-O binaries each return
0; corrupting the expected hash of the second string makes each return 1.
Disassembly shows the stack store in each read loop. The bounded IDA event
view shows stack writes between every adjacent heap read in its visible
run-zero prefix: eight reads and 14 stack writes on x86-64, four reads and
nine stack writes on arm64. The view truncates later events, so the full
interleaving is established by disassembly and complete temporal capture,
not by claiming the view contains all events.

| Architecture | Complete returned runs | Previous: strings / stream rows / ctree uses | Current: strings / stream rows / ctree uses |
|---|---:|---:|---:|
| x86-64 | 4 | 0 / 0 / 0 | 2 / 8 / 2 |
| arm64 | 6 | 0 / 0 / 0 | 2 / 12 / 2 |

The four matched IDA 9.4 SP1 profiles use byte-identical input and probe
scripts per architecture. Both current candidates have eight exact read
fragments, appear in every scheduled run and display as transient `secret!`
and `second!` annotations. The current profiles pass 10/10 checks, including
visible stack-write interleaving, no final image strings, no saved comments,
unchanged function bytes and consumed-key revocation/restoration. The previous
plugin passes the six unaffected checks and fails the four expected string
and display checks. The no-stack-hash fixture still passes 9/9 checks;
the permuted-read and same-object-write probes each pass 9/9. Portable
controls cover heap, image and stack strings, stack/heap scope mismatch,
wide and overflowing stack writes, and all earlier read/write cases: 470
interleaved checks. All 21 CTest suites pass at `-j 4`. A prior `-j 20`
attempt hit the unrelated `vm_transitions` 100 ms solver timeout; that suite
passed alone and again in the four-job run. Exact identities and raw-report
hashes are in `VMP_STACK_WRITE_READ_STREAMS_EVIDENCE.json`.

Reproduce the current x86-64 profile with:

```sh
xcrun --sdk macosx clang -O2 -arch x86_64 \
  -DNATIVE_DISJOINT_STACK_HASH=1 \
  tests/vmp_native/native_disjoint_strings.c -o build/vmp-stack-hash-x64
python3 tests/run_ida_smoke.py build/vmp-stack-hash-x64 \
  tests/ida_disjoint_string_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_STACK_HASH=1 \
  --output-dir build/vmp-stack-hash-reproduction
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| T1 | The hook's `STACK` tag denotes a complete range outside heap objects. Safe heap continuation depends on this. | A stack-labeled write overlapping the candidate allocation rejects; a wide/overflowing write remains a global barrier. A false scope tag outside the checked object remains a ledger-integrity risk. |
| T2 | All temporally relevant reads and writes were captured. The two strings depend on this. | The probe requires complete, nontruncated capture in every returned run; a falsely complete ledger missing a write would falsify the result. |
| T3 | Exact read bytes and spatial source sites agree across runs. Publication depends on this. | Eight fragments and four/six observations per candidate are required; the existing divergent-byte and source-site controls remain passing. |
| T4 | The native hash oracle detects an incorrect decoded value. Process evidence depends on this. | Both architectures return 0; a corrupted second expected hash returns 1. The independent disassembly shows the stack stores. |
| T5 | Ctree annotations refer to the current evidence and consumed key. Display depends on this. | Key edit removes both annotations and restoration recovers them; isolated runner integrity fields remain true. |

**High impact:** an exact stack accumulator no longer suppresses heap
plaintext. **Medium impact:** wider stack writes and any uncertainty in scope
still suppress a stream; VMP-emitted coverage, other architectures and
cross-thread memory effects remain unknown. **Low impact:** additional writes
consume the existing 256-visit budget and can increase abstention.

QG1: no normative premise. QG2: T1–T5 have falsification probes. QG3:
portable, native process, matched production and regression checks cover the
scoped change; the full review remains open. QG4: byte widths, limits,
counts and complexity are explicit. QG5: mismatch, wide and unknown effects
abstain. QG6: local source and binary hashes plus isolated IDA reports are
recorded. QG7: adjacent opportunity and limits are bounded above.
