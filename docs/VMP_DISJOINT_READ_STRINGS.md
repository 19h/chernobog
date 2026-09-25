# Two complete read strings in one heap allocation

Historical checkpoint for commit `d6ffcb1b`: the evidence and admission
description below record that revision. The later
`VMP_COMPLETED_READ_PREFIX.md` narrows abstention for incomplete spatial
suffixes without rewriting these measurements or their source hashes.

Review requirements 3a and 3b require use-specific bytes and allocation
identity. An allocation-wide permuted-read group previously required every
observed byte to form one contiguous string. Two independent strings at
offsets 0–7 and 16–23 therefore produced no candidate even when all reads,
lifetimes and values were exact. The projector now partitions the observed
addresses at gaps and publishes each complete, NUL-terminated component with
its own execution-order fragments. It retains the allocation generation as
the object identity and the component's first byte as the use offset.

## Admission and bounds

The existing temporal contract remains: every read has an exact matching data
event; all reads belong to one live allocation generation; captures are
complete; calls, allocation changes and unattributed effects interrupt groups;
and the candidate shape and bytes agree across every scheduled run. Partition
is permitted only at a real observed address gap whose preceding byte is NUL.
An adjacent byte after NUL is an ambiguous interior terminator. A component
without a terminal NUL, a duplicate observed address, a fragment crossing a
component boundary or a write intersecting that component's observed bytes
causes abstention. A disjoint write can veto one completed component while
the other survives. An incomplete extra component vetoes the whole group.

```text
for each valid allocation-wide group of exact read fragments:
    reject duplicates, interruption and excess captured bytes
    split sorted observed addresses only after NUL and across a gap
    require every component to end in NUL
    assign every original read to exactly one component
    for each non-forward component with sufficient read sites:
        verify the component against intervening heap writes
        decode its exact bytes and retain the original read witnesses
publish only matching semantic keys, spatial read shapes and values in all runs
```

For `N` observed bytes and `P` fragments, the partition and assignment cost
is `O(N + P log N)` time and `O(N + P)` space, after the existing `std::map`
construction; `N` is capped by the 4,096-byte snapshot limit. Existing write
checks visit at most 256 indexed writes per extension and completed stream.
The two fixture strings are 8 bytes each, separated by 8 unobserved bytes in
one 32-byte allocation. These are observed use strings, not inferred values
for the intervening bytes or the allocation's final state.

## Controlled observations

The x86-64 and arm64 Mach-O fixtures each allocate one buffer, decode two
encoded 8-byte payloads into it, read each byte through two instruction sites
under two input-dependent orders, hash the observed sequence, erase all 32
bytes with volatile stores and free the buffer. The two unmodified binaries
exit 0. Changing only the expected second-string hash makes each exit 1.
Disassembly confirms 32 byte stores before `free`; the bounded evidence view
truncates later memory events and is not used to establish that erasure.

| Architecture | Complete returned runs | Before: strings / streams / ctree uses | After: strings / streams / ctree uses |
|---|---:|---:|---:|
| x86-64 | 4 | 0 / 0 / 0 | 2 / 8 / 2 |
| arm64 | 6 | 0 / 0 / 0 | 2 / 12 / 2 |

The matched prior/current IDA 9.4 SP1 profiles use byte-identical inputs and
probe scripts per architecture. Each new candidate is observed in every run
with eight original read fragments; the values are `secret!` and `second!`.
The current profiles pass all nine probe checks, including no final image
strings, absent saved comments, unchanged function bytes, and immediate
revocation/restoration of both ctree annotations after a consumed-key edit.
The prior plugin passes the five unaffected checks and fails the four expected
candidate/display checks. Portable controls additionally verify that changing
one component across runs suppresses only that component, that an incomplete
third component vetoes the group, and that an overlapping write vetoes only
its affected component. The evidence executable reports 428 interleaved read
checks. The existing multisite, permuted-read and same-object-write IDA
probes pass 10/10, 9/9 and 9/9 checks respectively; all 21 CTest suites pass.
Exact hashes are recorded in
`VMP_DISJOINT_READ_STRINGS_EVIDENCE.json`.

Reproduce the current x86-64 profile with:

```sh
xcrun --sdk macosx clang -O2 -arch x86_64 \
  tests/vmp_native/native_disjoint_strings.c -o build/vmp-disjoint-x64
python3 tests/run_ida_smoke.py build/vmp-disjoint-x64 \
  tests/ida_disjoint_string_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/vmp-disjoint-reproduction
```

## Assumption register and scope

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| D1 | Exact temporal/data capture contains every relevant read and write. Candidate validity depends on this. | Require all returned runs to report complete capture; truncated runs abstain. An omitted write in a falsely complete ledger would falsify the result. |
| D2 | Allocation ID, generation and offset identify the two components. Their separation depends on this. | Same-object disjoint spans pass; duplicate addresses, crossing fragments, an incomplete third span and overlapping writes reject as specified. |
| D3 | The encoded fixture and native hash oracle test actual runtime strings. The process result depends on this. | Both architectures exit 0; corrupting the expected second hash exits 1. Disassembly checks the heap reads and 32 volatile byte stores. |
| D4 | Spatial site shapes and values agree over all scheduled runs. Consensus depends on this. | The probe requires eight fragments per string and four/six eligible observations; a changed second-run byte suppresses only its string in the portable control. |
| D5 | Display belongs to the current IDB and consumed key. The annotations depend on this. | The key edit removes both annotations; restoration recovers both. Source input, script, IDA and plugin hashes remain unchanged in each isolated runner report. |

**High impact:** one allocation can yield multiple independently witnessed use
strings. **Medium impact:** spatially incomplete components still suppress the
allocation group; an independently provable component after an incomplete one
is an opportunity for a future narrower ownership rule. **Low impact:**
partitioning is bounded by the existing snapshot cap. VMP-emitted coverage,
other architectures and true heap address reuse in this fixture remain
unknown.

QG1: no normative premise. QG2: D1–D5 list falsification probes. QG3: the
disjoint-component change has portable, native process, baseline/current IDA
and regression coverage; the full review remains open. QG4: byte offsets,
limits, counts and complexity are explicit. QG5: incomplete, duplicate,
overlap and interruption cases retain abstention. QG6: source, binary,
plugin, IDA and raw-report hashes are recorded. QG7: adjacent opportunity
and limits are bounded above.
