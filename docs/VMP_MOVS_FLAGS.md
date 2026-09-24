# Status flags across x86 string moves

Review row 2a calls for per-flag transfer through instructions that preserve
the modeled status bits. Intel specifies that `MOVS`/`MOVSB`/`MOVSW`/
`MOVSD`/`MOVSQ`, including the `REP` form, does not modify flags
([Intel instruction reference](https://cdrdv2-public.intel.com/868141/253667-089-sdm-vol-2b.pdf)).
The shared x86-64/i386 native abstract step now retains CF, PF, AF, ZF, SF
and OF through decoded `NN_movs`. The transfer invalidates RSI/ESI and
RDI/EDI, and invalidates RCX/ECX when a repeat prefix is present. Other
general-register values are retained. The possible destination alias clears
retained stack words and writable-memory bytes. No copied byte value or
destination alias is inferred. The transfer
is conditional on normal completion in the existing flat, unchanged-code
model; faults, concurrent writes and self-modification are outside the proof.
The fixtures use byte moves; wider element sizes and `REPNE` pass the same
decoded case but have no separate process oracle in this changeset.

This follows an observed `REP MOVSB` in the supplied VMP initializer at
`0x100248011`. It does not establish a condition in that selected root: the
exact prior/current inspection remains 75 nodes, 77 edges and three
unresolved facts, with identical read-only IDB inventories and records.

## Executed and production controls

Eight added assembly functions execute for 256 inputs on each architecture.
Their string source and copy count are fixed; the input sweep repeats each
operation rather than varying its operands. The process and IDA controls are:

| Shape | Native result | Current owned / ownerless IDA result |
|---|---:|---|
| `STC; REP MOVSB; SETB` | 1 | Proved CF condition |
| `XOR` to set ZF; `REP MOVSB; SETE` | 1 | Proved ZF condition |
| `STC; MOVSB; SETB` | 1 | Proved CF condition |
| `STC; CMPSB; SETB` with equal bytes | 0 | Unresolved; [`CMPSB` changes flags](https://cdrdv2-public.intel.com/868140/253666-089-sdm-vol-2a.pdf) |
| Locally store a target, copy one byte through an unknown destination pointer, `PUSH [slot]; RET` | 7 | Unresolved target; no owned edge |
| Keep target in RAX/EAX through `REP MOVSB`, then `PUSH register; RET` | 7 | Exact register-definition target and owned edge |
| Keep target in RCX/ECX through plain `MOVSB`, then `PUSH register; RET` | 7 | Exact register-definition target and owned edge |
| `REP MOVSB` consumes one count; add resulting count to target before `PUSH register; RET` | 7 | Unresolved target; count register invalidated |

The owned harness passes **19,198 native checks and 248 IDA assertions per
architecture**. The ownerless harness passes its **4,094 existing native
checks and 972 read-only IDA assertions per architecture**; its native oracle
does not execute these eight functions, and its deliberately corrupted oracle
is rejected. Matched previous/current owned runs pass 242/248 assertions per
architecture; four focused ownerless runs pass 28 assertions each. On the
same binaries and probes, the previous plugin lacks the three new condition
facts and two new transfer targets. The expectation-only
`CHERNOBOG_MOVS_BASELINE=1` setting
makes the recorded environment digests differ; scan-depth settings match.
All 21 CTest suites pass. The refactored focused-probe path also passes its
37-check prior ALU regression on the final x86-64 binary.

The process harness previously supplied a 32-bit C local to assembly controls
that can write an 8-byte x86-64 word. The local is now a `uint64_t` object,
and those external prototypes take `void *`: the maximum native store is
8 bytes into an 8-byte object, while i386 stores at most 4 bytes. Before this
correction, one optimized x86-64 build printed only 71 checks because an
adjacent counter was overwritten. The corrected final binaries report the
exact count below.

Source, binary, tool, plugin and raw-report SHA-256 values are in
`VMP_MOVS_FLAGS_EVIDENCE.json`. Reproduce with fresh directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/movs-flags-owned-repeat
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/movs-flags-ownerless-repeat
```

## Assumption register and falsification probes

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| MS1 | Decoded `NN_movs`, with or without `REP`, leaves all six tracked status flags unchanged after normal completion. The three new condition facts depend on this. | Check Intel's instruction contract and execute separate CF/ZF `REP MOVSB` and CF plain `MOVSB` fixtures on x86-64 and i386. Require the `CMPSB` control, which changes flags, to remain unresolved. |
| MS2 | A string move changes its pointer registers, and a repeat prefix changes its count register; unrelated general registers retain their values. The two new transfer targets and count abstention depend on this partition. | Keep a target in RAX/EAX through `REP MOVSB` and in RCX/ECX through plain `MOVSB`; require both exact targets. Add the consumed REP count to a target and require abstention. |
| MS2a | A string destination can alias any retained memory or stack word. Sound post-copy memory facts depend on clearing them. | Store an exact target, copy to a runtime-disjoint but statically unknown pointer, then require `PUSH [slot]; RET` to remain unresolved without a user edge. |
| MS3 | The process oracle's disjoint destination has enough storage for the widest assembly store. Native check counts depend on this. | Inspect all alias stores and the `uint64_t` destination size: 8 bytes ≤ 8 bytes on x86-64, 4 bytes ≤ 8 bytes on i386; execute the final 256-input loops. The prior 32-bit local failed this bound. |
| MS4 | Prior/current differences are attributable to plugin bytes. The five-gain conclusion depends on this. | Compare exact fixture, IDAPython probe and IDA hashes for both architectures and analysis paths; require five baseline unknowns, five current proofs and three unchanged abstentions. |
| MS5 | The supplied initializer is one selected static root. Its unchanged result has only that scope. | Rehash the input and compare all 75 nodes, 77 edges, three records, and before/after IDB inventories under both plugins. Other protected roots and runtime-entered bytes remain unmeasured. |

With S ≤ 64 stack words and B ≤ 128 writable bytes, the string-move state
step takes O(S + B) time and O(1) additional space to invalidate implicit
effects while retaining unaffected registers and the six
status bits. The existing bounded graph analysis still admits at most 64
owned or 128 ownerless nodes, 128 rounds and 256 incoming references per
node. Counts are dimensionless integers: 19,198 = 73 × 256 + 2 × 255,
with no rounding error. Byte widths are physical memory bytes; 8 bits =
1 byte.

- **High impact:** three condition facts and two transfer targets per
  architecture survive string moves that previously erased the full state.
- **Medium impact:** the `CMPSB`, unknown-alias and consumed-count controls
  retain their abstentions, and the native oracle's 8-byte destination is bounded.
- **Low impact:** the selected protected initializer is unchanged; broader
  protected recovery effectiveness remains unknown.

QG1: no normative premise. QG2: MS1–MS5, including MS2a, contain falsification probes.
QG3: plain/repeated forms, two flags, register partition, both architectures, owned publication,
ownerless inspection, negative controls, protected comparison and oracle
storage are covered; the full review remains open. QG4: widths, limits and
check arithmetic are explicit. QG5: `CMPSB`, memory aliases and exceptional
execution are not conflated with flag-preserving normal completion. QG6:
Intel's primary instruction reference and hash-matched executed/IDA reports
support the claims. QG7: selected-root and runtime limits are explicit.
