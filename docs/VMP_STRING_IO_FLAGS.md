# Status flags across x86 string stores and loads

This is a historical checkpoint for repeat-count handling. The later
`VMP_STRING_REPEAT_COUNT.md` establishes zero after normally completed
natural-address-size `REP STOS` and `REP LODS`; hashes and counts below refer
to the earlier revision.

Review rows 1b and 2a require the native abstract state to retain facts through
instructions with known architectural effects. Intel specifies that `STOS` and
`LODS`, including repeat forms, leave flags unchanged
([Intel instruction reference](https://cdrdv2-public.intel.com/671110/325383-sdm-vol-2abcd.pdf)).
The shared x86-64/i386 transfer now preserves CF, PF, AF, ZF, SF and OF for
both decoded instructions. `STOS` invalidates retained stack and writable-memory
facts because its implicit destination can alias them, and invalidates RDI/EDI.
`LODS` invalidates RAX/EAX and RSI/ESI while retaining locally established
memory facts. A repeat prefix also invalidates RCX/ECX. The abstraction does
not infer copied values, count-zero no-op effects, or direction-dependent
pointer values. These transfers describe normal completion in the existing
flat, unchanged-code model.

## Executed and production controls

Seven assembly functions execute for each of 256 input values on x86-64 and
i386. Inputs repeat fixed string operands; the 256 calls do not represent 256
distinct string contents. The original `MOVS` controls remain in the same
binary and probe.

| Shape | Native result | Current owned and ownerless IDA result |
|---|---:|---|
| `STC; REP STOSB; SETB` | 1 | Proved CF condition |
| `STC; LODSB; SETB` | 1 | Proved CF condition |
| ZF set; `REP LODSB; SETE` | 1 | Proved ZF condition |
| `STC; SCASB; SETB` with equal bytes | 0 | Unresolved condition; `SCASB` changes flags |
| Local target store; `STOSB` to unknown-alias destination; `PUSH [slot]; RET` | 7 | Unresolved target; no owned user edge |
| Target in RDX/EDX across `REP STOSB`; `PUSH register; RET` | 7 | Proved register target and owned user edge |
| Local target store; `LODSB`; `PUSH [slot]; RET` | 7 | Proved memory target and owned user edge |

The i386 `LODSB` memory fixture restores its callee-saved ESI through a known
stack word and an explicit stack-pointer adjustment. A `POP` would clear the
model's writable-memory map independently of `LODS`; the first i386 probe
detected this fixture confound and was discarded. Both final native binaries
pass **20,990 checks each**, calculated as `80 × 256 + 2 × 255`; the 255
additional two-check inputs belong to existing loop controls. The i386
processes use pinned QEMU user-mode translation, while x86-64 processes run
under macOS translation on this arm64 host.

The current plugin passes **269 owned IDA assertions** and **1,042 ownerless
IDA assertions** per architecture. The ownerless native control separately
passes 4,094 checks per architecture and rejects its deliberately corrupted
oracle. Four previous-plugin IDA runs use the same fixture, probe and IDA
bytes, with only the plugin bytes and the expectation marker different. That
plugin has zero of the three new condition facts and two new target proofs;
the current plugin has all five. Both preserve the `SCASB` and unknown-alias
abstentions. All 21 CTest suites pass. The exact supplied VMP initializer
remains 75 nodes, 77 edges and three unresolved facts; its current protected
report is byte-identical to the prior `MOVS` checkpoint report. These results
do not establish protected edge recovery.

The owned IDA wrapper processes in the final run took 5.36 s and 6.03 s for
x86-64 and i386; ownerless wrappers took 11.1 s and 7.28 s. Their recorded
peak resident values span 143,671,296–189,382,656 bytes. These values are
`wait4` observations of the Python runner subprocess that launches IDA, so
they are **not** plugin latency or IDA peak-memory estimates. Exact identities,
nanosecond observations and raw-report hashes are in
`VMP_STRING_IO_FLAGS_EVIDENCE.json`.

Reproduce with hash-matched local tools and fresh output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/string-io-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/string-io-ownerless-reproduction
python3 -B tests/run_ida_smoke.py samples/foo_x86_vmp \
  tests/ida_protected_region_inspect.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/string-io-protected-reproduction \
  --set CHERNOBOG_IDA_DIRECT_JUMP_DECODE=1 \
  --set CHERNOBOG_PROTECTED_REGION_ROOT=0x1002946b5 \
  --set CHERNOBOG_PROTECTED_REGION_EXPECT=complete
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| S1 | Intel's normal-completion `STOS`/`LODS` contract applies to both decoded `NN_stos`/`NN_lods` forms. The three flag facts depend on it. | Execute plain and repeated byte forms on x86-64/i386; require `SCASB`, which changes flags, to remain unresolved. Test wider sizes and exceptional paths before expanding the claim. |
| S2 | Unknown `STOS` destination aliasing requires invalidating all retained writable bytes and stack words. The unresolved transfer depends on this. | Store a target locally, execute `STOSB` to an externally supplied pointer, and require no proved target or owned user edge. |
| S3 | `LODS` reads but does not write retained memory. The memory target proof depends on this. | Store the target before `LODSB`, restore i386 ESI without an intervening `POP`, then require the exact memory target and native return value. An inserted aliasing write must revoke it. |
| S4 | An unaffected register survives `STOS`; a repeat consumes the count register. The register target proof depends on the former. | Carry RDX/EDX through `REP STOSB` to `PUSH; RET`; future count tests must require abstention when the old count is needed. |
| S5 | The prior/current change is attributable to plugin bytes in this fixed fixture. The five-gain comparison depends on this. | Require equal binary, probe and IDA hashes, separate plugin hashes, and matching three unknown-to-proved conditions plus two unknown-to-proved targets on both architectures and analysis paths. |
| S6 | The selected supplied initializer represents only its bounded static root. The unchanged protected observation depends on that scope. | Rehash the sample and require identical report bytes and read-only IDB inventory; dynamic entry, other roots and protected ground-truth edges remain unknown. |

For at most 64 retained stack words and 128 writable bytes, the `STOS` step
invalidates them in O(S + B) time and O(1) additional space; `LODS` changes
three fixed register slots in O(1) time and space. Existing graph limits are
64 owned or 128 ownerless nodes, 128 rounds and 256 incoming references per
node. Counts are dimensionless. The tested byte element is 8 bits = 1 byte.

- **High impact:** three additional condition facts and two transfer targets
  per architecture survive common string instructions.
- **Medium impact:** destination aliasing and comparison flags retain explicit
  abstentions; the i386 restore sequence isolates the memory-read transfer.
- **Low impact:** the selected protected root is unchanged, so protected
  effectiveness remains unknown.

QG1: technical scope. QG2: S1–S6 include falsification probes. QG3: both
architectures, owned/ownerless analysis, previous/current attribution,
negative controls, protected control and installation are covered at the stated
scope; the full review remains open. QG4: counts, units and complexity are
explicit. QG5: `SCASB`, aliases and exceptional execution retain uncertainty.
QG6: Intel's primary instruction reference and hash-linked local execution and
IDA reports support the claims. QG7: adjacent risks and unknown protected
effectiveness are bounded above.
