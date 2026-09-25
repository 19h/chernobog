# Undefined-result BSWAP16 in static native analysis

Review rows 1b, 2a and V require native CFG and flag facts to distinguish an
unknown register value from an unknown successor. The source-emitted protected
corpus reaches 16-bit `BSWAP` on all 384 incomplete concrete captures. The
native emulator still stops there: Intel specifies an undefined 16-bit result,
so those captures cannot be continued with an assigned register value.

The read-only x86 region analyzer now admits **only** a decoded register
instruction whose bytes are exactly `66 0F C8` through `66 0F CF` in 32- or
64-bit mode. Under normal completion it adds the encoded fallthrough, clears
the entire destination register's abstract value, and retains the six modeled
status flags. If the destination is SP, it also clears tracked stack words.
Other 16-bit `BSWAP` encodings remain region frontiers; the ordinary state
transfer clears all abstract facts for those unsupported encodings. The node
field `abstract_effect=undefined-register-result` makes the admitted case
visible. The [Intel instruction reference](https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf)
specifies the undefined 16-bit result, unaffected flags and `#UD` for a LOCK
prefix. The exact three-byte gate excludes LOCK and other unmodeled prefixes.

The extra gate and transfer use O(1) time and state per visited instruction.
The existing ownerless analysis bounds remain 128 nodes, 128 fixed-point
rounds and 256 incoming references per node; this change does not enlarge
those quotas or execute a protected handler.

## Independent checks

The same native fixture runs on x86-64 and i386. It executes two paths
containing `BSWAP AX`, discards the instruction's result, and checks the flag
dependent return. Each architecture passes 4,606 process checks. A changed
ordinary expectation and a changed BSWAP flag expectation each make its
process exit 1. The latter fails at `od_bswap_flag` after one successful
check. The i386 process runs under the pinned QEMU image; x86-64 runs through
the macOS process loader on this host.

Fresh IDA 9.4 SP1 inspections pass 1,662 x86-64 and 1,612 i386 checks. Each
architecture has three exact BSWAP fallthroughs: the joined carry test proves
false, the direct preserved-carry test proves true, and a predicate computed
from the undefined register result remains unresolved. The last fixture is
deliberately not native-executed. The read-only inspection preserves the IDB
inventory and ordinary published evidence. A fresh inspection of the exact
supplied VMP hello executable passes 8/8 checks and retains its 75-node,
77-edge initializer graph with three unresolved facts; this graph contains no
new BSWAP continuation claim. All 21 configured CTest suites pass. Exact
source, fixture, binary, plugin, IDA and report identities are in
`VMP_BSWAP16_ABSTRACT_EVIDENCE.json`.

Reproduce the process and IDA controls with a fresh output directory:

```sh
python3 -B tests/run_ownerless_dataflow.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/bswap16-abstract-reproduction \
  --linux32-image chernobog-vmp-linux32:test
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| B1 | The Intel `BSWAP` normal-completion and flag contract applies to these x86-64/i386 controls. Static fallthrough and preserved-flag facts depend on it. | Execute both discarded-result flag paths and corrupt the expected BSWAP result; reject any exit or flag disagreement. A pre-Intel486 processor is outside this process corpus. |
| B2 | The exact three-byte encoding is decoded as a 16-bit register operation in the IDA database. Admission depends on that byte/decode identity. | Recheck bytes, width and mode for every admitted node; any prefix, width or byte change must lose the special transfer. |
| B3 | An undefined 16-bit result supplies no known destination-register bits. Downstream abstention depends on full-register invalidation. | Set a known EAX/RAX before `BSWAP AX`, then use AX in `TEST`/`SETZ`; the static predicate must remain unresolved on both architectures. |
| B4 | The finite fixture paths and IDA inventories represent the tested scope. The reported counts depend on them. | Match binary, plugin, IDA, script and report hashes; rerun both architectures and the supplied initializer, then compare checks and IDB inventories. Protected-path recovery after BSWAP remains unknown. |

**High impact:** static flag and CFG analysis can continue past this exact
undefined-result instruction without assigning its value. **Medium impact
risk:** a later computation that consumes the destination register must
abstain; the negative fixture enforces this. **Low impact:** nonexact prefix
forms remain explicit frontiers. Concrete VMP handler completion, logical VM
state and protected recovery rates remain unknown.

QG1: technical claims only. QG2: B1–B4 include falsification probes. QG3:
the exact encoding, normal fallthrough, undefined register, affected stack
tracking, unsupported forms and both analysis modes are addressed within this
checkpoint; the full review remains open. QG4: limits, process counts and
O(1) incremental cost are explicit. QG5: value-dependent predicates abstain
and native tracing retains its stop. QG6: Intel's instruction reference and
hash-bound local process/IDA artifacts are primary evidence. QG7: protected
coverage and prefix limits are bounded above.
