# LAHF and SAHF per-bit status transfer

Review row 2a requires the x86 flag state to preserve facts at individual
bits. Previously `LAHF` and `SAHF` reached the generic unsupported-instruction
transfer. The production state now admits exact, single-byte `9F` (`LAHF`)
and `9E` (`SAHF`) encodings in 32- and 64-bit modes. Other encodings remain
unsupported region frontiers and clear the ordinary abstract state.

`LAHF` writes AH bits 7, 6, 4, 2 and 0 from SF, ZF, AF, PF and CF. It writes
known zero to AH bits 5 and 3 and known one to bit 1. Each unknown flag leaves
only its corresponding AH bit unknown. Other accumulator bits and all flags
remain unchanged. `SAHF` updates those five flags individually from AH and
leaves OF unchanged; an unknown AH bit invalidates only its corresponding flag.
These mappings follow the [Intel instruction reference](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf).
In 64-bit mode, normal execution also requires
`CPUID.80000001H:ECX.LAHF_SAHF_64[0] = 1`. Successful x86-64 process
execution shows that this translated runtime accepts the instructions;
CPUID enumeration was not separately recorded. The static facts are
conditional on normal completion and do not claim that every target CPU
supports the feature.

The two transfers inspect five bits and use O(1) time and O(1) additional
space per instruction. The existing owned/ownerless graph limits and fixed
point budgets are unchanged.

## Executed and static controls

The IDA-free test exhausts 4,096 known-mask/value flag profiles and 256
concrete AH values. It checks reserved AH bits, partial knowledge, unaffected
accumulator bits, unknown-bit abstention, and OF preservation. The native
x86-64 process passes 37,630 checks; the i386 process passes 36,350 checks
under the pinned QEMU image. Both execute seven new controls per input: exact
CF and OF effects, a `LAHF`/`SAHF` round trip, an input-dependent unknown CF,
an exact AH constant, all five loaded flags plus OF, and the raw `LAHF` byte.

Fresh IDA 9.4 SP1 owned-function inspections pass 453 x86-64 and 386 i386
checks. The corresponding ownerless inspections pass 1,730 and 1,680 checks;
their separate process controls pass 4,606 checks per architecture. Both
prefixed `SAHF` and prefixed `LAHF` stop before use as explicit frontiers. In each
IDA analysis path four added fixture `SETcc` values are proved and the input-dependent
`SAHF` carry result remains unresolved. A fresh inspection of the exact
supplied VMP hello binary passes 8/8 checks and retains 75 initializer nodes,
77 edges and three unresolved facts. This fixture does not establish
protected-path use of `LAHF` or `SAHF`. All 21 configured CTest suites pass.
Source, binary, plugin, IDA and raw-report hashes are in
`VMP_STATUS_AH_FLAGS_EVIDENCE.json`.

Reproduce with fresh output directories:

```sh
python3 -B tests/run_native_dataflow.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/status-ah-owned-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/status-ah-ownerless-reproduction
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| H1 | The Intel `LAHF`/`SAHF` bit mapping and normal-completion semantics apply to the selected modes. All transferred facts depend on this contract. | Check the 256 concrete AH values and native raw flag/AH outputs. Change one expected bit and reject; a CPU without the long-mode CPUID feature must not count as a normal-completion oracle. |
| H2 | IDA's decoded instruction and loaded byte agree on exact one-byte `9E` or `9F`. Production admission depends on this identity. | Recompute byte, size and mode for every inspected fixture; both `66 9E` and `66 9F` controls must stop at `unsupported_status_ah_encoding` before the use. |
| H3 | The six-bit abstract domain represents CF/PF/AF/ZF/SF/OF independently. Partial AH and preserved OF conclusions depend on this state contract. | Enumerate all 4,096 known-mask/value profiles, 256 AH values, an input-dependent carry and an OF-preserving `SAHF` path. |
| H4 | The hash-bound process and IDA artifacts represent the measured scope. Reported counts depend on them. | Rehash sources, binaries, plugin and reports; rerun both architectures and reject changed outcomes or an altered IDB inventory. Protected prevalence and effectiveness remain unknown. |

**High impact:** exact status transfers preserve per-flag facts through AH
without making unknown bits concrete. **Medium impact risk:** a 64-bit target
without `LAHF_SAHF_64` support raises `#UD`; the static facts require normal
completion. **Low impact:** prefixed forms remain explicit abstentions.
Protected-corpus recovery rates, additional x86 status instructions and
whole-program exception behavior remain unknown.

QG1: technical claims only. QG2: H1–H4 include falsification probes. QG3:
portable, native, owned, ownerless and supplied-sample controls cover this
checkpoint; review row 2a remains in progress. QG4: bit positions, counts and
O(1) cost are explicit. QG5: unknown AH bits and unsupported encodings abstain.
QG6: Intel's instruction reference and hash-bound local execution/IDA reports
are primary evidence. QG7: feature gating and unmeasured protected paths are
bounded above.
