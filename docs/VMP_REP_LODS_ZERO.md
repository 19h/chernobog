# Exact zero-count REP LODS transfer

Review rows 1b and V require exact native targets without treating an
unresolved memory read as a known value. The
[Intel instruction reference](https://cdrdv2-public.intel.com/868137/325462-089-sdm-vol-1-2abcd-3abcd-4.pdf)
specifies `REP LODS` repetition using the address-size count register.
When that register is exactly zero before the instruction, no iteration
executes. The accumulator, source index, count, memory and status flags retain
their input values under this normal-completion transfer. This result is
independent of the DS base in i386 because no memory element is accessed.

The production x86 abstract transfer now recognizes this case only for the
decoded `REP LODS` operand shape, a natural address size, no segment override
or LOCK prefix, and an exact zero count. The transfer leaves its entire state
unchanged. Nonzero or unresolved counts retain the previous conservative
behavior. The new admission uses the existing finite-count helper and takes
O(1) time and O(1) extra space for the fixed x86 register width.

The same-source x86-64 Mach-O and i386 ELF32 fixtures set the count to zero,
set the source index to zero, load an exact function address into the
accumulator, execute `F3 AC`, then transfer with `PUSH accumulator; RET`.
Each executable calls the routine for 256 inputs and observes result 73 on
every call. The x86-64 process ran on macOS arm64 with x86-64 translation;
the i386 process ran under QEMU 9.2.0 in the pinned Linux image. The input
is deliberately unused, so these 256 calls check repeatability and stack
return behavior, not 256 distinct pre-instruction states.

Fresh IDA 9.4 inspections of each exact binary use the same probe source for
the prior installed plugin and the changed plugin. The prior plugin reports a
candidate with an unknown target and no plugin edge. The changed plugin
reports an exact register-definition target and one user jump edge. Changing
`xor ecx, ecx` to `mov cl, 1` in a disposable IDB removes the proof and edge;
restoring the bytes restores both. The original fixture binaries are never
patched. The changed-plugin IDA probe passes 6/6 checks on each architecture;
the prior-plugin baseline passes 4/4 expected-control checks on each.
Repository CTest passes 23/23 tests. This fixture is separate from the
historical 56-edge bounded-comparison benchmark and does not change its
recorded denominator.

`VMP_REP_LODS_ZERO_EVIDENCE.json` pins the two executable hashes, source,
IDA/probe/plugin identities and four raw report hashes. Reproduce the x86-64
process and changed-plugin IDA control with a fresh output directory:

```sh
xcrun clang -arch x86_64 -O2 -g0 \
  tests/vmp_native/rep_lods_zero.S \
  tests/vmp_native/rep_lods_zero_main.c -o build/rep-lods-zero-x64
build/rep-lods-zero-x64
python3 -B tests/run_ida_smoke.py build/rep-lods-zero-x64 \
  tests/ida_rep_lods_zero_probe.py \
  --ida '/Applications/IDA Professional 9.4.app/Contents/MacOS/idat' \
  --plugin ../ida-sdk/src/bin/plugins/chernobog.dylib \
  --output-dir build/rep-lods-zero-recheck \
  --set CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=64
```

The i386 executable can be rebuilt and run with the pinned
`chernobog-vmp-linux32:qemu9.2` image. The image is identified by its
immutable SHA-256 in the evidence file. Run the same IDA probe on the
generated ELF32. For a prior-plugin control, use the previous installed
plugin artifact and add `--set CHERNOBOG_REP_LODS_ZERO_BASELINE=1`.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| L1 | IDA's `REP LODS` operands and prefix represent the bytes `F3 AC` in the two fixtures. The exact-state admission depends on this decode. | Compare both instruction bytes and decoded operands; alter the prefix or operand shape and require abstention. |
| L2 | The count register is exactly zero at the instruction, and the normal-completion path executes no iteration. Accumulator and index preservation depend on this. | Replace the full-register zeroing with a partial `CL` write; require an unresolved target and no user edge. Execute both architectures with zero count and a null source index. |
| L3 | The target address loaded before `REP LODS` is exact in each IDA image. The two new edge claims depend on this. | Rehash the binaries, decode the address-materialization instruction and compare the published target with the separate symbol and executed result. |
| L4 | The prior/current IDA runs differ in plugin implementation and the probe's expected-result switch, with identical input, probe and IDA bytes. Attribution depends on these identities. | Compare the pinned hashes and runner manifests; reject any unexpected input, script or tool change. |

- **Medium impact:** one previously unresolved exact transfer becomes a proved
  native edge on each architecture.
- **Low impact:** zero-count `REP LODS` needs no i386 DS-base assumption.
- **Medium risk:** nonzero/unknown counts, address-size overrides and protected
  corpus effectiveness remain unresolved by this fixture.

QG1: technical scope only. QG2: L1-L4 include falsification probes. QG3:
both architectures, process results, prior/current IDA facts and mutation
revocation are checked. QG4: 256 exact calls per executable and O(1)
transfer bounds are explicit. QG5: the zero-count admission excludes
unproved count and prefix cases. QG6: Intel semantics and hash-linked local
source, binary, plugin and IDA reports support the claim. QG7: protected
recovery and wider repeat behavior remain explicit unknowns. Full review
completion remains in progress.
