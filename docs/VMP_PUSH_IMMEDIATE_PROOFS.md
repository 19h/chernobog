# Exact immediate and register-source proofs for native PUSH/RET

Review rows 1a, 1b and 2a require stack-transfer targets to follow the
instruction's exact source and width. The portable `classify_push_return`
previously accepted an immediate proof whose value differed from the modeled
PUSH operand. It also accepted a register proof naming a different register.
The two production adapters constructed matching proofs, but the classifier's
API admitted an inconsistent caller-supplied proof. It now rejects both
mismatches without changing unresolved-transfer handling or the stack-write
metadata.

Both production adapters now read exact loaded instruction bytes for an
immediate PUSH. They admit only unprefixed `6A ib` and `68 id` with a 32-bit or
64-bit machine-word push, require the decoder's low immediate bits to match
the bytes, and sign-extend the encoded value to that word width. Other
encodings, missing bytes and operand disagreement abstain. Intel's
[PUSH instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf#page=513)
specifies the opcodes, operand sizes and sign extension. The result remains a
metadata transfer: the PUSH writes the stack before RET reads it, so no native
instruction replacement follows from a zero net stack-pointer delta.

The portable test covers all 256 `imm8` encodings in each of 32-bit and
64-bit modes. It checks 512 expected word values and 512 decoder-disagreement
rejections. Five `imm32` values per mode add 10 expected values and 10
disagreement rejections. Prefix, wrong-opcode, truncation, unsupported-mode
and missing-buffer controls abstain. Separate classifier controls reject a
wrong immediate target and a wrong register source on each architecture while
retaining matching proofs and the established width/stack negatives. The
`chernobog.core` CTest passes.

A new static ELF32 fixture contains an executed `PUSH imm32; RET` that reaches
`pi32_target` and exits with status 0 under QEMU i386. It also contains two
unentered encoding controls: `6A 80` and an operand-size override. Fresh IDA
9.4 SP1 runs with the prior installed and rebuilt plugins each pass 12/12
probe checks. Both publish the exact `0x4010f0` target, retain the target's
function ownership, and produce byte-identical probe reports. The negative
byte decodes as `0xffffff80` at 32-bit width; neither unentered control has a
published return edge. The latter checks do not claim execution of those
controls or prove that IDA invoked this helper for them.

The existing ownerless dataflow suite supplies actual byte-decoded `6A FF`
and `68 FF FF FF FF` controls. With the rebuilt plugin, its x86-64 and i386
runs respectively pass 1,900 and 1,850 IDA checks; both sign-extension facts
are proved in each mode and no IDA errors are recorded. Each architecture's
native driver passes 4,606 checks and rejects two deliberately corrupted
oracles. The runner now includes the classifier and get-PC adapter sources in
its source-hash manifest. These controls confirm the two production analysis
paths on admitted static encodings; they do not establish a protected-sample
recovery gain. Exact file, plugin, report and tool hashes are in
`VMP_PUSH_IMMEDIATE_PROOFS_EVIDENCE.json`.

## Reproduction and bounds

```sh
clang -target i386-linux-gnu -nostdlib -static -fuse-ld=lld \
  -Wl,-e,_start tests/vmp_native/push_immediate32.S \
  -o build/push-immediate32-reproduction
ctest --test-dir build -R '^chernobog\.core$' --output-on-failure
python3 -B tests/run_ida_smoke.py build/push-immediate32-reproduction \
  tests/ida_push_immediate32_probe.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/push-immediate32-ida-reproduction
python3 -B tests/run_ownerless_dataflow.py --ida "$IDA_CONSOLE" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/push-immediate-ownerless-reproduction
```

The byte decoder reads at most five bytes and uses `O(1)` time and space.
The classifier scans at most `R` listed register-source slices for a matching
register, `O(R)` time and `O(1)` additional space; production currently lists
one source. The exhaustive `imm8` loop has 256 values per mode, dimensionless
counts and exact arithmetic. Process times are not used as plugin-latency
measurements.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| P1 | Loaded bytes and IDA operands describe the same 32-bit or 64-bit PUSH. Production target facts depend on this. | Compare the opcode and every encoded immediate byte with the decoder operand; mutate either and require abstention. Unsupported prefixes remain unresolved. |
| P2 | The Intel PUSH/RET normal-completion semantics apply to admitted x86 modes. Sign extension and stack-effect conclusions depend on this. | Exhaust `imm8`, test both `imm32` sign regions, execute the ELF32 transfer, and compare defined architectural effects on an independent native x86 host when available. |
| P3 | The linker keeps the fixture target address inside the unsigned `imm32` range. The ELF32 execution and IDA target comparison depend on this. | Rehash and inspect `68 id`, resolve the target independently, require QEMU exit 0 and exact IDA xref `0x4010f0`. |
| P4 | The matched prior/current IDA reports measure the same file and probe. The no-regression observation depends on this. | Require source binary, IDA and probe hashes to match, compare full probe JSON, and keep plugin hashes distinct. |
| P5 | The ownerless fixtures exercise the rebuilt production path. Their sign-extension conclusions depend on these source and plugin identities. | Require both per-architecture raw inspection checks, two corrupted-oracle rejections, and the expanded source manifest. |

**High impact:** an inconsistent immediate or register-source proof can no
longer authorize a native edge through the portable classifier. **Medium
impact:** raw-byte immediate decoding prevents an IDA operand-width ambiguity
from becoming an exact target. **Low impact:** the admitted encodings and
fixtures do not measure whole-protector CFG recovery.

QG1: technical claims only. QG2: P1–P5 have falsification probes. QG3: both
adapters, matching and inconsistent proofs, two execution modes and a native
ELF32 transfer are covered; the complete review remains in progress. QG4:
widths, counts and complexity are exact. QG5: unsupported bytes and unentered
controls are not promoted to successful recovery. QG6: the Intel instruction
reference, source hashes, exact fixture, QEMU result and IDA reports are
primary evidence. QG7: impact and limits are bounded above.
