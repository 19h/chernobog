# Immediate logical operations on partially known x86 registers

Review rows 2a and 2b require local status facts and their `SETcc` consumers.
The previous register model preserved known bits through immediate `AND`, but
immediate `OR` and `XOR` discarded the entire register fact when any source bit
was unknown. The production transfer now implements, within the written slice,
`OR`: `known' = known | immediate`, `value' = (value | immediate) & known'`;
`XOR`: `known' = known`, `value' = (value ^ immediate) & known'`. The existing
register write applies x86-64 zero extension for a 32-bit destination. When
an immediate `AND`, `OR` or `XOR` leaves an exact destination slice, the
transfer derives ZF, SF and PF from that result. CF and OF have already been
cleared by the logical-operation transfer; AF remains unknown. These rules
follow the [Intel Software Developer's Manual, revision 090](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf),
Volume 2, `AND`, `OR` and `XOR`.

The portable test enumerates all `3^8 = 6,561` abstract byte states, eight
immediates and two new operations: `6,561 * 8 * 2 = 104,976` result comparisons
against every concrete byte represented by each state. Additional checks
cover an `AH` slice, 32-bit zero extension and rejected invalid slices.
Time is `O(3^8 * 8 * 2 * 2^8)` for the fixed exhaustive oracle; each abstract
transfer uses `O(1)` time and space.

An independent assembly/C fixture executes five routines for each of 256
inputs: 1,280 checked results per architecture. macOS x86-64 executes under
the arm64 host's translation facility; Linux i386 executes under QEMU user
mode in the pinned cross-toolchain image. Fresh IDA 9.4 SP1 databases load
the same input binary under the immediately preceding installed plugin and
the newly built plugin. The result is identical for both architectures:

| Site type | Prior proofs | Current proofs | Native result |
|---|---:|---:|---|
| `AND 1; OR 2; AND 2; CMP 2; SETZ` | 0 | 1, value `1` | `1` for all 256 inputs |
| `AND 1; XOR 2; AND 2; CMP 2; SETZ` | 0 | 1, value `1` | `1` for all 256 inputs |
| `AND 1; OR 1; SETNZ` | 0 | 1, value `1` | `1` for all 256 inputs |
| `AND 1; OR 2; TEST 1; SETNZ` | 0 | 0 | input bit 0 |
| `AND 1; XOR 2; TEST 1; SETNZ` | 0 | 0 | input bit 0 |

The same current plugin also passes the exact historical protected
`combined-0` 97-head read-only inspection: all three conditions and one
PUSH/RET target remain unresolved. No protected recovery gain is attributed
to this local transfer change.

The [retained capture](VMP_PARTIAL_LOGIC_CAPTURE.json.gz) contains source
hashes, native output, four probe reports and runner manifests, and the
protected-regression report. Its SHA-256 is
`646a81f85cda01175f901c8ac1d07be582785b11dd588ac494a7d8648166a5ac`.
The x86-64 binary SHA-256 is
`a3ea7004880f567c529322d30738acee85a058434947b3ac7382cc42db0b2cfd`;
the i386 binary SHA-256 is
`81be78701b0870cd70abc02f6420f09d8c4735aade30e524460912ae0957ac48`.
The prior plugin is
`d1e7eaf261add8185be694a8e38050fa292f1d43610d3747b691bed850b207eb`;
the candidate plugin is
`1ab83450e7db25b1a745e3b58d300f787415cf717b24827ea62851fc40dfc1d5`.
The Linux cross-toolchain image ID is
`sha256:7b1781979ac73774803cdcd1ce8797d345cbae204731e0e684c1d74e89bef654`;
compiler, QEMU and loader hashes are retained in the capture.
Verify the retained result with:

```sh
python3 -B tests/verify_partial_logic_archive.py \
  --archive docs/VMP_PARTIAL_LOGIC_CAPTURE.json.gz
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| L1 | Intel normal-completion integer `AND`/`OR`/`XOR` semantics apply to the admitted x86-64 and i386 instructions. Transfer and flag results depend on this. | Compare the manual's defined flags and execute 1,280 outputs per architecture; repeat on physical x86 if translation is suspect. Exceptional prefixes and faults are outside these fixtures. |
| L2 | IDA decodes the intended immediate and register slice. The three new facts depend on exact operand identity. | Require same-binary prior/current probes, fixture symbols, source hashes and exhaustive byte-state results; mutate an opcode or immediate and rerun the probe. |
| L3 | A fresh IDA database and unchanged plugin artifact represent each comparison. The measured proof delta depends on this. | Require runner input, plugin, script and IDA hashes; compare repeated read-only queries and instruction bytes/comments before and after. |
| L4 | The two negative paths retain input-dependent bit 0. Their no-proof result depends on that dynamic input. | Execute all 256 inputs and require both zero and one outcomes; verify zero live `SETcc` proofs in both plugins. |

**High impact:** three previously absent local proofs per architecture now reach
the production `SETcc` evidence API. **Medium risk:** the fixture covers local
immediate operations, not arbitrary path joins or memory operands. **Low
impact:** the selected historical protected region is unchanged and still has
zero proved conditions. Full VMP review completion remains in progress.

QG1: technical scope only. QG2: L1–L4 have falsification probes. QG3:
portable, native, production IDA and protected-regression paths are covered.
QG4: byte-state, input and proof counts are dimensionless and reproducible.
QG5: dynamic-bit controls and the unchanged protected abstentions are
explicit. QG6: Intel's primary manual and hash-bound source/process/IDA
captures establish provenance. QG7: join, memory and protected recovery
limits are stated.
