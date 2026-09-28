# Status flags from partially known logical results

Review rows 2a and 2b require per-flag analysis and native `SETcc` value
facts. The previous transfer could retain known register bits through an
immediate logical operation, but derived ZF, SF and PF only when its entire
result slice was exact. The production transfer now derives each status bit
independently from a partially known result. For an operand of width `w`,
known-bit mask `K`, and known-one mask `V`:

- ZF is false when `(V & mask(w)) != 0`; it is true when all `w` bits are
  known zero. Otherwise it remains unknown.
- SF equals the sign bit when that bit is known.
- PF equals even parity of the low byte when all eight low bits are known.

Immediate `AND`, `OR` and `XOR` now apply those rules after their register
transfer. `TEST reg, immediate` applies the immediate mask to a copy of the
source; `TEST reg, reg` with the same register slice reads that slice without
writing it. The existing logical transfer clears CF and OF and leaves AF
unknown. The rules and the invalidity of `LOCK TEST` follow the
[Intel Software Developer's Manual, revision 090](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf),
Volume 2, `AND`, `OR`, `XOR` and `TEST`.

The portable test checks all `3^8 = 6,561` partial byte profiles against
all `4^8 = 65,536` represented concrete byte completions for ZF/SF/PF.
It also checks a partial 64-bit result, an `AH` slice and invalid-slice
abstention. Each production flag transfer uses `O(1)` time and space for a
fixed x86 operand width. The exhaustive byte oracle scans at most
`6,561 * 256 = 1,679,616` candidate bytes and evaluates 65,536 matching
completions; these are exact dimensionless counts.

An independent assembly/C fixture executes ten routines for every input
byte: 2,560 checked results on each of x86-64 macOS and i386 Linux under
QEMU user mode. Fresh IDA 9.4 SP1 databases compare the exact same binary
under the preceding installed plugin and the new plugin. Both architectures
produce the same result:

| Result fact | Prior proofs | New proofs | Native control |
|---|---:|---:|---|
| OR forces nonzero, sign or low-byte parity | 0 | 3 | constant `1` |
| XOR fixes a known sign bit | 0 | 1 | constant `1` |
| AND leaves a known zero sign bit | 0 | 1 | constant `1` |
| TEST immediate fixes zero or nonzero | 0 | 2 | constant `1` |
| TEST of the same partial register fixes sign | 0 | 1 | constant `1` |
| Input-dependent OR parity and TEST low bit | 0 | 0 | both `0` and `1` observed |

Thus eight `SETcc=1` proofs per architecture, 16 total, are new. An
in-database mutation replaces one `AND` with three-byte `LOCK TEST`; IDA
decodes `TEST` with `aux_lock`, and neither plugin publishes a proof. Restoring
the instruction restores the new proof in both architectures. The prior
partial-logic fixture still proves its three values. The exact historical
97-head protected root still reports three unknown conditions and one
unresolved PUSH/RET target; independent Capstone verification and read-only
IDB inventory checks pass. No protected recovery gain is attributed to this
change. All 23 CTest suites pass.

The [retained capture](VMP_PARTIAL_STATUS_CAPTURE.json.gz) has SHA-256
`1792ba6f6292cbb49f6f17c9e67d65d0c4e916776432f6599c09d618495ba3d8`.
It contains source hashes, native output, four matched IDA probe/runner pairs,
the earlier fixture regression, and the protected-root and independent
decoder reports. The x86-64 and i386 fixture SHA-256 values are
`652c3541e1d314b160af6b799cf24aee3764463c6f60802a016529af90ba947b`
and `02c8e0cd5b7fcb1215385f011243d4c375bf700c16272c690aa42ead8bbc6481`.
The prior installed plugin is
`56d55e6d6a554207f1811d777158c54c00f30dab76eafd2f7155a0a8d2de1f8e`;
the measured candidate is
`840c735b894451d336b8fab25e2bf32ef99c1ce18ff70d86da0b66e802939527`.
The Linux cross-toolchain image ID and the IDA executable hash are retained
in the capture. Verify it with:

```sh
python3 -B tests/verify_partial_status_archive.py \
  --archive docs/VMP_PARTIAL_STATUS_CAPTURE.json.gz
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| F1 | Intel normal-completion logical flag rules apply to the admitted instructions. The ZF/SF/PF conclusions depend on this. | Compare the primary manual, execute all ten routines on both architectures and reject a `LOCK TEST` decode as a source of facts. Exceptional faults are outside the admitted fixture paths. |
| F2 | Unknown bits in a `Word` can vary independently. The three partial-flag rules depend on this abstraction. | Enumerate all 6,561 abstract byte profiles and every compatible concrete byte; reject any claimed flag that varies across completions. |
| F3 | IDA decodes each intended immediate, register width and prefix. The eight new facts depend on exact operand identity. | Hash the same binary across prior/current runs; inspect live proof sites and require the patched invalid-prefix instruction to decode as `TEST` with `aux_lock`. |
| F4 | Fresh IDA runs and unchanged artifacts establish the paired comparison. The proof delta depends on this. | Require runner input, script, plugin and IDA hashes, repeated stable queries and byte/comment inventories around the ten functions. |
| F5 | The selected protected root represents only one static normal-completion region. The no-gain statement depends on that scope. | Recheck all 97 nodes, four unresolved records and the independent decoder result; do not infer other paths or VM semantics. |

**High impact:** 16 newly measured native value proofs across two
architectures. **Medium risk:** partial memory operands and cross-path
relationships remain outside this transfer. **Low impact:** the selected
protected root's recovery is unchanged. The full review remains in progress.

QG1: technical scope only. QG2: F1–F5 include falsification probes. QG3:
portable, native, production IDA, invalid-prefix and protected regression
paths are covered for this change. QG4: counts and constant-space transfer
bounds are explicit. QG5: dynamic outcomes and protected abstentions remain
explicit. QG6: Intel's primary manual and hash-bound reports establish
provenance. QG7: memory, path and VM limits are stated.
