# Partial facts across two x86 register operands

Review rows 2a and 2b require exact register facts and per-flag conditions
through native logical instructions. The previous production transfer kept
partial bits for immediate operands but discarded them when both operands
were registers and either value was not fully known. The new transfer reads
both register slices before the destination write and computes a partial
result for `AND`, `OR`, `XOR` and `TEST`.

For operand-known masks `K_a`, `K_b` and known-one masks `V_a`, `V_b`, all
restricted to the instruction width:

- `AND`/`TEST`: known ones are `V_a & V_b`; known zeros are
  `(K_a & ~V_a) | (K_b & ~V_b)`.
- `OR`: known ones are `V_a | V_b`; known zeros are
  `K_a & K_b & ~(V_a | V_b)`.
- `XOR`: known bits are `K_a & K_b`; their values are
  `(V_a ^ V_b) & K_a & K_b`.

`XOR` of an identical register slice remains exactly zero even if that
slice is unknown. `TEST` updates flags without writing either register.
Other operations write the partial result to the destination slice, keeping
unaffected bytes and applying architectural zero extension for a 32-bit
destination in x86-64 mode. ZF, SF and PF are then derived independently
from the partial result. These normal-completion and width rules follow the
[Intel Software Developer's Manual](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf),
Volumes 1 and 2, `AND`, `OR`, `XOR`, `TEST` and 64-bit register widths.

The portable oracle checks all `3^4 = 81` low-nibble abstract profiles on
each operand: `81^2 = 6,561` profile pairs and four operations, or 26,244
abstract results. It compares every compatible concrete pair, 262,144
result pairs across the four operations. The enumeration scans at most
`6,561 * 16^2 * 4 = 6,718,464` candidate pairs. Additional controls cover
poisoned unknown bits, identical-slice XOR, `AH`/low-byte offsets, 16-bit
partial writes, x86-64 zero extension and invalid slices. Each production
transfer uses `O(1)` time and space for a fixed x86 operand width.

An independent native fixture checks 330,752 results per architecture:
12 one-input routines over all 256 byte inputs and five two-input routines
over all `256^2 = 65,536` input pairs. It runs as x86-64 on macOS under
the arm64 host's translation facility and as i386 Linux under QEMU user
mode. Fresh IDA 9.4 SP1 runs use the same binary and probe for the preceding
installed plugin and the candidate plugin on each architecture.

| Production result | Prior proofs per architecture | Current proofs per architecture |
|---|---:|---:|
| Register `AND`/`OR`/`XOR` value and flag facts | 0 | 9 |
| Register `TEST` and reflexive `AND` facts | 0 | 4 |
| Reflexive `XOR` exact zero control | 1 | 1 |
| Three input-dependent controls | 0 | 0 |

Thus 13 `SETcc=1` facts per architecture, 26 total, are new. Four of the
new sites have **two partially known inputs**. The three negative controls
include `TEST` of two independently input-dependent low bits; actual native
outputs contain both zero and one. The preceding partial-status fixture
still passes on both architectures. The exact historical protected 97-head
root still reports three unknown conditions and one unresolved PUSH/RET
target; independent Capstone verification and the read-only IDB inventory
check pass. No protected recovery gain is attributed to this change. All 23
CTest suites pass.

The [retained capture](VMP_REGISTER_LOGIC_CAPTURE.json.gz) has SHA-256
`69f748674c605143fa5fc20de6f7032fac7e5f74aeb767908f9ce4236aaba08c`.
It contains source hashes, native output, four matched IDA reports and
runner manifests, two prior-status regressions, and the protected-root and
independent decoder reports. The x86-64 and i386 fixture SHA-256 values are
`94847143669d368de79e42e003398408c1bdefcf36e2cdcf1bc6dca8b91856ad`
and `942a36b341f3063cb4c360034d9c6320779fe32ef85e2b6a4c2ffdee6333f752`.
The predecessor plugin is
`ae7c0ad6c0ec022e89fabaed9e244e394f78b16df79121ae65fd4ba03fb03307`;
the candidate plugin is
`8d88cd46e0f6eb9874b4a3de7fe5c738b9407c7c9edca5e8034bf2255b542dea`.
The capture records the IDA executable hash and pinned Linux image ID.
Verify the archive with:

```sh
python3 -B tests/verify_register_logic_archive.py \
  --archive docs/VMP_REGISTER_LOGIC_CAPTURE.json.gz
```

Four separate mutations of the retained proof value, dynamic-control
record, binary identity and protected node count are rejected by the
verifier.

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| R1 | Intel normal-completion bitwise and register-width rules apply to the admitted instructions. All derived results depend on this. | Check the primary manual, execute both native architecture matrices, and retain unsupported prefixes/faults outside the admitted paths. |
| R2 | Unknown bits of distinct abstract registers may vary independently, while an identical slice is correlated with itself. The partial-result equations depend on this. | Compare all 6,561 nibble-profile pairs against concrete pairs; require reflexive XOR to be exactly zero and two-input dynamic `TEST` to remain unresolved. |
| R3 | IDA's decoded register slices and instruction widths match the fixture. The 26 new facts depend on this. | Hash each same-binary prior/current pair, inspect its function symbols and proof sites, and compare repeated read-only queries and byte/comment inventories. |
| R4 | Fresh IDA databases and unchanged artifacts establish the measured delta. The prior/current comparison depends on this. | Require runner input, plugin, script and IDA hashes and zero process/runner failures. |
| R5 | The selected protected root is one static bounded region. Its zero-gain result does not characterize other protected paths. | Require the exact 97 nodes, four abstentions and independent file-backed decoding before comparing this root. |

**High impact:** 26 additional measured local value proofs across two
architectures. **Medium risk:** register correlations beyond identical
slices, memory operands and cross-path relationships remain unresolved.
**Low impact:** the selected protected root is unchanged. Full review
implementation remains in progress.

QG1: technical scope only. QG2: R1–R5 include falsification probes. QG3:
portable, native, production IDA and protected regressions cover this
transfer. QG4: input and oracle counts and transfer bounds are explicit.
QG5: correlated identical slices and independently variable negative cases
are separate. QG6: Intel's primary manual and hash-bound local reports
establish provenance. QG7: memory, path and protected limits are stated.
