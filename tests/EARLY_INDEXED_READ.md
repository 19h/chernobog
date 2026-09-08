# Exact addresses for early constant reads

The preoptimized constant folder previously treated a unique native `dr_R`
reference as the effective address of every microcode load at that instruction.
An indexed load can have one reference to the array or jump-table base while its
runtime address still depends on an unknown index. Substituting the first entry
in that case changes the function.

The folder now obtains a load address from the actual microcode expression and
its bounded state of constants established earlier in the same block. Exact
stack-slot forwarding remains available. A native data reference alone supplies
no address proof. The forward evaluator also recognizes the full address of a
global, `mop_a(mop_v)`, independently of the global's contents; low-address and
undefined forms remain unresolved. The original address-of operand retains its
symbolic representation.

The benign fixture returns one of four distinct `uint32_t` values according to
an unknown input. The probe adds exactly one read reference from the indexed
instruction to the table base in a disposable database. The read must remain a
load. A second function reads element 2 at the exact address
`table + 2 × 4 bytes = table + 8 bytes`; that load must become the scalar
`0x3456789A`. A third function first loads the constant index 2 from memory and
uses it in the indexed address; both reads must fold to the same scalar. The
table and index use a separate translation unit, and LTO is disabled, so the
compiler leaves those reads available to the analysis pass.

## Reproduction

On the local macOS toolchain, build an x86-64 fixture and run it with the selected
IDA 9.4 plugin artifact:

```sh
cc -arch x86_64 -O1 -fno-lto tests/early_constants/indexed_fixture.c tests/early_constants/indexed_table.c -o /tmp/chernobog-early-indexed-fixture
python3 tests/run_ida_smoke.py --ida /path/to/idat --plugin /path/to/chernobog.dylib --output-dir /tmp/chernobog-early-indexed-validation /tmp/chernobog-early-indexed-fixture tests/ida_early_indexed_read_smoke.py
```

The probe writes `early_indexed_microcode.txt` before checking the result. RAX
is disabled by the runner's default. It modifies only the copied database's
xref metadata, not the raw fixture bytes.

The separate CFF regression checks every native switch case key after the
recorded table-lowcase normalization and its corresponding microcode target,
rather than only the number of cases:

```sh
python3 tests/run_ida_smoke.py --ida /path/to/idat --plugin /path/to/chernobog.dylib --set CHERNOBOG_CFF_REQUIRE_SWITCH=1 --output-dir /tmp/chernobog-cff-table-validation obfuscator_sample.uu.unpacked.elf tests/ida_cff_dispatcher_probe.py
```

`cff_dispatcher.json` records the LOCOPT block topology and instructions. This
assertion requires a LOCOPT-only dump; the optional `CHERNOBOG_CFF_DUMP_GLBOPT=1`
mode is for diagnosing later representations, not this regression assertion.

## Assumption register and bounded scope

- E1: The image's read and write permissions describe the memory during the
  analyzed execution. Database-memory constants require positive read permission,
  nonwritable storage, loaded bytes, and no recorded writes. The fixture uses a
  const table. Writable globals remain loads even without write xrefs; the
  [alias-store and call regression](EARLY_WRITABLE_READ.md) falsifies that older
  admission rule. Runtime permission changes remain outside this static model.
- E2: The effective address is represented by the evaluated microcode operands.
  The SDK identifies `mop_a` as an address operand and `mop_v.g` as the global's
  linear address. Low-address and undefined address-of forms are not evaluated.
  The fixed and known-index assertions test global-address and index propagation;
  the unknown-index assertion rejects inference from a base xref.
- E3: The compiler leaves the intended loads in the fixture. Separate compilation
  units and disabled LTO preserve this opportunity; retained preoptimized
  microcode is the authoritative check. Source syntax alone is insufficient.
- E4: Preserving a switch case map establishes the load-folding regression only.
  The reference selector has an unsigned range-check self-loop. The recurrent
  rewrite handler separately rejects that unsupported topology; proving the
  self-loop impossible for every rewritten incoming state remains separate work.
- E5: Live observations use the local IDA 9.4 runtime on arm64 macOS analyzing
  x86-64 inputs. Other runtime/platform combinations remain unmeasured.

The existing forward state restarts at each block, holds at most 256 register
constants, and bounds nested expression evaluation to depth 16. Removing the
xref scan does not increase those bounds. For I microinstructions, the register
analysis remains O(I) with those fixed bounds; ordered stack-slot operations
retain their existing size dependence. No elapsed-time speedup is claimed.

High impact correction: an array-base reference no longer destroys dynamic
indexed-load or switch semantics. Medium impact capability: exact global-address
expressions permit fixed loads without borrowing xref addresses. Medium impact
limitation: indexed addresses that cannot be proved constant remain loads.
The older vector/heavy smoke's original low-address fixture is unavailable in
the inspected corpus; its behavior under this change is unknown.

## Baseline evidence

On 2026-09-08, plugin SHA-256
`2880bea68c13e2887b687dccd729c0668d6d15ef76da682a6a042e5607cfa1ad`
failed both new assertions with status 6:

- `/tmp/chernobog-early-indexed-before-02`: the unknown-index read became
  `0x12345678`, the table's first entry. Fixture SHA-256:
  `a56a34cf1f59df052762388d928a5987abd16416ad221648c0a3b75dc43fb9dd`.
- `/tmp/chernobog-cff-table-regression-before-02`: the 249-case table lost its
  `m_jtbl` map and became an `m_ijmp` block with zero successors. Input SHA-256:
  `0504e7c58519da9bc2f45f84e4a264c5a3ba03ae4683e372570ba15999d0b17d`.

A control run with `CHERNOBOG_IDA_EARLY_CONSTANTS=0` retained the CFF table and
250 successors (249 case targets plus the default). Its artifact is
`/tmp/chernobog-cff-dispatcher-no-early-constants/cff_dispatcher.json`.

## Modified verification

On 2026-09-08, plugin SHA-256
`5e595e591de1ad3dd0f6012e4ce63b4bbaa0cc2ac2e758c235b0161cb6db3e28`
(build source fingerprint `dac1293b6fb0`, SDK `940`) passed both assertions:

- `/tmp/chernobog-early-indexed-after`: the unknown-index function retains its
  memory load, while the fixed and known-index functions contain the expected
  `0x3456789A` result without memory loads.
- `/tmp/chernobog-cff-table-regression-after-02`: all 249 normalized case keys
  map to their original native targets, and the switch retains 250 successors
  including its default. Native keys start at `0xE5A9399`; subtracting the
  recorded `switch_info.get_lowcase()` gives the LOCOPT table indices 0–248.

Each baseline/modified pair has matching input, executed-probe, IDA executable,
and Chernobog configuration digests. All artifact-integrity checks pass. The
full native plugin build and all nine CTest entries passed in the parent run
(7.53 s total for CTest). These correctness runs do not establish a speedup.
The standalone indexed fixture is compiled by the explicit command above;
it is not an additional CTest entry.

Provenance is the production forward evaluator, local SDK operand declarations,
reproducible fixture sources, copied live probes, and retained run artifacts.
Independent source review found no confirmed defect in this scoped change.
Quality review checks address-versus-content semantics, explicit unknown-index
rejection, retained fixed-load capability, exact target mapping, artifact
identity, stated model assumptions, and the separate unresolved self-loop proof.
