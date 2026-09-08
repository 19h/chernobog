# Early constant reads from writable memory

The preoptimized constant folder admitted loaded database bytes when their
addresses had no recorded `dr_W` references, including bytes in writable
segments. An indirect store can modify those bytes without such a reference.
Clearing tracked registers and stack slots after a store or call does not
prevent a subsequent fixed-address load from reading the unchanged IDB value.

The independent fixture demonstrates two cases:

- `early_alias_store_then_read(pointer, value)` stores through its pointer
  argument, then reads a writable global initialized to 7. Calling it with
  that global's address and value 11 must return 11.
- `early_call_then_read(value)` passes another writable global's address to
  a separately compiled mutator, then rematerializes the global address and
  reads it. The global is initialized to 9; passing 13 must return 13.

The native executable checks those results and two controls, returning zero
only when all four match. The IDA probe verifies loaded bytes, original segment
permissions, absent write references, and the native load instructions before
inspecting their preoptimized microcode. It does not edit xrefs, permissions,
or input bytes.

`read_constant_memory()` now requires positive `SEGPERM_READ` and absence of
`SEGPERM_WRITE`. Unknown permissions and execute-only segments do not satisfy
that condition. The existing scalar widths (1, 2, 4, or 8 bytes), loaded-byte,
single-segment, nonexternal, and known-write-reference checks remain. Effective
addresses still require the microcode proof introduced by the indexed-read
correction. The separate stack-slot lookup precedes database-memory admission
and is unchanged.

## Reproduction

```sh
cc -arch x86_64 -O1 -fno-lto tests/early_constants/writable_fixture.c tests/early_constants/writable_data.c -o /tmp/chernobog-early-writable-fixture
/tmp/chernobog-early-writable-fixture
python3 tests/run_ida_smoke.py --ida /path/to/idat --plugin /path/to/chernobog.dylib --verbose --output-dir /tmp/chernobog-early-writable-validation /tmp/chernobog-early-writable-fixture tests/ida_early_writable_read_smoke.py
```

The fixture uses Clang's `optnone` attribute to preserve the call's subsequent
address materialization and the stack control's native store/load. The global
objects are ordinary, nonvolatile `uint32_t` objects. Separate translation units
and disabled LTO preserve the memory-read opportunities. RAX is disabled by the
runner's default.

The probe saves `early_writable_report.json` and `early_writable_microcode.txt`
before its writable-load assertions. Successful runs also save the stack
control's final pseudocode. The runner's `run.json` identifies the exact binary,
plugin, probe, IDA executable, configuration, and artifact integrity.

## Assumptions and falsification probes

- W1: The database's positive read and nonwrite permissions are the premise
  for treating its loaded bytes as constants. Writable-global counterexamples
  test the rejected case; the readonly control tests retained admission. Medium
  impact limitation: this does not establish operating-system immutability or
  address readonly MMIO/volatile semantics.
- W2: The native load survives compilation and the aliasing writes lack `dr_W`
  references at the globals. The probe checks both rather than inferring them
  from C syntax. The native executable supplies an independent result check.
- W3: Clearing block-local state is insufficient to establish global
  immutability across calls, predecessor blocks, or prior invocations. The call
  fixture rematerializes its address after the call, so loss of a cached
  address register cannot accidentally conceal the defect.
- W4: The stack control verifies native and final scalar results. Hex-Rays
  canonicalizes its frame accesses to `%var_4` moves before the inspected
  maturity; this fixture does not directly exercise the raw `m_ldx` stack-slot
  forwarding branch. That branch and its ordering are unchanged by this fix.
- W5: Live observations use IDA 9.4 on arm64 macOS analyzing x86-64 input.
  Other host/guest combinations remain unverified by this fixture.

High impact correction: an indirect store or call no longer permits writable
IDB initialization bytes to replace the subsequently observed value. Medium
impact limitation: writable load-time values without an immutability proof are
left as loads. The added permission check has constant time and storage cost;
the existing read/xref work and forward-state bounds are unchanged. No measured
speedup is claimed.

## Baseline evidence

On 2026-09-08, the native fixture exited 0. Its SHA-256 was
`b2cc32c7f482305cad20b01edbe4d84bec9324000a4d3bd3d9870b335961409d`.
The executed probe SHA-256 was
`7d670a34a29d207effba130761293ca91d26d5d7028d21b82593b549db38cce3`.

The preserved baseline plugin was copied before the source change to
`/tmp/chernobog-early-writable-baseline-artifact/chernobog.dylib`; SHA-256:
`5e595e591de1ad3dd0f6012e4ce63b4bbaa0cc2ac2e758c235b0161cb6db3e28`
(build source fingerprint `dac1293b6fb0`, SDK `940`).

`/tmp/chernobog-early-writable-before-02` failed with runner/process status 6.
Both globals had permission bits 6 (read/write), unchanged initial bytes, and
zero write xrefs. The alias load became `m_mov #7`; the after-call load became
`m_mov #9`. The readonly control still became `0x23456789`. All runner artifact
integrity checks passed.

The control run `/tmp/chernobog-early-writable-control`, using the same fixture,
probe, and baseline plugin with `CHERNOBOG_IDA_EARLY_CONSTANTS=0`, passed. Both
writable loads remained, and the final stack-control pseudocode returned
878082202 (`0x3456789A`). This changed-configuration control isolates the early
folder; it is not a timing comparison.

## Modified-plugin evidence

The matched run `/tmp/chernobog-early-writable-after` passed with runner/process
status 0 using plugin SHA-256
`dc88aca772593f79c8d4f113a3697ee165e5a14c51f72b86d004e149b7a99797`
(build source fingerprint `9108f9cbd7db`, SDK `940`). Each writable native read
retained one `m_ldx`, with no constant replacement at that instruction. The
readonly read retained the `0x23456789` fold, and final stack-control pseudocode
returned 878082202 (`0x3456789A`).

The before/after `run.json` records have identical input and probe hashes
listed above, IDA executable SHA-256
`387d681d6fb4f4c1c485a60025cae3f0affa6f5ea1efce3b1809639cb1aaeb28`,
and configuration SHA-256
`b1256521b6d90be3a772eaba3cc9473b6ff7f0d173e2ce2e8b32b1347b0cf8c7`.
Every artifact integrity check passed in both runs. This is a paired
correctness result; the single-run elapsed times do not establish performance.

## Integrated display verification

Plugin SHA-256
`901d114b02156e02695782415779b40422a6b7702c1e2c46ab78b1cdefe5ca1a`
(source fingerprint `7bc4785e3333`, SDK `940`) retains this permission correction
and adds [address-preserving CFString display](NUMERIC_CFSTRING_DISPLAY.md).
The following live probes passed on that artifact:

| Probe | Retained run directory | Verified behavior |
| --- | --- | --- |
| Writable reads | `/tmp/chernobog-lifecycle-writable` | Alias-store and after-call loads remain; readonly and scalar stack controls pass |
| Indexed reads | `/tmp/chernobog-lifecycle-indexed` | Unknown-index load remains; fixed and known-index reads fold |
| Native switch map | `/tmp/chernobog-lifecycle-cff` | All 249 normalized cases and default target survive |
| Bounded libc | `/tmp/chernobog-lifecycle-bounded` | Runtime search summaries recover the fixture string and invalidate after an input edit |
| UTF-8 | `/tmp/chernobog-lifecycle-utf8` | Initial/repeated literals, encoding, protected metadata, and invalidation pass |
| Aldaz display | `/tmp/chernobog-numeric-cfstring-aldaz-after-ui-03` | All 11 expected strings appear on both uncached displays; checked data bytes remain unchanged |

Each run has status 0 and passing artifact-integrity checks. For the first five,
input, probe, IDA, and configuration hashes match the preceding permission-fix
run. The Aldaz probe now inspects `get_pseudocode()` rendered lines, where
`hxe_func_printed` annotations live; direct `str(cfunc)` output prints the AST
and omits those decorations. The exact same revised probe fails with the
earlier permission-only artifact `dc88aca7…`, so this is a matched restoration
of displayed information. A separate diagnostic checks all seven transformed
address expressions and their individual annotation lines; none replaces an
object pointer with a C-string pointer. The numeric fixture report records
rejection and header-change controls. These concurrent correctness runs do
not establish a speedup or complete CFF unflattening.
