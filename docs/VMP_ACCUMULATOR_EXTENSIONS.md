# Accumulator sign extension and retained native facts

Review rows 1b and 2a require exact register effects and independent flag
knowledge. The prior plugin treated `CBW`, `CWDE`, `CDQE`, `CWD`, `CDQ` and
`CQO` as unsupported instructions and discarded the entire abstract state.
The current local VMP emitter snapshot includes all six forms in its native
mutation templates. Its hash differs from the original review's recorded
`vmp/core/intel.cc` hash; both identities are retained in the evidence manifest.
No equality between those source revisions or their generated binaries is
assumed [S6].

## Production contract [S1–S3]

Both owned-function analysis and the read-only ownerless region analysis now
apply the following normal-completion transfers. Admission requires agreement
between IDA's instruction kind, execution mode, instruction size and exact
loaded bytes. Other prefix combinations remain unsupported; the ownerless
graph reports `unsupported_accumulator_extension_encoding` and stops before
subsequent uses.

| Instruction | Admitted bytes | Register effect | Modes |
|---|---|---|---|
| CBW | `66 98` | Sign-extend AL into AX; preserve the remaining accumulator bits | 32/64 bit |
| CWDE | `98` | Sign-extend AX into EAX; clear upper RAX in long mode | 32/64 bit |
| CDQE | `48 98` | Sign-extend EAX into RAX | 64 bit |
| CWD | `66 99` | Fill DX from AX's sign; preserve other destination bits | 32/64 bit |
| CDQ | `99` | Fill EDX from EAX's sign; clear upper RDX in long mode | 32/64 bit |
| CQO | `48 99` | Fill RDX from RAX's sign | 64 bit |

These instructions leave flags unchanged and do not write memory. Their
operand-size and sign-copy contracts follow Intel SDM revision 090,
Volume 2A, sections `CBW/CWDE/CDQE` and `CWD/CDQ/CQO`, pages 3-138 and 3-257.
Long-mode 32-bit writes follow Volume 1, section 3.4.1.1.
The [Intel SDM](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)
artifact is hash-bound in the evidence manifest. These facts do not describe
exceptional execution; Intel specifies `#UD` for a LOCK prefix.

The portable helper caches the input before an aliased accumulator write.
Each known low source bit remains independently known. The extended bits
become known only when the source sign bit is known. `CWD`, `CDQ` and `CQO`
therefore establish their complete written slice from a known sign bit even
when the other source bits are unknown. An unknown sign leaves that slice
unknown; a long-mode 32-bit destination still has known-zero upper bits.
Unaffected registers, abstract stack words, locally established memory and
CF/PF/AF/ZF/SF/OF remain intact.

```text
input := cached source word
written := destination slice mask
copied := low source mask for CBW/CWDE/CDQE, otherwise zero
destination := preserve bits outside written; copy known bits in copied
if input sign is known:
    fill written minus copied with that sign and mark those bits known
if long mode and destination width is 32 bits:
    set upper 32 destination bits to known zero
```

Each transfer uses O(1) time and O(1) additional space. Existing bounded
graph and fixed-point limits are unchanged.

## Measured controls [S1–S5]

The portable oracle intersects every compatible concrete completion for all
`3^8 = 6,561` partial byte states. It exhausts all `2^16 = 65,536` word
values in each mode for `CWDE` and `CWD`, including destination aliases and
unaffected slices. Separate sign-only, unknown-sign, 32-bit zero-extension
and 64-bit extension controls pass. The byte oracle scans `3^8 · 2^8`
candidates, with `4^8 = 65,536` compatible completions; this finite test is
not an exhaustive enumeration of 32- or 64-bit inputs.

The instruction oracle in `tests/vmp_native/sign_extension_asm.c` emits
literal GNU assembly from C string literals; it does not call the abstract
helper. Two native binaries execute fifteen recorded corner values under every
combination of the six status flags. The x86-64 binary checks
`6 · 15 · 64 = 5,760` instruction cases; the i386 binary checks
`4 · 15 · 64 = 3,840`. Each case compares accumulator and high-register
results, initial status bits and the complete captured before/after flags.
Each binary also checks a group of static controls over 512 signed inputs.
The reported totals are 6,272 and 4,352 check groups, respectively. x86-64
execution is translated on this arm64 host; i386 execution uses the pinned
QEMU container recorded by the runner.

Fresh IDA 9.4 SP1 runs use byte-identical binaries with the prior installed
plugin and the new plugin. The prior runs pass 48 x86-64 and 40 i386 checks;
the new runs pass 60 and 50. In each analysis path the prior plugin proves
none of the selected positive values, whereas the new plugin proves eight
x86-64 and six i386 values plus one stack-mediated transfer target. The
partial-AH `CWD` case proves DX from its known sign while AL remains
input-dependent. An input-dependent `CDQ` result remains unresolved.
Additional address-size prefixes before both opcode families abstain.
Ownerless calls preserve their checked item/byte/owner/comment/reference
inventory. An owned `CWDE`-to-`CDQ` byte patch immediately revokes the old
publication, then proves the changed zero result after analysis; restoring
the opcode recomputes the one result. Full save/reopen, rebase and undo
coverage for these additional forms remains unmeasured.

Matched prior/new inspection of `samples/foo_x86_vmp` passes 8/8 checks per
profile. Both reports are identical: 75 initializer nodes, 77 edges and
three unresolved facts, with unchanged IDB inventory. None of these 75
heads has an admitted accumulator-extension encoding. This sample therefore
shows no measured protected recovery gain for this change. All 21 configured
CTest suites pass after rebuilding the affected targets.

Reproduce the architecture and production checks with fresh directories:

```sh
python3 -B tests/run_sign_extension.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --linux32-image chernobog-vmp-linux32:test \
  --output-dir build/accumulator-extension-reproduction
ctest --test-dir build -R '^chernobog\.x86_abstract$' --output-on-failure
```

Use `--baseline` with the archived prior plugin to check the same binaries
against the previous behavior. Source, binary, plugin, runtime and report
identities are in `VMP_ACCUMULATOR_EXTENSIONS_EVIDENCE.json`; historical
manifests remain unchanged.

## Assumption register and bounded expansion

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| S1 | Intel normal-completion register and flag semantics apply in the admitted modes. All transferred facts depend on this. | Compare native results and all 64 status profiles; repeat on physical x86-64. LOCK-prefixed exceptional execution must not count as an admitted oracle case. |
| S2 | Loaded bytes, IDA decode and mode agree. Production admission depends on this identity. | Recompute opcode/size/mode; additional `67` prefixes before `98` and `99` must stop the ownerless graph and yield no owned exact value. |
| S3 | Word known/value masks represent independent canonical bits. Partial-register conclusions depend on this domain. | Intersect all compatible byte completions, exhaust signed words, test unknown and known sign bits, aliases, retained high slices and long-mode zero extension. |
| S4 | Hash-bound process and IDA artifacts describe the measured scope. Check counts and matched-plugin comparisons depend on this. | Rehash sources, binaries, tools and reports; reject a binary mismatch, changed native result or mutation of an inspected input/plugin artifact. |
| S5 | Current owned proof dependencies revoke changed bytes; selected ownerless inventory bounds the read-only claim. Lifecycle conclusions depend on those fields. | Patch `98` to `99`, query before analysis, recompute the different fact, restore, and compare inventories. Expand separate save/reopen/rebase controls before claiming the complete lifecycle matrix. |
| S6 | The current emitter's six mutation templates are relevant to future corpus coverage. VMP-specific expected benefit depends on this. | Pin both source hashes, generate paired fixtures with recorded settings and inspect actual emitted heads. The supplied initializer contains none of these admitted forms; broader protected gain remains unknown. |

**High impact:** per-bit sign extension retains facts through all six
accumulator forms. **Medium impact:** a known sign can supply an exact
high-register value without a complete source value. **Medium impact risk:**
translation-specific oracle behavior and the distinct emitter snapshot require
separate physical-machine and paired-source controls. **Low impact:** other
prefix combinations remain explicit abstentions. Wider protected effectiveness
and the complete review remain in progress.

QG1: technical claims only. QG2: S1–S6 include falsification probes. QG3:
all six admitted forms, both modes, partial knowledge, native flags, owned and
ownerless facts, mutation freshness and the protected control are covered at
the stated scope. QG4: integer counts, bit/byte units and complexity are
explicit. QG5: unknown signs, unsupported encodings, translation and source
revision differences retain their bounds. QG6: Intel SDM and hash-bound local
primary sources/process reports establish provenance. QG7: protected gain and
remaining lifecycle/architecture coverage are explicit unknowns.
