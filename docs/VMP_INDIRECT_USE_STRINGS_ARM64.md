# ARM64 indirect-call display control

The source fixture in `VMP_INDIRECT_USE_STRINGS.md` was also compiled as a
thin ARM64 Mach-O executable. Its two modeled `strlen` calls compile to `BLR`
register instructions. The production IDA 9.4 SP1 run reports two modeled
use strings and two transient ctree annotations. The previous plugin reports
the same candidates and zero modeled annotations on the same binary. This
measures ARM64 coverage for the indirect-call display rule implemented in
commit `b408e26a14ed92da4b97eca491553086e66d7b1c`.

| Check | Previous plugin | Installed `b408e26` plugin |
|---|---:|---:|
| Scheduled, returned, temporally complete runs | 4 / 4 / 4 | 4 / 4 / 4 |
| Allocation lifetimes | 8 | 8 |
| Modeled `strlen` candidates | 2 | 2 |
| Modeled ctree annotations | 0 | 2 |
| Probe errors | 0 | 0 |

Both probes require one ctree call per candidate site, a register call operand,
four observations in four eligible runs, no saved use comments, and unchanged
function bytes. On the enabled run, patching either the consumed key or the
dispatch pointer removes modeled display; exact byte restoration returns two
annotations. The native fixture exits 0. Separately corrupted first and
second value oracles each exit 1. Neither plaintext appears in `strings`
output. The updated probe also passes the original x86-64 fixture.

The fixture is independent source-built code. It does not establish literal
recovery in `samples/hikari-console-max-stable.uu`; that input's protector
settings and semantics are not independently attested.

## Assumption register

| ID | Assumption and dependent result | Stress test or limit |
|---|---|---|
| A1 | IDA's ARM64 ctree call EA corresponds to the `BLR` site. Both annotations depend on this. | The probe requires one ctree call per candidate site, a four-byte decoded instruction, and a register operand. A removed or reassigned call has no exact-site annotation. |
| A2 | The observed target binding and bytes represent each semantic use occurrence. The target labels and plaintexts depend on this. | Candidate callee and model kind are validated against retained bindings; all four runs agree. A changed dispatch byte revokes display. The conclusion is limited to the scheduled runs. |
| A3 | The source-built fixture's process oracle checks both decoded values. The native result depends on this. | Positive exit 0 and two separately corrupted oracle exits 1. The test does not cover a protector-generated ARM64 byte loop. |

## Reproduction and provenance

```sh
xcrun clang -arch arm64 -O1 -g0 -fno-builtin -fno-inline \
  -Wl,-no_fixup_chains -Wl,-no_data_const \
  tests/vmp_native/indirect_temporal_strings.c \
  -o build/vmp-indirect-temporal-arm64
python3 tests/run_ida_smoke.py build/vmp-indirect-temporal-arm64 \
  tests/ida_indirect_temporal_string_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/vmp-indirect-temporal-arm64-reproduction
```

The source, binary, IDA, plugin, runner, and probe identities are in
`VMP_INDIRECT_USE_STRINGS_ARM64_EVIDENCE.json`. The earlier x86-64 evidence
retains its historical probe-source hash.

## Bounded adjacent findings and quality gates

| Impact | Finding |
|---|---|
| Medium | The ARM64 fixture's two executed-read candidates also have surviving exact pointer expressions and display. This is separate from the modeled-call result. |
| Medium | Memory-indirect x86 calls, multiple targets at one site, and protected ARM64 string lifetimes remain unmeasured. |

QG1: No normative conclusion is required. QG2: A1–A3 identify assumptions
and stress tests. QG3: This validates ARM64 register-indirect display for
review item 3b; the wider review remains open. QG4: All counts are exact and
dimensionless; ARM64 instruction width is four bytes. QG5: The probe accepts
two-byte and four-byte register-operand call sites and requires exact
ctree use sites. QG6: Hashes and intact-run checks are in the linked evidence.
QG7: Adjacent findings are bounded by impact and input scope.
