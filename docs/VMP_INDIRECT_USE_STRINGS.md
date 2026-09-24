# Observed indirect-call use strings

Review item 3b now displays modeled use-time strings on an indirect ctree call
when the current instruction at the exact use site decodes as an indirect call.
The displayed callee address is the target observed during execution. The
candidate already requires matching site, callee, argument, model kind,
allocation origin, and plaintext across every scheduled run. The display
retains the direct-call static callee check for direct calls. It changes no
ctree node, saved comment, function byte, or candidate publication rule.

The implementation decodes a candidate-bearing call site once per visited
ctree expression and accepts only register or memory indirect-call operands.
For `E` visited expressions, `C` published candidates, `S` candidate sites,
and `M` candidate comparisons at matched expressions, traversal costs
`O(E log S + M)`, with `M <= E × C`; the site map stores `O(S + C)`
references, excluding the existing bounded output text. An exact ctree call and valid
argument index are required. A modeled use whose call is absent from the
ctree receives no annotation.

## Assumption register and falsification probes

| ID | Assumption and dependent result | Probe or limit |
|---|---|---|
| A1 | The ctree call's EA identifies the executed native call. Both displayed modeled uses depend on this. | The fixture has exactly one ctree call at each candidate site, and both sites decode as two-byte register-indirect calls. A call removed or moved by decompilation receives no annotation. |
| A2 | The runtime use's callee is the observed modeled target, and four-run consensus excludes a target change for the same semantic use occurrence. The `observed-target` label depends on this. | The retained `UseSnapshot::semantic_key()` includes callee; both fixture candidates have four observations in four eligible runs. A target-changing control at the consumed dispatch pointer removes the annotations until its original byte is restored. |
| A3 | The consumed image and function profile remain current at print time. Display freshness depends on this. | Separate key-byte and dispatch-byte edits each remove the modeled annotations; exact restoration returns two. The prior direct-call probe additionally checks code and profile edits. |
| A4 | The fixture's decoded bytes and expected strings represent its native behavior. The plaintext oracle depends on this. | The unmodified x86-64 Mach-O executable exits 0; separately corrupted first and second value oracles each exit 1. Neither plaintext appears as a literal in `strings` output. |

## Production evidence

The fixture `tests/vmp_native/indirect_temporal_strings.c` independently
allocates, decodes, consumes through a volatile function pointer, erases, and
reuses two 16-byte allocations. Its machine code contains `callq *%rax` at
both observed sites. It is source-built test code, not protector output.

| Control | Observed result |
|---|---|
| Previous installed plugin, same binary and probe | Four returned and temporally complete runs, eight allocation lifetimes, two modeled `strlen` candidates, zero modeled ctree annotations |
| Modified production plugin, same binary and probe | Same execution and candidate counts, two modeled ctree annotations carrying `secret!` and `second!`, each labeled `observed-target=0x100001030` |
| Database byte edits | Key and dispatch edits each remove the modeled display; restoring the exact bytes restores two annotations. No saved or saveable use comments or function-byte changes. |
| Direct-call regression | The earlier `tests/ida_temporal_string_smoke.py` passes all 22 checks with the modified plugin. |
| Native and repository tests | Positive fixture exits 0; either corrupt value oracle exits 1; all 21 CTest suites pass. |

The baseline and modified IDA runs use IDA 9.4 SP1 on the same x86-64 Mach-O
fixture. Each runner reports intact input, copied script, plugin, and IDA
artifacts. Exact hashes and run records are in
`VMP_INDIRECT_USE_STRINGS_EVIDENCE.json`. Reproduce the production check with:

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-inline \
  -Wl,-no_fixup_chains -Wl,-no_data_const \
  tests/vmp_native/indirect_temporal_strings.c -o build/vmp-indirect-temporal
python3 tests/run_ida_smoke.py build/vmp-indirect-temporal \
  tests/ida_indirect_temporal_string_probe.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/vmp-indirect-temporal-reproduction
```

## Bounded adjacent findings

| Impact | Finding |
|---|---|
| Medium | The same native fixture publishes three executed-read candidates, but only one has an exact surviving pointer expression in its ctree. The unmatched read sites remain without display. |
| Medium | The probe covers x86-64 register-indirect calls through one global pointer. ARM64 `BLR`, memory-indirect x86 calls, multiple observed targets, and protected binaries remain unmeasured. |
| Low | Ctree text identifies an observed target for the scheduled runs; it does not claim a static or universal dispatch target. |

## Quality gates

QG1: No normative conclusion is required. QG2: A1–A4 list dependency and
falsification probes. QG3: This change covers indirect-call display within
review item 3b; the full review remains open. QG4: All counts are exact,
dimensionless run, allocation, candidate, annotation, and test counts. QG5:
Direct calls preserve static callee matching; indirect calls require exact
native instruction and ctree sites. QG6: The source, binary, plugin, IDA, and
probe identities are recorded in the linked evidence. QG7: Adjacent findings
are bounded above.
