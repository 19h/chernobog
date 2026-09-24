# Cross-run consensus for variable read order

Exact heap reads can cover the same contiguous string span in different
execution orders across runs. The prior permuted-stream projector assembled
each run's bytes correctly but keyed consensus on the lowest-address read's
execution occurrence. In the new two-run regression that occurrence is 4 in
one run and 8 in the other, so the prior projector returned no candidate.

The consensus key now uses the first executed fragment's occurrence to identify
the stream and orders its fragment shape by address. The published witnesses
retain their actual lowest-address read occurrence, allocation identity,
sequence and full execution-order fragments. UTF-8 value agreement and all
existing lifetime, contiguous-coverage and write checks still gate publication.
The normalized key is internal; no event is rewritten.

## Independent observations

The native fixture selects offset order `3,1,6,0,7,2,5,4` or
`7,6,5,4,3,2,1,0` from its ABI input and reads all eight bytes at one static
instruction site. The process calls both modes and compares the assembled
scalar against an independently encoded oracle. On x86-64 and arm64 the
positive executable exits 0; changing only the expected value exits 1.
`strings` finds no `secret!` literal in the x86-64 positive binary.

In isolated IDA 9.4 SP1 runs, the installed prior plugin yields zero candidates
on each architecture. The modified plugin yields one `secret!` candidate:
four of four complete x86-64 runs and six of six complete arm64 runs, with
eight exact fragments per run. The arm64 corpus includes two additional
call-site inputs inferred by IDA. Each modified profile records first-read
offsets 3 and 7, one indexed-read ctree annotation, no stored comments,
unchanged function bytes, and key-edit revocation/restoration. All four matched
profiles pass nine probe checks. The earlier fixed-permutation x86-64 and arm64
fixtures each pass nine checks on the modified plugin. All 21 CTest suites pass.
Exact source, binary, tool, plugin and raw-report hashes are in
`VMP_VARIABLE_READ_ORDER_EVIDENCE.json`.

Reproduce one architecture with the exact fixture and installed plugin:

```sh
xcrun clang -arch x86_64 -O1 -g0 -fno-builtin -fno-unroll-loops \
  -D_FORTIFY_SOURCE=0 -Wl,-no_fixup_chains -Wl,-no_data_const \
  tests/vmp_native/native_permuted_variable.c \
  -o build/vmp-permuted-variable-reproduction
python3 -B tests/run_ida_smoke.py build/vmp-permuted-variable-reproduction \
  tests/ida_permuted_variable_probe.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --set CHERNOBOG_EXPECT_COUNT=1 \
  --output-dir build/vmp-permuted-variable-reproduction-ida
```

## Assumption register and bounds

| ID | Assumption and dependent result | Falsification probe or boundary |
|---|---|---|
| V1 | Complete temporal and data ledgers record the actual read bytes and relevant writes. The reconstructed value depends on this. | The independent native scalar oracle, corrupted-value controls, duplicate/hole/internal-NUL portable controls, and complete-capture checks probe it. A falsely complete ledger could invalidate the result. |
| V2 | The first executed read occurrence identifies the same logical stream across runs. Cross-run matching depends on this. | The two-run test varies the anchor occurrence from 4 to 8 while retaining the first read occurrence; both architectures witness offsets 3 and 7. Extra same-site reads before the stream may change the normalized occurrence and conservatively cause abstention. |
| V3 | One allocation generation contains the exact contiguous spatial span in each run. Publication depends on this. | Existing lifetime, overlap and quota regressions pass; a hole, duplicate, internal NUL or overlapping write vetoes the new portable consensus. Spatial gaps remain unsupported. |
| V4 | The measured IDA corpus exercises both control paths. The architecture comparison depends on this. | Each modified run reports its original fragment address; the observed first-read offsets include both 3 and 7. The probe compares candidate observations with the actual four- or six-run corpus. |
| V5 | Current IDB bytes and the consumed key match the evidence. Ctree display depends on this. | Both architecture probes verify unchanged function bytes, absent saved comments and immediate display revocation/restoration after patching the key byte. |

For completed streams with fragment lengths `L_1 ... L_C`, spatial shape
normalization adds `O(sum L_i log L_i)` time and `O(max L_i)` temporary memory.
Each run retains at most 4,096 use snapshots and each group at most 4,096
captured bytes; the coarse worst-case sorting bound is
`O(C * 4,096 log 4,096)` comparisons. The counts are bytes or events, not SI
physical quantities. The original bounded write scans remain unchanged.

**High impact:** a value observed through different indexed-read schedules can
now reach the same evidence-backed ctree site on x86-64 and arm64. **Medium
impact:** spatial gaps, multiple read sites in one logical stream, changed
first-read occurrence and other architectures still abstain. **Low impact:**
shape sorting adds bounded per-candidate work without extra persistent state.

QG1: no normative premise. QG2: V1–V5 include stress probes. QG3: variable
read-order consensus has portable, independent process, prior-plugin,
modified-plugin, fixed-order regression and UI evidence; the full review
remains open. QG4: byte/event limits, exact counts and complexity are stated.
QG5: divergent values, malformed spans and writes retain veto behavior.
QG6: local primary source, binaries, plugin, IDA and raw reports are hashed.
QG7: remaining stream shapes and sorting cost are bounded above.

Subsequent implementation: exact reads from two static sites within one
allocation generation are now grouped and displayed through a surviving exact
fragment-site ctree expression. See `VMP_MULTISITE_READ_STREAMS.md`. The
hashes and measurements above remain the historical variable-order checkpoint.
