# Byte-count shift semantics in the complete MBA miss audit

This checkpoint extends the independent semantic miss checker for review row
4a. It accepts `m_shl`, `m_shr` and `m_sar` with a 1-, 2-, 4- or 8-byte value
and exactly one unsigned count byte. The value/result widths must match;
wider counts, effects and unsupported nested shapes abstain. Production
matching, verification and mutation are unchanged.

## Pinned integer contract

For result width w bits, count k in [0, 255], unsigned x and signed s(x):

| Operation | k < w | k >= w |
|---|---|---|
| SHL | `(x * 2^k) mod 2^w` | 0 |
| SHR | `floor(x / 2^k)` | 0 |
| SAR | `(s(x) >> k) mod 2^w` | all-one bits if s(x) < 0, otherwise 0 |

The local Hex-Rays SDK `intval64_t` operators are in `hexrays.hpp` (SHA-256
`7ced9073b5b1fe06357f51e5983e041cae0b6b0f8f69d790f443031ec05022ff`);
the guarded shift helpers are in `pro.h` (SHA-256
`2bc2eff3d473258204318afe355b965e67dfc292fe26f8ff9601f848bfc50565`).
The linked IDA `libida.dylib` SHA-256 is
`d9d66e2c276265a59a69db13a30ee39c9af8d733d6fc7183e5b678a08188ba96`.
The one-byte bound avoids the SDK helper's conversion of larger counts.

`mba_shift_sdk_oracle.cpp` executes those SDK operators at four widths, four
values and four counts (0, w-1, w, 255): 64 input rows and 192 results. All
192 agree with independent masked-integer and Z3-bitvector evaluation. One
altered SDK result is rejected. The exact 1,563-byte oracle output is
`VMP_MBA_SHIFT_SDK_ROWS.csv` (SHA-256
`bacdb52b40640dcda3d6a4da333bfd81db9487f7e4a3391a73b2b5f72e84a5f1`);
`VMP_MBA_SHIFT_SDK_AUDIT.json` records the check. These finite boundaries do
not enumerate all 64-bit values.

## Protected-matrix result

The source-pinned matcher matrix has 14,047 events and zero omissions. The
previous audit abstained on 61 shift roots and 42 shallow nested shifts. All
103 now refute replacement by any constant or a current same-width operand
under unconstrained snapshot bytes. None proves a new value reduction.
Complete totals are 13,393 refuted, 649 unsupported and five existing catalog
applications. There are 25,855 integer-replayed SAT witnesses and 1,377
rejected-rule counterexamples. The remaining abstentions are 341 unsupported
nested values/loads, 117 reserved or condition microregister cases, 117 nested
instruction shapes, 48 operand effects or storage kinds, and 26 nonzero root
instruction-property cases.

The complete 77,251,597-byte audit is retained as
`VMP_MBA_SHIFT_AUDIT.json.gz` (SHA-256
`1e898cdad7b4fa7876f24d9bd695a48da2010865e6b44713776d86d8872f318e`).
It contains 1,229 unique proofs, 9,724 candidate findings, captured inputs,
checker/Z3 hashes and integer witnesses. The captured report SHA-256 is
`b2a56f35acaf3983203b993fb33a1eab858167163b77d4e3dc94554677412cba`.
The original 40-process reports and paired quota controls are in
`VMP_MBA_COMPLETE_CAPTURE.tar.gz`; their source hashes are unchanged.

## Reproduction

```sh
c++ -std=c++17 -Wno-nullability-completeness -Wno-varargs \
  -I../ida-sdk/src/include \
  -L'/Applications/IDA Professional 9.4.app/Contents/MacOS' \
  -Wl,-rpath,'/Applications/IDA Professional 9.4.app/Contents/MacOS' \
  -lida tests/mba_shift_sdk_oracle.cpp -o build/mba-shift-sdk-oracle
build/mba-shift-sdk-oracle > build/mba-shift-sdk-rows.csv
python3 -B tests/verify_mba_shift_sdk.py \
  --sdk build/mba-shift-sdk-rows.csv \
  --fixtures build/flag-component-fixtures.json \
  --output build/mba-shift-sdk-audit.json
python3 -B tests/verify_mba_semantic_miss.py \
  --report build/mba-expanded-matrix-v2/protected_mba_analysis.json \
  --output build/mba-complete-shift-audit-replay.json
```

The fixture JSON is available in `VMP_INTEGER_FLAGS_CAPTURE.json.gz`; the
matcher report is in `VMP_MBA_COMPLETE_CAPTURE.tar.gz`. The component semantic
suite passes 569 controls, including rejected wider counts, nested shifts and
symbolic/integer boundaries. Audit elapsed time can differ on replay.

## Assumption register and bounded expansion

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| H1 | The pinned SDK shift operators describe captured microcode values; the 103 classifications depend on this. | Execute all three SDK operators at four widths and boundary counts; compare with independent integer and Z3 results. |
| H2 | An unsigned byte is the complete accepted count domain. | Reject wider counts and mismatched value/result widths; test count 255 and k=w. |
| H3 | Captured snapshot bytes are unconstrained normal-completion inputs. | Replay SAT witnesses with integer arithmetic; require separate reachability and alias evidence for native-path claims. |

| Impact | Remaining opportunity or risk |
|---|---|
| High | The 649 unsupported events require state, effect or deeper-expression contracts. |
| Medium | Wider shift counts need the SDK's large-count conversion behavior pinned before admission. |
| Low | This audit-only extension leaves production behavior unchanged. |

Quality gates: the analysis is descriptive; H1–H3 have falsification probes;
all 14,047 events reconcile; widths and counts are exact; unsupported cases
abstain; SDK executions, pinned artifacts and integer witnesses provide
provenance; remaining scope is bounded. Native reachability, faults, arbitrary
identities and protected recovery remain unknown.
