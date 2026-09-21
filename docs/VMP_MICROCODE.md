# CALL-context microcode stack effects

The legacy get-PC filter changed a decoded RET into JMP before standard
microcode generation. In an admitted function region, this omitted RET's POP.
The generated continuation consequently started with SP lower by one word.
The implementation now emits a natural-width `m_pop` followed by a direct
`m_goto`, preserving the standard generator's stack semantics.

The later conversion pass now accepts an initial `m_ijmp` with its preceding
effects retained, requires an exact destination block entry, and leaves
high-level `m_ret` contracts intact. Both paths require a current, uniquely
entered CALL context contained in the function. A tail may precede the function
entry address; the bounded search now handles that layout. Flowchart repair
also requires the uniquely entered context.

This is a further implementation checkpoint for requirement 1c. The full review
remains **incomplete and active**. Automatic region ownership, structural
rollback, stale inferred noreturn flags, and the wider lifecycle/corpus matrix
are still required. The earlier native checkpoint and its historical artifact
remain documented in [VMP_GET_PC.md](VMP_GET_PC.md).

**Verified behavior**

The independent fixture set contains four x64 and three ELF32 functions:
ordinary captured-PC return, stack-top return-address adjustment, a backward
tail, and a summary with a nonzero stack delta. The nonzero-delta continuation
explicitly restores its extra stack word before the outer return.

The capture probe first admits the known fixture gadget into the function when
necessary. This is explicit test setup, not evidence that automatic function
admission is complete. It records native SP metadata and initial microcode.
The verifier independently executes the captured scalar IR under a bounded
flat-memory model, rejecting unsupported operations and transfers. Comparisons
include SP, architectural registers present in the IR, represented status
flags, and every byte in a 128-byte stack window. State is checked both at the
first recovered continuation and at function exit. Reference SP, retained
CALL-slot bytes, and return value are checked against the fixture contract.

| Evidence | Result |
|---|---|
| x64 direct generator | 4 functions × 64 seeds × 2 boundaries = 512 matching state comparisons |
| x64 post-generation conversion | 512 matching state comparisons |
| ELF32 direct generator | 3 functions × 64 seeds × 2 boundaries = 384 matching state comparisons |
| ELF32 post-generation conversion | 384 matching state comparisons |
| Direct-target checks | Each admitted gadget return has exactly one direct branch to its specified continuation |
| Legacy negative control | 128 mismatching continuation-boundary states across 256 comparisons on two x64 functions. The final constant return alone masked the defect |
| Entry/region guards | Four alternate-entry and two cross-function return sites remain indirect |
| Executed effect oracle | Two x64 CALL contexts pass result, final SP, retained stack-slot bytes, and all six defined arithmetic-flag checks |
| Executed region fixture | All four x64 functions return the expected value; process exits 0 |
| Pseudocode | All seven functions reduce to returning 7 under the stated region/returning contracts, through both conversion paths |
| Native regressions | Existing 53-assertion x64 and 16-assertion ELF32 probes pass |
| CTest | 12/12 pass |

The 1,792 positive state comparisons use seed values 0–63. The seed supplies
deterministic initial register bytes and Boolean values for represented flags.
These are finite fixture checks, not held-out protector seeds or a general
equivalence theorem. Hex-Rays does not represent AF in the captured fixture IR;
the executed oracle checks AF along with CF, PF, ZF, SF, and OF.

The execution oracle is an x86-64 executable on the arm64 host through macOS
translation. ELF32 execution was not performed. The IR model follows the
standard Hex-Rays scalar stack lowering, including matched PUSH/POP elimination;
it does not prove physical dead-stack writes, fault equivalence, or concurrent
memory behavior. Native instruction bytes remain unchanged.

**Counterexample retained: stale noreturn metadata**

The unmodified ELF32 pseudocode check failed for the backward and nonzero-delta
functions after test-driven tail admission. Both retained `FUNC_NORET` despite
having no user type or noreturn address attribute. Requesting noreturn
reanalysis did not clear the flag. Their initial IR still passed the effect
comparison, while pseudocode incorrectly displayed empty noreturn functions.

The final isolated lowering test explicitly supplies the known returning-function
contract for ELF32 before requesting pseudocode. It records the prior flags
and the fact that the contract was supplied. This establishes conditional
lowering behavior; it does **not** establish automatic stale-metadata repair.
The failed run is retained in `build/vmp-microcode-return-reanalysis` and must
not be counted as a successful end-to-end result.

**Assumption register**

| ID | Assumption and dependent result | Stress test / falsification probe |
|---|---|---|
| M1 | The fixture's admitted native region is the decompiler's intended input | Record staged admission; test tails before the entry and nonzero SP deltas. Automatic admission and rollback remain separate obligations |
| M2 | A unique current CALL context supplies the return target | Alternate-entry and cross-function controls retain indirect transfers; ambiguous or unsupported contexts are rejected |
| M3 | Standard Hex-Rays scalar IR defines the comparison memory model | Independent bounded interpreter, explicit supported-operation set, stack-byte comparison, and legacy counterexamples. Faults, segmentation, concurrency, and physical dead-slot writes remain outside this IR claim |
| M4 | A returning fixture contract is available when requesting the ELF32 pseudocode result | Record original `FUNC_NORET` and explicit override; retain the failing unassisted run. Production noreturn freshness remains unresolved |
| M5 | The executed x64 oracle is independent evidence at its measured scope | Capture physical SP, stack bytes, result, and six flags. Distinguish translated execution from physical x86 hardware and from ELF32 decode-only tests |

Primary implementation references are the local SDK's `m_push`, `m_pop`,
`m_ijmp`, `m_goto`, `codegen_t::emit`, and kernel-register allocation contracts
in `ida-sdk/include/hexrays.hpp`, plus function-region/noreturn contracts in
`ida-sdk/include/funcs.hpp`. Exact SDK, source, executable, plugin, capture,
and verifier hashes are recorded in
[VMP_MICROCODE_EVIDENCE.json](VMP_MICROCODE_EVIDENCE.json).

The final plugin SHA-256 is
`ff7a167009b5bdf0e04c5353ce7e36082c1539eb0c656573c6d9ac44ffde6b19`.
Ten isolated final runs use `build/vmp-microcode-reviewed-` followed by
`64-standard`, `64-fixed`, `64-fallback`, `32-standard`, `32-fixed`,
`32-fallback`, `alternate`, `callee`, `native64`, or `native32`.
All have successful runner status, unchanged run artifacts, and no detected
IDA internal-error diagnostic. Legacy and failed diagnostic runs are separate.

**Reproduction**

Use the existing isolated IDA runner with locally configured `CHERNOBOG_IDAT`
and `CHERNOBOG_PLUGIN`. The capture probe accepts the following explicit test
settings:

- `CHERNOBOG_MICROCODE_FUNCTIONS`: comma-separated fixture function names.
- `CHERNOBOG_MICROCODE_ADMIT_GADGET=1`: admit the fixture's known gadget tail.
- `CHERNOBOG_MICROCODE_DECOMPILE=1`: require pseudocode returning 7.
- `CHERNOBOG_MICROCODE_RETURNING_CONTRACT=1`: supply the returning-function
  contract; used only by the ELF32 pseudocode controls.
- `CHERNOBOG_MICROCODE_ALTERNATE_ENTRY=1` or
  `CHERNOBOG_MICROCODE_CALLEE_ONLY=1`: stage the corresponding negative control.

Standard lowering disables both `CHERNOBOG_IDA_CALL_POP_CODEGEN` and
`CHERNOBOG_IDA_GENERATED_GOTOS`. The fixed-generator run enables only the first;
the fallback run enables only the second. Guard runs enable both.

```sh
cmake --build build --target chernobog -j 4
xcrun clang -arch x86_64 -g0 -Dmain=gp_fixture_main -c tests/vmp_native/get_pc.S -o build/get-pc-effect-fixture.o
xcrun clang++ -arch x86_64 -std=c++17 -O2 -mno-red-zone tests/get_pc_effect_oracle.cpp build/get-pc-effect-fixture.o -o build/get-pc-effect-oracle
xcrun clang -arch x86_64 -g0 tests/vmp_native/get_pc_regions.S build/get-pc-effect-fixture.o -o build/vmp-get-pc-regions
build/get-pc-effect-oracle
build/vmp-get-pc-regions
clang -target i386-unknown-linux-gnu -c tests/vmp_native/get_pc32.S -o build/vmp-get-pc32.o
clang -target i386-unknown-linux-gnu -c tests/vmp_native/get_pc_regions32.S -o build/get-pc-regions32.o
ld.lld -m elf_i386 -e _start --build-id=sha1 build/vmp-get-pc32.o build/get-pc-regions32.o -o build/vmp-get-pc-regions32
python3 tests/verify_get_pc_microcode.py build/vmp-microcode-reviewed-64-standard build/vmp-microcode-reviewed-64-fixed --require-direct
python3 tests/verify_get_pc_microcode.py build/vmp-microcode-reviewed-32-standard build/vmp-microcode-reviewed-32-fallback --require-direct
python3 tests/verify_get_pc_microcode.py build/vmp-microcode-reviewed-alternate --guards
ctest --test-dir build --output-on-failure
```

For each fixture/seed the verifier executes at most 128 IR instructions and
retains a fixed 128-byte memory window plus touched registers and two snapshots.
Its comparison cost is O(S·F·(N+W+R)) for S seeds, F functions, N ≤ 128 executed
instructions, W = 128 bytes, and R retained register bytes. This is a test bound,
not a production decompilation latency estimate.

Bounded findings: **high impact**, validating only final return values would
miss the legacy continuation-boundary stack error; **high impact**, correct
initial IR does not imply correct pseudocode when stale function metadata can
discard the body; **medium impact**, using the function entry as a lower address
bound incorrectly excludes backward tails. These findings remain within the
native-analysis scope. Full protected-corpus coverage and performance gains
remain unknown.

Checkpoint quality checks cover the stated contracts, finite calculations,
positive/negative execution evidence, and primary-source provenance. The full
requirement-coverage gate remains open; no complete-review claim follows from
this checkpoint.
