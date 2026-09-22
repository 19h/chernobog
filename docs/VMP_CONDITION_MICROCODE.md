# Local SETcc and CMOV microcode consumers

Historical checkpoint: the counts and manifest below describe the initial
SETcc/register-source implementation. The subsequent memory-source consumer,
read/fault contract, expanded fixtures and current evidence are documented in
[VMP_CMOV_MEMORY.md](VMP_CMOV_MEMORY.md). Its results supersede the memory-source
rejection described in this archived checkpoint.

This checkpoint advances implementation-ledger item 2b. Chernobog now consumes
fresh local flag facts during instruction-to-microcode generation, before the
existing optimization pipeline. It does not establish completion of item 2b or
measure recovery on the supplied protected executable.

## Implemented behavior

`EarlyHexRaysAnalysis` handles SETcc byte destinations in registers or ordinary
memory, and register-source CMOV with 16-, 32-, or 64-bit operands in the
corresponding x86 execution modes. A known condition replaces SETcc with a byte
assignment of **either 0 or 1**. CMOV selects its source or old destination at
the native operand width. A temporary separates the read from the native
operand writer; false 32-bit CMOV in 64-bit mode still clears the upper half.
Intel specifies both this upper-half behavior and an unconditional source read
for CMOV. Memory-source CMOV therefore retains the standard generator.
[Intel SDM, CMOVcc](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf),
[Intel SDM, SETcc](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf).

The implementation uses the installed SDK's `codegen_t::load_operand`,
`store_operand`, and `emit` contracts. The accepted captures explicitly contain
byte writes to AL/AH, byte `m_stx` stores, and `m_xdu` for the 32-to-64-bit
destination write. No instruction bytes, function ownership, or persistent
value facts are changed by the consumer. Its counters are exposed as
`codegen_setcc` and `codegen_cmov` through `chernobog_early_stats()`.

`CHERNOBOG_IDA_CONDITION_CODEGEN=0` disables this consumer. The existing global
analysis/early-Hex-Rays disable controls still apply. The instruction filter
installs when either the condition consumer or the existing get-PC consumer is
enabled; the accepted condition runs explicitly disable get-PC code generation.
`CHERNOBOG_IDA_FLAG_SCAN_DEPTH` controls the prefix depth, default 8, clamped to
1–64 instructions.

Each generation recomputes the flag result from the current IDB. It requires a
function owner matching the MBA entry, rejects snippet mode, and verifies that
every supporting instruction lies in the decompilation ranges. The existing
local analyzer stops at alternate entries, calls, ownership/mode changes, and
unsupported block boundaries; unknown effects invalidate facts. LOCK/REP
prefixes in the target or retained support reject this consumer. SETcc with
segment overrides or non-native address size also retains standard generation.

## Reproducible evidence

`tests/run_conditions_microcode.py` builds independent instruction fixtures,
executes them, captures actual `MMAT_GENERATED` IR with the consumer disabled
and enabled, completes ordinary decompilation, and runs an independent scalar
IR interpreter. Its evidence manifest hashes the source files, plugin, SDK
headers, binaries, native observations, and IDA captures. The archived manifest
is `VMP_CONDITION_MICROCODE_EVIDENCE.json`; its artifact root is
`build/vmp-conditions-final`.

| Measurement | x86-64 Mach-O | i386 ELF |
|---|---:|---:|
| Fixture functions | 45 | 45 |
| Executed records: 45 functions × 128 inputs | 5,760 | 5,760 |
| Functions admitted by the consumer | 40 | 40 |
| Native-result/IR-effect comparisons | 5,120 | 5,120 |
| Captures per enabled/disabled mode | 50 | 50 |
| Complete decompilations per mode | 45 | 45 |
| Deliberately corrupted IR rejected | 3 | 2 |

Thus the accepted checkpoint contains 11,520 executed records, 10,240 effect
comparisons, 200 initial-microcode captures, and 180 complete decompilations.
The 1,280 records from five rejected functions per architecture are retained
observations, **not** successful transformation comparisons.

The fixtures cover all 16 condition codes under the known XOR flag profile,
both SETcc outcomes, AL/AH preservation, byte stores and guard bytes,
16-/32-/64-bit CMOV destinations as applicable, and false 32-bit CMOV upper-half
clearing. Inputs include zero, all ones, sign boundaries, byte/word boundaries,
and deterministic mixed-bit values. This is finite evidence, not exhaustive
64-bit input enumeration or both outcomes of every individual condition code.

Five initial rejection controls per architecture cover memory-source CMOV on
both outcomes, unknown flags, a prefix beyond the default depth, and an
alternate entry. Further captures patch the flag producer to an unknown-input
TEST, restore it, add/remove an alternate entry, and request snippet mode.
Rejected captures must match the disabled baseline's entire generated IR;
restored captures must match the initial replacement. Baseline native bytes
must match enabled native bytes. Corrupting a SETcc constant, AH alias, or
x64 zero extension must be detected by the independent verifier.

The interpreter checks the full destination register, every byte in a guarded
memory window, preservation of other represented general-purpose registers,
DS and five defined status flags at the condition boundary. Executed observations
independently check the return register, eight memory bytes and those five flags.
AF is undefined after XOR and is excluded. Unsupported IR is an audit failure.
The result is a normal-completion, flat-memory comparison, not an exception,
concurrency, or physical-hardware equivalence claim.

The host is arm64: x86-64 execution uses macOS translation; i386 execution uses
`qemu-i386` in the pinned Linux image recorded in the manifest. These are
independent of the production abstract evaluator but are not physical x86
measurements. Elapsed times and resident bytes in the manifest characterize
these runs only; no performance improvement is inferred. The final existing
CTest suite passes 18/18; its log is `build/vmp-conditions-final-ctest.log`.

Example reproduction, with the existing local executable variables configured:

```sh
python3 -B tests/run_conditions_microcode.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" \
  --output-dir build/conditions-reproduction \
  --linux32-image chernobog-vmp-linux32:test --docker-context orbstack
```

The output directory must be new. Omitting `--linux32-image` runs only x86-64.
The image recipe is `tests/vmp_corpus/linux32.Dockerfile`.

## Assumption register and falsification

| ID | Assumption / dependent result | Stress test or falsification probe |
|---|---|---|
| C1 | Current IDB ownership and code references describe all entries into the admitted local prefix; all folded conditions depend on this contract | Unknown-input patch, alternate-entry insertion/removal, ordinary alternate-entry fixture and snippet rejection pass. Undiscovered runtime entries remain outside the claim |
| C2 | SDK operand generation preserves native slices and destination-width effects | Actual generated AL/AH, byte-store and 16/32/64-bit captures agree with executed observations; wrong alias and missing zero extension are rejected |
| C3 | Observations describe normal completion in flat user memory; effect comparisons depend on this model | Guarded memory comparisons pass; both memory-source CMOV fixtures are unchanged. Faulting/segmented/volatile-memory equivalence is unknown |
| C4 | Translation runtimes execute the tested instruction semantics independently of the plugin | Native observations also agree with separately specified expected results. Physical x86 replication remains unknown |
| C5 | Current-generation recomputation prevents reuse of stale condition facts | Same-IDB patch/restore and code-reference insertion/removal controls pass. Complete close/reopen, rebase, undo and plugin-unload microcode coverage remains unknown |

For depth D ≤ 64 and architectural register count R, local replay storage is
O(D + R), including support addresses and the existing abstract stack. Excluding
IDA index lookup costs, replay and support checks cost O(D·R + X), where X is
the number of code-reference records inspected; condition evaluation considers
at most 64 flag assignments. Matching and application each recompute this
bounded prefix. This is not a bound on total function size or all xref fan-in.

## Bounded remaining work and quality gates

- **High impact:** preserve and validate unconditional memory reads before
  admitting memory-source CMOV. The current rejection is deliberate and tested.
- **High impact:** measure the consumer on source-emitted protected functions
  and extend the microcode lifecycle matrix. Current fixture results establish
  neither protected-corpus recovery rates nor complete item-2b coverage.
- **Medium impact:** extend native flag profiles and destination/address forms,
  and measure repeated prefix-replay cost. All-condition coverage under one
  profile does not close these dimensions.

QG1: no normative judgment is required. QG2: C1–C5 and falsification probes are
explicit. QG3: the scoped implementation and evidence are covered; the global
review remains incomplete. QG4: widths are in bits/bytes and counts are directly
reproducible. QG5: rejected effects and unknown dimensions remain explicit;
snippet-context reuse was found and guarded during the scope review. QG6:
Intel primary documentation, installed SDK contracts and hashed observations
support the stated claims. QG7: adjacent opportunities are bounded above.
