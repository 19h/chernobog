# VMP review: native-analysis implementation checkpoint

2026-09-21. Full objective status: **incomplete, active**. The requirement ledger
is [VMP_IMPLEMENTATION.md](../docs/VMP_IMPLEMENTATION.md). This report verifies
the changes below; it does not imply protected-binary corpus coverage or full
VM recovery.

The subsequent get-PC and linked ELF32 checkpoint is documented in
[VMP_GET_PC.md](../docs/VMP_GET_PC.md), with separate artifact hashes and scoped
results. Historical hashes and run outcomes below remain unchanged.

The production plugin now uses a portable x86 flag model and a bounded,
single-entry instruction replay. It models all six arithmetic status flags,
all sixteen condition codes (including IDA mnemonic aliases), register slices,
constant arithmetic/logic/shifts, and the supported instructions' individual
flag effects. Unknown effects invalidate facts. CF survives INC/DEC; CMC
inverts it; SETcc writes 0 or 1; 32-bit register writes clear upper bits in
64-bit mode. Values are never inferred from initial writable-memory contents.

The native engine uses these facts for Jcc CFG metadata and SETcc/CMOV
annotations. It revalidates non-taken branch proofs after IDA's initial analysis
wave before restoring ordinary fallthrough edges. This handles IDA removing
nonpersistent `fl_F` edges after the instruction callback. No instruction bytes
are patched by this implementation.

Stack-mediated transfer classification records execution/operand widths, zero
net SP change, the retained stack write, target proof kind, defining instruction
addresses, register dependencies, and exact immutable-memory bytes. The IDA
adapter recovers adjacent `push register/memory/immediate; near ret` targets
when proved, annotates unknown candidates, and rejects extra return adjustment,
far returns, operand-size mismatches, and alternate entry into the RET. The
initial register replay is single-entry and at most 64 instructions. It does
not infer a unique target from repeated concrete witnesses.

**Verification performed**

This first-checkpoint table and its artifact hash are historical. The subsequent
lifecycle checkpoint below records the current artifact and additional checks.

| Check | Result and exact scope |
|---|---|
| Portable arithmetic | 4 operations × 256 left inputs × 256 right inputs × 2 incoming carry states = 524,288 cases, compared with independent integer/nibble/parity arithmetic |
| Executed x86 arithmetic | Same 524,288 cases compared with results and captured EFLAGS from an x86-64 executable on this macOS host |
| Executed x86 shifts | 3 operations × 256 values × 256 encoded counts × 2 initial flag states = 393,216 cases; every claimed defined flag and the result agree |
| Partial flag conditions | 3^6 = 729 known-zero/known-one/unknown profiles × 16 conditions = 11,664 profiles; consensus checked over every compatible complete flag assignment |
| Width and alias boundaries | 8/16/32/64-bit wrap and overflow, unknown carry/count, zero shift, undefined flags, AH/AL writes, EAX zero extension; executed SETcc and false CMOV r32 controls |
| Mapping counterexamples | Both false triple-NOT identities rejected for all 65,536 byte pairs; double-NOT identities accepted; constant-target masked-select counterexample checked |
| Sanitizers | Portable test executable passes AddressSanitizer and UndefinedBehaviorSanitizer on the arm64 host |
| Native flags in IDA | 33 cases pass at default depth 8 and at depth 64; a 40-NOP window remains unknown at depth 8 and resolves at depth 64 |
| Native stack transfer in IDA | 12 cases pass: 3 exact, 5 unresolved, 4 rejected; target function ownership retained |
| Broader CTest baseline | 12/12 pass, including static analysis, block merge, program model, evidence, rax hybrid, core, Z3, symbolic executor, and MBA catalog; 8.06 s reported for that single run |

The final IDA artifact for this checkpoint has SHA-256
`d4d331daa93784b18ed4c320cbf3417cb8a78c0a0a0735e2fa8b1191df53e343`.
The full CTest run preceded the final adapter-only BSWAP/PUSHA/POPA preservation
addition; the final artifact then passed the two 33-case flag smoke runs,
including the added BSWAP control, and the 12-case stack smoke. No whole-program
performance conclusion follows from these timings.

Retained isolated run artifacts:

- `"${TMPDIR:-.}"/chernobog-vmp-flags-validation-4`: default depth, 33 cases.
- `"${TMPDIR:-.}"/chernobog-vmp-flags-validation-5`: depth 64, 33 cases.
- `"${TMPDIR:-.}"/chernobog-vmp-stack-validation-2`: stack transfer, 12 cases.

Each directory contains `run.json`, input/plugin hashes, `ida.log`, and the
probe's structured records. Earlier failed smoke runs remain available under
`*-validation-1`; they exposed missing mnemonic aliases and lost fallthrough
edges and are not reported as successes.

**Reproduction**

```sh
cmake --build build -j 4
ctest --test-dir build --output-on-failure
xcrun clang++ -std=c++17 -O2 -Wall -Wextra -Wconversion -Wshadow -arch x86_64 -Isrc tests/x86_abstract_tests.cpp -o "${TMPDIR:-.}"/chernobog-x86-abstract-native
"${TMPDIR:-.}"/chernobog-x86-abstract-native
xcrun clang++ -std=c++17 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Isrc tests/x86_abstract_tests.cpp -o "${TMPDIR:-.}"/chernobog-x86-abstract-sanitized
"${TMPDIR:-.}"/chernobog-x86-abstract-sanitized
xcrun clang -arch x86_64 -g0 tests/vmp_native/flags.S -o "${TMPDIR:-.}"/chernobog-vmp-flags
xcrun clang -arch x86_64 -g0 -Wl,-no_pie tests/vmp_native/stack.S -o "${TMPDIR:-.}"/chernobog-vmp-stack
"${TMPDIR:-.}"/chernobog-vmp-stack
python3 tests/run_ida_smoke.py "${TMPDIR:-.}"/chernobog-vmp-flags tests/ida_x86_flags_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN"
python3 tests/run_ida_smoke.py "${TMPDIR:-.}"/chernobog-vmp-flags tests/ida_x86_flags_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --set CHERNOBOG_IDA_FLAG_SCAN_DEPTH=64
python3 tests/run_ida_smoke.py "${TMPDIR:-.}"/chernobog-vmp-stack tests/ida_stack_transfer_smoke.py --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN"
```

The standalone stack fixture executes only its three valid positive transfers
and returns zero if each returns the expected value. Unsupported/faulting
negative controls are decoded in IDA, not executed.

**Per-session lifecycle checkpoint**

This checkpoint is historical. Persistent ownership and later lifecycle results
are recorded in [NATIVE_PROOF_OWNERSHIP.md](../docs/NATIVE_PROOF_OWNERSHIP.md).

The native engine now retains at most 4,096 ownership records for its new
stack-transfer and flag facts. Records include supporting instruction bytes,
consumed memory bytes, selected-target bytes, permissions, execution bitness,
and code ownership. Byte patches, item destruction, new alternate entries,
write references, and segment permission changes revoke affected records.
Autoanalysis completion also checks current dependency bytes and ownership.
Reanalysis is queued at the original proof source and metadata site.

Revocation removes only edges inserted or promoted by the record and only the
exact comment line inserted by the record. Preexisting user edges, external
reassertions of a formerly owned edge, and user comment lines are preserved.
The flag consumer retains skipped instruction/data metadata rather than
retyping a gap that could not be reconstructed reliably after invalidation.

`ida_native_proof_lifecycle_smoke.py` passed 10 flag controls and 8 stack
controls in separate fresh IDA processes. These cover exact-to-unknown-to-exact
byte changes, alternate-entry addition/removal, external edge ownership,
comment preservation, pointer replacement/restoration, read-only-to-writable
permission changes, and a newly introduced write reference. The existing
33-case default-depth flag and 12-case stack probes also passed. CTest passed
12/12 in 8.16 s; this is one run, not a latency estimate. The runner's 11 unit
tests include path redaction while retaining hash-based artifact attribution.

Plugin SHA-256:
`3889ec077781062d828926405bd5a3c6f3766da183fc2a3285cbc11ada2e4721`.
Fixture hashes and individual assertions are in the relative run directories
`build/vmp-lifecycle-flags-run-1` and `build/vmp-lifecycle-stack-run-1`.
Regression runs are in `build/vmp-lifecycle-flags-baseline-1` and
`build/vmp-lifecycle-stack-baseline-1`. Report paths and known local roots in
runner console/log output are redacted; input, script, executable, and plugin
hashes remain exact. Configure `CHERNOBOG_IDAT` and `CHERNOBOG_PLUGIN` for the
local installation, then use the existing runner with the lifecycle probe.

Assumption L1: ownership records remain available for this engine session.
Dependent result: the tested revocation behavior. Falsification probes still
required include save/reopen, plugin reload, rebase, undo/redo, and legacy
metadata migration. That checkpoint did not persist its ownership
ledger and did not establish those cases. Assumption L2: the recorded byte,
permission, and topology dependencies cover the admitted local proof;
additional function-tail and SETcc/CMOV lifecycle controls remain required.

With F retained records and D dependencies per record, range invalidation costs
O(F·D) and byte freshness checks O(F·D·W), where each recorded dependency has
W ≤ 16 bytes. Storage is O(F·D·W); F is capped at 4,096 and each local replay at
64 instructions. The stack address calculation can retain separate base/index
definition lists. Large-corpus latency remains unmeasured. High-impact remaining
scope: persist metadata ownership and invalidate it across database relocation
and reopen before claiming complete lifecycle support.

**Assumptions and falsification probes**

| Assumption | Probe / limit | Dependent result |
|---|---|---|
| Instruction semantics follow ordinary x86/x64 user-mode rules | Executed arithmetic, shifts, SETcc and CMOV controls; widths/mode checks | Flag and register facts |
| A locally replayed prefix is single-entry and contiguous | Alternate-entry, call, unknown-register, unknown-count, alias, depth controls | Native condition and register-target facts |
| Read-only image bytes are admissible constants under the IDB memory model | Require positive read permission, no write permission, fully loaded same-segment range, no known write references; writable controls remain unresolved | Direct/indexed memory targets |
| A stack pair is not a general jump-byte replacement | Retain write size/offset, reject width changes/far returns/RET adjustment/alternate entries; native bytes untouched | Stack transfer metadata only |
| Small-width exhaustive tests do not prove every width or entire protected programs | Separate wider boundary cases and explicit remaining corpus work | Limits on the coverage claims above |

Time complexity of one local replay is O(D·R), with D ≤ 64 and fixed R = 16
general-purpose registers. Register/flag working state is O(R); retained
instruction provenance is O(D). Each condition checks at most 64 complete flag
states. Exact byte-pointer reads consume 4 or 8 bytes. No SMT solver or emulation
engine is invoked by this path.

Remaining work includes native 32-bit fixtures, broader generated and held-out
corpora, the additional get-PC/call-as-jump forms, persistent metadata lifecycle
and invalidation tests, dedicated microcode consumers, and every runtime-string,
visualization, and VM-region requirement in the ledger. Unknown cases are
abstentions, not recovered cases.

Quality checks for this checkpoint: assumptions and probes are explicit;
integer counts are exact; source/tests and isolated run records supply primary
provenance; positive and negative controls cover the stated slice. The complete
requirement-coverage gate remains open. High-impact adjacent finding: validating
the pure flag model alone would have missed IDA's delayed fallthrough removal.
