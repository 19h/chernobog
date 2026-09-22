# Memory-source CMOV: observable reads and fault ordering

The condition consumer now handles ordinary memory-source CMOV under an
explicit flat-memory model. A proven false condition still performs one read;
destination selection and any 32-to-64-bit zero extension occur only after
that read completes. Native instruction bytes remain unchanged. This advances
review item 2b; protected-corpus measurements and the complete microcode
lifecycle matrix remain incomplete.

## Production representation

The existing fresh flag analysis, owner/range checks, depth budget, snippet
rejection and disable controls remain in force. Memory sources must use native
address size with no segment override. Operand widths are 16 or 32 bits in
i386 mode, and 16, 32 or 64 bits in x86-64 mode. The SDK computes the effective
address; Chernobog emits one typed read before the selected destination write.
Intel specifies an unconditional CMOV source read and upper-half clearing on
false 32-bit CMOV in 64-bit mode.
[Intel SDM, CMOVcc](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf).

Final pseudocode uses `__chernobog_read_u16`, `__chernobog_read_u32` or
`__chernobog_read_u64`. These are **decompiler intrinsics**, not calls added to
the binary or recovered application functions. Their contract is:

```text
read_uN(address), for N ∈ {16, 32, 64}:
    attempt one N/8-byte read at address
    if inaccessible: fault before any architectural destination update
    otherwise return Σ memory[address+i] · 2^(8i), 0 ≤ i < N/8
    preserve memory, architectural registers and status flags
```

The result is an unsigned N-bit value. The consumer then writes that value for
a true condition, or the old destination at operand width for a false
condition. The native operand writer retains partial-register and zero-extension
semantics. The intrinsic's `const volatile` pointer type preserves read
observability; it does not change the IDB's memory qualifiers.

The helper is not marked pure or side-effect-free, spoils no architectural
registers, and initially declares all memory visible because its address is
generally symbolic. Memory barriers constrain reordering. Hex-Rays may narrow
visibility to live memory regions during optimization; the audited argument
pointer fixtures retain their `GLBLOW` dependency. This conservatively exposes
memory reads without inventing writes. The implementation follows the SDK's
helper-call, call-information and operand-generation interfaces.
[Hex-Rays SDK microcode interfaces](https://cpp.docs.hex-rays.com/hexrays_8hpp_source.html).

`chernobog_early_stats().codegen_cmov_memory` counts successful memory-CMOV
lowerings; these also contribute to `codegen_cmov`. The existing
`CHERNOBOG_IDA_CONDITION_CODEGEN=0` disables all condition lowering. If custom
generation declines, its appended microinstructions are removed before
requesting standard generation.

An initial experiment kept an ordinary `m_ldx` with persistence, barrier and
non-propagation flags. Actual `MMAT_GLBOPT3` and final pseudocode discarded the
unused false-path load. That representation was rejected. The accepted typed
intrinsic survives both optimization and final pseudocode, including when its
result is unused.

## Accepted evidence

The artifact root is `build/vmp-cmov-memory-accepted`; the archived manifest is
`VMP_CMOV_MEMORY_EVIDENCE.json`. `tests/run_conditions_microcode.py` reproduces
the complete build, execution, matched IDA runs and independent verification.
It records hashes for 20 source files, four SDK headers, the plugin and all
selected evidence artifacts. The same runner command documented in
`VMP_CONDITION_MICROCODE.md` now exercises this expanded suite.

| Measurement | x86-64 Mach-O | i386 ELF |
|---|---:|---:|
| Disassembled fixture functions | 53 | 53 |
| Executed ordinary observations: 51 × 128 | 6,528 | 6,528 |
| Functions transformed and independently compared | 48 | 48 |
| Generated-IR effect comparisons | 6,144 | 6,144 |
| Captures per run | 58 | 58 |
| Matched generated runs + two optimized runs | 4 | 4 |
| Complete decompilations per run | 53 | 53 |
| Protected-page observations | 144 | 144 |
| Observed read faults | 96 | 96 |
| Successful reads ending exactly at a page boundary | 48 | 48 |
| Ordinary-effect corruption controls rejected | 7 | 6 |
| Fault-order corruption controls rejected | 2 | 2 |

Totals are 13,056 ordinary observations, 12,288 effect comparisons, 464
microcode captures, 424 complete decompilations, and 288 page-boundary
observations containing 192 faults. Ordinary observations from three rejected
functions per architecture remain controls, not successful transformations.
Two additional segment/address-size controls are decoded and decompiled but
not executed. They retain the disabled baseline's entire generated IR.

The previous all-condition, SETcc, alias, register-CMOV, unknown-input, depth,
patch/restore, alternate-entry and snippet controls remain. New fixtures cover
true/false memory reads at every admitted width. Store–read–store fixtures
require the first value to be read and both stores to survive in order, even
when the false condition discards the read value.

Generated microcode is independently interpreted against executed results,
guarded memory, five defined status flags, and one ordered read event of the
correct address and width. The helper metadata must retain its read dependency,
lack architectural clobbers, and disallow side-effect-free elimination.
Unsupported IR fails verification. `MMAT_PREOPTIMIZED` and `MMAT_GLBOPT3`
captures each retain exactly one read for all eight memory fixtures; the
store-order controls and final pseudocode must also retain those reads.

The separate fault oracle maps two pages it owns and makes the second
inaccessible. For each of six memory-CMOV functions and eight destination
values, it tests zero accessible source bytes, N/8−1 accessible bytes, and
exactly N/8 accessible bytes. Signal-context observations record the faulting
instruction, fault-byte offset, complete destination register and five defined
flags. Both true and false CMOV fault at the expected read, preserving the
pre-read destination and flags. In particular, false 32-bit CMOV does **not**
clear the upper half before a failed read; it clears it after a successful read.

The initial-IR interpreter reproduces those fault observations and successful
boundary reads. Deliberately removing the read or inserting an architectural
destination write before it must fail. Other corruption controls detect wrong
constants, aliases, widths, lost zero extension, side-effect-free read metadata,
and missing memory dependencies. Fault-state equivalence is checked at generated
microcode; later-stage checks establish read retention and ordering, not
physical-register signal-context equivalence after optimization.

The host is arm64. x86-64 fixtures execute through macOS translation and i386
fixtures through the pinned QEMU Linux runtime recorded in the manifest. These
observations are independent of the plugin's evaluator, but physical x86
replication remains unknown. The existing CTest suite passes 18/18; its log is
`build/vmp-cmov-memory-ctest.log`. Recorded timings characterize these runs only;
no speedup or protected-corpus recovery rate is inferred.

## Assumptions, bounds and quality gates

| ID | Assumption / dependent claim | Falsification probe or remaining limit |
|---|---|---|
| M1 | Current IDB ownership and code references describe the admitted single-entry prefix | Existing unknown-input, patch, alternate-entry and snippet controls pass. Undiscovered runtime entries remain outside the proof |
| M2 | Native address size and flat segment bases describe the source address | Segment/address override controls reject. Non-flat segmentation, TLS overrides and other execution modes remain outside this consumer |
| M3 | One fixed-width little-endian read models ordinary memory | Width, read-count, guard-byte, store-order and page-boundary tests pass. Concurrent modification, MMIO transaction details and atomicity are not claimed |
| M4 | SDK operand/helper metadata preserves the stated data and effect dependencies | Real generated/optimized IR, final pseudocode, clobber/dependency checks and corrupted-IR controls pass. Forced SDK allocation failures were not injected |
| M5 | Translation and signal-context reporting reflect the tested x86 operations | Independently specified result equations and IR/fault models agree. Physical-hardware and other OS/SDK replication remain unknown |

Prefix costs and depth bounds remain those in `VMP_CONDITION_MICROCODE.md`.
Each admitted memory instruction adds one address calculation, one read
intrinsic and a bounded scalar destination write. The abstract read inspects
W ∈ {2, 4, 8} bytes, O(W) time and O(1) additional model state; this is not a
claim about real memory latency or full-function optimization complexity.

- **High impact:** protected-corpus recovery/error measurements and the full
  microcode lifecycle matrix still need authoritative evidence.
- **Medium impact:** conservative memory visibility can inhibit optimization;
  narrowing it requires an independently established alias bound.
- **Medium impact:** more address forms, flag profiles, physical hardware and
  OS/SDK versions would test generalization beyond the accepted fixtures.

QG1: no normative judgment is required. QG2: M1–M5 identify dependencies and
falsification probes. QG3: this checkpoint implements and verifies the admitted
memory-CMOV contract; the full review remains incomplete. QG4: widths, byte
offsets and counts are reproducible. QG5: the discarded-load counterexample
changed the implementation, and later-stage signal-state claims remain bounded.
QG6: Intel/SDK primary sources and hashed executed observations support the
claims. QG7: adjacent opportunities are bounded above.
