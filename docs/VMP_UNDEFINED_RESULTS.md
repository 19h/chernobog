# Closed dependence slices for undefined register results

Review rows 3a, 3b, 6a and V remain in progress. This checkpoint removes one
protected execution barrier under an explicit normal-execution contract.
The paired Mach-O corpus, binary hashes, native observations, baseline and
candidate captures are retained in `VMP_UNDEFINED_RESULTS_CAPTURE.json.gz`.
`VMP_UNDEFINED_RESULTS_EVIDENCE.json` records their provenance and audit results.

## Architectural and observation contract

The [Intel instruction reference](https://cdrdv2-public.intel.com/774492/325383-sdm-vol-2abcd.pdf),
BSWAP section, defines an undefined result for a 16-bit operand, preserves
flags, and specifies an invalid-opcode exception for a LOCK prefix.
An arbitrary emulator result therefore cannot establish a hardware register
value. The temporal API now accepts an exact operand-size override, optionally
a non-W REX prefix in long mode, only when a bounded dependence certificate
removes the entire destination GPR's uncertainty before observable use.
SP, unsupported prefixes and uncertified encodings retain their boundary.
Ordinary function capture and publication do not acquire this admission.

The certificate follows at most 64 instruction occurrences through fallthrough
and fixed direct jumps. It represents register aliases, full versus partial
replacement, conditional writes and six status flags independently. Additional
BSWAP16 occurrences introduce additional unknown GPRs. BSF/BSR destinations and
undefined flag results remain unknown until overwritten. Register intermediates
may carry uncertainty; an address, memory write, control choice or surviving
output may not. Calls, conditional branches, cycles and unsupported effects
reject the certificate. A full 32-bit write replaces a GPR in both supported
x86 modes, including zero extension in long mode.

No BSWAP16 value is assigned. The backend retains a private representative
while executing the admitted interval's other instructions. Every entered
instruction must still match its certified bytes and the native-region plan.
Unknown GPRs and affected flag-register observations are suppressed. A backend
stop before the next hook suppresses the union of possible pre-state and
post-state dependence, including newly derived registers. A stop inside a
slice cannot establish complete execution, complete temporal prefix or complete
final-register capture. Abstract instruction counts and certificates are
separate from backend instruction execution.

The string inspection includes abstract-step counts, slice counts and unfinished
slice status in each retained run. Its contract identifies undefined-result
modeling; the existing detail view exposes these fields. Completed observations
remain uses under explicit allocation, memset and free models. Native callee
equivalence, universal input coverage and logical VM identity remain unknown.

## Independent verification

`tests/verify_native_undefined_slices.py` checks certificate bytes against the
complete archived binaries, decodes operands with Capstone 5.0.7, and checks
value/address dependencies, destination widths and implicit flag dependencies
against a separate instruction-effect inventory. Its symbolic replay uses
arbitrary functions of the admitted inputs, rather than the production transfer
implementation. Partial and conditional writes retain the old destination;
undefined registers and flags receive independent fresh symbols in the two
executions. A counterexample query asks whether any observable operand,
unsuppressed intermediate or surviving output can differ. Only UNSAT passes;
each query has a 5,000 ms timeout. This proves dependence elimination under the
inventoried instruction effects, not numerical instruction execution or native
callee equivalence. The paired process and register-byte oracles independently
check the recovered concrete values.

The final candidate audit proves 26 distinct certificates comprising 232
instruction occurrences. Forty trace captures contain 172 entered abstract
steps. One safe symbolic control passes; four controls with an exposed register,
partial overwrite, unknown address or surviving flags are refuted. Runtime
controls cover private representatives, both x86 register widths, four- and
eight-byte return slots, absent certificates and interrupted dependence
propagation and the 64/65 certificate quota. All 23 CTest suites pass; the final expanded hybrid controls pass
separately.

| Binary label | Baseline completed runs / 4 | Candidate completed runs / 4 | Candidate instruction counts | Remaining stop |
|---|---:|---:|---|---|
| Original | 4 | 4 | 171 | Return sentinel |
| Mutation 0 | 4 | 4 | 303 | Return sentinel |
| Mutation 1 | 0 | 4 | 344 | Return sentinel |
| Mutation 12648430 | 4 | 4 | 331 | Return sentinel |
| Virtualization 0 | 0 | 0 | 2721 | Time budget |
| Virtualization 1 | 0 | 0 | 2809 | Time budget |
| Virtualization 12648430 | 0 | 0 | 40 | Uncertified BSWAP16 |
| Combined 0 | 0 | 0 | 2983 | Time budget |
| Combined 1 | 0 | 0 | 2758 | Time budget |
| Combined 12648430 | 0 | 0 | 4096 | Instruction budget |

Counts include explicitly reported abstract steps. Time-limited counts are
observations of this run, not deterministic execution lengths. Three independent
native process executions per binary agree with the unprotected main's two
eight-byte comparisons; two altered-oracle controls reject. All completed
candidate captures agree with both expected return registers, two released
allocation lifetimes, six modeled calls and the eight-byte return-stack delta.

The completed-run string inspection recovers `secret!` and `second!` for all
three mutation seeds with four witnesses per value. Protected completed-run
coverage rises from four to six of 18 expected value instances, and from eight
to twelve of 36 scheduled protected executions. Mutation 1's two values were
already available as incomplete-prefix observations in `VMP_PREFIX_STRINGS.md`;
this checkpoint establishes completed modeled execution for them. It does not
introduce a claim of new distinct plaintext or completed VM recovery.

## Bounds and assumptions

For D <= 64 and fixed R = 16 GPRs and F = 6 flags, dependence propagation and
cycle detection cost O(D log D) time and O(D) retained space, excluding decoder
cost. Encodings retain at most 15 bytes per step. The existing temporal API's
4,096-instruction request, 4,096-head plan, 64 observed-target extensions,
1,000 ms execution deadline and 64 entered certificates per run remain bounded.
These are distinct limits. Solver complexity is not claimed polynomial.

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| U1 | Normal flat user-mode execution excludes timing, asynchronous signal/debug contexts and privilege/segment transitions. All continuation claims depend on this. | Exact prefix and SP rejection; unrepresented instructions/control choices stop. No signal-context equivalence is claimed. |
| U2 | The whitelisted descriptors contain every dependence of the represented effects. Closed-slice admission depends on this. | Independent file-backed Capstone inventory, arbitrary-function symbolic proof, four refuted controls and unsupported-effect rejection. |
| U3 | Instruction bytes and the captured image remain the intended snapshot. All concrete observations depend on this. | Exact runtime byte gates; existing changed-code controls; string data/profile edits invalidate the retained lease and exact restoration revalidates it. |
| U4 | The paired fixed-seed corpus and explicitly bound ABI models describe these observations. Concrete recovery metrics depend on this. | Repeated protector hashes, independent native exits, altered byte oracles, four entry seeds, both return registers and complete allocation/release checks. Protector source-to-console and modeled-callee equivalence remain unknown. |
| U5 | Uncertainty remains private through interruption as well as normal completion. Register observations depend on this. | Budget stops after an unknown-to-register transfer suppress both registers; unfinished slices reject complete capture. Legacy and long-mode representative controls pass. |

Bounded scope: **high impact** dependence-safe continuation enables completed
mutation-1 observations; **medium impact** interruption suppression prevents
stale representative values from entering evidence; **high remaining impact**
time/head/extension costs, uncertified live results, real interpreter environment
effects and complete virtualization recovery remain open. Signal-context and
timing behavior require a different observation contract.

Quality gates: QG1 contains no normative conclusion; QG2 records U1-U5 and
their probes; QG3 covers this checkpoint and explicitly retains the full review
scope; QG4 reports integer counts, byte widths, ms limits and algorithm bounds;
QG5 retains unsupported and interrupted cases; QG6 pins source, binaries and
captures and cites the primary ISA contract; QG7 records impacts and remaining
work. This checkpoint does not complete the review.
