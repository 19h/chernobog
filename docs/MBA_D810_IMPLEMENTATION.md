# D810 corpus implementation contracts

This document records changes prompted by the four-binary review. The original
review artifacts remain historical evidence. The frozen 42-fixture CoBRA
promotion manifest is unchanged; additional shapes are supplemental fixtures.

## Compound arithmetic words

CoBRA candidate preparation can expose repeated pure arithmetic operands as
virtual words. The view retains the original scalar widths and exact immutable
operands. Affine regrouping uses coefficients modulo `2^w` and exact `+1`/`-1`
elimination; it never divides by a non-invertible coefficient. A matched pair
`c-x` and `x-(c+1)` is represented by one word and its complement, including
wraparound at `c = 2^w-1`.

Virtual words never enter a program snapshot, proof receipt or SDK emission.
Before the existing candidate and emitted-IR proofs, the implementation proves
the view's candidate for independent arbitrary words, then separately proves
that restoring the view agrees with the actual source expression. Accepted
width-specific universal Boolean identities assist those proofs. Restored
candidates remain subject to strict full-expression and actual emission costs,
frame identity, generation, cancellation and deadlines.

The view refuses memory reads and retains the original typed boundaries. The
combined real-input/virtual-input count is capped at eight in Normal and twelve
in Deep. Each preparation stage has at most 512 visits and depth 64; restored
materialization is also bounded. Constant-masked regions retain the existing
semilinear path, and inner MBA regions remain visible to their own simplifier.
Preparation, generation and restoration share the existing candidate deadline;
the remaining site deadline still bounds all subsequent proofs and emission.

Serialized structural keys and bounded affine maps give worst-case
`O(A*N^2*log N)` preparation time and `O(A*N^2)` key storage for `N <= 512`
visited nodes and `A <= 12` admitted inputs. These are bounds, not a measured
latency guarantee. Search and solver work have independent existing budgets.

## Assumption register

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| W1 | A compound word is only a candidate abstraction; its actual operands remain immutable and typed. | Prove the arbitrary-word theorem and actual restoration bridge separately; require both original-site and actual SDK emission proofs. Reject corrupted references at every admitted byte width. |
| W2 | Arithmetic regrouping preserves modular coefficients, including wraparound. | Exercise reassociated sums, products, complementary subtraction constants, and `UINT64_MAX` at the admitted widths. No division of modular coefficients is used. |
| W3 | The view cannot hide source effects or evade raw admission limits. | Refuse a hidden `Load`, excessive real inputs, excessive materialization, cancellation and expiry. Keep typed boundaries and constant-mask preparation. |
| W4 | Earlier proved equalities are valid only in their owning solver session and snapshot. | Repeat the complete reference proof in a fresh analysis; retain cancellation, stale-generation, malformed mapping, wrong-destination and corrupted-emission negative probes. |

Bounded additional risks are admission drift (high: retain the frozen fixture
and fault matrix), loss of useful correlations from abstraction (medium: keep
masked and inner MBA structure visible), and misleading single-run performance
conclusions (low: distinguish proof/search time from full decompilation time).

QG1 requires no normative conclusion. W1-W4 and their probes cover QG2. Coverage
is reported separately for core, SDK, installed plugin and native targets (QG3).
Widths are bits and budgets are measured in integer ns/ms (QG4). Unsupported,
late, cancelled or malformed work preserves the source (QG5). Validation binds
source and artifact identities (QG6), and the additional risks above are bounded
(QG7). A successful core test is not a claim of native corpus completion.

The candidate-view changes pass all 33 portable CTest suites, including the
unchanged 42-fixture candidate matrix in both profiles. The licensed production
SDK bridge passes CoBRA Normal, CoBRA Deep, all existing negative fault probes,
Legacy Normal and Legacy Deep. New core cases cover five compound/reassociated
shapes at all eight admitted widths, both proof boundaries, a separately proved
reference in a fresh analysis, and corrupted-reference rejection.

The four original input files were also re-captured with the resulting build.
All six ARM64 hard-MBA fixtures have compact value forms in Normal and Deep.
`test_xor` and `test_mba_guessing` reduce to their XOR forms in both profiles in
each of the three x86-64 inputs. These observations address candidate preparation;
they do not claim that memory-value admission or small CFG coverage is complete.

## Ordered memory-value slices

A bounded straight-line ctree pass materializes each admitted ordinary read in a
private local, ordered by its original native instruction address. Every read,
store, original lvalue and retained statement property remains in the staged
body. The six `test_chained_add` reads illustrate why AST preorder is insufficient:
the required element order is `0, 2, 1, 1, 0, 2`. Arithmetic can disappear; an
unused read remains an explicit statement with its original address and type.

Candidate generation may reuse a materialized scalar only when its evaluated
symbolic value is structurally identical in the current byte-array memory
version, or is an exact numeral. Parameter pointers share the same array:
possibly aliased stores and partial overlapping writes receive no disjointness
assumption. The complete source prefix remains the input to the candidate proof.
The actual detached SDK RHS is independently lifted for the emission proof. An
already proved RHS may replace its equal private program definition for later
sites; these substitutions compose sequentially within the staged slice.

The typed scalar lifter is shared with caller-context analysis. It preserves
integer promotions, signed extensions, Boolean conversion, comparisons and
bounded constant shift counts. Calls and loads require their separate explicit
adapters; the pure binding interface accepts only this MBA's bound locals.

A final frame check reconstructs the entire staged body from immutable source
frames, exact read copies and actual SDK emission receipts. It checks the full
local-variable frame, including all exposed SDK property bits. Body, locals,
native bytes, MBA owner, generation, cancellation and the absolute deadline are
rechecked before the no-throw body/local swaps. Rejection installs no temporary
local and changes no source expression. The legacy fallback exemption remains
unchanged in its existing paths; this new staged pass uses a strict deadline.

Admission is limited to 64 straight-line statements, 4096 ctree nodes, depth 64,
64 total symbolic storage regions, 256 core statements and 16384 native bytes.
Addresses use an unchanged scalar pointer base and constant scaled offsets.
Calls, branches, loops, volatile types, overlapping/escaping/shared locals,
ambiguous/RMW/vector accesses, duplicate read addresses, native control transfer
and unrepresented memory effects are refused. Native access order is checked
against decoded instructions. Accessible, nonescaping private frame accesses are
recognized separately. Without an exact typed private frame member, a canonical
register argument's eliminated spill requires an initial direct store of its
unchanged incoming register and read-only reuse.
No general stack-relative operand is exempted from the effect inventory.

The generation-only value preparation has `O(V*R)` structural comparisons for
`V <= 512` expression visits and `R <= 64` materialized representatives. Native
inventory is linear in the admitted byte range; frame reconstruction is linear
in staged nodes. Z3 simplification and solver queries retain their independent
step, resource and deadline bounds; these structural bounds are not a solver
latency guarantee.

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| M1 | Ordinary memory follows the existing sequential byte-array snapshot model. No asynchronous writer changes an ordinary read between modeled events. | Keep volatile observations and unknown calls outside admission; havoc splits memory versions in core tests. Concurrent/external mutation requires an independent observation model and is not silently correlated. |
| M2 | IDA's safe nonescaping scalar locals denote accessible private frame storage. Parameter accesses do not alias that private storage. | Require SDK safety flags and native spill/frame recognition; refuse unrepresented accesses, overlapping locals and address escape. All parameter-to-parameter aliases remain possible in the SMT array. |
| M3 | Native instruction order is the relevant observable external-memory order within the admitted straight-line range. | Decode unique read addresses and widths; reject branches, calls, RMW, hidden effects and reordered/dropped/duplicated staged events. |
| M4 | Previously proved staged definitions remain equal under subsequent memory versions. | Keep exact store order and independently prove source/emitted RHS values; test possibly aliased partial writes, endian-dependent forwarding and havoc. |
| M5 | The source and actual emitted SDK frames remain immutable through commit. | Inject read address/width/EA, destination, body, local frame, generation, cancellation and post-proof expiry faults; require unchanged body and locals on rejection. |

Additional bounded risks are concurrent-memory assumptions (high, M1), private
frame interpretation (high, M2), and expression growth during store forwarding
(medium, bounded nodes/resources/deadlines). This pass does not claim an alias
partition beyond the private-frame contract or whole-native-function equivalence
for arbitrary external interleavings.

The memory changes pass all 33 CTest suites and the three core suites with CoBRA
excluded. The unchanged licensed five-mode SDK matrix passes, together with 44
supplemental memory probes (two controls and 42 negative probes). The latter
include malformed emitted frames, stale generations, volatile/unsupported
source admission, cancellation, and a deterministic 150 ms late proof under a
100 ms allowance. Rejected probes preserve both body and local-variable table.
The raw source-input cap is checked before generation-only value correlation.

Both memory fixtures simplify in Normal and Deep in each of the three original
x86-64 binaries. `tests/verify_mba_d810_memory.py` compiles those 12 actual captured
outputs with UBSan and checks 39936 deterministic result, store and memory-event
fault-prefix cases. This is an emitted-C oracle under M1-M2, separate from SDK
frame proofs and native instruction-byte immutability; it is not a claim of
arbitrary concurrent native execution equivalence.

## Bounded control-flow specialization

A separate ctree interpreter follows typed scalar state through complete paths.
It handles `for`, `while`, `do`, switch fallthrough, nearest-scope `break`, and
nearest-loop `continue`. It retains unknown data conditionals and specializes
both continuations. Unresolved loop/switch state, labels/gotos/assembly, resource
limits, or any failed proof discard the whole staged body.

Every removed guard or selected switch value has an independent candidate proof
and a proof of the actual detached SDK constant in its path context. A second
interpreter execution reconstructs the emitted body using the immutable proof
certificates and exact query programs. It checks all retained expressions,
destinations, types, addresses and properties. Native bytes, complete source
body/locals, owner, generation, cancellation and deadline remain commit gates.
Calls and other unsupported data expressions remain unchanged; their effects
invalidate scalar facts conservatively. No case-count, magic-value, recurrence
or diversity threshold in the existing classifier is relaxed.

A private assignment of a ternary value can be lowered to two assignments under
the original condition. Each selected arm is first converted to the ternary's
common type, preserving its subsequent assignment conversion. Private dead
scalar definitions are removed only after dependency liveness reaches a fixed
point. Potentially observable reads/calls, unsafe destinations and potentially
trapping expressions remain. A negative same-width signed literal retains an
explicit cast when its hexadecimal spelling would otherwise be unsigned C.

Switch selectors are limited to 32 or 64 bits; narrow case-value promotion is
outside this adapter. Bounds are 4096 source/output nodes, depth 64, 256 interpreter steps, 16 forks,
128 proof certificates and 16384 native bytes. Output growth is additionally
capped at `2 * source_nodes + 64`. A failed attempt uses at most 250 ms in Normal
or 1000 ms in Deep, capped by the remaining phase allowance. These are cooperative
deadlines: late results are rejected, not a hard scheduler latency guarantee.
Structural interpretation/replay is `O(S*N)` for `S <= 256`, `N <= 4096`;
liveness is bounded by 64 scalar regions. Search/SMT resources remain independently
bounded. All allocations and replay precede the body/local-table swaps.

The portable memory adapter also recognizes exact nonvolatile integral/pointer
members wholly inside IDA's private local-frame area when the compiler spill's
ctree local has been eliminated. It does not exempt arbitrary stack-relative
addresses. Ordinary-load opcode admission excludes acquire/exclusive/atomic
loads. M1-M2 continue to bound this interpretation of frame storage.

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| C1 | Safe scalar locals retain their values between copied statements unless an unsupported effect invalidates the context. | Address-taken/shared/overlapping/volatile state is excluded; mutable escaped-state and dynamic-loop controls reject the complete transformation. |
| C2 | A complete finite path can be specialized without changing its ordered data/effect expressions. | Replay every certificate against the same query and compare the complete staged body/locals; reject dropped, duplicated, changed and reordered frames, stale generations, cancellation and expiry. |
| C3 | Fixture references are specific to their binary and typed arithmetic. | The PE opaque-helper fixture uses XOR constant `0xCC8CAC2CD812A432`; Mach-O uses `0xCD455C2CD812A432`. Compile actual captured code under separate controlled helper bindings. Do not infer native equivalence from the C spelling of a signed literal. |
| C4 | Unbounded and unknown-state programs must retain their source behavior. | Reject real dynamic loops/switches, typed volatile state, escaped mutable state and an observable nonterminating cycle; no prefix of a failed specialization is installed. |
| C5 | Printed signed literals preserve the SDK expression's widening semantics. | Independently prove and compile actual SDK emissions for `0xFFFFFFFF`, `0x80000000`, and `0xADC07CB7` sign-extended from 32 to 64 bits. |

All 20 designated CFG functions in each of the original PE and large Mach-O
inputs lose their loops/switches in Normal and Deep (80 captures). The emitted-C
oracle checks 42496 cases with UBSan, using scalar inputs in `[-10000, 10000]` to
avoid signed C overflow in retained arithmetic. Its opaque helper reads use
controlled readable objects. The SDK path proofs use the complete admitted
bit-vector domain; the compiled oracle is a distinct, bounded check.

The original sample passes 116 supplemental SDK cases. The compiled ARM64
fixture passes 121 cases, including five rejection controls, plus three
independently proved signed-literal emissions. Cancellation/expiry injected after
the final emitted proof leaves the complete body and local-variable table
unchanged. The frozen 42-fixture promotion manifest remains unchanged.

## Region diagnostics and commit accounting

Each outcome event carries its own phase, source EA when known, ctree/microcode
maturity, source generation and mutation epoch, block/statement coordinates,
bounded structural region key, stage, and rejection/generation reason. Outcomes
separate extraction refusal, unchanged generation, generated candidates, generator
failure, verified/disproved/unknown proofs, exhaustion, emission rejection and
actual application. The pre-existing `last_*` fields remain compatibility fields;
they do not attribute an earlier region's outcome.

Every function budget retains at most 32 detailed events. Outcome counters remain
complete, with an explicit `unrecorded` count for omitted details. Counts describe
events, not distinct sites: one site can generate a candidate, pass both proofs,
and commit, or later expire. Keys are bounded FNV correlation identifiers, not
collision-resistant identity or proof authority. Diagnostic collection is
observational: resolver exceptions do not alter proof acceptance. Recording is
`O(1)` per event after bounded key construction; merging examines at most 32
stored events and the fixed outcome array. Storage is constant per function.

`catalog_applied`, semantic `applied`, ctree `cleanup_applied`, and
`handler_changes` describe their respective passes. Catalog and semantic
application events are recorded only after actual IR swaps. Progress messages
explicitly identify a handler pass or ctree snapshot and its generation; an early
zero-change pass no longer announces completion of the whole decompilation.
`tests/verify_mba_d810_diagnostics.py` checks actual capture schemas, complete
counter/detail/overflow accounting, and agreement between application events and
catalog plus semantic mutations.

Snapshot validation can execute a callback or substantial frame reconstruction.
The commit gate therefore polls cancellation again after that work, samples the
clock afterwards, then rechecks the cheap generation/owner token before swapping.
The intentional legacy deadline waiver still never waives cancellation. The
ordered-memory pass charges preflight and snapshot copying against its absolute
phase deadline. Its last analysis is accounted after the final gates so a late
rejection remains visible in diagnostics.

The complement view's arbitrary-word theorem retains a purely Boolean miter as
bitwise logic. Expanding that miter into modular products made the 64-bit selector
sensitive to native solver search scheduling on x86-64. Arithmetic views retain
the separately proved word identities. This changes proof preparation, with no
change to either proof boundary, site allowance, emission frame, or cost test.

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| D1 | Diagnostics describe individual immutable attempts and actual commits, not final-output quality by themselves. | Validate event coordinates/snapshot, exact counters plus overflow, and catalog-only rewrites in actual captures. Keep explicit compact-form and emitted-C oracles. |
| D2 | Expensive identity validation can observe cancellation or advance the deadline. | Cancel inside the unchanged callback, including the legacy-waived path; advance a deterministic clock by 150 ms under a 100 ms allowance. Require rejection. |
| D3 | Memory preflight/snapshot work consumes the same phase allowance. | Inject 150 ms before snapshot construction under a 100 ms budget; require no proof/emission visitation and unchanged body/locals. |
| D4 | SDK mutations occur on the owning analysis thread with generation changes for project-owned edits. | Revalidate complete frames/native bytes and the generation/owner immediately before commit; reject stale generations and changed source frames. This does not establish thread-safe mutation by arbitrary external plugins. |
| D5 | Native evidence must correspond to the exact artifact source and runtime. | Bind supplemental bridge/fixture hashes, embedded revision and source fingerprint, kernel/decompiler version, OS/architecture, exact 124-case matrix and three literal cases. Reject missing, duplicate, failed or mismatched evidence. |

The supplemental SDK matrix consists of 47 memory cases, 72 control cases and
five rejection controls, plus three signed-literal emissions. The native bundle
and strict six-target promotion checker require that matrix in addition to the
unchanged frozen 42-fixture Normal/Deep and legacy acceptance evidence. Synthetic
checker fixtures only test fail-closed validation; they are not native evidence.

Additional bounded risks are truncated detail history (medium: exact counts and
explicit overflow), accidental diagnostic influence (medium: isolated resolver
and fixed storage), and native solver scheduling sensitivity (medium: retain the
Boolean proof shape and qualify each native target). Core, SDK, corpus, emitted-C
oracle, installed-artifact and six-target results remain separate evidence
boundaries. Historical review artifacts retain their original source identities.

Native write-event matching uses the assignment expression's instruction EA.
A lvalue's EA can identify a separate address calculation, including GCC's LEA;
that metadata remains unchanged in the emitted frame. The native inventory still
requires every external write exactly once at the expected width and rejects an
unknown, displaced, unrepresented or read-modify-write store. The supplemental
constant-store fixture includes a corrupted-assignment-EA rejection probe.
Unknown expression EAs are serialized as `null`, including IDA's `BADADDR`
sentinel; they are never presented as physical addresses.

This write-anchor follow-up passes all 34 CTest suites and 37 runtime/checker
unit cases. Local licensed SDK probes pass the 124-case matrix on the compiled
Mach-O ARM64 and GCC-produced ELF x86-64/ARM64 fixtures. Production integration
captures cover both memory fixtures in Normal/Deep across the three supplied
x86-64 binaries and both ELF fixtures (20 captures); their emitted-C value,
store, ordered-read and fault-prefix oracle passes 66560 UBSan checks. Native
host execution remains a separate six-target qualification boundary.
