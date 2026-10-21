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
recognized separately; a canonical register argument's eliminated spill requires
an initial direct store of its unchanged incoming register and read-only reuse.
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
