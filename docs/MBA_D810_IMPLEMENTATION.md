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
