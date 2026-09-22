# Paired protected corpus

The x64 corpus now contains an original executable and nine protected variants:
mutation, virtualization, and combined protection, each with three generator
seeds. All 30 executions match an independent integer oracle and the corresponding
original stdout, covering 16,800 observation records. Each protected artifact was
generated twice with identical SHA-256. This establishes a behavior-checked input
corpus for Chernobog recovery evaluation. Recovery accuracy remains **unknown**.

Primary evidence is `build/vmp-corpus-release/corpus.json`; its hash, source
provenance, artifact inventory and limitations are retained in
[VMP_PAIRED_CORPUS_EVIDENCE.json](VMP_PAIRED_CORPUS_EVIDENCE.json).
The runner is [run_vmp_corpus.py](../tests/run_vmp_corpus.py), with independent
assembly fixtures in [pair.S](../tests/vmp_corpus/pair.S). No Chernobog production
analysis implementation changed at this checkpoint.

**Experiment and observed contract**

Only `corpus_transform` and `corpus_branch` are selected for protection. Both
read a 32-bit memory word, XOR an input, rotate left by five bits, add a second
input modulo 2^32, store the result, and return it. The branch routine selects
the XOR operand using unsigned input comparison. The unprotected capture wrapper
samples RAX, CF/PF/AF/ZF/SF/OF, caller stack-pointer delta, the output word, and
two adjacent guard words. Flags are sampled before any caller instruction that
changes flags; all six sampled flags are defined by the final ADD. The Python
oracle computes arithmetic and flags directly without using Chernobog's decoder,
emulator, abstract interpreter, or SMT summaries.

Each input seed produces 6^3 = 216 corner triples and 64 xorshift32 triples.
Two functions give (216 + 64) × 2 = 560 records per execution. Ten binaries and
three input seeds give 10 × 3 × 560 = 16,800 records. After removing repeated
corners, each binary receives 816 distinct function/input tuples. Counts are
exact; finite sampling is not a universal equivalence proof. Guard checks do
not establish preservation of arbitrary memory, all registers, or exception
behavior. Stack delta is measured at the normal returning call boundary.

| Parameter | Recorded value |
|---|---|
| Format / execution | Mach-O x86-64; compatibility translation on arm64 macOS |
| Protector seeds | 0, 1; reserved evaluation seed 0xC0FFEE |
| Input seeds | 0x31415926, 0x9E3779B9; reserved evaluation seed 0xD1B54A35 |
| Project settings | Document version 2; protection, VM and procedure options 0 |
| CompilationType | Mutation 1; virtualization 0; combined 2 |
| Integrity | Original, protector, SDK, referenced sources and protected outputs unchanged during run |
| Repetition | Nine of nine protected outputs identical on two generation attempts |

Reserved seeds are explicit corpus partitions. They have now been evaluated;
there was no frozen Chernobog recovery experiment or independent blind test.
Repeatability applies to generation from the same compiled original, not an
assertion that every fresh compiler/linker invocation is byte-reproducible.

The source's `Core::Compile` resets its C PRNG seed to zero
(`vmp/core/core.cc`, near `rand_seed = 0`). Lua's POSIX PRNG can use a different
generator (`vmp/third-party/lua/lmathlib.c`). Consequently, the harness supplies
the requested C seed through a test-only `srand` interposer. An independent
probe verifies that requesting seed 1 with override 17 produces the same four
`rand` outputs as an ordinary seed-17 call, and differs from ordinary seed 1.
Every recorded protector seed application must match the selected seed; the
Lua compilation callback also emits that seed. Native fixture execution uses
a separate environment without inherited loader-injection variables.

The compiler retains LC_UUID and uses `-no_fixup_chains`, `-no_data_const`, and
16,384 bytes of header padding to accommodate the supplied serializer. Selected
function bytes must change and remain in an initialized, file-backed text
section. Packing is disabled in the requested project options. Implicit
license-dependent flags and exact source-to-console build equivalence remain
**unknown**; neither is inferred from source filenames or requested options.

**Reproduction and limits**

Set `VMP_CONSOLE` and `VMP_SOURCE_TREE` to the local inputs, then use a new output
directory:

```sh
python3 -B tests/run_vmp_corpus.py --protector "$VMP_CONSOLE" \
  --source-tree "$VMP_SOURCE_TREE" --output-dir build/vmp-corpus-reproduction
ctest --test-dir build -R '^chernobog.vmp_corpus$' --output-on-failure
```

Seven harness tests cover manually computed flag corners, valid records, changed
observables and identities, malformed/truncated/extra records, environment
isolation, process limits/accounting, and Mach-O section bounds. All 18 configured
CTest tests passed in 8.98 s. Existing compiled tests were executed; this was not
a fresh rebuild of all production targets.

Each process records elapsed nanoseconds and peak resident bytes via `wait4`.
Convert elapsed time using seconds = nanoseconds × 10^-9. Native executions in
this run ranged from 0.024146500 s to 0.207443417 s and from 3,391,488 to
14,389,248 peak resident bytes. These are individual process observations,
including launch, translation and formatted output, with a 20 ms polling
interval; they are not recovery latency or speedup estimates. Timeouts and
the 2 MiB output threshold are polled limits, so temporary-file output can
overshoot before termination. Retained output is bounded per stream.

For N records of bounded width, oracle checking costs O(N) time and O(N) space
for the decoded records; at most 16 mismatch examples are retained. Artifact
hashing and section extraction add O(B) time and O(B) peak working space for
the largest loaded artifact of B bytes. These bounds exclude protector and
native process internals, whose resource use is measured separately.

**Assumption register and bounded scope**

| ID | Assumption / dependent result | Falsification probe |
|---|---|---|
| C1 | The supplied protector represents relevant transformations; vendor-specific conclusions depend on this. | Hash binary and source separately; compare emitted behavior. Exact build linkage remains unknown. |
| C2 | The independent arithmetic and capture wrapper describe the selected observable contract. | Manual corner values, original execution, all protected executions, and field-by-field rejection tests must agree. |
| C3 | C PRNG control suffices for repeatable generation in this environment. | Verify the interposer and every seed marker, then compare complete repeated output hashes. Revalidate after toolchain or protector changes. |
| C4 | Compatibility execution implements the tested normal x64 cases. | Repeat on physical x64 hardware before claiming hardware-independent coverage; that result is unknown. |
| C5 | These small arithmetic functions are corpus infrastructure, not representative coverage. | Add x86-32, string lifetimes, recognizer negatives and measured analysis outcomes before broader acceptance. |

High impact: a behavior-correct protected binary can still defeat CFG recovery;
oracle correctness must remain separate from recovered-edge and false-edge
counts. Medium impact: generator seed resets can silently collapse a randomized
test matrix; whole-artifact repetition checks expose only the tested environment.
Medium impact: loader compatibility settings affect whether a fixture is usable
before analysis begins. No packing recovery or licensing changes are included.

QG1: technical scope. QG2: C1–C5 include falsification probes. QG3: this x64
behavior-corpus checkpoint is covered; the full review remains incomplete.
QG4: integer counts and resource units are explicit. QG5: finite sampling,
ABI/memory limits and translation are not generalized. QG6: local primary
source and artifact hashes are recorded. QG7: adjacent risks are bounded above.
Remaining acceptance work includes x86-32 and Chernobog edge coverage, false
edges, unresolved candidates, literal accuracy, solver rejection reasons and
analysis resource measurements.
