# Chernobog improvements from the supplied VMP tree

Reviewed 2026-09-21 against Chernobog commit
`c4440677e39f296e18bbd6f82eab50b878cebead` and the local tree
`vmp`. Source hashes and arithmetic-check results are in
[VMP_REVIEW_EVIDENCE.json](VMP_REVIEW_EVIDENCE.json).

The largest identifiable opportunities are native CFG recovery, per-flag x86
analysis, and temporally accurate string evidence. Full VM recovery requires a
separate analysis model. Expanding the MBA rule count alone does not address
these gaps. These are source-derived priorities; relative recovery rates and
speedups are **unknown** until measured on protected fixtures.

Subsequent fixture inspection: the user supplied a protected x86-64 macOS
hello-world executable attributed to this source tree. Its original function
bytes are absent from the static image and its section metadata matches the
tree's packing path. See [VMP_HELLO_FIXTURE.md](VMP_HELLO_FIXTURE.md) for hashes,
entry/initializer observations, assumptions, and benchmark implications. This
does not retroactively change the source-only baseline below or establish VM
coverage.

The later user-supplied VMP, Morok and Hikari binaries are catalogued with
exact hashes and provenance bounds in
[PROTECTED_SAMPLE_CORPUS.md](PROTECTED_SAMPLE_CORPUS.md). Subsequent
fixed-seed Morok measurements use a distinct keygen binary.

This review assesses native binary analysis. No supplied VMP executable was
run, no protected-binary recovery benchmark was performed, and no production
code was changed. The existing untracked `ATHENA_MAPPING.md` is useful context,
but its identity and rewrite proposals require the corrections below. The
relationship between its Athena name and this VMP distribution is **unknown**;
this review does not assume they are identical products or revisions.

**Assumption register**

| ID | Assumption and dependent conclusions | Stress test / falsification probe |
|---|---|---|
| A1 | The supplied source describes transformations relevant to the user's target corpus. All expected VMP-specific coverage gains depend on this. | Generate or obtain paired fixtures with recorded protector build, settings, architecture, and seed. Reject a claimed mapping when emitted instructions disagree. `core/version.h` says `1.0.0`; that does not establish a commercial release identity. |
| A2 | This checkout and existing configured build are the intended Chernobog baseline. All implementation-gap claims depend on this. | Record Git revision and file hashes; rebuild the three selected targets. Reassess after source changes. |
| A3 | Ordinary x86/x64 user-mode semantics are the initial recovery domain. Proposed native normalizations depend on this. | Negative cases cover operand-size overrides, far returns, extra stack adjustment, entry into the middle of a pattern, observable stack writes, memory faults, and unsupported execution modes. Keep unsupported cases unresolved. |
| A4 | Existing current-function execution and evidence freshness contracts remain design constraints. Runtime and VM proposals depend on this. | Use a fixture whose interpreter lies outside the selected function; require a reported boundary stop. Recovered VM regions need explicit bounds and ownership before execution can be admitted. |
| A5 | Better analysis means more correct recovered edges/expressions/literals under bounded latency. Priority order depends on this objective. | Measure semantic mismatches, recovery coverage, abstentions, latency, and peak memory independently. Reduced pseudocode size alone does not establish correctness. |

**Implementation order [A1–A5]**

Impact labels describe expected effect on analysis capability, not measured gains.

| Order | Change | Impact | Existing implementation seam | Acceptance evidence |
|---|---|---|---|---|
| 0 | Correct mapping and establish a paired fixture corpus | High: prevents invalid rewrite specifications | `docs/ATHENA_MAPPING.md`, existing native/catalog/evidence harnesses | Counterexamples rejected; deterministic manifests and original/protected behavior agree |
| 1 | Recover exact native stack-mediated transfers and get-PC forms | High: restores inputs needed by later passes | `native_engine.cpp`, `get_pc_ida.cpp`, `native_classifier.*` | Correct target and stack effects; no false function merge on negative cases |
| 2 | Replace the coarse flag scan with per-flag abstract interpretation | High: covers more generated predicates | `native_engine.cpp`, portable classifier tests | All admitted predicates agree with architectural semantics; unknown flags preserve uncertainty |
| 3 | Capture string bytes at their uses, including heap lifetimes | High: supports plaintext absent from final image writes | `emu_driver.*`, `evidence.*`, ctree display consumers | Decrypt/use/erase and allocation-reuse fixtures display the correct use-specific value |
| 4 | Test canonicalization and width handling before adding MBA identities | Medium: avoids redundant or unsound rules | AST builder, existing rule registry and verifier | Actual failing microcode shapes simplify with preserved widths and memory dependencies |
| 5 | Add evidence-linked CFG and lifetime visualization | Medium: exposes why recovery succeeded or stopped | Existing edge, state, memory, and provenance records | Selecting a result reveals source EAs, runs, proof status, assumptions, and invalidation state |
| 6 | Introduce a separate VM-region model and incremental semantic summaries | High potential; largest scope and unknown coverage | New analysis family sharing existing proof/evidence services | Recognition survives register renaming and handler cloning before any claim of semantic lifting |

**1. Native CFG recovery [A1–A3]**

VMP explicitly converts non-immediate near jumps to `push operand; ret` in its
native mutation path. Chernobog's `handle_push_return` accepts only an immediate
push; its indirect-branch handler explicitly excludes returns. This establishes
a recognizer gap, but does not establish that every such sample fails in IDA:
IDA's own analysis may recover some cases.
VMP emitter (`vmp/core/intel.cc:16360`),
[current recognizer](../src/ida_analysis/native_engine.cpp:1225),
[indirect handler](../src/ida_analysis/native_engine.cpp:1442).

Extend the portable classifier to describe a stack-mediated transfer, its
operand width, stack delta, address dependencies, and supported execution mode.
Resolve register operands through exact reaching definitions; admit memory
operands only with an established address and memory value at that point.
Unresolved candidates can be annotated without inventing an edge or merging
functions. Multiple concrete runs finding one target remain observations,
not proof that the target is unique.

The initial milestone is metadata recovery with preserved stack effects. Byte
replacement requires a stronger equivalence argument: the pair writes stack
memory, a return can have additional adjustment, and external entries into the
pair invalidate a single-entry summary. Call-as-jump recovery is a later slice
requiring return-address provenance and an explicit stack-effect model.

VMP also replaces a call to the following instruction with a push-based
address-materialization sequence. Its x64 operands use `cpu_address_size()`;
`regEAX` is an internal register identifier, not evidence of an emitted
32-bit `eax` operand. The existing mapping's x64 `push eax` example must be
described with the actual 64-bit widths.
Emitter (`vmp/core/intel.cc:16218`).

**2. Per-flag analysis [A1–A3]**

The current state representation contains CF and ZF only. Its scan already
passes a whitelist of flag-preserving instructions and recognizes `clc`/`stc`;
those are not new features. However, `cmc` stops the scan, and the generic
flag-writer barrier loses facts about individual preserved flags. The branch
consumer accepts eight condition opcodes, with partial CF/ZF reasoning.
[Flag state](../src/ida_analysis/native_engine.cpp:65),
[effects and scan](../src/ida_analysis/native_engine.cpp:603),
[consumer](../src/ida_analysis/native_engine.cpp:1379).

VMP's source tracks known flag masks and evaluates combined signed conditions;
its random-command generator performs `30 + rand() % 10` iterations per call,
meaning 30–39 iterations, not a fixed instruction count.
Flag evaluator (`vmp/core/intel.cc:16918`),
generator (`vmp/core/intel.cc:17542`).

An independent Chernobog implementation can represent CF/PF/AF/ZF/SF/OF as
known-zero, known-one, or unknown, with separate instruction effects for
preservation, definition, inversion, and undefined results. Evaluate a
condition only when every completion of the unknown flag bits yields the same
answer. A bounded local transfer pass is sufficient for the first milestone:

```text
state := unknown registers and flags
for instruction in a verified single-entry region, up to budget D:
    decode width and effects
    invalidate unsupported writes and potentially aliased memory facts
    apply supported abstract register and flag effects
    evaluate any condition over all compatible flag states
    emit a fact only if all compatible states agree
```

With fixed architectural register count R and six flags, the local pass costs
O(D·R) time and O(R) working space, excluding optional retained evidence.
Constant-count condition evaluation enumerates at most 2^6 = 64 flag states.
CFG joins, loops, and SMT queries need separate budgets; this complexity is not
a claim about general symbolic execution.

`setcc` requires a byte assignment on both outcomes: true writes 1, false
writes 0. The mapping's false-case NOP proposal is incorrect. Memory-source
`cmovcc` needs separate handling of memory access/exception behavior, and
partial-register effects remain part of the summary. First implement value
facts and microcode simplification under a stated memory model rather than
unqualified native instruction deletion.
[Intel SDM, SETcc](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf#page=599).

**3. String recovery needs time and object identity [A1, A2, A4]**

VMP's `VirtualString` allocates a byte buffer, decrypts into it, and can zero and
delete it on release. Chernobog captures final writes but its runtime-string
consensus explicitly filters out non-image memory. Consequently, this path
cannot directly project those heap buffers, even if their execution and memory
accesses are successfully observed. A prior call-boundary or missing-summary
stop may prevent execution from reaching them at all.
String lifetime (`vmp/runtime/string_manager.cc:139`),
[final capture](../src/hybrid/emu_driver.cpp:1699),
[image-only projection](../src/hybrid/evidence.cpp:293).

Introduce bounded use-site byte snapshots and an allocation identity with a
lifetime generation. Key observations by semantic use, call context, object,
offset, and event sequence; compare bytes across runs without requiring equal
heap addresses. A snapshot at use remains evidence of that use after a later
erase; it must not be presented as the object's final or universal value.
Preserve existing consumed-byte freshness checks and distinguish modeled-call
results from directly executed observations. Cap both bytes per snapshot and
total retained bytes. For U uses and at most B bytes each, capture costs
O(U·B) time and space before the global cap.

There are also distinct string encodings in the source: loader overloads operate
on bytes or 16-bit units, whereas `VirtualString` iterates bytes using the
recorded byte size. A UTF-16 interpretation does not by itself select the
wide-loader transform. Any future static recognizer needs evidence for the
specific routine, key, bounds, and unit width, followed by existing encoding
validation. General constant-XOR support does not establish that such a loop
will be recognized.
Loader overloads (`vmp/core/intel.cc:22388`),
[current static recovery](../src/deobf/handlers/string_decrypt.cpp:296).

**4. MBA work: verify the missing shape [A1–A3]**

De Morgan rules already exist as `And_HackersDelightRule_3` and `Or_MbaRule_1`.
The AST builder also represents stack/global operands. Their presence disproves
an assumption that every NOR/NAND expression or stack operand requires a new
rule; it does not prove cross-instruction simplification coverage.
[AND rule](../src/deobf/rules/rules_and.h:58),
[OR rule](../src/deobf/rules/rules_or.h:58),
[operand builder](../src/deobf/analysis/ast_builder.cpp:178).

Collect representative microcode and classify each miss as recognition,
reaching-definition/aliasing, width conversion, rewrite ordering, or an actually
missing identity. Use typed bitvector expressions with explicit truncation and
extension. A same-width proof does not justify a mixed-width rewrite; two
syntactically equal memory locations are not necessarily the same value across
an intervening write. New rules still use the production verifier, where
unknown/unsupported proofs are rejected.
[Verifier](../src/deobf/rules/rule_verifier.cpp:9).

Two proposed identities in mapping §15.1 are false:

```text
~~(~(x & c)) = ~(x & c), not x & c
~~(~(x | c)) = ~(x | c), not x | c
```

For w-bit values define NOT(x) = x XOR (2^w − 1). Three NOT operations leave
one NOT. At w = 8, x = c = 0, either proposed left side is 255 and its proposed
right side is 0. Exhaustive enumeration of 256 × 256 = 65,536 pairs produced
65,536 mismatches for each proposed identity. The corrected double-NOT
identities passed every pair. These integer results are exact, with no rounding
error; this finite check is not a mixed-width proof.

Mapping §15.2 also allows an invalid exception to the all-zero/all-one mask
requirement when both targets are constants. At width 32, let
`dest0=0x1000`, `dest1=0x10ff`, `idx=1`. The masked sum is `0x1001`, whereas
`idx ? dest1 : dest0` is `0x10ff`. Being a control-flow target does not make
that identity valid. An alternative rewrite needs its own exact equivalence
proof under the actual constraints.

**5. Separate VM architecture and inspectable evidence [A1, A2, A4]**

`vm_mba` requires a `prog_bb_<digits>` function name followed by specific
IP-advance, bytecode-read, and accumulator/threading checks. It is not a generic
VMP devirtualizer. Relaxing only the name check would not supply the missing
semantics.
[Admission](../src/deobf/handlers/vm_mba.cpp:449).

The supplied VMP source includes randomized register roles, forward/backward
bytecode reading, stateful decoding, multiple dispatch forms, and handler
cloning. These properties motivate a separate region descriptor and semantic
summary model. A native address alone need not identify a unique logical VM
state. Candidate summaries need an explicit input-state contract, memory and
flag effects, and bounded transitions before they can support semantic lifting.
Direction (`vmp/core/intel.cc:27734`),
read/dispatch construction (`vmp/core/intel.cc:27795`),
register assignment (`vmp/core/intel.cc:28572`),
cloning (`vmp/core/intel.cc:30169`).

The first milestone is recognition and visualization of region candidates,
role hypotheses, and unresolved effects. The next is validation of isolated
semantic summaries. Full bytecode lifting is a subsequent project. Existing
function-boundary execution stops must remain visible; increasing the instruction
budget alone does not solve region ownership or missing environment semantics.
[Execution contract](../RAX_HYBRID.md:3).

For visualization, reuse ordered `ExecPoint`, `ExecEdge`, `DataAcc`, `StatePoint`,
and evidence provenance. Show observed edges separately from statically proven
edges, and display trace truncation, boundary stops, and counterexamples as
first-class results. A synchronized CFG, memory-lifetime timeline, and proof
detail pane would let an analyst inspect a simplification's basis.
[Existing event types](../src/hybrid/emu_driver.hpp:26).

**Validation and bounded expansion**

The VMP unit tests already contain original-versus-generated comparisons for
results and flags. The reviewed helpers use 100 random trials per invocation;
they are useful evidence of an oracle pattern, not exhaustive proofs, and the
Windows allocation/inline-assembly setup is not directly portable to this host.
An independent corpus can retain the same comparison principle with recorded
seeds and architecture-specific runners.
Original helpers (`vmp/unit-tests/intel_tests.cc:1203`).

The minimum benchmark matrix separates mutation, virtualization, and combined
protection; x86 and x64; deterministic corner cases and recorded random seeds;
and positive/negative recognizer fixtures. Compare observable results, memory,
stack effects, and architecturally defined flags. Report correctly recovered
edges over oracle edges, false edges, unresolved candidates, literal accuracy,
solver rejection reasons, elapsed seconds, and peak bytes. Mask undefined flags
according to the instruction model. Hold seeds out to detect overfitting.

Additional opportunities and risks remain bounded to this analysis task:

| Impact | Pattern beyond a vendor-specific handler | Consequence |
|---|---|---|
| High | Allocation reuse and erase-before-exit defeat address-only/final-state evidence | Use-time object evidence benefits many runtime decryptors, not only VMP |
| High | Native function boundaries can partition interpreter code incorrectly | Record boundary incompleteness explicitly; whole-function claims require complete region evidence |
| Medium | Many syntactically different handlers can have equal semantic effects | Proven normalized summaries could reduce duplicate work; hash equality alone is insufficient |
| Medium | A generator's output can validate recognition without validating ISA correctness | Keep an independent architectural oracle and negative fixtures |
| Low | The local version file contains generic version values | Hash source and fixture artifacts; do not infer support for current commercial VMP releases |

No work in packing, licensing, anti-debugging, or .NET IL execution is needed to
establish these native-analysis findings. Those subsystems were not assessed.

**Checks performed and quality gates**

The focused build completed with `ninja: no work to do`. CTest passed
`chernobog.core`, `chernobog.evidence`, and `chernobog.mba_catalog`: 3 passed,
0 failed, 13.82 s reported total elapsed time. This is one baseline run, not a
latency estimate and not validation of the proposed features.

```sh
cmake --build build --target chernobog_core_tests chernobog_evidence_tests chernobog_catalog_tests -j 2
ctest --test-dir build -R '^chernobog\.(core|evidence|mba_catalog)$' --output-on-failure
```

The arithmetic check is reproducible using Python integer masking:

```python
m = 255
inv = lambda n: (~n) & m
for op in (lambda x, c: x & c, lambda x, c: x | c):
    assert sum(inv(inv(inv(op(x, c)))) != op(x, c)
               for x in range(256) for c in range(256)) == 65536
    assert all(inv(inv(op(x, c))) == op(x, c)
               for x in range(256) for c in range(256))
```

QG1: technical assessment; no ethical judgment required. QG2: assumptions and
falsification probes registered above. QG3: source-to-implementation mapping,
priorities, and acceptance criteria supplied. QG4: exact finite-width checks,
explicit complexity scope, bytes/bits/seconds distinguished. QG5: identified
mapping contradictions corrected here; unsupported implementation cases remain
explicit abstentions. QG6: local primary-source references and hashes recorded,
SETcc checked against Intel documentation. QG7: bounded adjacent opportunities
and excluded subsystems identified. Feature effectiveness, commercial-version
coverage, and performance gains remain **unknown**, not inferred from passing
baseline tests.
