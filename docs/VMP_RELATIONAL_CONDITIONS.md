# Compound condition facts across correlated alternatives

Review rows 2a and 2b now consume universal condition truth across bounded
alternative states. A condition can have a known outcome even when the joined
flag bits cannot decide it. Native Jcc publication, SETcc/CMOV value facts,
current proof validation, false-branch restoration and the Hex-Rays generation
filter use the same current condition query [C1, C2]. Ownerless inspection
reports the same universal truth without publishing ordinary edges.

## Condition and flag contracts [C1]

`X86ConditionFact` retains the original must-analysis `flags`, plus an optional
condition `value`, supporting EAs, alternative-analysis use and widening.
The query first evaluates the joined or verified-prefix flag profile. If its
outcome is unknown, a reached, converged alternative input at a graph join
is evaluated over every completion of every represented state. Every outcome
has to agree. Unknown members, disagreement, bottom or nonconvergence cannot
establish a new value. The preceding universal branch filtering stage remains
fixed; provisional states never authorize further exclusions.

CF=1/ZF=0 and CF=0/ZF=1 universally satisfy BE and refute A while their joined
CF/ZF bits remain unknown. Likewise, SF≠OF and SF=OF can be represented by
two concrete alternatives whose individual SF/OF joins are unknown. A
condition result does not set either joined flag bit. Existing flag-query
callers retain their original per-bit result.

Current native and ownerless condition records expose `condition_basis` and
`condition_widened`. A successful alternative result has basis
`universal-alternatives`. Owned must/prefix results use
`joined-or-prefix-flags`; ownerless rows use `joined-flags` unless a universal
alternative supplies truth. On unresolved ownerless rows this is the fallback
flag representation; `status`/`outcome` retain the abstention. Native records
also expose their unchanged `flags_known` and `flags_value`. Widening describes
the alternative analysis used for this query, rather than unrelated analyses.

## Consumers and validity [C2]

An owned Jcc publishes its selected architectural successor through the
existing ownership mechanism. SETcc writes one byte on either outcome, and
CMOV retains existing source-memory reads, fault ordering and partial-register
effects. The generation filter still requires the current function entry,
supported operands and complete supporting instruction spans within the MBA
range. Snippet generation remains excluded. The emission implementation is
unchanged; the condition admission query now retains correlations.

All condition consumers share `x86_condition_prefix_supported`. LOCK, REP
and REPNE condition prefixes decline. Owned graphs containing such conditions
decline, verified prefixes stop before them, and ownerless inspection exposes
an `unsupported_condition_prefix` frontier without a condition fact. LOCK on
Jcc, SETcc or CMOVcc causes architectural #UD; REP/REPNE are conservatively
outside this model, without claiming that every such encoding faults.
The self-red-team found that the preceding native analyzer published a
condition for IDA's decoded `LOCK JBE`. Four literal fault controls now cover
Jcc, SETcc, register CMOV and memory CMOV on both architectures [C2, C4].

Proofs retain the complete original scoped graph support, including inactive
arms. Current validation recomputes the condition and checks dependency
coverage. Changing one flag-setting byte or adding an external entry to a
consumer invalidates the proof. Stale owned edges/value facts are revoked
through their existing receipts during reanalysis. Restoring bytes and actual
owners reestablishes admission. The UI's existing exact-record comparison
rejects changed truth or basis; no new proof cache is introduced.

The false-branch continuation repair also recomputes universal truth. It does
not reconstruct a fallthrough from joined bits that lost the deciding relation.
Ownerless facts remain read-only and unpublished; their node flag masks remain
the must-analysis masks. Their original architectural graph retains both Jcc
successors, with the proven condition recorded separately.

## Bounds [C1]

```text
if the condition has an unsupported prefix: return unknown condition
flags, support := current must or verified-prefix analysis
value := evaluate(condition, flags)
if value is unknown and a converged alternative graph input is reached:
    for each alternative:
        outcome := evaluate condition over all compatible flag completions
        if unknown or different from another outcome: return unknown
    value := shared outcome
    support := all original graph instructions
return unchanged joined flags, value, support, analysis basis and widening
```

K≤8 alternatives, F=6 status bits, up to 64 owned nodes subject to the
configured scan depth, 128 ownerless nodes, 128 rounds per pass and 256 incoming
references per instruction retain their existing bounds. Universal evaluation
costs O(K·2^F) time and O(1) additional space for one condition. The preceding
must, unfiltered alternative and fixed refined passes retain the bounds in
`VMP_BRANCH_FEASIBILITY.md`. Ownerless inspection shares its lazy alternative
pass across condition and transfer rows. Owned proof checks and generation
queries recompute their own scoped analyses; interactive latency is unknown.

## Independent measurements [C3, C4]

Ten relations are checked: BE true, A false, and both outcomes of L, GE, LE
and G. Each relation has Jcc, SETcc, register CMOV and memory CMOV fixtures.
Each also has a conflicting alternative whose outcome depends on the input.
A ninth-state overflow control has a constant native BE result but loses
the required relation under conservative widening.

An independent Boolean C evaluator computes the expected result from the
literal flag profiles, rather than plugin fields. Actual x86-64/i386 execution
checks every fixture over −256 through 255. The exact count is
(40 positive + 40 conflicting + 1 overflow)·512 + 4 SIGILL controls
= 41,476 per architecture, 82,952 per plugin profile.
Each fault control runs in a separate child and requires SIGILL, with core
file creation disabled. Preceding/current production measurements use
matching binary hashes and fresh IDA databases.

| Measurement | Preceding plugin | Current plugin |
|---|---|---|
| Positive condition observations across two architectures and query paths | 0/160 admitted | 160/160 exact |
| Conflicting/overflow observations across those paths | 164 unresolved | 164 unresolved |
| Invalid LOCK condition observations across those paths | 16 admitted | 0 admitted; explicit ownerless frontiers |
| Owned Jcc publications | None of the 20 selected edges | All 20 selected edges |
| SETcc/CMOV custom generation | 0/60 selected lowerings | 60/60 selected lowerings |
| Production assertions per architecture | 578 | 1,013 |

The current SDK emits ten byte assignments, ten register CMOV replacements
and ten memory CMOV replacements per architecture. An independent interpreter
checks the generated snippets under both concrete flag profiles. It compares
the full return register, other architectural GPRs, five modeled status
registers, DS, memory and read count/width/address. Each memory replacement is
also checked with each of four source bytes absent, requiring a read fault
before any architectural destination write. This gives
30·2 + 10·2·4 = 140 effect/fault checks per architecture, 280 total.

The new probes check byte-patch revocation and restoration for all four
consumer families, external-entry invalidation, original support coverage,
unknown common decisive bits, overflow abstention, read-only query inventory,
UI freshness and snippet rejection. After a predicate patch creates
disagreement, SETcc/CMOV custom generation declines again. Restoration
reestablishes condition facts.

The unchanged emission families additionally pass the existing independent
microcode regression: 12,288 effect comparisons across x86-64/i386,
192 native read-fault observations, width/partial-register controls, seven
effect-oracle mutation controls on x86-64 and six on i386, and read retention at
PREOPTIMIZED and GLBOPT3 maturities. Both architectures retain all eight
checked memory-read families at each maturity. This supplies the wider
emission contract; the new compound fixtures have 8-bit SETcc and 32-bit
CMOV destinations.

Portable tests retain 746,496 independently enumerated condition unions and
add explicit eight-state true/false and nine-state widening controls.
All 21 CTest suites pass. Existing owned/ownerless dataflow checks remain
453/386 and 1,730/1,680 respectively. The previous branch-refinement corpus
passes 1,056 checks per architecture; its compound JBE now has a proven
condition while its common CF/ZF bits remain unknown. The containing-set
corpus retains 293 checks per architecture. Historical evidence documents
the behavior of its recorded revision and is unchanged.

The checked supplied VMP initializer still has 75 nodes, 77 edges and three
unresolved facts in both profiles, with 8/8 inspection checks. Its condition
records acquire the new basis/widening fields; the original flag masks and
semantic facts agree. No protected gain is measured in this region. Execution
uses macOS x86-64 translation on an arm64 host and the recorded QEMU i386
environment; physical x86 hardware equivalence is unknown [C4]. Source and
observation hashes are in `VMP_RELATIONAL_CONDITIONS_EVIDENCE.json`.

### ISA and emulator provenance [C4]

Intel SDM revision 090 specifies #UD for LOCK in CMOVcc (Volume 2A, 3-160),
Jcc (Volume 2A, 3-503) and SETcc (Volume 2B, 4-623–624). The inspected
[official combined manual](https://cdrdv2-public.intel.com/874240/325462-090-sdm-vol-1-2abcd-3abcd-4.pdf)
has SHA-256 `3686e42931e893b5016c70fb131403795ef173237d073afcfec52755fcd3ea50`.

The earlier Ubuntu image's QEMU 8.2.2 returns normally from the LOCK JBE
control: its child exits 99 and the strict parent oracle exits 5. This is
a detected emulator disagreement with the specified #UD, not a passing
fault observation. The selected replacement is built from the
[official QEMU 9.2.0 archive](https://download.qemu.org/qemu-9.2.0.tar.xz),
SHA-256 `f859f0bc65e1f533d040bbe8c92bcfecee5af2c921a6687c652fb44d089bd894`.
Its [i386 decoder](https://github.com/qemu/qemu/blob/v9.2.0/target/i386/tcg/decode-new.c.inc)
checks unsupported LOCK before generation. All four strict guest fault
controls pass with this binary. The runtime image ID, executable hashes,
actual QEMU version and base package inventory are recorded separately;
the unchanged base `qemu-user` package version does not identify the replacement
executable. Existing dataflow and cover regressions retain the earlier
recorded environment; primary condition, emission and branch regressions
use the replacement.

On i386, IDA autoanalysis initially leaves the invalid-condition roots as
data. The probe explicitly creates instruction items before requesting owned
scope, then checks both owned and ownerless consumers. Executable bytes and
the independent fault oracle remain unchanged.

## Reproduction

```sh
mkdir -p build/qemu-context
curl -fL https://download.qemu.org/qemu-9.2.0.tar.xz \
  -o build/qemu-context/qemu-9.2.0.tar.xz
docker --context orbstack image inspect chernobog-vmp-linux32:test
docker --context orbstack build -t chernobog-vmp-linux32:qemu9.2 \
  -f tests/vmp_corpus/relations32.Dockerfile build/qemu-context
python3 -B tests/run_relational_conditions.py --ida "$CHERNOBOG_IDAT" \
  --plugin "$CHERNOBOG_PLUGIN" --output-dir build/relations-reproduction \
  --linux32-image chernobog-vmp-linux32:qemu9.2
ctest --test-dir build --output-on-failure
```

Use a fresh output directory. `--baseline` requires the preceding compound
abstentions and invalid LOCK admissions.
The observed base image is
`sha256:7b1781979ac73774803cdcd1ce8797d345cbae204731e0e684c1d74e89bef654`;
the derivative is
`sha256:91a6e07bec9b5ef76ccee2f076aa419b5e79a93e15c69de67017e0b8a3a38bc2`.
The recipe pins the source archive and preserves the base runtime. Build-stage
APT dependency versions can change; a rebuilt executable's identity is measured
again rather than assumed identical.
The evidence retains the recipe hash used for the observed image, before its
formatting, separately from the current source hash.
The runner sets the owned flag and register scan depths to 64 for this
join/overflow corpus, verifies binary/source/tool identities and independently
interprets current generated snippets. The previous branch-refinement runner's
`--relational-condition-baseline` retains its earlier public-condition contract.

## Assumption register

| ID | Assumption and dependent results | Stress test / falsification probe |
|---|---|---|
| C1 | Existing abstract transfers overapproximate represented normal completions. Universal condition results depend on this. | 746,496 concrete union comparisons, both relation outcomes, conflicting alternatives, eight/nine-state controls and existing entry/loop/budget tests. No unknown or bottom result becomes a known condition. |
| C2 | Current bytes, ownership, entries and the existing generation range/operand model describe the query. Publication and lowering validity depend on this. | Patch a predecessor byte, inject a consumer entry, require immediate stale-fact rejection and later generation decline, restore owners, reject snippets, compare ordinary query inventories and reject all four invalid LOCK consumers. |
| C3 | Literal profiles, executed Boolean contracts and the independent IR interpreter specify results separately from production fields. Selected-fixture counts depend on this. | Compare both concrete profiles, partial-register/width regressions, source-byte fault positions, full architectural state and read footprints; retain the existing corrupted-oracle controls. |
| C4 | Recorded tools, translations and matching binaries define the measurement environment. Cross-profile comparisons depend on this. | Verify all report/source/binary/tool hashes after measurement, compare the supplied initializer's original fields, record scan depths and require SIGILL for every LOCK control. The older emulator fails this probe; the recorded replacement passes. Physical hardware and broader protected coverage remain unknown. |

## Bounded scope expansion

- **High impact:** Relational condition truth can now feed native edges and
  value lowering without inventing common status bits. Unknown-input
  constraints and whole-program predicate reachability remain unknown.
- **Medium impact:** Eight-state widening can discard a universal relation;
  the constant-result overflow control measures this abstention explicitly.
- **Medium impact:** Complete graph support can exceed a generation range or
  configured scan depth. Those queries decline; larger budgets alone do not
  establish missing ownership or memory semantics.
- **High impact:** Invalid-prefix decoding can otherwise authorize facts for
  an instruction that faults. The shared admission guard closes the measured
  cases; the emulator counterexample requires explicit fault controls when
  extending the supported instruction model.
- **Medium impact:** Additional owned queries recompute bounded graphs.
  Protected recovery rates, interactive latency and the historical edge
  scorer's current score remain unknown.

## Self-red-team and quality gates

QG1 passes: no normative content is needed. QG2 passes: C1–C4 enumerate
assumptions and probes. QG3 passes for condition truth and all four consumer
families on both architectures/query paths; the full review remains in progress.
QG4 passes: counts, widths, source-byte faults and resource bounds are explicit.
QG5 passes: flag-mask preservation, conflicting inputs, widening, generated
memory effects, invalid prefixes, entry mutations and historical contracts are distinguished.
QG6 passes: primary source and observation identities bind the measurements.
QG7 passes: remaining opportunities and limits have impact labels.
