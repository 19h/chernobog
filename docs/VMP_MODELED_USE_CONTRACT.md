# Modeled-use call contract and freshness

Review requirements 3a, 3b and 5 require modeled argument bytes to remain
attributable to the call model used during execution. Previously, the general
use-string projector could accept an exact modeled snapshot with a valid
allocation lifetime and cross-run agreement without retaining the named model
contract or checking a corresponding observed CALL transfer. A later callee
rename could leave the already published string visible. This checkpoint
closes those admission and display gaps for direct modeled calls. Executed-read
strings continue through their separate read/data-event validator.

## Admission and currentness

The session retains the exact named call-summary vector supplied to its worker
and copies it into published target evidence. For every modeled snapshot, the
projector requires the scheduled run to report external-model use, the use's
selected-function context, a unique callee binding whose recorded name
classifies to its recorded kind, the same snapshot model kind, a supported
argument position, and a dynamic CALL transfer at the use site to that callee.
The transfer must be the latest transfer preceding the snapshot sequence in
the same run and seed. Duplicate run identities, duplicate binding addresses
and duplicate transfer sequences abstain. The existing exact-byte, lifetime,
UTF-8 and every-run consensus checks still apply.

The bounded evidence view adds `model_bindings` rows with address, kind, name,
`model-contract` truth and the explicit assumption that the callee body was
not executed. At most 64 bindings appear in this display; admission uses the
full retained contract. Strict IDC use-string queries and transient ctree
display now recheck each recorded callee name and model classification against
the current IDA database. A renamed callee revokes both. After restoring the
name, an already sealed print lease can display the strings again if the
function profile and consumed bytes still match. Strict IDC remains stale
until re-exploration because its profile identity is exact.

The contract is provenance for **emulator-selected** behavior. A named
`strlen` model and an observed CALL do not prove that a native callee executed
or that an arbitrary protected import has the same semantics. No VM-region
identity or universal function proof follows from these strings.

For `M` model bindings, `E` transfer edges, `R` scheduled runs and `U` modeled
uses, construction and lookup add
`O(M log M + E log R + sum(E_r log E_r) + U(log R + log M + log E_r))`
time, where `E_r` is the edge count in a run. Additional index space is
`O(M + E + R)`, excluding existing snapshots and their bytes. Existing caps
include 4,096 use attempts and 1,048,576 retained snapshot bytes per run;
the evidence-view contract display caps at 64 rows.

## Executed evidence

The independent `temporal_strings.S` Mach-O exits 0 after checking that its
two native `strlen` results sum to 14. Fresh IDA 9.4 SP1 with the revised
signed plugin publishes `secret!` and `second!` from four returned, temporally
complete modeled runs: eight allocation lifetimes, 36 use snapshots and zero
truncations or environment-model failures. The view shows four named bindings
(`_free`, `_malloc`, `_memset`, `_strlen`), and the probe checks the matching
observed CALL transfers. It passes 27/27 checks, including callee rename,
name restoration, strict re-exploration, key/code/profile mutation and
transient annotation controls.

The archived prior plugin, on the identical fixture, probe and IDA binary,
passes 25/27. Its two failures are the absent named-contract view and the
still-visible uses after a callee rename; it already publishes the two
plaintexts. Portable controls reject absent, mismatched, mislabeled and
duplicate contracts; absent or wrong transfer edges; a run that does not
report model use; and duplicate scheduled run identities. Fresh x86-64 and
arm64 executed-read controls retain two strings and two annotations, passing
10/10 each. All 21 configured CTest suites pass with four parallel jobs.
Exact file identities and raw-report hashes are recorded in
`VMP_MODELED_USE_CONTRACT_EVIDENCE.json`.

Reproduce the current temporal profile with a fresh output directory:

```sh
python3 tests/run_ida_smoke.py build/vmp-temporal-strings \
  tests/ida_temporal_string_smoke.py \
  --ida "$CHERNOBOG_IDAT" --plugin "$CHERNOBOG_PLUGIN" --enable-rax \
  --output-dir build/ida-modeled-binding-reproduction
```

## Assumption register and bounded scope

| ID | Assumption and dependent result | Stress test or falsification probe |
|---|---|---|
| M1 | The session copies the same named model vector supplied to the worker. Modeled-use attribution depends on that vector. | Portable absent, wrong-kind, wrong-name and duplicate-binding controls reject. Compare session copy and worker construction in source. Coherently forged worker events and contract remain outside this check. |
| M2 | A recorded CALL edge is the latest transfer before the model's captured argument in the same run. Dynamic call attribution depends on this sequence. | Remove the edge, change it to a jump, or duplicate a transfer sequence; the projector abstains. A false emulator trace could still falsify attribution. |
| M3 | Run outcome flags accurately report model and temporal capture. Publication depends on them. | Clear model-used in one synthetic run or mark temporal capture incomplete; consensus abstains. An incorrectly asserted complete trace remains unknown. |
| M4 | The current IDA callee name and classification identify the same model boundary. Strict queries and display freshness depend on this. | Rename the callee: both revoke. Restore its name: sealed display recovers; re-exploration restores strict IDC. A same-name semantic replacement is outside name identity and requires independent execution. |
| M5 | The native fixture's aggregate result and matched IDA artifacts isolate this plugin change. The observed regression difference depends on those identities. | Native process exits 0; matched reports have identical input, probe and IDA hashes, distinct plugin hashes and unchanged-artifact flags. Other protected binaries remain unmeasured here. |

**High impact:** an unbound modeled snapshot can no longer become a displayed
plaintext solely through matching bytes and lifetimes. **Medium impact:** a
callee rename now revokes both strict queries and transient display; restoring
the name has the documented profile-dependent behavior. **Low impact:** the
64-row contract view can omit bindings even though the full contract governs
admission. Protected call semantics, same-name binary replacement, and the
full review lifecycle remain unknown.

QG1: no normative premise. QG2: M1–M5 include falsification probes. QG3:
portable negative controls, native execution, matched IDA and cross-architecture
regressions cover this scoped change; the full review remains open. QG4:
sequences, counts, byte limits and asymptotic bounds are explicit. QG5:
ambiguous bindings, transfers, runs and changed names abstain. QG6: local
source, fixture, plugin, IDA and raw-report hashes identify the primary
evidence. QG7: impact and display limits are bounded above.
