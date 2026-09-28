# Owned protected condition diagnostics

The protected i386 corpus contains two owned `CMOV` sites in
`virtualization-0` and one owned `SETcc` site in `combined-12648430`.
The matched enabled/disabled microcode study in `VMP_CONDITION_CORPUS.md`
observed zero lowering events at these sites. The existing native proof API
also omitted unresolved conditions. This checkpoint adds a separate read-only
`chernobog_native_condition_diagnostics(ea)` API and a **Condition sites** tab
in the evidence view. It does not change native proof admission, Hex-Rays
generation, item classification, or published IDA edges.

The API resolves the selected function owner and enumerates at most 4,096
instruction heads. It retains at most 64 condition sites and 64 support
addresses per site, reporting omitted rows and head truncation. For each
decoded x86 `Jcc`, `SETcc`, or `CMOVcc`, it records the exact instruction
bytes, condition use, six-bit abstract flag mask/value, bounded analysis
support, and a `true`, `false`, or `unknown` model decision. A decided row is
explicitly **decided under the local model**, not a proof that byte deletion
or microcode lowering preserves all effects. The GUI checks owner and source
bytes for navigation; Reload recomputes model decisions.

## Protected observations

| Binary | Owner | Site | Use | Bytes | Decision |
|---|---:|---:|---|---|---|
| `virtualization-0` | `0x806f37b` | `0x8073520` | `CMOV` | `0f45c6` | unknown |
| `virtualization-0` | `0x806f37b` | `0x8089c3f` | `CMOV` | `0f43fc` | unknown |
| `combined-12648430` | `0x8053948` | `0x80c8325` | `SETcc` | `0f9cc0` | unknown |

The first owner has 63 enumerated heads and three condition sites, including
one additional unresolved `Jcc`; the second has 43 heads and one condition
site. Neither inspection reached a limit. Two IDA console probes compare the
entire inspected function item inventory and native proof list before and
after repeat queries. Both report identical inventories and proofs. They
also check source-byte navigation and a deliberately altered captured byte
string. An actual IDA Qt probe displays all three rows in the first owner,
opens one unresolved result, and enables navigation only with matching source
bytes. The three probes and their exact hashes are recorded in
`VMP_CONDITION_DIAGNOSTICS_EVIDENCE.json`.

## Assumption register and scope

| ID | Assumption and dependent result | Falsification probe |
|---|---|---|
| D1 | The behavior-validated i386 paired artifacts in `build/predicate-protected-i386-b89d23fc-v1` are the selected protected inputs. The three-site observation depends on their exact bytes. | Reject a different SHA-256, owner, site byte sequence, or protected-corpus report. |
| D2 | IDA's current function ownership and decoded instruction heads define this diagnostic scope. The inventory count and GUI contents depend on that classification. | Compare a fresh IDB inventory and run ownerless candidate inspection separately; do not equate absence from this API with absence from executable bytes. |
| D3 | The bounded local x86 flag model applies to the three decoded sites. Their unknown decisions depend on the current model and graph. | Change the graph or modeled effects and rerun both exact-site probes. A new decided result requires separate consumer-effect and proof checks. |

**High impact:** owned protected predicate abstentions are visible beside
native proofs, with exact source addresses. **Medium risk:** functions with
more than 4,096 heads or 64 conditions are incomplete by design; the API
reports truncation. **Low risk:** a matching source byte sequence alone does
not prove the analysis graph or decision remains current; the GUI labels
that state and requires Reload for a new decision.

At most 64 sites invoke the existing bounded condition analysis. With
`H <= 4096` enumerated heads, `K <= 64` retained sites, and `S <= 64`
displayed support addresses, the inspection costs
`O(H + K * T_condition(H))` time and `O(K * S)` output space, excluding the
bounded analysis workspace. No elapsed-time gain or protected condition
folding is inferred from these diagnostics.

## Reproduction and quality gates

Run `tests/ida_condition_diagnostics_probe.py` with `tests/run_ida_smoke.py`
on each exact binary, passing the selected owner/site cases through
`CHERNOBOG_CONDITION_CASES` and the companion path through
`CHERNOBOG_VIEW_MODULE`. Run `tests/ida_condition_diagnostics_gui_probe.py`
with the same runner and IDA GUI executable on `virtualization-0`.
The evidence manifest pins input, plugin, script, report, and IDA hashes.

QG1: no normative claim is needed. QG2: D1–D3 have explicit probes.
QG3: the selected visibility gap and GUI path are covered; broader review
requirements remain in progress. QG4: head, site, support, byte and time
bounds are explicit. QG5: unknown decisions are not promoted to proofs.
QG6: the claims derive from pinned source and actual IDA captures.
QG7: ownerless and larger-function limitations are labeled above.
