# AMD64 finite dispatch and outlined calls

The shared finite-domain evaluator supports stack-address arithmetic feeding
correlated byte lookups, signed relative jump tables, and single-target indirect
calls. Stack addresses remain unconstrained values identified by their frame,
offset and address-view metadata. No concrete stack address or alignment is
substituted. Every admitted byte assignment must produce the same call target,
or the complete conditional target set.

A proven call can supply its existing function type before native ABI argument
collection. This preserves narrow argument widths and used return values without
guessing a prototype. The instantiated MBA verifier also accepts object, stack
and local addresses as opaque values. Distinct address origins remain independent;
proofs do not assume image load addresses, pointer alignment or equalities between
different objects.

AMD64 stack values can follow a unique predecessor chain across calls only when the
SDK's complete may-def list excludes the queried slot. Escaped locals, ambiguous
predecessors, partial writes, unknown instructions and conflicting effects stop
propagation. The paired disjoint/escaped-local fixtures exercise this boundary.

## Control flow and instruction boundaries

Boolean switches with complete 0/1 case coverage become ordinary conditions.
The original false/true mapping and target-evaluation effects are preserved.
Predicates recovered from earlier instructions are captured at their original
IR evaluation point before branching. An intervening store or call must not
turn a historical comparison into a read of the new memory state.
Relative tables retain the displacement's signed extension before adding the
base address. Native jumps represented as tail calls can also enter a proven
shared-frame continuation; a real call does not establish that relationship.

Automatically named, bounded continuations can consume the incoming RBP/RSP or
nonvolatile registers before redefining them. AMD64 decoding uses variable-length
instructions and SIB base/index registers. Conventional frame-building prefixes,
user prototypes and incoming call references exclude independent functions.
Projection leaves native bytes and IDB function ownership unchanged. Native
frame and stack lifting remains with the SDK. A projected snippet can retain
frame-bookkeeping expressions in its pseudocode; this adapter does not claim
complete reconstruction of source-level local variables.

Address proof and decompilable boundaries are separate checks. AMD64 jump-address
diagnostics may include a decodable executable address that lies inside an
existing IDA item. Such a result retains the native jump and records the unresolved
boundary. It does not overwrite another instruction stream or create a function.
Partial range coverage cannot retain orphan projected blocks. Cached proofs check
all root/source chunks and their bytes, including noncontiguous function tails.

### Explicit orphan-region recovery

After decompiling a function, `chernobog_recover_indirect_regions(ea, flags)`
returns JSON for ownerless regions reached by its fresh static target proofs.
It does not use concrete execution observations as proof. Re-decompile after
applying recovery to discover further bounded continuations.

| Flags | Effect |
| --- | --- |
| `0` | Preview candidate boundaries and refusal reasons; no IDB mutations |
| `1` | Create bounded ownerless continuation functions at compatible boundaries |
| `3` | Also select a proven entry stream overlapping unprotected ownerless code |

Recovery requires an executable, bounded linear region with an incoming-frame
witness and a terminal instruction. It rejects existing function ownership,
data items, user names/types/comments, forced operands in replaced items,
incoming calls and references into abandoned instruction bytes. It decodes at
most 256 instructions and 4 KiB per candidate. Existing compatible items and
their operand representations remain intact. Only incompatible items are
removed; native bytes are never patched. A creation failure is reported as an
incomplete IDB recovery, rather than successful recovery.

For `N` decoded instructions, `B` inspected bytes and `X` incoming references,
region preflight takes `O(N * B + X)` time and `O(N + B)` storage. The decoded
body is limited to 4 KiB; an overlapping existing item can add at most 14 B at
each boundary. There are at most 64 candidate addresses per function snapshot.

Selecting an overlapping entry is an explicit analysis choice. The target proof
does not establish that the previous instruction stream is unreachable. Apply
such recovery to an analysis copy when both streams need to remain available.

## Outlined callee preservation

For a conventional framed AMD64 callee marked outlined, the adapter validates the
complete bounded native body, a known ordinary calling convention, the register
save prefix and the matching restore sequence at every normal return. Custom
calling conventions, writes into the saved frame slots, explicit SP-relative
stores, frame-pointer redefinitions, mismatched stack deltas/restores, unmodeled
jump exits and already-emitted native restores decline the adapter.

When the inlined IR omits those restores, the adapter captures the proven
nonvolatile general registers at the original call and restores them on every
validated normal return edge. Native frame-pointer/stack handling remains with
the decompiler. Ordinary calls retain their ABI clobbers. This prevents a callee's
scratch table pointer from replacing the caller's live object pointer.

| Bound | Limit |
| --- | --- |
| Finite domain | 256 exhaustive assignments; 4,096 expression nodes |
| Continuation prefix | 32 decoded instructions; at most 15 B per AMD64 instruction |
| Function snapshot | 128 chunks; 16 KiB total code per root/source function |
| Outlined native body | One chunk, 16 KiB, at most 1,024 instructions |
| Inlined IR | At most 128 blocks and 8,192 inspected instructions |

For `I` native instructions, `M` IR instructions, `R` admitted registers and `E`
normal exits, preservation uses `O((I + M) log I + R * E)` time and
`O(I + E + R)` auxiliary storage. All searches have the limits above.

## Assumption register and falsification probes

| Assumption or boundary | Impact | Probe |
| --- | --- | --- |
| Read-only image bytes describe the lookup tables | High | Change one table row or make its segment writable; the call proof must fail |
| Identical stack-address origins denote one value in the same MBA | High | Retain frame and address-view identity; distinct frame offsets fail an equality proposal |
| Ordinary callees honor their ABI and implicit stack contracts, including indirect writes | High | Decline custom conventions, direct saved-slot overwrites and mismatched pops; arbitrary indirect alias corruption is not proved absent |
| SDK may-def memory effects cover writes to an AMD64 stack slot | High | Pair a disjoint-local propagation test with an escaped-local refusal test; retain unknown effects as barriers |
| Native frame/SP metadata describes a continuation | High | Revalidate frame data and every function chunk; incomplete or overlapping instruction streams remain unprojected |
| A Boolean predicate may take either value | Medium | Enumerate both outcomes; this does not establish individual reachability |
| The stored callee prototype describes its ABI | High | Use it only after an exact target proof; absent prototypes retain native inference |
| An explicitly selected orphan stream is the desired analysis view | High | Preview boundaries, reject protected metadata/references, retain the original database for alternate streams |

The high-impact boundary outside this adapter is simultaneous recovery of
overlapping native instruction streams and arbitrary state-dependent dispatch.
An exact target address is not a proof that the SDK can represent both streams
at that boundary.
The medium-impact opportunity is further interprocedural state reconstruction;
concrete observations alone do not authorize replacing an unresolved transfer.

## Verification

```sh
python3 tests/build_x86_finite_fixture.py build/fixtures/x86-finite
python3 tests/build_x86_finite_fixture.py build/fixtures/x86-finite-false --runtime 0
```

Run `tests/ida_x86_finite_probe.py` with `tests/run_ida_smoke.py` and an explicit
plugin artifact. It checks signed relative destinations, native save captures,
negative ABI cases, nested/register-only continuations, typed calls, address MBA,
cache reuse, unchanged bytes and function owners, and table-proof invalidation.
`tests/ida_x86_region_recovery_probe.py` checks preview, protected metadata,
explicit overlap selection, byte preservation and projection-cache upgrades.
The fixture contains no bytes from another program. The two standalone native
fixture outcomes are 94 and 92, respectively.

Primary ABI references: [System V AMD64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI)
and [Microsoft x64 register conventions](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions#x64-register-usage).
The callback and microcode contracts are those in the released IDA SDK headers
`hexrays.hpp`, `funcs.hpp` and `intel.hpp`.
