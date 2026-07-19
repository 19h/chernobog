# Current-function rax hybrid analysis

## Scope invariant

The integration has no whole-database emulation entry point. `Ctrl+Shift+E`
snapshots the mapped image needed as memory context, but creates exactly one
`FuncRange`: the function displayed in the active Hex-Rays view. One worker and
one rax engine are owned by that per-IDB session. Selecting another function
cancels and replaces the generation.

The Hex-Rays flowchart callback is also a current-function prerequisite. Before
the first whole-MBA deobfuscation pass for the focused function, Chernobog reuses exact
fresh evidence, waits for a matching in-flight job, or synchronously explores
that function. Background and "decompile all" requests are not admitted; batch
callers must set `CHERNOBOG_RAX_BATCH_EA`. It does not explore callees or
enumerate the database. Disabled
or unavailable rax fails open to the existing deobfuscation pipeline; a bounded
job failure or user cancellation is reported and likewise does not fabricate
evidence.

Database bytes, instruction boundaries, call-site tracker values, names, and
segment permissions are read on IDA's main thread. The worker receives only an
immutable `ProgramImage`, one function, bounded run requests, and POD call
summaries. It never calls the IDA SDK.

## Implemented analysis categories

1. **Concrete path and input exploration**: deterministic ABI seeds, distinct
   register-tracker-proven incoming call contexts, and queued Z3 model replays;
   per-run instruction and wall-time caps; complete engine context restoration
   between runs.
2. **Control-flow observation**: ordered execution, conditional outcomes,
   computed call/jump targets, returns, coverage, and architectural register
   state immediately before conditional instructions.
3. **Memory and object-layout semantics**: typed reads/writes, loaded pointer
   values, executable pointer candidates, exact final written ranges, and
   image/stack/heap/other scope classification.
4. **Runtime materialization**: final image writes are projected as runtime
   ASCII C strings only when the same address and NUL-terminated value occur in
   every run with available memory observation. Exact-address CFString and
   admitted C-string call operands in the current final ctree are replaced with
   transient literals. Conflicts, missing runs, stack/heap values, binary data,
   and unterminated prefixes fail closed. Decrypted/generated buffers and
   write-to-executable/self-modifying-code observations remain available as
   typed evidence.
5. **Static differential analysis**: IDA-versus-rax instruction size, flow,
   direct target, and conditional fallthrough comparison at IDA instruction
   heads in every chunk of the selected function. On AArch64, IDA macro heads
   are expanded into their physical 4-byte instructions before comparison so
   an 8-byte IDA macro is not reported as a decoder error.
6. **SMIR effects**: bounded rax 1.3 caller-owned effect negotiation; register
   reads/writes, constant results, memory address expressions, flag effects,
   completeness/partial status, and encoded control targets remain available
   as typed evidence.
7. **Function behavior and ABI recovery**: return/termination/fault/timeout/
   budget/environment-boundary outcome, retired and attempted instruction
   counts, modeled call count, and stack-pointer delta per input. Objective-C
   method profiles model `self` and `_cmd` separately from explicit parameters.
8. **Environment modeling and gap discovery**: bounded summaries for known
   memory/string, allocation, deallocation, termination, Objective-C ARC, and
   random-number functions. A named but unmodeled external target is reported
   and stopped before its placeholder bytes execute; the missing model is
   therefore explicit evidence rather than a fabricated continuation.
9. **Z3 cross-checking**: an exact current-byte check precedes every lookup.
   A concrete opposing branch observation vetoes a universal opaque-predicate
   rewrite only when the backend captured every executed-code and image-data
   dependency without trace truncation. Matching observations are logged only
   as corroboration; they never establish UNSAT or universality.
10. **Z3 input exchange**: pre-predicate architectural states are mapped to
   Hex-Rays micro-register identifiers for constraint consumers. An explicit
   ABI-argument-order model-replay queue lets a solver submit up to 32 model
   arguments to the active function; queued models cannot select another
   function or initiate a sweep.
11. **Indirect-control recovery**: unresolved indirect-call/jump handlers can
    inspect observed targets. They log candidates but retain the indirect
    operation because finite concrete coverage cannot prove target uniqueness.
12. **Permission, fault, and image-boundary diagnosis**: strict IDA segment
    permissions are enforced, execution outside the snapshotted image is
    stopped at the first source/target boundary, and rax stop metadata remains
    distinct from Chernobog's application-level outcome.
13. **Provenance and invalidation**: every observation carries database,
    function byte hash, complete image hash, function generation, focus EA,
    worker ticket, run ID, and seed. Before publication, display, Z3, or handler
    consumption, every function chunk plus the exact code/data ranges consumed
    by the trace are byte- and initialized-mask-compared with the live IDB;
    stale evidence fails closed. Immediately before a Chernobog-owned
    deobfuscation pass, an exact-fresh prerequisite can open a display-only
    projection; the pass then seals that projection to the exact resulting
    function bytes and closes the sealing lease at `CMAT_FINAL`. This permits
    cross-run runtime literals to survive only Chernobog's bounded mutation
    window while the original evidence remains stale for branch/Z3 proof
    consumers. Every changed function byte must also belong to an explicitly
    registered Chernobog patch site and equal its registered result. Later or
    unregistered function-byte edits, topology changes, and entry-profile
    changes fail the sealed identity check. Consumed data-byte
    changes are also never promoted to proof freshness. AArch32 entry
    ARM/Thumb state is compared.
14. **Reproducibility and regression evidence**: seeds, source-level input
    order, run identifiers, unique sites, observation multiplicities, decoder
    mismatch categories, and exact consumed ranges are retained so two runs or
    two decoder versions can be compared without conflating sites with events.

No rax evidence path patches database bytes or rewrites microcode. After fresh
evidence publication, a guarded main-thread consumer may add exact decoder
crefs; corroborated dynamic crefs/drefs; metadata on undefined data; function,
i386 purge, and analysis-comment hints. Dynamic actions require at least two
distinct runs by default, and incomplete switch/opaque metadata plus
`FUNC_NORET` remain opt-in. Consensus runtime strings rewrite only the newly
built current-function ctree into transient display literals. They become an
IDB string only when the identical NUL-terminated bytes are already loaded and
undefined; rax final-memory bytes are never copied into the IDB. Existing
Chernobog transformations retain their independent proof obligations.

## Application-mode execution model

The mapped database image supplies bytes and permissions, but it is not treated
as a bootable machine image. The code hook checks every instruction before
execution:

- code outside the snapshot becomes `escaped-image` at the first attempted PC;
- an IDA external segment (`SEG_XTRN`) is never executed as code;
- a recognized external call is evaluated by its bounded summary and resumes
  at the architectural return address;
- an unknown external call becomes `unmodeled-external`, with its address and
  symbol retained;
- a summary precondition or memory operation failure becomes
  `environment-model-failure`.

The implemented summary families are `memcpy`, `memmove`, `memset`, `strcpy`,
`strncpy`, `strlen`, `strcmp`, allocation/callocation/deallocation,
termination, Objective-C retain/autorelease identity operations, release/weak/
pool operations, `objc_storeStrong`, Objective-C allocation/pool creation,
`arc4random`, and `arc4random_uniform`. Symbol spelling is canonicalized across
leading import/jump prefixes and import suffixes. Every summarized external call
marks the run exploratory because the host model, not guest code, supplied part
of its semantics.

For an Objective-C instance or class method named using IDA's canonical
`-[Class selector:]` or `+[Class selector:]` form, AArch64 argument registers
are initialized as follows:

| Source-level value | AArch64 register | Deterministic entry |
|---|---:|---|
| `self` / class object | `X0` | mapped synthetic object unless observed at a call site |
| `_cmd` | `X1` | mapped NUL-terminated selector unless observed at a call site |
| first explicit parameter | `X2` | first deterministic/Z3 source-level argument |
| remaining explicit parameters | `X3` onward, then stack | ABI order |

Call-site tracker overrides use physical ABI positions and can therefore supply
observed `X0`/`X1`. Z3 model replay inputs use source-level explicit-parameter
order and automatically skip those hidden arguments. A run with synthetic
Objective-C entry context is exploratory and cannot veto a universal Z3 claim.

## Evidence strength

Evidence has three bounded interpretations:

1. Static decode/SMIR records are facts about the supplied bytes and the
   selected decoder/lifter versions.
2. Concrete execution records are witnesses that the observed transition or
   value occurred under the recorded input and environment.
3. A concrete opposing branch can veto a universal Z3 result only when all
   executed code and immutable image-data dependencies were captured, no trace
   was truncated, no external summary supplied semantics, permissions were not
   violated, execution did not escape, and Objective-C entry state was
   observed rather than synthesized.

Finite concrete runs do not prove reachability completeness, target uniqueness,
or a universal branch property. Matching rax and Z3 outcomes are corroboration;
an eligible concrete counterexample is falsification of the universal claim.

## Interpreting the report

- `job=completed` means the bounded worker job finished; it does not mean the
  emulated function returned.
- `runs_ran=N/M` distinguishes submitted inputs from inputs for which a backend
  execution actually started.
- `entry:` reports native/Objective-C flavor, canonical name/selector, known
  explicit argument count, and hidden argument count. Verbose per-run input
  lines distinguish deterministic, call-site, and Z3 origins and retain
  source-level positional values separately from physical ABI overrides.
- `coverage: physical=A/B` counts distinct executed physical instruction
  addresses intersected with the static physical instruction set. It is not
  IDA pseudocode coverage and does not include unmatched execution addresses.
- `branches=S sites/O observations` separates unique conditional instruction
  sites from run/repetition observations. Indirect control similarly separates
  sites, unique `(site,target)` pairs, and observations.
- `decoder=C compared/M mismatched/F flags` separates comparison count, unique
  mismatch sites, and mismatch dimensions. A mismatch site can contribute more
  than one size/flow/target/fallthrough flag.
- `memory: observation_available=N/M` states whether the backend installed a
  data/fetch hook. Zero reads or writes is interpretable as a negative
  observation only for an available run.
- `context=... complete/incomplete` is the Z3-counterexample eligibility
  boundary, not an emulation-success indicator.
- Per-run `retired` is the backend's cumulative retired-instruction count;
  `attempted` is the sum of bounded rax control-stop steps. A known run requires
  equality. The report labels unavailable attempted-step metadata rather than
  assuming a value.
- `outcome=unmodeled-external` with `stop_pc`, `target`, and `name` means
  Chernobog deliberately stopped before executing an import placeholder. It is
  an environment coverage boundary, not a decoder fault.
- `entry_context=synthetic` means deterministic Objective-C `self`/`_cmd`
  placeholders were used; `observed/native` means that restriction does not
  apply.

## Actions

- Opening/decompiling the focused function automatically performs the bounded
  current-function prerequisite immediately before its first whole-MBA
  deobfuscation pass when no exact fresh evidence exists.
- `Ctrl+Shift+E`: explore the displayed function.
- `Show current-function rax evidence`: print the typed summary and bounded
  detail (runs, decoder differences, branches, indirect targets, runtime
  strings) to the Output window.
- `Cancel current-function rax exploration`: cancel queued runs; a rax call
  already in progress stops cooperatively at its next instruction boundary.
- In IDA batch mode, set `CHERNOBOG_RAX_BATCH_EA` to an address in the target
  function, load the plugin, and call `ida_loader.run_plugin(plugin, 0x524158)`
  (`0x524158` is ASCII `RAX`). Execution completes synchronously because
  text-mode IDA neither registers GUI actions nor provides a reliable UI timer
  loop.

## Runtime configuration

All values are read when an exploration starts.

| Variable | Default | Hard bound / meaning |
|---|---:|---|
| `CHERNOBOG_RAX_ENABLED` | `1` | Master action/component switch |
| `CHERNOBOG_RAX_DISABLE` | `0` | Fail-closed static ABI disable switch |
| `CHERNOBOG_RAX_LOG_LEVEL` | `1` | 0 quiet, 1 summary, 2 trace |
| `CHERNOBOG_RAX_MAX_INSNS` | `200000` | Instructions per run; zero resets to default; maximum 100000000 |
| `CHERNOBOG_RAX_TIMEOUT_MS` | `1000` | Wall time per run; zero resets to default; maximum 60000 ms |
| `CHERNOBOG_RAX_EXPLORE_RUNS` | `4` | Deterministic inputs, range 1–32 |
| `CHERNOBOG_RAX_MAX_CALLSITE_INPUTS` | `8` | Distinct tracker contexts, range 0–32 |
| `CHERNOBOG_RAX_MAX_IMAGE_BYTES` | `536870912` | Snapshot cap, 1 MiB–4 GiB |
| `CHERNOBOG_RAX_MAX_STATIC_INSNS` | `65536` | Static heads, range 1–1000000 |
| `CHERNOBOG_RAX_POLL_MS` | `50` | Active UI polling, range 10–1000 ms |
| `CHERNOBOG_RAX_STATIC` | `1` | Decoder comparison |
| `CHERNOBOG_RAX_SMIR` | `1` | Stateless effect analysis |
| `CHERNOBOG_RAX_DREFS` | `1` | Memory observations |
| `CHERNOBOG_RAX_RUNTIME_STRINGS` | `1` | Capture final written ranges |
| `CHERNOBOG_RAX_SMC_EVIDENCE` | `1` | Record write/execute evidence |
| `CHERNOBOG_RAX_IMPORT_SUMMARIES` | `1` | Known external-call models |
| `CHERNOBOG_RAX_STRICT_PERMS` | `1` | Honor IDA segment permissions |
| `CHERNOBOG_RAX_MAX_RUNTIME_BYTES` | `1048576` | Final dirty bytes per run, maximum 64 MiB |
| `CHERNOBOG_RAX_BATCH_EA` | unset | Batch/text-mode only: address inside the target function (base autodetection, `0x` accepted); invalid or unset aborts with `BADADDR` |
| `CHERNOBOG_RAX_APPLY_ANALYSIS` | `1` | Guarded current-function evidence-to-IDB consumer; `0` retains reporting/display only |
| `CHERNOBOG_RAX_MIN_DYNAMIC_RUNS` | `2` | Corroboration floor for dynamic xrefs/data metadata, range 1–32 |
| `CHERNOBOG_RAX_MIN_NORET_RUNS` | `3` | Conclusive non-returning-run floor for comments, range 2–64 |
| `CHERNOBOG_RAX_SET_NORET` | `0` | Opt in to setting `FUNC_NORET` and reanalysis |
| `CHERNOBOG_RAX_SWITCH` | `0` | Opt in to incomplete observed-target custom-switch metadata |
| `CHERNOBOG_RAX_OPAQUE` | `0` | Opt in to observed-only opaque-predicate comments |

## Build and ABI

The rax source is the `vendor/rax` git submodule, pinned to commit
`776cec9d64e6bbeea43f77edd3f0e402f3b60cad`. Configuration fails when the
submodule is absent, checked out at another revision, or contains uncommitted/
untracked files; it never fetches rax or borrows a checkout from another
repository. Cargo is invoked with
`--locked --release` and an explicit target triple. Supported build mappings
are macOS arm64/x86_64, Linux aarch64/x86_64 GNU, and Windows x86_64 MSVC.
Universal Mach-O builds are rejected; configure one architecture per build.

The plugin requires rax C API 1.3 or later within major version 1. The archive
is statically linked, and its `rax_*` symbols are hidden on Mach-O and ELF so a
co-loaded viy plugin cannot interpose its embedded ABI.

## Backend capability boundary

Availability is checked at runtime. A backend without stepping produces static
decode/SMIR evidence but no concrete trace. A backend without memory hooks can
still produce control-flow evidence, while data accesses, final writes,
runtime strings, and SMC observations remain absent. Absence is reported as
unknown, never as negative evidence; its branch observations are also excluded
from universal-claim vetoes because consumed data context is incomplete.
AArch64 currently supplies distinct load/store/fetch hooks and preserves
X0-X30, SP, PC, PSTATE, V0-V31, FPCR, and FPSR across host register updates.
AArch32 concrete execution additionally
requires an authoritative IDA `T` segment-register value at the selected
function entry; unknown state disables dynamic execution rather than guessing
ARM or Thumb.

SVE state, operating-system services, Objective-C message dispatch, dynamic
loader behavior, threads, signals, and asynchronous device behavior are not
fabricated. Encountering code that requires one of these remains an explicit
incomplete-context or environment-boundary result.
