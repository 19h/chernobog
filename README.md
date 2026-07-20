<h1 align="center">chernobog</h1>

<img width="1536" height="597" alt="chernobog" src="hero.png" />

---

<h5 align="center">
chernobog is a Hex-Rays decompiler plugin that defeats Hikari LLVM obfuscation.<br/>
Where IDA shows tangled switch dispatchers, chernobog restores the original control flow.<br/>
Flattening, bogus branches, encrypted strings—all reversed automatically.<br/>
<br/>
Opaque predicates evaluated. Dead code eliminated. Constants decrypted in place.<br/>
Instruction substitutions simplified back to their obvious forms.<br/>
The obfuscation dissolves. The algorithm emerges.
</h5>

> [!NOTE]
> **Chernobog 6** is a major release. New since 5.3.0:
>
> - **rax hybrid engine** — bounded, focused-function emulation that materializes runtime strings and projects decoder, branch, memory, and Z3 cross-check evidence into the IDB (see [`RAX_HYBRID.md`](RAX_HYBRID.md))
> - **Native pre-lift analysis** — early native/Hex-Rays enrichment passes that repair call/pop and get-PC control flow, resolve indirect targets, and fold constants before decompilation
> - **Recurrent-switch CFF recovery** — encoded recurrent switch dispatchers are classified and rewritten with exact Z3 transition proofs
> - **VM-family MBA recovery** with exact-Z3 affine reconstruction, plus **cross-function Hikari CFG recovery**, reversible native opaque-predicate and branch patching, and writable-constant inlining
> - **Select/cmov cascade collapse** and static XOR/NOT stack-string recovery
> - **Multi-database support** (`PLUGIN_MULTI`) — isolated state per open database
>
> Chernobog 6 **requires IDA Pro 9.4** (SDK `940`); older SDKs are rejected at build time.

## Features

Chernobog automatically detects and reverses the following Hikari obfuscation techniques:

### Control Flow Obfuscation
- **Control Flow Flattening (CFF)** - Restores the original control flow graph using Z3 symbolic execution to solve dispatcher state machines. A single two-phase handler (keyed on state values and block start addresses, not block indices) covers:
  - Single-level and hierarchical/nested dispatchers
  - Mixed switch and cascading-conditional dispatchers
  - State-variable aliasing and conditional (data-dependent) transitions
  - Index-based jump-table flattening
  - Encoded recurrent switch dispatchers, using bounded CFG recurrence,
    distributed-backedge, selector-transform, and target-diversity evidence;
    exact Z3 transition proofs replace the dispatcher with direct CFG edges
    before ctree construction
  - Hikari magic-constant dispatch detection
- **Bogus Control Flow (BCF)** - Identifies and removes opaque predicates, dead branches, and unreachable code blocks, including arithmetic identity predicates such as `x*(x+1) % 2 == 0` (always true)
- **Basic Block Splitting** - Merges artificially split basic blocks back together
- **Indirect Branches** - Resolves computed branch targets whose offset expression folds to an exact address, following register copies, zero/sign extensions, and add/subtract offsets (other bitwise or combined forms only when they reduce to a constant)
- **Indirect Calls** - Resolves Hikari's `call(table[index] - offset)` pattern to direct calls
- **Recurrent-Resolver Argument Cleanup** - Neutralizes call-site argument expressions in ABI registers that a recurrent, statically closed resolver thunk provably never reads; the physical ABI slots are retained so live arguments do not shift (default-on at `MMAT_CALLS`)
- **Select-Chain Collapse** - Collapses long cascades of conditional-move (select) diamonds from LLVM select lowering into equivalent branchless expressions, keeping very long chains within Hex-Rays' structural limits
- **Cross-Function Dispatch (opt-in, `CHERNOBOG_HIKARI_CFG`)** - Recovers Hikari's two-target ARM64 dispatch encoding across IDA function boundaries (relocation table + `CSET` index + signed bias, with an observed XOR key), adds exact IDB edges/comments, and can optionally rewrite side-effect-free dispatch tails to direct conditional branches

### Data Obfuscation
- **String Encryption** - Decrypts XOR- and bitwise-NOT-encrypted strings and annotates them in the disassembly
- **Constant Encryption** - Resolves encrypted constants (XOR patterns with global variables)
- **Stack String Construction** - Reconstructs strings built character-by-character on the stack
- **Global Constant Inlining** - Replaces loads from read-only globals with immediate values

### Code Transformation (108 MBA Rules)
Mixed Boolean-Arithmetic (MBA) simplification using Z3-certified rules and lazy commutative matching:

**Addition patterns:**
- `x - (~y + 1)` → `x + y` (two's complement)
- `(x | y) + (x & y)` → `x + y`
- `(x ^ y) + 2*(x & y)` → `x + y`
- `2*(x | y) - (x ^ y)` → `x + y`
- `~(~x + ~y) + 1` → `x + y + 2`

**Subtraction patterns:**
- `x + ~y + 1` → `x - y`
- `~(~x + y)` → `x - y`
- `x + (-y)` → `x - y`
- `(x + y) - y` → `x`

**XOR patterns:**
- `(x | y) - (x & y)` → `x ^ y`
- `(~x & y) | (x & ~y)` → `x ^ y`
- `(x + y) - 2*(x & y)` → `x ^ y`
- `(x | y) & (~x | ~y)` → `x ^ y`

**AND patterns:**
- `(x + y) - (x | y)` → `x & y`
- `~(~x | ~y)` → `x & y` (De Morgan)
- `x & (x | y)` → `x` (absorption)

**OR patterns:**
- `(x & y) + (x ^ y)` → `x | y`
- `~(~x & ~y)` → `x | y` (De Morgan)
- `x | (x & y)` → `x` (absorption)

Additional carry-disjoint rules include `x + (y & ~x)` → `x | y`,
`((y | ~x) + x) + 1` → `x & y`, and
`(x & y) + (~x & y)` → `y`.

**Negation, NOT, and multiplication identities:**
- `~~x` → `x`, `-x - 1` → `~x`, `~(x - 1)` → `-x`
- `-(-x)` → `x`, `~x + 1` → `-x`, `-(x - y)` → `y - x`, `-(x + y)` → `-x - y`
- `x * 2` → `x + x`, `x * (-1)` → `-x`, `(-x) * (-y)` → `x * y`
- Absorbing identities: `x + 0` → `x`, `x | x` → `x`, `x & x` → `x`

All 108 registered rules are checked for
8-, 16-, 32-, and 64-bit equivalence before admission.

### VM-Family MBA Recovery

With `CHERNOBOG_VM=1`, functions named `prog_bb_<digits>` are admitted only
after structural checks for instruction-pointer advancement and bytecode reads,
plus at least one of: an accumulator write, a threaded successor, or repeated
instruction-pointer advancement. The handler recovers SSE/scalar
accumulator packing, removes masked carrier constants, simplifies local MBA
identities, and persists handler summaries. Its optional Z3 residual pass is
enabled separately with `CHERNOBOG_VM_Z3=1`.

### Opaque Predicate Elimination
- **Jump Optimization** - Z3-based analysis for complex conditional simplification
- **Predicate Rules** - Pattern-based simplification for self-comparisons, tautologies, and identity patterns:
  - `setz x, x` → `1`, `setnz x, x` → `0`
  - `jb x, x` → never taken, `jae x, x` → always taken
- **Native Opaque Branches (opt-in, `CHERNOBOG_NATIVE_OPAQUE`)** - Before Hex-Rays lifts the function, proves and reversibly patches constant ARM64 `B.cond`/`CBZ`/`CBNZ` terminators to a direct `B` or `NOP` (original bytes retained for revert; input binary unchanged)

### Function Call Obfuscation
- **Identity Function Calls** - Detects and resolves identity-function call chains to their final targets (analysis/annotation only; no structural rewrite is applied)
- **Hikari Function Wrappers** - Identifies `HikariFunctionWrapper_*` functions that forward to `objc_msgSend` or the dynamic loader (`dlsym`/`dlopen`), resolves the real target (an `ObjC_Wrapper_*` identity for Objective-C, or the looked-up symbol for dynamic loads), and annotates the call sites with the resolved API. Only wrappers with a proven runtime API are admitted; the wrapper functions themselves are not renamed
- **Saved-Register Slot Resolution (savedregs)** - Resolves indirect call targets and string arguments read from saved-register stack slots using conservative reaching-definition tracing; results are IDB annotations (microcode is not mutated)

### Platform-Specific
- **Obfuscated Objective-C Method Calls** - Identifies direct and indirect `objc_msgSend` call sites on macOS/iOS binaries, traces selector strings and receivers, and annotates call sites with the resolved method signature
- **Pointer Reference Resolution** - Handles ObjC class references through indirection tables; CFConstantString annotations require an exact-length admissible UTF-8 payload, and encrypted/runtime-initialized payloads remain unannotated

### IDA Analysis Enrichment

Chernobog improves the native IDB before Hex-Rays lifting. The default-on,
per-database engine integrates selected viy analysis techniques without
importing the plugin wholesale:

- correct x86 redundant-prefix decoding; recover call/pop and constant
  push/return control flow
- annotate architectural-zero, adjacent-opposite, entry-flag, and locally
  proven x86 flag predicates
- add exact indirect targets resolved by IDA's register tracker and conservatively
  retype bounded jump-over-garbage gaps
- after autoanalysis, perform one bounded IDA decoder/xref pass for direct-call
  orphan functions and wrapper outlining; functions containing proven get-PC
  transfers also absorb only reachable, non-call code heads without another
  function owner or user name
- project fresh current-function rax evidence into guarded code/data references,
  undefined data types/strings, pointer offsets, function candidates, i386 purge
  metadata, and analysis comments

The post-autoanalysis pass is native metadata analysis, not execution. rax is
never run as a database sweep: it snapshots and explores only the focused
function, uses one worker, and does not recursively emulate callees. Dynamic
IDB mutations require at least two distinct runs by default; setting
`FUNC_NORET`, incomplete switch metadata, and observed-only opaque-predicate
comments remain separate opt-ins.

### Ctree-Level Optimizations
Applied after microcode optimization for additional cleanup:
- **Constant Folding** - Folds XOR expressions involving read-only globals to constants by reading the actual bytes from the binary (Hikari constant/string decryption at the Ctree level)
- **Switch Folding** - Collapses switches whose controlling expression is provably constant (e.g. `HIDWORD(x)` or `x >> N` state variables), removing the unreachable cases
- **Indirect Call Resolution** - Resolves Hikari's `(table[index] - offset)(args)` indirect calls to direct calls in the Ctree
- **String Decryption** - Decrypts strings visible only at Ctree maturity

## Requirements

- IDA Pro 9.4 with Hex-Rays decompiler (the build rejects any SDK whose `IDA_SDK_VERSION` is not `940`)
- CMake 3.27+
- Ninja build system
- Rust stable toolchain with Cargo
- IDA SDK (set `IDASDK` environment variable)
- Git
- macOS 13.3+ on Apple hosts (the default deployment target; the bundled Z3 4.16's C++20 formatting path requires it — set `CMAKE_OSX_DEPLOYMENT_TARGET` to override)

Optional, per target:

- Docker — only for Linux builds from a non-Linux host
- LLVM (`clang-cl`, `lld-link`, `llvm-lib`, `llvm-rc`) plus an xwin sysroot (`XWIN_ROOT`) — only for Windows cross-builds

## Building

```bash
# Set your IDA SDK path
export IDASDK=/path/to/idasdk

# Materialize pinned source dependencies
git submodule update --init --recursive

# Build the plugin
make build

# Or manually with CMake
mkdir build && cd build
cmake .. -G Ninja
ninja
```

The build fetches and statically links Z3. rax is pinned as the `vendor/rax`
git submodule and is also linked statically; initialize it with
`git submodule update --init --recursive` after cloning. Neither a separate Z3
installation nor a rax shared library is required. Cargo must have the Rust
target matching the CMake target (for example, `rustup target add
aarch64-apple-darwin`). Configuration fails if the submodule is missing or is
checked out at a revision other than the repository pin, or if its worktree is
dirty.

### Windows Cross-Compile With Clang

Windows builds can be cross-compiled with `clang-cl` targeting
`x86_64-pc-windows-msvc`; no MinGW GCC toolchain or GitHub Windows runner is
required. This remains a local and manually-dispatched compatibility build;
published Windows release artifacts are compiled natively with MSVC.

```bash
# Prepare an xwin CRT/SDK sysroot once
xwin --accept-license splat --output /path/to/xwin

# Point the build at the sysroot and configure/build
export XWIN_ROOT=/path/to/xwin
cmake --preset windows-clang-release
cmake --build --preset windows-clang-release

# Or via Makefile
make build-windows-clang
```

This preset expects LLVM tools (`clang-cl`, `lld-link`, `llvm-lib`, and
`llvm-rc`) to be available in `PATH`.

### Build Every Platform From One Command

On macOS, `make all-platforms` now builds:

- an arm64 macOS plugin at `out/artifacts/chernobog_macos-arm64.dylib`
- an x86_64 macOS plugin at `out/artifacts/chernobog_macos-x86_64.dylib`
- a Linux x86_64 plugin at `out/artifacts/chernobog_linux-x86_64.so`
- a Windows x86_64 plugin at `out/artifacts/chernobog_windows-x86_64-clang.dll`

```bash
export IDASDK=/path/to/idasdk
export XWIN_ROOT=/path/to/xwin
make all-platforms
```

Notes:

- Linux builds run in Docker on non-Linux hosts and require `docker`.
- The local all-platform command uses the `clang-cl` + `xwin` flow above.

GitHub Actions builds native Linux ARM64, Windows x86-64, and Windows ARM64
release artifacts. Windows releases use the Visual Studio generator and MSVC
on native Windows runners, and CI verifies both the PE machine type and the
base IDA 9.4 register-finder import. Unix builds retain the current IDA 9.4 SDK
patch and its matching runtime stubs; the ABI-compatible base SDK pin is
Windows-specific. The ARM64 jobs select
`aarch64-unknown-linux-gnu` and `aarch64-pc-windows-msvc`, respectively. Unix
CI runs the portable CTest suite; the macOS x86-64 job uses the native
`macos-15-intel` runner instead of executing its tests through Rosetta. Windows
CI disables the tests because the SDK checkout does not include the IDA runtime
DLL required by the catalog test executable.

## Installation

```bash
# Automatic installation to ~/.idapro/plugins
make install
```

On macOS, `make install` also ad-hoc codesigns the copied dylib
(`codesign -s - -f`), replacing any existing signature.

Or manually copy the built plugin. The ida-cmake build writes the plugin into
the IDA SDK's plugin directory (`$IDASDK/bin/plugins`, `$IDASDK/src/bin/plugins`
for the GitHub SDK layout, or `$IDABIN/plugins` when the `IDABIN` environment
variable is set) as `chernobog.dylib`/`.so`/`.dll` (no `64` suffix):
- macOS: `$IDASDK/bin/plugins/chernobog.dylib` → `~/.idapro/plugins/`
- Linux: `$IDASDK/bin/plugins/chernobog.so` → `~/.idapro/plugins/`
- Windows: `$IDASDK\bin\plugins\chernobog.dll` → `%APPDATA%\Hex-Rays\IDA Pro\plugins\`

Plugin discovery order is not treated as decompiler availability. If Chernobog
loads before the Hex-Rays dispatcher is ready, it logs a waiting message and
retries from loader/database notifications plus a bounded deferred GUI timer.
Manual invocation also retries activation.

## Usage

### Quick Start

1. Open a Hikari-obfuscated binary in IDA Pro
2. Navigate to an obfuscated function and open it in the decompiler (F5)
3. Right-click in the pseudocode view and select **"Deobfuscate (Chernobog)"**
   - Or press `Ctrl+Shift+D`
4. The function will be reanalyzed with obfuscation removed

### Automatic Mode

Set the environment variable `CHERNOBOG_AUTO=1` to automatically deobfuscate
functions when they are decompiled. When the variable is unset, auto mode can
also be enabled by creating an empty `~/.chernobog_auto` marker file; an explicit
`CHERNOBOG_AUTO` value (including `0`) overrides the marker.

### Analyze Without Modifying

To see what obfuscation types are present without making changes:
1. Right-click and select **"Analyze obfuscation (Chernobog)"**
   - Or press `Ctrl+Shift+A`
2. Check the IDA output window for the analysis results

### Explore the Current Function With rax

Before Chernobog's first whole-MBA deobfuscation pass for the focused function, it
automatically reuses fresh rax evidence or performs one bounded synchronous
exploration of that function. This prerequisite is scoped to the function being
viewed; background/"decompile all" requests do not trigger rax, and callees are
not recursively emulated.
Consensus NUL-terminated runtime strings are materialized as transient literals
in the current pseudocode; the rax projection itself does not copy final-memory
bytes into the IDB.

Open the function in pseudocode and press `Ctrl+Shift+E`, or select **Explore
current function with rax** from the pseudocode popup. Chernobog snapshots and
explores only the displayed function plus its mapped memory context; it does
not enumerate or emulate every function. Use **Show current-function rax
evidence** for decoder/SMIR, concrete path, branch, indirect-target, memory, and
Z3 cross-check evidence. Application-mode execution models bounded imports,
stops before unknown external code, and treats synthetic Objective-C entry
state or host summaries as exploratory rather than proof-complete. Use
**Cancel current-function rax exploration** to stop queued runs. In IDA's
text/batch mode, set `CHERNOBOG_RAX_BATCH_EA` to an address inside the target
function and invoke the plugin with argument `0x524158` (ASCII `RAX`) to run the
exploration synchronously. The complete report semantics, capability boundaries,
and configuration are in [`RAX_HYBRID.md`](RAX_HYBRID.md).

An analogous analysis-only probe exists for control-flow flattening: set
`CHERNOBOG_CFF_BATCH_EA` to an address inside the target function and invoke the
plugin with argument `0x434646` (ASCII `CFF`) to generate uncached `MMAT_LOCOPT`
microcode, run the flattening detector, and print its verdict to the output
window. No mutation components are enabled, so it reports detector behavior
without applying any deobfuscation.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CHERNOBOG_AUTO=1` | Auto-deobfuscate on decompilation |
| `CHERNOBOG_VERBOSE=1` | Enable verbose logging |
| `CHERNOBOG_DEBUG=1` | Enable debug output to `/tmp/chernobog_debug.log` |
| `CHERNOBOG_RESET=1` | Clear decompiler cache on startup |
| `CHERNOBOG_DISABLE=1` | Disable transformations while retaining plugin lifecycle and optional cache reset |
| `CHERNOBOG_IDA_ANALYSIS=0` | Disable native IDA analysis enrichment, early Hex-Rays enrichment, and rax evidence materialization |
| `CHERNOBOG_IDA_EARLY_HEXRAYS=0` | Disable all flowchart/codegen/generated/preoptimized analysis-quality passes while retaining later Chernobog deobfuscation |
| `CHERNOBOG_IDA_CALL_POP_FLOWCHART=0` | Disable call/pop CFG repair at `hxe_flowchart` |
| `CHERNOBOG_IDA_CALL_POP_CODEGEN=0` | Disable return-to-direct-jump repair in the pre-MBA microcode filter |
| `CHERNOBOG_IDA_GENERATED_GOTOS=0` | Disable the generated-MBA return/indirect-jump fallback |
| `CHERNOBOG_IDA_EARLY_CONSTANTS=0` | Disable constant folding at `hxe_preoptimized` |
| `CHERNOBOG_IDA_FORCE_CHAR_STRINGS=0` | Disable character numforms for reconstructed string stores at `hxe_preoptimized` |
| `CHERNOBOG_IDA_GADGET_SCAN_DEPTH=<n>` | Bound call/pop gadget scans (default 8; range 1..64 instructions) |
| `CHERNOBOG_IDA_EARLY_MAX_BLOCKS=<n>` | Bound each early Hex-Rays pass (default 100000; range 1..1000000 blocks) |
| `CHERNOBOG_IDA_EARLY_MAX_INSNS=<n>` | Bound each early Hex-Rays pass (default 1000000; range 1..100000000 microinstructions/native heads) |
| `CHERNOBOG_IDA_POST_SCAN_HEADS=<n>` | Bound the one-shot native orphan-call scan to `n` heads in executable segments (default 1000000; hard range 1..100000000) |
| `CHERNOBOG_IDA_POST_SCAN_FUNCTIONS=<n>` | Bound the one-shot wrapper scan to `n` IDA functions (default 100000; hard range 1..10000000) |
| `CHERNOBOG_IDA_POP_RET_DEPTH=<n>` | Bound call/pop-return get-PC gadget scans (default 4; range 1..64) |
| `CHERNOBOG_IDA_FLAG_SCAN_DEPTH=<n>` | Bound x86 flag-predicate back-scans (default 8; range 1..64) |
| `CHERNOBOG_IDA_REGISTER_SCAN_DEPTH=<n>` | Extra register-tracker depth for indirect-target resolution (default 0; range 0..1024) |
| `CHERNOBOG_IDA_ORPHAN_SCAN_INSNS=<n>` | Bound the orphan-callee decoder scan (default 2000; range 1..1000000) |
| `CHERNOBOG_IDA_WRAPPER_MAX_INSNS=<n>` | Maximum instructions for a function to qualify as an outlinable wrapper (default 20; range 1..256) |
| `CHERNOBOG_IDA_WRAPPER_MAX_CALLERS=<n>` | Maximum callers for wrapper outlining (default 1; 0 = unlimited; up to 1000000) |
| `CHERNOBOG_IDA_MAX_GAP=<n>` | Maximum jump-over-garbage gap retyped between heads (default 0x100; capped at 1 MiB) |
| `CHERNOBOG_IDA_ENTRY_WINDOW=<n>` | Instruction window for entry-flag predicate proofs (default 0x10; capped at 1 MiB) |
| `CHERNOBOG_IDA_GET_PC_TRACE=1` | Emit exact classifier and transactional native-edge diagnostics for call/pop fixture debugging |
| `CHERNOBOG_CFF_BATCH_EA=<addr>` | Text/batch mode: with plugin argument `0x434646` (ASCII `CFF`), run the analysis-only flattening detector on the containing function and print detector evidence; no mutation components are enabled |
| `CHERNOBOG_RAX_APPLY_ANALYSIS=0` | Retain current-function rax reporting/display evidence but suppress all IDB materialization from it |
| `CHERNOBOG_RAX_MIN_DYNAMIC_RUNS=<n>` | Minimum distinct current-function runs for dynamic xrefs/types (default 2; range 1..32) |
| `CHERNOBOG_RAX_MIN_NORET_RUNS=<n>` | Minimum conclusive non-returning runs for a no-return comment (default 3; range 2..64) |
| `CHERNOBOG_RAX_SET_NORET=1` | Opt in to setting `FUNC_NORET`; comments alone remain default |
| `CHERNOBOG_RAX_SWITCH=1` | Opt in to incomplete observed-target custom-switch metadata |
| `CHERNOBOG_RAX_OPAQUE=1` | Opt in to observed-only opaque-predicate comments |
| `CHERNOBOG_MAX_FUNCSIZE_KB=<n>` | Set Hex-Rays' process-local function-size ceiling to decimal `n` KiB (1..1048576); leaves `hexrays.cfg` unchanged |
| `CHERNOBOG_WRITABLE_CONST=1` | Inline loaded 1/2/4/8-byte writable scalars with classified direct reads, no direct writes, no address escape, and no loader fixup on the scalar |
| `CHERNOBOG_WRITABLE_CONST=2` | Additionally admit address-taken scalars/objects (including resolved data-pointer xrefs without retained fixups) and relocation-backed code-pointer slots in writable data; requires ruling out indirect mutation |
| `CHERNOBOG_NATIVE_OPAQUE=1` | Before Hex-Rays lifting, reversibly rewrite proven constant ARM64 `B.cond`/`CBZ`/`CBNZ` terminators to `B` or `NOP`; writable seeds additionally require `CHERNOBOG_WRITABLE_CONST=1` or `2` |
| `CHERNOBOG_PATCH_BRANCHES=1` | Reversibly patch a proven ARM64 indirect tail `BR` to an equivalent in-range direct `B`; re-decompile once after discovery |
| `CHERNOBOG_DEAD_GLOBAL_STORES=1` | Remove direct stores to auto-named writable scalars with write xrefs but no direct reads, fixups, data references, or user/export names |
| `CHERNOBOG_HIKARI_CFG=1` | Recover exact two-target ARM64 Hikari dispatch edges across IDA function boundaries and add IDB xrefs/comments |
| `CHERNOBOG_HIKARI_CFG=2` | Additionally rewrite side-effect-free dispatch tails to reversible direct conditional branches |
| `CHERNOBOG_MBA_AFFINE=1` | Enable exact-Z3 affine MBA reconstruction (opt-in) |
| `CHERNOBOG_MBA_DEBUG=1` | Log affine decisions to `/tmp/chernobog_mba_debug.log` |
| `CHERNOBOG_VM=1` | Enable VM-family detection and rewriting (opt-in) |
| `CHERNOBOG_VM_Z3=1` | Enable additional exact-Z3 VM residual simplification |
| `CHERNOBOG_VM_CARRIER_POOL=...` | Comma-, semicolon-, or whitespace-separated VM carrier constants, parsed with base autodetection |
| `CHERNOBOG_VM_DEBUG=1` | Log VM decisions to `/tmp/chernobog_vm_debug.log` |
| `CHERNOBOG_VM_DUMP_JSON=1` | Dump VM summaries to `/tmp/chernobog_vm_summary_<EA>.json` |

File-based debug and dump output (`CHERNOBOG_DEBUG`, `CHERNOBOG_MBA_DEBUG`,
`CHERNOBOG_VM_DEBUG`, `CHERNOBOG_VM_DUMP_JSON`) is available on macOS and Linux
only; it is compiled out and has no effect in Windows builds.

Each native-analysis pass gated by `CHERNOBOG_IDA_ANALYSIS` also has an
individual default-on toggle; set any to `0` to disable that pass alone while
leaving the rest of the enrichment engine active: `CHERNOBOG_IDA_REDUNDANT_PREFIX`,
`CHERNOBOG_IDA_CALL_POP` (native call/pop get-PC recovery, distinct from the
`CHERNOBOG_IDA_CALL_POP_FLOWCHART`/`_CODEGEN` early-Hex-Rays toggles above),
`CHERNOBOG_IDA_PUSH_RET`, `CHERNOBOG_IDA_ZERO_REGISTER`,
`CHERNOBOG_IDA_OPPOSITE_BRANCHES`, `CHERNOBOG_IDA_ENTRY_PREDICATES`,
`CHERNOBOG_IDA_KNOWN_FLAGS`, `CHERNOBOG_IDA_INDIRECT_BRANCHES`,
`CHERNOBOG_IDA_JUMP_GAPS`, `CHERNOBOG_IDA_ORPHAN_FUNCTIONS`, and
`CHERNOBOG_IDA_OUTLINE_WRAPPERS`.

The current-function rax evidence consumer (`CHERNOBOG_RAX_APPLY_ANALYSIS`)
similarly exposes per-category toggles — code and data references, code
creation, pointer offsets, data typing, string creation, comments, function
recovery, stack purge, argument registers, and no-return comments — each a
`CHERNOBOG_RAX_*` switch documented in [`RAX_HYBRID.md`](RAX_HYBRID.md).

Raising `CHERNOBOG_MAX_FUNCSIZE_KB` admits larger functions to Hex-Rays and can
materially increase decompilation time and memory use. It does not override
Hex-Rays' separate structural-complexity limit.

`CHERNOBOG_WRITABLE_CONST=1` models the load-time value of writable scalar
seeds. It is intended for static initializer and Hikari constant-pool analysis.
Indirect stores or external runtime mutation are not provably excluded by IDA's
direct xrefs; use the mode only when those mutation paths have been ruled out
for the analyzed corpus. Tier 1 rejects address-taken scalars. Tier 2 accepts
loader-fixup references to those scalars and therefore depends on the stronger
assumption that no escaped pointer is used to mutate them before a folded load.
Tier 2 also permits exact indirect-tail resolution through pointer-width loader
fixups in writable data when the resolved target is an executable function
entry; this additionally assumes the pointer slot itself is not mutated first.

`CHERNOBOG_NATIVE_OPAQUE=1` runs once per database after autoanalysis and before
Hex-Rays constructs the function CFG. It interprets only straight-line facts
inside each IDA native basic block: integer constants, exact read-only or
explicitly admitted scalar loads, non-escaping `X29`-relative stack slots,
AArch64 `NZCV`, and the terminal `B.cond`/`CBZ`/`CBNZ`. Calls invalidate
register, flag, and stack facts. Unknown instructions, operand extensions,
shift forms, aliases, widths, stores, or branch predicates fail closed. A
proven taken edge becomes an in-range direct `B`; a proven fallthrough becomes
`NOP`. Both use IDA's patch database, retain original bytes for revert, update
code references, and annotate the proof site; the input binary is unchanged.
The scan is `O(I + X)` time and `O(R + S)` transient state per block, where
`I` is decoded instructions, `X` is scalar-classification references, `R` is
tracked registers, and `S` is tracked stack slots. Writable-mode assumptions
remain exactly those described above; mode 0 admits only read-only storage.

`CHERNOBOG_PATCH_BRANCHES=1` is independent and remains disabled by default.
It activates only after exact target evaluation, requires the native instruction
to be an ARM64 register `BR`, requires a 4-byte-aligned external function entry
within the signed 26-bit `B` range, and uses IDA's reversible patch API (the
input file is unchanged). The first decompilation discovers and patches the
tail; re-decompile the function to let Hex-Rays regenerate microcode from the
direct branch.

`CHERNOBOG_DEAD_GLOBAL_STORES=1` is a closed-world analysis mode. Its static
gate rejects direct reads, loader/data references, fixups, user-named objects,
unaligned or non-scalar destinations, and non-writable or executable segments.
IDA xrefs cannot prove the absence of an indirect read or an external observer;
the mode therefore requires that those paths be ruled out for the corpus.

`CHERNOBOG_HIKARI_CFG` recognizes the ARM64 Hikari pattern that initializes
two-entry relocation tables in one root block, indexes them with `CSET`, and
adds a shared signed 32-bit bias before `BR`. Recovery requires two loader
fixups, a unique pair of executable function-entry targets, and an XOR key
observed in the same register in the corpus. Tier 1 leaves instructions intact.
Tier 2 rewrites only compact spans containing whitelisted loads/addressing and
arithmetic, with no external incoming edge or observable store/call; the
predicate-result store is retained. IDA retains the original bytes for revert,
and the input file is never modified.

### Plugin Info

Press `Ctrl+Shift+H` to display plugin information and supported obfuscation types.

## How It Works

Chernobog combines IDA processor/IDB listeners with Hex-Rays ingress,
optimizer, and ctree callbacks. It loads as one instance per open database
(`PLUGIN_MULTI`): every optimizer callback, analysis cache, and evidence store
is keyed by database context, so multiple IDBs open in one IDA process stay
fully isolated. The system uses a multi-phase approach:

### Phase 0: Native analysis and decompiler ingress

Default-on, bounded analysis-quality passes run at the same stages as the
corresponding IDA and Hex-Rays analysis mechanisms:

- `ev_ana_insn`/`ev_emu_insn`: repair native instructions, xrefs, junk gaps,
  call/pop and push/return control flow, opaque branches, and statically
  resolved indirect targets while IDA autoanalysis is constructing the IDB.
- `auto_empty_finally`: close proven get-PC functions over unowned non-call
  CFG successors, then promote direct orphan callees and mark small wrapper
  functions as outlined.
- `hxe_flowchart` and the microcode filter: repair call/pop successors and
  translate resolved gadget returns before microcode generation.
- `hxe_microcode`: provide a generated-MBA fallback for unresolved
  return/indirect-jump terminators.
- `hxe_preoptimized`: fold bounded static constants and attach character
  numforms before later optimizer passes consume the MBA.

These static passes do not run rax or emulate the program. The separate rax
path remains an explicit, bounded exploration of the focused function as
described above. The early stages are also distinct from Chernobog's existing
LOCOPT and final-ctree algorithms; similarity of an output rewrite does not
make the analysis stages equivalent.

For a native flowchart with `B` blocks, `E` edges, `I` instructions, and `K`
marked call/pop sites, repair costs
`O(I + B log B + K log B + E)` time and `O(B)` transient state. For an MBA
with `R` candidate return terminators, generated-goto repair costs
`O(B log B + R log B + E)` time and `O(B)` state. For an MBA whose blocks
contain `I_b` microinstructions, constant resolution has the
conservative worst-case bound `O(Σ_b I_b²)` for SDK def-list construction and
worst-case abstract-state invalidation; the register domain is capped at 256
exact ranges. Character collection adds `O(I + C log C)` time and `O(S + C)`
state, where `S` is the number of exact stack/frame slots and `C` the number of
candidate character bytes. Native post-analysis scans are `O(H + F + G)` time
and `O(G)` worklist state, where `H` is the bounded executable-head count, `F`
the bounded function count, and `G` the reachable non-call edges of affected
get-PC functions. Later autoanalysis completions examine only retained targets.

Early folding carries exact register and stable frame-slot facts forward only
within one microblock. Calls clear both domains; unknown/overlapping register
or memory definitions invalidate affected facts. Static memory folding requires
loaded 1/2/4/8-byte storage outside external segments and rejects every
observed direct `dr_W` reference. This admits initialized writable bytes used
by string reconstructors. IDA's direct-xref model cannot exclude an indirect
or external mutation; disable
`CHERNOBOG_IDA_EARLY_CONSTANTS` when that closed-world assumption is invalid
for the analyzed input.

### Phase 1: Analysis and Transformation (MMAT_LOCOPT)
Both analysis and application run at `MMAT_LOCOPT` — the earliest maturity at
which Hex-Rays invokes the block optimizer, and the first point at which the CFG
can be modified safely:
- **Pattern Detection**: Identifies obfuscation patterns (flattening, MBA, encrypted strings, etc.)
- **Z3 Symbolic Execution**: Analyzes dispatcher state machines and solves for control flow transitions
- **CFG Reconstruction**: Applies control flow changes, storing transitions by state values and block start addresses (not block indices) for stability across maturity levels
- **Recurrent-Switch Reconstruction**: Enumerates bounded paths from each
  encoded case back to the dispatcher, proves a unique next target for every
  feasible path, separates infeasible paths from unresolved ones, specializes
  shared side-effecting frontiers, and bypasses the dispatcher so Hex-Rays can
  prune it in its normal optimizer lifecycle. Rewrites are
  planned against stable addresses, applied transactionally from an MBA
  snapshot, verified, and rolled back if any application step rejects. The pass is
  fail-closed if state storage escapes, a call can spoil private state, any
  transition is ambiguous, path/solver bounds are exceeded, or a rewrite would
  skip observable effects.
- **MBA Simplification**: Z3-certified simplification with average O(1) root-opcode lookup and lazy commutative matching
- **Peephole Optimization**: Local optimizations (constant folding, dead code elimination)

### Phase 2: Late Passes (MMAT_CALLS, MMAT_GLBOPT1, MMAT_GLBOPT2, hxe_glbopt)
- **Indirect Call Resolution and Resolver Cleanup (`MMAT_CALLS`)**: Once call arguments are materialized, indirect calls are resolved, a first VM-family pass runs, and pure call-site argument expressions that a recurrent, statically closed resolver thunk provably never reads are neutralized (physical ABI slots are retained so live arguments do not shift)
- **Deferred Reapplication (`MMAT_GLBOPT1`)**: Global-constant inlining is retried and the deferred identity-call and deflattening analyses are applied — or flattening is freshly re-detected — once addresses have resolved
- **Late VM/MBA Recovery (`MMAT_GLBOPT2`)**: VM-family and residual MBA passes run again
- **Late Branch Resolution (`hxe_glbopt`, auto mode only)**: Register-defined indirect tail targets are resolved in microcode and constant same-block conditional branches are simplified; with the separate `CHERNOBOG_PATCH_BRANCHES=1` opt-in a resolved ARM64 `BR` tail is additionally patched to a reversible direct `B`. Native opaque-predicate patching runs earlier, at flowchart/auto-analysis time (see `CHERNOBOG_NATIVE_OPAQUE`)

### Phase 3: Ctree Cleanup (CMAT_FINAL)
- **High-Level Optimization**: Additional cleanup at the decompiler AST level
- **String Annotation**: Exact-address ciphertext/plaintext pairs are emitted
  as persistent pseudocode comments. Bytewise initializers are grouped only
  within the same linear ctree block; conflicting branch-local reconstructions
  are rejected, as are conflicting plaintext producers for one exact address.
  Indexed source bytes are evaluated only when the global-constant admission
  proof establishes the requested element width.
- **Switch Folding**: Collapses switches whose controlling expression is provably constant, removing the unreachable cases

The Ctree cleanup hook runs automatically only in auto mode; the manual
**Deobfuscate (Chernobog)** action applies its Ctree passes through its own path.

### Key Technical Features

#### Z3 Integration
The Z3 theorem prover is used for:
- Solving control flow state machines
- Evaluating opaque predicates (always-true/false detection)
- Verifying expression equivalence for complex patterns
- Analyzing jump conditions

#### Two-Phase Deobfuscation
Many handlers use a two-phase analyze/apply approach to ensure stability:
1. Analysis phase captures transitions using state values and addresses
2. Application phase verifies and applies changes when CFG is stable

#### Lazy Commutative Matching
Rather than pre-generating factorially many pattern variants, the matcher tries
the swapped operand order at match time for the five commutative microcode
operators (`m_add`, `m_mul`, `m_and`, `m_or`, `m_xor`) with binding rollback.
Add/subtract equivalences such as `x + (-y) == x - y` are separate registered
rules rather than generated variants.

## Testing

The executable regression suite is integrated with CTest:

```bash
# Native Release build and all tests
cmake --preset native-release
cmake --build --preset native-release
ctest --test-dir build --output-on-failure

# Explicit macOS architecture builds
cmake --preset macos-arm64-release
cmake --build --preset macos-arm64-release
ctest --test-dir out/build/macos-arm64-release --output-on-failure

cmake --preset macos-x86_64-release
cmake --build --preset macos-x86_64-release
ctest --test-dir out/build/macos-x86_64-release --output-on-failure
```

Test coverage includes:
- exact-width bit-vector and target-endian decoding semantics
- alignment-independent SIMD hashing and comparison
- unique-model Z3 solving, including ambiguous/unsatisfiable/64-bit cases
- all 108 registered MBA rules, Z3-verified at 8, 16, 32, and 64 bits
- commutative AST matching and binding rollback for five microcode operators
- Hikari XOR-string recovery with both terminator forms and corruption rejection
- rax hybrid-engine regression: ARM64 memory mapping and accounting, external/application boundaries, Objective-C entry ABI, decoder/SMIR analysis, in-flight cancellation, and worker/evidence generation

Disposable live-IDB scripts under `tests/ida_early_*_smoke.py` cover x86
call/pop CFG recovery at native, flowchart, and codegen stages plus ARM64
preoptimized constant/character reconstruction. The parameterized
`tests/ida_native_negative_smoke.py` covers ordinary calls, multi-caller
prologues, orphan callee promotion, and indirect SEH dispatchers.
`tests/ida_cff_plugin_probe.py` repeats uncached decompilation and asserts that
the reference recurrent dispatcher is absent from every result, proven-unused
recurrent-resolver arguments are neutralized, and output converges
deterministically after Hex-Rays type propagation.
`tests/ida_decompile_probe.py` and `tests/ida_interr_scan.py` provide targeted
and whole-IDB decompiler regression checks for timeouts and internal errors.
`tests/ida_rax_smoke.py`, `tests/ida_rax_deobf_smoke.py`, and
`tests/ida_rax_gui_lifecycle_smoke.py` cover current-function rax exploration,
automatic rax-before-deobfuscation integration, and GUI first-view string
materialization (the last requires the graphical IDA executable).
`tests/ida_cff_detector_smoke.py` drives the headless CFF detector probe
(`CHERNOBOG_CFF_BATCH_EA`), `tests/ida_cff_switch_probe.py` checks recurrent
switch-dispatch classification, and `tests/ida_cff_transition_probe.py` is a
plugin-free dump of transition microcode.

The CTest targets are SDK-linked but do not constitute a live-IDB decompiler
integration test. Runtime validation requires an IDA/Hex-Rays build compatible
with the SDK used to compile the plugin and a representative binary corpus.

Use the pristine runner for live tests so an existing IDA user directory,
database cache, or installed plugin cannot affect the result:

```bash
python3 tests/run_ida_smoke.py \
  --ida /path/to/idat \
  --plugin /path/to/chernobog.dylib \
  --output-dir /tmp/chernobog-smoke \
  --set CHERNOBOG_SMOKE_EA=0x401000 \
  /path/to/original-binary tests/ida_decompile_probe.py
```

The runner copies the raw input, creates an isolated `IDAUSR`, records SHA-256
digests for the input and exact plugin artifact, requires a Chernobog `PASS`
marker because IDA does not consistently propagate `qexit(N)`, and disables
rax execution/materialization by default. `--enable-rax` opts in. Database
inputs (`.i64`, `.idb`, and sidecar formats) are rejected unless
`--allow-database` is explicit. A retained `--output-dir` contains `ida.log`
and the disposable database for audit. The required log pattern can be
overridden with `--expect-log`; `--ida` and `--plugin` default to the
`CHERNOBOG_IDAT` and `CHERNOBOG_PLUGIN` environment variables, `--license`
(default `IDA_LICENSE_FILE`) supplies an optional key file, `--ida-user-template`
selects the source of the isolated user directory (default `~/.idapro`), and
`--verbose` echoes runner activity.

IDA does not unload a previously mapped plugin image when the dylib/so/DLL is
rebuilt in place. Restart IDA before GUI validation and match the startup line
`[chernobog] build=<revision> dirty=<0|1> source=<fingerprint> sdk=940 rax=<revision> dbctx=<id>`
to the artifact under test; otherwise GUI output can come from stale code.

## Limitations

- Requires functions to be decompilable by Hex-Rays
- Custom or heavily modified Hikari variants may not be fully supported
- Encoded recurrent switch dispatchers are rewritten only when every bounded
  returning path has a unique proved target and the complete rewrite plan is
  side-effect safe; unsupported graph shapes remain intact
- Some obfuscation patterns may require manual cleanup after automated processing
- Anti-analysis tricks (anti-debug, VM detection) are not handled
- General Z3 analysis is bounded by a 5 s default query timeout (shorter for
  opaque-predicate and rule-verification checks). Recurrent-switch recovery
  uses at most 1 s per query and a 30 s total solver deadline, plus 32 blocks
  per path, 256 paths per case, and 4096 total paths; exceeding any bound leaves
  the original dispatcher intact

## Contributing

Contributions are welcome! Areas that could use improvement:

- Support for additional obfuscation modes
- Performance optimizations for large functions
- Support for other LLVM-based obfuscators (additional OLLVM variants, etc.)
- Additional MBA simplification rules
- New dispatcher/flattening patterns for the deflatten handler

When adding new MBA rules, define the rule with the `DEFINE_MBA_RULE` macro and
register it with `REGISTER_MBA_RULE` in the matching `rules_*.cpp`:
```cpp
DEFINE_MBA_RULE(MyRule, "my_rule",
    sub(x_0(), neg(x_1())),  // pattern: x - (-y)
    add(x_0(), x_1())        // replacement: x + y
);

REGISTER_MBA_RULE(MyRule);   // without this the rule is never applied
```
`DEFINE_MBA_RULE` only defines the rule class; it takes effect only once
`REGISTER_MBA_RULE` adds it to the registry. New rules must pass Z3 equivalence
verification at 8, 16, 32, and 64 bits during registry initialization or they
are rejected and logged. Rules that need constant-operand validation use
`DEFINE_MBA_RULE_WITH_CHECK`.

## License

This project is provided for educational and research purposes.

## Acknowledgments

- The IDA Pro and Hex-Rays teams for their excellent reverse engineering tools
- The Z3 theorem prover team for their powerful SMT solver
- The Hikari project for documenting their obfuscation techniques
- The D810 project for foundational deobfuscation research
- The reverse engineering community for their research on deobfuscation
