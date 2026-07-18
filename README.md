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

## Features

Chernobog automatically detects and reverses the following Hikari obfuscation techniques:

### Control Flow Obfuscation
- **Control Flow Flattening (CFF)** - Restores the original control flow graph using Z3 symbolic execution to solve state machines. Includes 7 specialized unflatteners:
  - `HikariUnflattener` - Hikari-style state machine patterns
  - `OLLVMUnflattener` - O-LLVM switch-based flattening
  - `FakeJumpUnflattener` - Opaque predicate branches (always-taken/never-taken)
  - `BadWhileLoopUnflattener` - Fake `while(1)` loops with guaranteed breaks
  - `JumpTableUnflattener` - Index-based jump table flattening
  - `SwitchCaseUnflattener` - Obfuscated switch statements
  - `GenericUnflattener` - Heuristic-based fallback for unknown patterns
- **Bogus Control Flow (BCF)** - Identifies and removes opaque predicates, dead branches, and unreachable code blocks
- **Basic Block Splitting** - Merges artificially split basic blocks back together
- **Indirect Branches** - Resolves computed branch targets with support for multiple encodings (direct, offset, XOR, combined)
- **Indirect Calls** - Resolves Hikari's `call(table[index] - offset)` pattern to direct calls

### Data Obfuscation
- **String Encryption** - Decrypts XOR-encrypted strings and annotates them in the disassembly
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
- `~(~x + ~y) + 1` → `x + y`

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
`(x & y) + (~x & y)` → `y`. All 108 registered rules are checked for
8-, 16-, 32-, and 64-bit equivalence before admission.

### VM-Family MBA Recovery

With `CHERNOBOG_VM=1`, functions named `prog_bb_<digits>` are admitted only
after structural checks for instruction-pointer advancement, bytecode reads,
and accumulator writes or threaded successors. The handler recovers SSE/scalar
accumulator packing, removes masked carrier constants, simplifies local MBA
identities, and persists handler summaries. Its optional Z3 residual pass is
enabled separately with `CHERNOBOG_VM_Z3=1`.

### Opaque Predicate Elimination
- **Jump Optimization** - Z3-based analysis for complex conditional simplification
- **Predicate Rules** - Pattern-based simplification for self-comparisons, tautologies, and identity patterns:
  - `setz x, x` → `1`, `setnz x, x` → `0`
  - `jb x, x` → never taken, `jae x, x` → always taken
  - `x*(x+1) % 2 == 0` → always true

### Function Call Obfuscation
- **Identity Function Calls** - Removes identity function wrappers used to hide call targets
- **Hikari Function Wrappers** - Unwraps indirect function calls through Hikari-generated wrapper functions
- **Register Demotion (savedregs)** - Reverses patterns where registers are demoted to stack variables

### Platform-Specific
- **Obfuscated Objective-C Method Calls** - Resolves obfuscated `objc_msgSend` calls on macOS/iOS binaries
- **Pointer Reference Resolution** - Handles ObjC class references through indirection tables

### Ctree-Level Optimizations
Applied after microcode optimization for additional cleanup:
- **Constant Folding** - Simplifies constant expressions in the decompiler output
- **Switch Folding** - Reconstructs switch statements from flattened control flow
- **Indirect Call Resolution** - Resolves remaining indirect calls in the Ctree
- **String Decryption** - Decrypts strings visible only at Ctree maturity

## Requirements

- IDA Pro 9.0+ with Hex-Rays decompiler
- CMake 3.27+
- Ninja build system
- IDA SDK (set `IDASDK` environment variable)
- Git

## Building

```bash
# Set your IDA SDK path
export IDASDK=/path/to/idasdk

# Build the plugin
make build

# Or manually with CMake
mkdir build && cd build
cmake .. -G Ninja
ninja
```

The build always fetches and statically links Z3 from source, so the first
configure/build takes longer and does not require a separate Z3 installation.

### Windows Cross-Compile With Clang

Windows builds can be cross-compiled with `clang-cl` targeting
`x86_64-pc-windows-msvc`; no MinGW GCC toolchain or GitHub Windows runner is
required.

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
- Windows builds still use the local `clang-cl` + `xwin` flow above.

## Installation

```bash
# Automatic installation to ~/.idapro/plugins
make install
```

Or manually copy the built plugin:
- macOS: `build/chernobog64.dylib` → `~/.idapro/plugins/`
- Linux: `build/chernobog64.so` → `~/.idapro/plugins/`
- Windows: `build/chernobog64.dll` → `%APPDATA%\Hex-Rays\IDA Pro\plugins\`

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

Set the environment variable `CHERNOBOG_AUTO=1` to automatically deobfuscate functions when they are decompiled.

### Analyze Without Modifying

To see what obfuscation types are present without making changes:
1. Right-click and select **"Analyze obfuscation (Chernobog)"**
   - Or press `Ctrl+Shift+A`
2. Check the IDA output window for the analysis results

### Environment Variables

| Variable | Description |
|----------|-------------|
| `CHERNOBOG_AUTO=1` | Auto-deobfuscate on decompilation |
| `CHERNOBOG_VERBOSE=1` | Enable verbose logging |
| `CHERNOBOG_DEBUG=1` | Enable debug output to `/tmp/chernobog_debug.log` |
| `CHERNOBOG_RESET=1` | Clear decompiler cache on startup |
| `CHERNOBOG_DISABLE=1` | Disable transformations while retaining plugin lifecycle and optional cache reset |
| `CHERNOBOG_MAX_FUNCSIZE_KB=<n>` | Set Hex-Rays' process-local function-size ceiling to decimal `n` KiB (1..1048576); leaves `hexrays.cfg` unchanged |
| `CHERNOBOG_WRITABLE_CONST=1` | Inline loaded 1/2/4/8-byte writable scalars with classified direct reads, no direct writes, no address escape, and no loader fixup on the scalar |
| `CHERNOBOG_WRITABLE_CONST=2` | Additionally admit address-taken scalars and relocation-backed code-pointer slots in writable data; requires ruling out indirect mutation |
| `CHERNOBOG_PATCH_BRANCHES=1` | Reversibly patch a proven ARM64 indirect tail `BR` to an equivalent in-range direct `B`; re-decompile once after discovery |
| `CHERNOBOG_DEAD_GLOBAL_STORES=1` | Remove direct stores to auto-named writable scalars with write xrefs but no direct reads, fixups, data references, or user/export names |
| `CHERNOBOG_HIKARI_CFG=1` | Recover exact two-target ARM64 Hikari dispatch edges across IDA function boundaries and add IDB xrefs/comments |
| `CHERNOBOG_HIKARI_CFG=2` | Additionally rewrite side-effect-free dispatch tails to reversible direct conditional branches |
| `CHERNOBOG_MBA_AFFINE=1` | Enable exact-Z3 affine MBA reconstruction (opt-in) |
| `CHERNOBOG_MBA_DEBUG=1` | Log affine decisions to `/tmp/chernobog_mba_debug.log` |
| `CHERNOBOG_VM=1` | Enable VM-family detection and rewriting (opt-in) |
| `CHERNOBOG_VM_Z3=1` | Enable additional exact-Z3 VM residual simplification |
| `CHERNOBOG_VM_CARRIER_POOL=...` | Comma-separated VM carrier constants, parsed with base autodetection |
| `CHERNOBOG_VM_DEBUG=1` | Log VM decisions to `/tmp/chernobog_vm_debug.log` |
| `CHERNOBOG_VM_DUMP_JSON=1` | Dump VM summaries to `/tmp/chernobog_vm_summary_<EA>.json` |

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

Chernobog operates as a Hex-Rays optimizer callback, integrating directly into IDA's microcode optimization pipeline. The system uses a sophisticated multi-phase approach:

### Phase 1: Analysis (MMAT_PREOPTIMIZED)
- **Pattern Detection**: Identifies obfuscation patterns (flattening, MBA, encrypted strings, etc.)
- **Z3 Symbolic Execution**: Analyzes state machines and solves for control flow transitions
- **State Storage**: Results stored using addresses (not block indices) for stability across maturity levels

### Phase 2: Transformation (MMAT_LOCOPT)
- **CFG Reconstruction**: Applies control flow changes when the graph is stable
- **MBA Simplification**: Z3-certified simplification with average O(1) root-opcode lookup and lazy commutative matching
- **Peephole Optimization**: Local optimizations (constant folding, dead code elimination)

### Phase 3: Ctree Cleanup (CMAT_FINAL)
- **High-Level Optimization**: Additional cleanup at the decompiler AST level
- **String Annotation**: Decrypted strings annotated in the output
- **Switch Reconstruction**: Flattened control flow converted back to switch statements

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

#### Pattern Fuzzing
The pattern matcher automatically generates equivalent variants:
- Commutative: `x + y == y + x`
- Add/Sub equivalence: `x + neg(y) == x - y`
- Configurable depth and variant limits

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
- all 104 registered MBA rules, Z3-verified at 8, 16, 32, and 64 bits
- commutative AST matching and binding rollback for five microcode operators
- Hikari XOR-string recovery with both terminator forms and corruption rejection

The CTest targets are SDK-linked but do not constitute a live-IDB decompiler
integration test. Runtime validation requires an IDA/Hex-Rays build compatible
with the SDK used to compile the plugin and a representative binary corpus.

## Limitations

- Requires functions to be decompilable by Hex-Rays
- Custom or heavily modified Hikari variants may not be fully supported
- Some obfuscation patterns may require manual cleanup after automated processing
- Anti-analysis tricks (anti-debug, VM detection) are not handled
- Z3 analysis has configurable timeouts; extremely complex state machines may not solve

## Contributing

Contributions are welcome! Areas that could use improvement:

- Support for additional obfuscation modes
- Performance optimizations for large functions
- Support for other LLVM-based obfuscators (additional OLLVM variants, etc.)
- Additional MBA simplification rules
- New unflattener strategies for novel patterns

When adding new MBA rules, use the `DEFINE_MBA_RULE` macro:
```cpp
DEFINE_MBA_RULE(MyRule, "my_rule",
    sub(x_0(), neg(x_1())),  // pattern: x - (-y)
    add(x_0(), x_1())        // replacement: x + y
);
```

## License

This project is provided for educational and research purposes.

## Acknowledgments

- The IDA Pro and Hex-Rays teams for their excellent reverse engineering tools
- The Z3 theorem prover team for their powerful SMT solver
- The Hikari project for documenting their obfuscation techniques
- The D810 project for foundational deobfuscation research
- The reverse engineering community for their research on deobfuscation
