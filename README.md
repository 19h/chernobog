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

### Code Transformation (90+ MBA Rules)
Mixed Boolean-Arithmetic (MBA) simplification using pattern matching with automatic fuzzing for commutative variants:

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

**And many more...** (~90+ rules derived from Hacker's Delight, OLLVM patterns, and algebraic factorizations)

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

## Installation

```bash
# Automatic installation to ~/.idapro/plugins
make install
```

Or manually copy the built plugin:
- macOS: `build/chernobog64.dylib` → `~/.idapro/plugins/`
- Linux: `build/chernobog64.so` → `~/.idapro/plugins/`
- Windows: `build/chernobog64.dll` → `%APPDATA%\Hex-Rays\IDA Pro\plugins\`

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

### Plugin Info

Press `Ctrl+Shift+H` to display plugin information and supported obfuscation types.

## Architecture

```
src/
├── plugin/
│   ├── deobf_plugin.cpp          # IDA plugin entry point & hexrays callbacks
│   └── component_registry.cpp    # Modular component registration system
│
├── deobf/
│   ├── deobf_main.cpp            # Main deobfuscation orchestration
│   ├── deobf_types.h             # Common types and enums
│   ├── deobf_utils.cpp           # Utility functions
│   │
│   ├── analysis/                 # Core analysis infrastructure
│   │   ├── z3_solver.cpp         # Z3 symbolic execution engine
│   │   ├── ast.cpp               # AST tree representation for patterns
│   │   ├── ast_builder.cpp       # AST construction helpers
│   │   ├── pattern_match.cpp     # Pattern detection utilities
│   │   ├── pattern_storage.cpp   # O(log n) pattern lookup
│   │   ├── pattern_fuzzer.cpp    # Commutative/associative variants
│   │   ├── chain_simplify.cpp    # XOR/AND/OR/ADD chain simplification
│   │   ├── expr_simplify.cpp     # Expression simplification
│   │   ├── cfg_analysis.cpp      # Control flow graph analysis
│   │   ├── opaque_eval.cpp       # Opaque predicate evaluation
│   │   ├── stack_tracker.cpp     # Virtual stack analysis
│   │   └── arch_utils.cpp        # Architecture-specific utilities
│   │
│   ├── rules/                    # MBA simplification rules
│   │   ├── pattern_rule.cpp      # Rule base class & macros
│   │   ├── rule_registry.cpp     # Central rule management
│   │   ├── rules_add.cpp         # 17 addition rules
│   │   ├── rules_sub.cpp         # 11 subtraction rules
│   │   ├── rules_xor.cpp         # 19 XOR rules
│   │   ├── rules_and.cpp         # 16 AND rules
│   │   ├── rules_or.cpp          # 15 OR rules
│   │   ├── rules_misc.cpp        # 20 misc rules (NEG, BNOT, MUL, etc.)
│   │   ├── rules_predicate.cpp   # ~30 predicate optimization rules
│   │   └── jump_rules.cpp        # ~10 jump optimization rules
│   │
│   └── handlers/                 # Deobfuscation handlers
│       ├── deflatten.cpp         # Z3-based control flow deflattening
│       ├── unflattener_base.cpp  # Unflattener framework (7 strategies)
│       ├── bogus_cf.cpp          # Bogus control flow removal
│       ├── mba_simplify.cpp      # MBA pattern matching integration
│       ├── peephole.cpp          # Peephole optimizers (7 optimizers)
│       ├── jump_optimizer.cpp    # Jump condition simplification
│       ├── string_decrypt.cpp    # String decryption (microcode)
│       ├── const_decrypt.cpp     # Constant decryption
│       ├── stack_string.cpp      # Stack string reconstruction
│       ├── global_const.cpp      # Global constant inlining
│       ├── indirect_branch.cpp   # Indirect branch resolution
│       ├── indirect_call.cpp     # Indirect call resolution (microcode)
│       ├── block_merge.cpp       # Basic block merging
│       ├── identity_call.cpp     # Identity function resolution
│       ├── hikari_wrapper.cpp    # Wrapper function resolution
│       ├── savedregs.cpp         # Register demotion reversal
│       ├── ptr_resolve.cpp       # Pointer reference resolution
│       ├── objc_resolve.cpp      # ObjC call resolution
│       ├── ctree_const_fold.cpp  # Ctree constant folding
│       ├── ctree_switch_fold.cpp # Ctree switch reconstruction
│       ├── ctree_indirect_call.cpp # Ctree indirect call resolution
│       └── ctree_string_decrypt.cpp # Ctree string decryption
│
├── common/
│   ├── warn_off.h                # Disable IDA SDK warnings
│   └── warn_on.h                 # Re-enable warnings
│
└── tests/
    ├── run_tests.sh              # Comprehensive test suite
    ├── test_components.sh        # Component-level tests
    └── test_individual_functions.sh  # Function-specific tests
```

## How It Works

Chernobog operates as a Hex-Rays optimizer callback, integrating directly into IDA's microcode optimization pipeline. The system uses a sophisticated multi-phase approach:

### Phase 1: Analysis (MMAT_PREOPTIMIZED)
- **Pattern Detection**: Identifies obfuscation patterns (flattening, MBA, encrypted strings, etc.)
- **Z3 Symbolic Execution**: Analyzes state machines and solves for control flow transitions
- **State Storage**: Results stored using addresses (not block indices) for stability across maturity levels

### Phase 2: Transformation (MMAT_LOCOPT)
- **CFG Reconstruction**: Applies control flow changes when the graph is stable
- **MBA Simplification**: Pattern-based simplification with O(log n) lookup and automatic fuzzing
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

The test suite validates all components:

```bash
# Run full test suite
./tests/run_tests.sh

# Verbose output
./tests/run_tests.sh --verbose

# Quick tests only
./tests/run_tests.sh --quick

# Test specific component
./tests/run_tests.sh --component mba
./tests/run_tests.sh --component unflattener
./tests/run_tests.sh --component predicate
```

Test coverage includes:
- AST system and pattern matching
- All 90+ MBA simplification rules
- Predicate rules and jump optimization
- Chain simplifier
- 7 peephole optimizers
- 7 unflattener strategies
- Full decompilation integration

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
