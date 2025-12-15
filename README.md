# Chernobog

**Chernobog** is a Hex-Rays IDA Pro plugin for deobfuscating binaries protected with the [Hikari](https://github.com/HikariObfuscator/Hikari) LLVM obfuscator.

> *In Slavic mythology, Chernobog (meaning "black god") is a deity of darkness - the natural counterpart to Hikari, which means "light" in Japanese.*

## Features

Chernobog automatically detects and reverses the following Hikari obfuscation techniques:

### Control Flow Obfuscation
- **Control Flow Flattening (CFF)** - Restores the original control flow graph from switch-based dispatcher loops, including support for nested/hierarchical flattening
- **Bogus Control Flow (BCF)** - Identifies and removes opaque predicates, dead branches, and unreachable code blocks
- **Basic Block Splitting** - Merges artificially split basic blocks back together
- **Indirect Branches** - Resolves computed branch targets to direct jumps

### Data Obfuscation
- **String Encryption** - Decrypts XOR-encrypted strings and annotates them in the disassembly
- **Constant Encryption** - Resolves encrypted constants (XOR patterns with global variables)
- **Stack String Construction** - Reconstructs strings built character-by-character on the stack

### Code Transformation
- **Instruction Substitution** - Simplifies complex arithmetic/logical expressions back to their original form:
  - `b - ~c - 1` → `b + c`
  - `(b|c) + (b&c)` → `b + c`
  - `(b^c) + 2*(b&c)` → `b + c`
  - `b + ~c + 1` → `b - c`
  - `(b ^ ~c) & b` → `b & c`
  - `(b&c) | (b^c)` → `b | c`
  - `(~a&b) | (a&~b)` → `a ^ b`
  - And more...

### Function Call Obfuscation
- **Identity Function Calls** - Removes identity function wrappers used to hide actual call targets
- **Hikari Function Wrappers** - Unwraps indirect function calls through Hikari-generated wrapper functions
- **Register Demotion (savedregs)** - Reverses patterns where registers are demoted to stack variables

### Platform-Specific
- **Obfuscated Objective-C Method Calls** - Resolves obfuscated `objc_msgSend` calls on macOS/iOS binaries

## Requirements

- IDA Pro 9.0+ with Hex-Rays decompiler
- CMake 3.10+
- Ninja build system
- IDA SDK (set `IDASDK` environment variable)

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

### Analyze Without Modifying

To see what obfuscation types are present without making changes:
1. Right-click and select **"Analyze obfuscation (Chernobog)"**
   - Or press `Ctrl+Shift+A`
2. Check the IDA output window for the analysis results

### Plugin Info

Press `Ctrl+Shift+H` to display plugin information and supported obfuscation types.

## Architecture

```
src/
├── plugin/
│   ├── deobf_plugin.cpp      # IDA plugin entry point
│   └── component_registry.cpp # Component registration system
├── deobf/
│   ├── deobf_main.cpp        # Main deobfuscation orchestration
│   ├── deobf_types.h         # Common types and enums
│   ├── analysis/
│   │   ├── pattern_match.cpp # Pattern matching utilities
│   │   ├── expr_simplify.cpp # Expression simplification
│   │   ├── cfg_analysis.cpp  # Control flow graph analysis
│   │   ├── opaque_eval.cpp   # Opaque predicate evaluation
│   │   └── stack_tracker.cpp # Virtual stack analysis
│   └── handlers/
│       ├── deflatten.cpp     # Control flow deflattening
│       ├── bogus_cf.cpp      # Bogus control flow removal
│       ├── string_decrypt.cpp # String decryption
│       ├── const_decrypt.cpp  # Constant decryption
│       ├── indirect_branch.cpp # Indirect branch resolution
│       ├── block_merge.cpp    # Basic block merging
│       ├── substitution.cpp   # Instruction substitution reversal
│       ├── identity_call.cpp  # Identity function removal
│       ├── stack_string.cpp   # Stack string reconstruction
│       ├── hikari_wrapper.cpp # Wrapper function resolution
│       ├── savedregs.cpp      # Register demotion reversal
│       └── objc_resolve.cpp   # ObjC call resolution
└── common/
    ├── warn_off.h            # Disable IDA SDK warnings
    └── warn_on.h             # Re-enable warnings
```

## How It Works

Chernobog operates as a Hex-Rays optimizer callback (`optinsn_t`), integrating directly into IDA's microcode optimization pipeline. When you trigger deobfuscation:

1. **Detection Phase**: The plugin analyzes the function's microcode to identify which obfuscation techniques are present
2. **Deobfuscation Pipeline**: Handlers are executed in a specific order to progressively simplify the code:
   - Block merging (simplest transformation first)
   - String/constant decryption
   - Stack string reconstruction
   - Substitution simplification
   - Indirect branch resolution
   - Identity call/wrapper removal
   - Register demotion reversal
   - ObjC call resolution
   - Bogus control flow removal
   - Control flow deflattening (most complex, done last)
3. **Refresh**: The decompiler view is refreshed to show the cleaned code

## Limitations

- Requires functions to be decompilable by Hex-Rays
- Custom or heavily modified Hikari variants may not be fully supported
- Some obfuscation patterns may require manual cleanup after automated processing
- Anti-analysis tricks (anti-debug, VM detection) are not handled

## Contributing

Contributions are welcome! Areas that could use improvement:

- Support for additional Hikari obfuscation modes
- Better handling of nested control flow flattening
- Performance optimizations for large functions
- Support for other LLVM-based obfuscators (OLLVM, etc.)

## License

This project is provided for educational and research purposes.

## Acknowledgments

- The IDA Pro and Hex-Rays teams for their excellent reverse engineering tools
- The Hikari project for documenting their obfuscation techniques
- The reverse engineering community for their research on deobfuscation
