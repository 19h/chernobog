#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Stack String Reconstruction Handler
//
// Hikari/OLLVM builds strings at runtime to defeat static strings analysis:
//   - Individual bytes are moved to sequential stack offsets
//   - Sometimes uses qmemcpy for chunks
//   - May use bitwise NOT (~) to hide characters
//   - Terminated with null byte
//
// Example:
//   byte_10001435D = 46;   // '.'
//   byte_10001435E = 112;  // 'p'
//   byte_10001435F = 108;  // 'l'
//   ...
//   byte_100014363 = 0;    // NULL
//
// Detection:
//   - Sequences of mov [stack_offset], imm8 instructions
//   - Sequential or near-sequential addresses
//   - Printable ASCII values (0x20-0x7E) or null terminator
//
// Reversal:
//   1. Identify byte-by-byte construction sequences
//   2. Handle bitwise transformations (~, ^)
//   3. Reconstruct the string
//   4. Annotate in IDA and optionally patch to direct string reference
//--------------------------------------------------------------------------
class stack_string_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);
    static bool detect_in_function(ea_t func_ea);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Instruction-level detection (called during microcode traversal)
    static int process_block(mblock_t *blk, deobf_ctx_t *ctx);

private:
    // Reconstructed string info
    struct stack_string_t {
        ea_t start_addr;            // Address where construction starts
        sval_t stack_offset;        // Base stack offset
        std::string value;          // Reconstructed string
        std::vector<ea_t> insn_addrs;  // Addresses of construction instructions
        bool uses_transform;        // Uses NOT/XOR transformation
    };

    // Byte store info for tracking
    struct byte_store_t {
        sval_t offset;              // Stack offset
        uint8_t value;              // Stored value (after any transforms)
        ea_t insn_addr;             // Instruction address
        bool transformed;           // Was a transform applied?
    };

    // Find stack string construction patterns in a block
    static std::vector<stack_string_t> find_stack_strings(mblock_t *blk);

    // Analyze a sequence of byte stores
    static bool analyze_byte_sequence(const std::vector<byte_store_t> &stores,
                                      stack_string_t *out);

    // Check if instruction is a byte store to stack
    static bool is_stack_byte_store(minsn_t *ins, byte_store_t *out);

    // Handle transformed bytes (NOT, XOR)
    static uint8_t resolve_byte_value(minsn_t *ins);

    // Check if byte is printable or control character
    static bool is_string_byte(uint8_t b);

    // Annotate reconstructed string in IDA
    static void annotate_string(const stack_string_t &str, ea_t func_ea);

    // Try to find the string usage and replace with direct reference
    static int patch_string_usage(mbl_array_t *mba, const stack_string_t &str,
                                  deobf_ctx_t *ctx);
};
