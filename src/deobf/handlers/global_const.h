#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Global Constant Inlining Handler
//
// Replaces loads from global addresses that contain constant numeric values
// with immediate operands.
//
// Example:
//   mov rax, [gvar_123]   ; where gvar_123 contains 0x12345678
// Becomes:
//   mov rax, 0x12345678
//
// This helps simplify code where constants are stored in data sections,
// making the decompiled output cleaner and more readable.
//--------------------------------------------------------------------------
class global_const_handler_t {
public:
    // Detection - check if there are inlinable global constants
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Instruction-level simplification (called from optinsn_t)
    static int simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx);

private:
    struct global_const_t {
        minsn_t *insn;          // The load instruction
        mop_t *gv_mop;          // The global variable operand
        ea_t gv_addr;           // Global variable address
        uint64_t value;         // Constant value
        int size;               // Size in bytes
    };

    // Find all global constants being loaded
    static std::vector<global_const_t> find_global_consts(mbl_array_t *mba);

    // Check if instruction loads from a known constant global
    static bool is_global_const_load(minsn_t *ins, global_const_t *out);

    // Check if an address is in a read-only data section
    static bool is_const_data(ea_t addr);

    // Check if value looks like a pointer (heuristic)
    static bool looks_like_pointer(uint64_t val, int size);

    // Read value from global
    static uint64_t read_global_value(ea_t addr, int size);

    // Replace load with constant
    static int replace_with_constant(mblock_t *blk, minsn_t *ins,
                                    const global_const_t &gc);
};
