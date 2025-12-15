#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Constant Decryption Handler
//
// Hikari's constant encryption:
//   - Replaces constants with XOR(encrypted_gv, key)
//   - Key may be in another global or immediate
//   - Creates GV for each encrypted constant
//
// Detection:
//   - Load from global followed by XOR with constant
//   - Globals with names like "CToGV"
//   - Patterns: load gv; xor key; use result
//
// Reversal:
//   1. Find XOR patterns with global loads
//   2. Read encrypted value from global
//   3. XOR with key to get original constant
//   4. Replace XOR expression with constant
//--------------------------------------------------------------------------
class const_decrypt_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    // Instruction-level simplification (called from optinsn_t)
    static int simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx);

private:
    // Find encrypted constant patterns
    struct encrypted_const_t {
        minsn_t *xor_insn;      // The XOR instruction
        ea_t gv_addr;           // Global variable holding encrypted value
        uint64_t xor_key;       // XOR key
        uint64_t encrypted_val; // Value in global
        uint64_t decrypted_val; // Result after XOR
        int size;               // Size in bytes
    };

    static std::vector<encrypted_const_t> find_encrypted_consts(mbl_array_t *mba);

    // Check if an instruction is an encrypted constant pattern
    static bool is_const_encryption_pattern(minsn_t *ins, encrypted_const_t *out);

    // Replace XOR with decrypted constant
    static int replace_with_constant(mblock_t *blk, minsn_t *ins,
                                    const encrypted_const_t &ec);

    // Read value from global variable
    static uint64_t read_global_value(ea_t addr, int size);
};
