#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Pattern matching for Hikari obfuscation detection
//--------------------------------------------------------------------------
namespace pattern_match {

// Opaque predicate patterns
struct opaque_pred_t {
    enum type_t {
        OPAQUE_ALWAYS_TRUE,
        OPAQUE_ALWAYS_FALSE,
        OPAQUE_UNKNOWN
    };

    type_t type;
    minsn_t *cond_insn;
    int true_block;
    int false_block;
};

// Check if a condition is an opaque predicate
opaque_pred_t analyze_predicate(mblock_t *blk, minsn_t *jcc_insn, deobf_ctx_t *ctx);

// Check if expression is always true/false
bool is_always_true(minsn_t *insn);
bool is_always_false(minsn_t *insn);

// Flattening patterns
struct flatten_info_t {
    int dispatcher_block;       // Block with switch statement
    int loop_entry_block;       // Loop entry
    int loop_end_block;         // Loop end (jumps back to entry)
    mop_t state_var;            // The state variable
    std::map<uint64_t, int> state_to_block;  // State value -> original block
};

bool detect_flatten_pattern(mbl_array_t *mba, flatten_info_t *out);

// String encryption patterns
struct string_enc_info_t {
    ea_t encrypted_addr;        // Address of encrypted data
    ea_t decrypt_space_addr;    // Address of decryption workspace
    ea_t key_addr;              // Address of XOR key (if global)
    std::vector<uint8_t> keys;  // XOR keys per element
    int element_size;           // 1, 2, 4, or 8 bytes
    int num_elements;
};

bool detect_string_encryption(mbl_array_t *mba, ea_t func_ea, std::vector<string_enc_info_t> *out);

// Constant encryption patterns
struct const_enc_info_t {
    ea_t const_gv_addr;         // Global variable holding encrypted constant
    uint64_t xor_key;           // XOR key
    uint64_t decrypted_value;   // Decrypted constant value
};

bool detect_const_encryption(mblock_t *blk, std::vector<const_enc_info_t> *out);

// Indirect branch patterns
struct indirect_br_info_t {
    ea_t jump_table_addr;       // Address of jump table
    std::vector<ea_t> targets;  // Target addresses from table
    bool is_encrypted;          // Jump targets encrypted
    uint64_t enc_key;           // Encryption key if encrypted
};

bool detect_indirect_branch(mblock_t *blk, indirect_br_info_t *out);

// Substitution patterns - maps complex expression to simple operation
struct substitution_info_t {
    enum orig_op_t {
        SUBST_ADD,
        SUBST_SUB,
        SUBST_AND,
        SUBST_OR,
        SUBST_XOR,
        SUBST_MUL
    };

    orig_op_t original_op;
    minsn_t *complex_insn;      // The obfuscated instruction
    mop_t operand1;             // First operand of original operation
    mop_t operand2;             // Second operand of original operation
};

bool match_substitution_pattern(minsn_t *insn, substitution_info_t *out);

// Split block patterns
struct split_block_info_t {
    std::vector<int> mergeable_blocks;  // Blocks that can be merged into one
};

bool detect_split_blocks(mbl_array_t *mba, std::vector<split_block_info_t> *out);

} // namespace pattern_match
