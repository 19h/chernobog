#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Indirect Branch Resolution Handler
//
// Hikari's indirect branches:
//   - Creates jump table (IndirectBranchingGlobalTable)
//   - Replaces direct branches with table lookups
//   - Optionally encrypts jump targets
//   - May use conditional local tables (HikariConditionalLocalIndirectBranchingTable)
//
// Table formats:
//   1. Direct addresses: table[i] = target_ea
//   2. Offsets from base: table[i] = target_ea - base_ea
//   3. XOR encrypted: table[i] = target_ea ^ key
//   4. Combined: table[i] = (target_ea - base_ea) ^ key
//
// Detection:
//   - ijmp (indirect jump) instructions
//   - Global arrays of code pointers
//   - XOR before address load (encryption)
//   - Local stack-based jump tables
//
// Reversal:
//   1. Find indirect jump instructions
//   2. Trace back to find jump table address
//   3. Emulate index computation to find possible values
//   4. Read and decode targets from table
//   5. Replace ijmp with switch or direct branches
//--------------------------------------------------------------------------
class indirect_branch_handler_t {
public:
    // Detection
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    // Table encoding type
    enum table_encoding_t {
        ENC_DIRECT,         // Direct addresses
        ENC_OFFSET,         // Offsets from base
        ENC_XOR,            // XOR encrypted
        ENC_OFFSET_XOR,     // Offset + XOR
        ENC_UNKNOWN
    };

    // Indirect branch info
    struct indirect_br_t {
        int block_idx;
        minsn_t *ijmp_insn;
        ea_t table_addr;
        std::vector<ea_t> targets;
        bool is_encrypted;
        uint64_t enc_key;
        table_encoding_t encoding;
        ea_t base_addr;             // Base address for offset encoding
        int entry_size;             // Size of each table entry (4 or 8 bytes)
        int table_size;             // Number of entries
        mop_t index_var;            // Variable used as index
        bool index_traced;          // Whether we traced the index
        std::set<int> possible_indices;  // Possible index values
    };

    // Index computation info
    struct index_computation_t {
        enum op_t {
            OP_DIRECT,      // index = var
            OP_AND,         // index = var & mask
            OP_MOD,         // index = var % divisor
            OP_SUB_AND,     // index = (var - sub) & mask
            OP_COMPLEX
        };

        op_t type;
        mop_t source_var;       // Source variable
        uint64_t mask;          // AND mask or MOD divisor
        uint64_t sub_value;     // Subtraction value
        int max_index;          // Maximum possible index value
    };

    static std::vector<indirect_br_t> find_indirect_branches(mbl_array_t *mba);

    // Analyze an indirect jump
    static bool analyze_ijmp(mblock_t *blk, minsn_t *ijmp, indirect_br_t *out);

    // Find the jump table
    static ea_t find_jump_table(mblock_t *blk, minsn_t *ijmp);

    // Analyze table encoding
    static table_encoding_t analyze_table_encoding(mblock_t *blk, minsn_t *ijmp,
                                                   uint64_t *out_key, ea_t *out_base);

    // Trace index computation
    static bool trace_index_computation(mblock_t *blk, minsn_t *ijmp,
                                       index_computation_t *out);

    // Emulate index values to find all possible indices
    static std::set<int> emulate_index_values(mbl_array_t *mba, mblock_t *blk,
                                              const index_computation_t &idx_comp);

    // Read targets from jump table with encoding support
    static std::vector<ea_t> read_jump_targets(ea_t table_addr, int max_entries,
                                               table_encoding_t encoding,
                                               uint64_t key, ea_t base,
                                               int entry_size);

    // Decrypt jump targets (legacy)
    static std::vector<ea_t> decrypt_targets(const std::vector<ea_t> &encrypted, uint64_t key);

    // Decode a single table entry
    static ea_t decode_table_entry(uint64_t raw_value, table_encoding_t encoding,
                                   uint64_t key, ea_t base);

    // Validate jump targets
    static bool validate_targets(const std::vector<ea_t> &targets, mbl_array_t *mba);

    // Replace indirect branch with direct branches
    static int replace_indirect_branch(mbl_array_t *mba, mblock_t *blk,
                                       const indirect_br_t &ibr, deobf_ctx_t *ctx);

    // Build switch from indirect branch
    static int build_switch(mbl_array_t *mba, mblock_t *blk,
                           const indirect_br_t &ibr, deobf_ctx_t *ctx);

    // Annotate unresolved indirect branch
    static void annotate_indirect_branch(mblock_t *blk, const indirect_br_t &ibr);
};
