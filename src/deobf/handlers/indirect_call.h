#pragma once
#include "../deobf_types.h"

//--------------------------------------------------------------------------
// Indirect Call Resolution Handler
//
// Hikari's IndirectCall obfuscation:
//   - Creates a global table of code addresses
//   - Replaces direct calls with: call(table[index] - offset)
//   - The offset is a constant value subtracted from each table entry
//
// Pattern in decompiled code:
//   v3 = &global_table;
//   ((void(*)(...))((char*)v3[index] - offset))(...);
//
// Pattern at microcode level:
//   mov reg1, #table_addr
//   add reg2, reg1, #(index * 8)
//   ldx reg3, ds.8, reg2
//   sub reg4, reg3, #offset
//   icall cs, reg4
//
// Detection:
//   - m_icall instructions with computed targets
//   - Target computed as: load_from_table - constant_offset
//   - Global tables containing code addresses
//
// Resolution evaluates only the actual call offset expression (m_icall.r),
// including exact loads from non-writable storage. No unrelated table or
// constant correlation is performed.
//--------------------------------------------------------------------------
class indirect_call_handler_t {
public:
    // Detection - checks for indirect call patterns
    static bool detect(mbl_array_t *mba);

    // Main deobfuscation pass
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

private:
    // Indirect call info
    struct indirect_call_t {
        int block_idx;              // Block containing the call
        minsn_t *call_insn;         // The call instruction
        ea_t table_addr;            // Global table base address
        int table_index;            // Index into table (-1 if variable)
        int64_t offset;             // Offset subtracted from table entry
        ea_t resolved_target;       // Computed target address
        bool is_resolved;           // Whether we successfully resolved it
        qstring target_name;        // Name of resolved target (if any)
        
        indirect_call_t() : block_idx(-1), call_insn(nullptr), table_addr(BADADDR),
                           table_index(-1), offset(0), resolved_target(BADADDR),
                           is_resolved(false) {}
    };

    // Find all indirect calls in the function
    static std::vector<indirect_call_t> find_indirect_calls(mbl_array_t *mba);

    // Analyze an indirect call to extract table/index/offset
    static bool analyze_indirect_call(mblock_t *blk, minsn_t *call_insn, 
                                      indirect_call_t *out);

    // Replace indirect call with direct call
    static int replace_indirect_call(mbl_array_t *mba, mblock_t *blk,
                                     indirect_call_t &ic, deobf_ctx_t *ctx);

    // Annotate unresolved indirect call
    static void annotate_indirect_call(mblock_t *blk, const indirect_call_t &ic);
};
