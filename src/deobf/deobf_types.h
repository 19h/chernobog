#pragma once
#include "../common/warn_off.h"
#include <hexrays.hpp>
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <xref.hpp>
#include <name.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <auto.hpp>
#include "../common/warn_on.h"

#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <functional>
#include <optional>
#include <memory>
#include <algorithm>

// Forward declarations
struct deobf_ctx_t;
class mblock_visitor_t;

//--------------------------------------------------------------------------
// Obfuscation detection flags
//--------------------------------------------------------------------------
enum obf_type_t : uint32_t {
    OBF_NONE            = 0,
    OBF_FLATTENED       = 1 << 0,   // Control flow flattening
    OBF_BOGUS_CF        = 1 << 1,   // Bogus control flow
    OBF_STRING_ENC      = 1 << 2,   // String encryption
    OBF_CONST_ENC       = 1 << 3,   // Constant encryption
    OBF_INDIRECT_BR     = 1 << 4,   // Indirect branches
    OBF_SUBSTITUTION    = 1 << 5,   // Instruction substitution
    OBF_SPLIT_BLOCKS    = 1 << 6,   // Split basic blocks
    OBF_FUNC_WRAPPER    = 1 << 7,   // Hikari function wrappers
    OBF_IDENTITY_CALL   = 1 << 8,   // Identity function indirect calls
    OBF_STACK_STRING    = 1 << 9,   // Stack string construction
    OBF_SAVEDREGS       = 1 << 10,  // Register demotion (savedregs patterns)
    OBF_OBJC_OBFUSC     = 1 << 11,  // Obfuscated ObjC method calls
    OBF_GLOBAL_CONST    = 1 << 12,  // Global constants that can be inlined
    OBF_PTR_INDIRECT    = 1 << 13,  // Indirect pointer references (off_XXXX -> symbol)
};

//--------------------------------------------------------------------------
// Detected pattern info
//--------------------------------------------------------------------------
struct pattern_info_t {
    obf_type_t type;
    ea_t addr;
    std::string description;
    std::vector<ea_t> related_addrs;
};

//--------------------------------------------------------------------------
// Deobfuscation context - maintains state during analysis
//--------------------------------------------------------------------------
struct deobf_ctx_t {
    mbl_array_t *mba;           // Microcode block array
    cfunc_t *cfunc;             // Current function being analyzed
    ea_t func_ea;               // Function entry address

    uint32_t detected_obf;      // Bitmap of detected obfuscations
    std::vector<pattern_info_t> patterns;

    // Flattening-specific
    mop_t *switch_var;          // Switch variable for deflattening
    int switch_block;           // Block containing the dispatcher switch
    std::map<uint64_t, int> case_to_block;  // Case value -> real block mapping

    // State transitions: {from_block, to_block, state_value}
    struct transition_t {
        int from_block;
        int to_block;
        uint64_t state_value;
    };
    std::vector<transition_t> transitions;

    // String encryption
    std::map<ea_t, std::string> decrypted_strings;

    // Constant encryption
    std::map<ea_t, uint64_t> decrypted_consts;

    // Statistics
    int blocks_merged;
    int branches_simplified;
    int strings_decrypted;
    int consts_decrypted;
    int expressions_simplified;
    int indirect_resolved;

    deobf_ctx_t() : mba(nullptr), cfunc(nullptr), func_ea(BADADDR),
                   detected_obf(OBF_NONE), switch_var(nullptr), switch_block(-1),
                   blocks_merged(0), branches_simplified(0), strings_decrypted(0),
                   consts_decrypted(0), expressions_simplified(0), indirect_resolved(0) {}
};

//--------------------------------------------------------------------------
// Expression node for symbolic analysis
//--------------------------------------------------------------------------
struct sym_expr_t {
    enum op_t {
        OP_CONST,       // Constant value
        OP_VAR,         // Variable/register
        OP_ADD,         // Addition
        OP_SUB,         // Subtraction
        OP_MUL,         // Multiplication
        OP_DIV,         // Division
        OP_AND,         // Bitwise AND
        OP_OR,          // Bitwise OR
        OP_XOR,         // Bitwise XOR
        OP_NOT,         // Bitwise NOT
        OP_NEG,         // Negation
        OP_SHL,         // Shift left
        OP_SHR,         // Shift right
        OP_SAR,         // Arithmetic shift right
        OP_LOAD,        // Memory load
        OP_UNKNOWN      // Unknown operation
    };

    op_t op;
    uint64_t const_val;
    int var_idx;
    int bit_size;
    std::shared_ptr<sym_expr_t> left;
    std::shared_ptr<sym_expr_t> right;

    sym_expr_t() : op(OP_UNKNOWN), const_val(0), var_idx(-1), bit_size(64) {}

    static std::shared_ptr<sym_expr_t> make_const(uint64_t val, int bits = 64) {
        auto e = std::make_shared<sym_expr_t>();
        e->op = OP_CONST;
        e->const_val = val;
        e->bit_size = bits;
        return e;
    }

    static std::shared_ptr<sym_expr_t> make_var(int idx, int bits = 64) {
        auto e = std::make_shared<sym_expr_t>();
        e->op = OP_VAR;
        e->var_idx = idx;
        e->bit_size = bits;
        return e;
    }

    static std::shared_ptr<sym_expr_t> make_binop(op_t o,
        std::shared_ptr<sym_expr_t> l, std::shared_ptr<sym_expr_t> r) {
        auto e = std::make_shared<sym_expr_t>();
        e->op = o;
        e->left = l;
        e->right = r;
        e->bit_size = l ? l->bit_size : 64;
        return e;
    }

    static std::shared_ptr<sym_expr_t> make_unop(op_t o, std::shared_ptr<sym_expr_t> operand) {
        auto e = std::make_shared<sym_expr_t>();
        e->op = o;
        e->left = operand;
        e->bit_size = operand ? operand->bit_size : 64;
        return e;
    }

    bool is_const() const { return op == OP_CONST; }
    bool is_var() const { return op == OP_VAR; }
};

using sym_expr_ptr = std::shared_ptr<sym_expr_t>;

//--------------------------------------------------------------------------
// Utility functions declarations
//--------------------------------------------------------------------------
namespace deobf {
    // Logging
    void log(const char *fmt, ...);
    void log_verbose(const char *fmt, ...);
    void set_verbose(bool v);

    // Microcode helpers
    minsn_t *find_insn_by_opcode(mblock_t *blk, mcode_t op);
    bool is_jcc(mcode_t op);
    bool is_unconditional_jmp(mcode_t op);
    const char *mcode_name(mcode_t op);

    // Pattern matching
    bool match_xor_pattern(minsn_t *insn, mop_t **out_left, mop_t **out_right);
    bool match_load_xor_pattern(mblock_t *blk, ea_t *out_enc_addr, uint64_t *out_key);

    // Expression analysis
    sym_expr_ptr mop_to_sym(const mop_t &mop, deobf_ctx_t *ctx);
    sym_expr_ptr simplify_expr(sym_expr_ptr expr);
    std::optional<uint64_t> eval_const_expr(sym_expr_ptr expr);
    bool exprs_equivalent(sym_expr_ptr a, sym_expr_ptr b);
}
