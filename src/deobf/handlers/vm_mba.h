#pragma once
#include "../deobf_types.h"

#include <chrono>
#include <unordered_set>

//--------------------------------------------------------------------------
// VM-family MBA handler
//
// Support for tail-call-threaded VM handlers that use MBA-padded micro-ops
// and SSE unpack idioms to write the threaded accumulator slot.
// Activation is explicit: set CHERNOBOG_VM=1.
//--------------------------------------------------------------------------

class vm_mba_handler_t {
public:
    struct micro_op_t {
        ea_t ea = BADADDR;
        int input_count = 0;
        std::vector<int> input_offsets;
        std::vector<int> input_widths;
        qstring primitive = "opaque";
        int ip_delta = 0;
        bool writes_accumulator = false;
    };

    struct handler_summary_t {
        ea_t ea = BADADDR;
        qstring name;
        int stride = 0;
        bool is_entry = true;
        bool is_terminal = false;
        bool threads_a2 = false;
        bool consumes_a2 = false;
        bool fused_superblock = false;
        int pack_writes = 0;
        int ip_advances = 0;
        int bytecode_reads = 0;
        uint64_t structural_hash = 0;
        std::vector<int> operand_offsets;
        std::vector<int> operand_widths;
        std::vector<micro_op_t> micro_ops;
        std::vector<ea_t> successors;
    };

    static void initialize();
    static void clear();
    static void clear_function(ea_t ea);

    static bool detect(mbl_array_t *mba);
    static int run(mbl_array_t *mba, deobf_ctx_t *ctx);

    static int simplify_insn(mblock_t *blk, minsn_t *ins, deobf_ctx_t *ctx);

    static bool is_candidate(ea_t ea);
    static bool get_summary(ea_t ea, handler_summary_t *out);
    static void dump_summary(ea_t ea);
    static void dump_statistics();

private:
    struct budget_t {
        std::chrono::steady_clock::time_point start;
        int changed = 0;
        int visited = 0;
    };

    static bool initialized_;
    static std::unordered_set<ea_t> candidates_;
    static std::map<ea_t, handler_summary_t> summaries_;
    static std::map<uint32_t, int> carrier_hits_;
    static std::unordered_set<uint64_t> pair_no_compact_cache_;

    static bool enabled();
    static bool name_matches(ea_t ea, qstring *out_name = nullptr);
    static bool is_prog_bb_name(const qstring &name);

    static handler_summary_t summarize(mbl_array_t *mba);
    static void rebuild_graph_metadata();
    static std::string summary_to_json(const handler_summary_t &summary);
    static void persist_summary(const handler_summary_t &summary);

    static int carrier_constant_eliminator(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int operand_pool_constant_pass(mbl_array_t *mba, deobf_ctx_t *ctx);
    static int simplify_block(mblock_t *blk, deobf_ctx_t *ctx);

    static bool is_carrier_constant(uint64_t value, int size = 4);
    static bool get_const(const mop_t &mop, uint64_t *out);
    static uint64_t mask_for_size(int size);
    static bool mops_same(const mop_t &a, const mop_t &b);

    static int simplify_killed_or_cap(minsn_t *ins);
    static int simplify_loword_killed_or_cap(minsn_t *ins);
    static int simplify_masked_bitwise_carriers(minsn_t *ins);
    static int strip_masked_or_caps(mop_t *mop, uint64_t live_mask, int size, int depth);
    static int simplify_nested_constant_ops(minsn_t *ins);
    static int simplify_local_identities(minsn_t *ins);
    static int simplify_hikari_pair_mba(minsn_t *ins);
    static int simplify_pack_idiom_marker(minsn_t *ins);
    static int split_scalar_pack_store(mblock_t *blk, minsn_t *ins);
    static bool match_pack_idiom(const mop_t &mop, mop_t *lo, mop_t *hi);
    static bool match_scalar_pack_expr(const mop_t &mop, mop_t *lo, mop_t *hi);
    static bool match_zext32_to_64(const mop_t &mop, mop_t *out);
    static bool match_shl32_hi(const mop_t &mop, mop_t *hi);
    static bool make_accumulator_half_dst(const mop_t &dst, uint64_t old_off,
                                          uint64_t new_off, mop_t *out);
    static bool match_cvtsi32_operand(const mop_t &mop, mop_t *out);
    static bool match_load_si128_low32(const mop_t &mop, mop_t *out);
    static bool is_helper_call(const minsn_t *ins, const char *needle);
    static int simplify_single_var_residual(minsn_t *ins);
    static bool replace_with_operand(minsn_t *ins, const mop_t &src);
    static bool replace_with_constant(minsn_t *ins, uint64_t value, int size = 0);
    static bool replace_with_and_not(minsn_t *ins, const mop_t &value,
                                     const mop_t &mask);
    static bool match_and_with_operand(const mop_t &mop, const mop_t &value,
                                       mop_t *other);
    static bool match_add_const(const mop_t &mop, mop_t *value, uint64_t *constant);
    static bool match_sub_operands(const mop_t &mop, mop_t *left, mop_t *right);
    static bool match_pair_mba_core(const mop_t &mop, mop_t *x, mop_t *y,
                                    uint64_t *constant);
    static bool replace_with_binary_const_expr(minsn_t *ins, mcode_t base_op,
                                               const mop_t &left, const mop_t &right,
                                               mcode_t outer_op, uint64_t constant);
    static bool eval_const_insn(const minsn_t *ins, uint64_t *out, int *out_size = nullptr);
    static bool is_pure_expr(const minsn_t *ins);
    static int expr_op_count(const minsn_t *ins);
    static void collect_free_mops(const minsn_t *ins, std::vector<mop_t> *out);
    static void collect_free_mops(const mop_t &mop, std::vector<mop_t> *out);
    static bool replace_with_simple_expr(minsn_t *ins, mcode_t op,
                                         const mop_t &var, uint64_t constant);
    static bool replace_with_binary_expr(minsn_t *ins, mcode_t op,
                                         const mop_t &left, const mop_t &right);

    static bool contains_pack_idiom(const minsn_t *ins);
    static bool contains_pack_idiom(const mop_t &mop);
    static bool contains_helper(const minsn_t *ins, const char *needle);
    static bool contains_helper(const mop_t &mop, const char *needle);
    static bool contains_text(const minsn_t *ins, const char *needle);
    static bool contains_text(const mop_t &mop, const char *needle);

    static bool is_accumulator_store(const minsn_t *ins);
    static bool is_ip_advance_store(const minsn_t *ins, int *delta);
    static bool is_tailcall_to_handler(const minsn_t *ins, ea_t *target);

    static void collect_bytecode_reads(const minsn_t *ins,
                                       std::map<int, int> *offset_widths);
    static void collect_bytecode_reads(const mop_t &mop,
                                       std::map<int, int> *offset_widths);
    static bool parse_ip_offset_text(const char *text, int *offset);

    static uint64_t hash_insn(const minsn_t *ins);
    static uint64_t hash_mop(const mop_t &mop);
};
