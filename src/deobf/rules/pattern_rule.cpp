#include "pattern_rule.h"

namespace chernobog {
namespace rules {

using namespace ast;

//--------------------------------------------------------------------------
// PatternMatchingRule implementation
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternMatchingRule::get_all_patterns() {
    if (patterns_initialized_) {
        return all_patterns_;
    }

    AstPtr base_pattern = get_pattern();
    if (!base_pattern) {
        patterns_initialized_ = true;
        return all_patterns_;
    }

    if (fuzz_pattern()) {
        // Generate all fuzzed variants
        all_patterns_ = PatternFuzzer::generate_variants(base_pattern);
    } else {
        // Just use the base pattern
        all_patterns_.push_back(base_pattern);
    }

    patterns_initialized_ = true;
    return all_patterns_;
}

minsn_t* PatternMatchingRule::apply_replacement(
    const std::map<std::string, mop_t>& bindings,
    mblock_t* blk,
    minsn_t* orig_ins) {

    if (!orig_ins) {
        return nullptr;
    }

    AstPtr replacement = get_replacement();
    if (!replacement) {
        return nullptr;
    }

    return build_replacement(replacement, bindings, blk, orig_ins->ea, orig_ins->d.size);
}

minsn_t* PatternMatchingRule::build_replacement(
    AstPtr replacement,
    const std::map<std::string, mop_t>& bindings,
    mblock_t* blk,
    ea_t ea,
    int size) {

    if (!replacement) {
        return nullptr;
    }

    // Handle leaf nodes
    if (replacement->is_leaf()) {
        // A replacement that is just a leaf means the result is a mov
        auto leaf = std::static_pointer_cast<AstLeaf>(replacement);

        mop_t src_mop = ast_leaf_to_mop(leaf, bindings);
        if (src_mop.t == mop_z) {
            return nullptr;
        }

        // Create mov instruction
        minsn_t* mov = new minsn_t(ea);
        mov->opcode = m_mov;
        mov->l = src_mop;
        mov->d.size = size > 0 ? size : src_mop.size;

        return mov;
    }

    // Must be a node
    auto node = std::static_pointer_cast<AstNode>(replacement);

    // Build left operand
    mop_t left_mop;
    if (node->left) {
        if (node->left->is_leaf()) {
            left_mop = ast_leaf_to_mop(
                std::static_pointer_cast<AstLeaf>(node->left), bindings);
        } else {
            // Nested operation
            minsn_t* sub_ins = build_replacement(
                node->left, bindings, blk, ea, size);
            if (sub_ins) {
                left_mop.create_from_insn(sub_ins);
                delete sub_ins;
            }
        }
    }

    // Build right operand
    mop_t right_mop;
    if (node->right) {
        if (node->right->is_leaf()) {
            right_mop = ast_leaf_to_mop(
                std::static_pointer_cast<AstLeaf>(node->right), bindings);
        } else {
            minsn_t* sub_ins = build_replacement(
                node->right, bindings, blk, ea, size);
            if (sub_ins) {
                right_mop.create_from_insn(sub_ins);
                delete sub_ins;
            }
        }
    }

    // Create instruction
    minsn_t* ins = new minsn_t(ea);
    ins->opcode = node->opcode;
    ins->l = left_mop;
    ins->r = right_mop;
    ins->d.size = size;

    return ins;
}

//--------------------------------------------------------------------------
// Validation helpers
//--------------------------------------------------------------------------
bool check_const_value(const std::map<std::string, mop_t>& bindings,
                       const std::string& name,
                       uint64_t expected,
                       int size) {
    auto it = bindings.find(name);
    if (it == bindings.end()) {
        return false;
    }

    const mop_t& mop = it->second;
    if (mop.t != mop_n) {
        return false;
    }

    uint64_t mask = size_mask(size);
    uint64_t value = mop.nnn->value & mask;
    uint64_t expect = expected & mask;

    return value == expect;
}

bool is_minus_2(const mop_t& mop) {
    if (mop.t != mop_n) {
        return false;
    }

    uint64_t mask = size_mask(mop.size);
    uint64_t minus_2 = (uint64_t)(-2) & mask;

    return (mop.nnn->value & mask) == minus_2;
}

bool is_minus_1(const mop_t& mop) {
    if (mop.t != mop_n) {
        return false;
    }

    uint64_t mask = size_mask(mop.size);
    return (mop.nnn->value & mask) == mask;
}

bool get_const_value(const mop_t& mop, uint64_t* out) {
    if (mop.t != mop_n) {
        return false;
    }

    *out = mop.nnn->value;
    return true;
}

} // namespace rules
} // namespace chernobog
