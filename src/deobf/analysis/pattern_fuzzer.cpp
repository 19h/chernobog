#include "pattern_fuzzer.h"
#include "../../common/simd.h"
#include <algorithm>
#include <numeric>
#include <unordered_set>

namespace chernobog {
namespace ast {

// Default configuration - OPTIMIZED defaults
PatternFuzzer::Config PatternFuzzer::config_ = {
    true,   // fuzz_commutative - Enable commutative - critical for matching
    false,  // fuzz_add_sub - Disabled - slow and rarely needed
    false,  // fuzz_associative - Disabled - slow
    32      // max_variants - Increased limit with optimization
};

void PatternFuzzer::set_config(const Config& cfg) {
    config_ = cfg;
}

const PatternFuzzer::Config& PatternFuzzer::get_config() {
    return config_;
}

//--------------------------------------------------------------------------
// Main entry point
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::generate_variants(AstPtr pattern) {
    if (!pattern) {
        return {};
    }

    std::set<mcode_t> excluded;
    auto variants = fuzz_recursive(pattern, excluded);

    // Deduplicate and limit
    variants = deduplicate(variants);

    if (variants.size() > static_cast<size_t>(config_.max_variants)) {
        variants.resize(config_.max_variants);
    }

    return variants;
}

//--------------------------------------------------------------------------
// Recursive fuzzer
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::fuzz_recursive(
    AstPtr node,
    const std::set<mcode_t>& excluded_ops) {

    if (!node) {
        return {nullptr};
    }

    // Leaf nodes don't get fuzzed
    if (node->is_leaf()) {
        return {node->clone()};
    }

    auto ast_node = std::static_pointer_cast<AstNode>(node);
    mcode_t op = ast_node->opcode;

    // Check if this opcode is excluded (to prevent infinite recursion in chains)
    if (excluded_ops.count(op) > 0) {
        // Just recurse on children without reordering
        return fuzz_unary_op(node, excluded_ops);
    }

    // Handle based on opcode type
    if (is_add_sub(op) && config_.fuzz_add_sub) {
        return fuzz_add_sub_op(node, excluded_ops);
    }

    if (is_commutative(op) && config_.fuzz_commutative) {
        return fuzz_commutative_op(node, excluded_ops);
    }

    // Non-commutative binary op or unary op
    return fuzz_unary_op(node, excluded_ops);
}

//--------------------------------------------------------------------------
// Commutative operation fuzzing
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::fuzz_commutative_op(
    AstPtr node,
    const std::set<mcode_t>& excluded_ops) {

    auto ast_node = std::static_pointer_cast<AstNode>(node);
    mcode_t op = ast_node->opcode;

    // Get all operands from chained operations
    auto operands = get_flat_operands(node, op);

    if (operands.size() < 2) {
        return fuzz_unary_op(node, excluded_ops);
    }

    // Generate all permutations
    auto perms = permute(operands);

    std::vector<AstPtr> results;

    // Exclude this opcode when recursing to prevent re-flattening
    std::set<mcode_t> new_excluded = excluded_ops;
    new_excluded.insert(op);

    for (const auto& perm : perms) {
        // Fuzz each operand recursively
        std::vector<std::vector<AstPtr>> operand_variants;
        for (const auto& operand : perm) {
            auto variants = fuzz_recursive(operand, new_excluded);
            operand_variants.push_back(variants);
        }

        // OPTIMIZED: Build combinations without copying vectors on every iteration
        // Use indices to track current combination, avoiding O(n!) allocations
        std::vector<size_t> indices(operand_variants.size(), 0);
        std::vector<std::vector<AstPtr>> combos;
        combos.reserve(config_.max_variants);
        
        bool done = false;
        while (!done) {
            // Build current combination from indices
            std::vector<AstPtr> combo;
            combo.reserve(operand_variants.size());
            for (size_t i = 0; i < operand_variants.size(); i++) {
                combo.push_back(operand_variants[i][indices[i]]);
            }
            combos.push_back(std::move(combo));
            
            // Check limit
            if (combos.size() >= static_cast<size_t>(config_.max_variants)) {
                break;
            }
            
            // Increment indices (like counting in mixed radix)
            done = true;
            for (size_t i = operand_variants.size(); i > 0; --i) {
                size_t idx = i - 1;
                indices[idx]++;
                if (indices[idx] < operand_variants[idx].size()) {
                    done = false;
                    break;
                }
                indices[idx] = 0;
            }
        }

        // Build binary trees from each combination
        for (const auto& combo : combos) {
            auto trees = build_all_binary_trees(combo, op);
            results.insert(results.end(), trees.begin(), trees.end());

            if (results.size() > static_cast<size_t>(config_.max_variants)) {
                break;
            }
        }

        if (results.size() > static_cast<size_t>(config_.max_variants)) {
            break;
        }
    }

    return results;
}

//--------------------------------------------------------------------------
// Add/Sub fuzzing (special due to interdependence)
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::fuzz_add_sub_op(
    AstPtr node,
    const std::set<mcode_t>& excluded_ops) {

    // Get operands with sign tracking
    auto signed_ops = get_add_sub_operands(node);

    if (signed_ops.size() < 2) {
        return fuzz_unary_op(node, excluded_ops);
    }

    // Generate all permutations
    auto perms = permute_signed(signed_ops);

    std::vector<AstPtr> results;

    // Exclude add/sub when recursing
    std::set<mcode_t> new_excluded = excluded_ops;
    new_excluded.insert(m_add);
    new_excluded.insert(m_sub);

    for (const auto& perm : perms) {
        // Fuzz each operand recursively
        std::vector<std::vector<SignedOperand>> operand_variants;
        for (const auto& sop : perm) {
            auto variants = fuzz_recursive(sop.operand, new_excluded);
            std::vector<SignedOperand> sov;
            for (const auto& v : variants) {
                sov.emplace_back(v, sop.is_negated);
            }
            operand_variants.push_back(sov);
        }

        // OPTIMIZED: Build combinations without copying vectors on every iteration
        std::vector<size_t> indices(operand_variants.size(), 0);
        std::vector<std::vector<SignedOperand>> combos;
        combos.reserve(config_.max_variants);
        
        bool done = false;
        while (!done) {
            std::vector<SignedOperand> combo;
            combo.reserve(operand_variants.size());
            for (size_t i = 0; i < operand_variants.size(); i++) {
                combo.push_back(operand_variants[i][indices[i]]);
            }
            combos.push_back(std::move(combo));
            
            if (combos.size() >= static_cast<size_t>(config_.max_variants)) {
                break;
            }
            
            done = true;
            for (size_t i = operand_variants.size(); i > 0; --i) {
                size_t idx = i - 1;
                indices[idx]++;
                if (indices[idx] < operand_variants[idx].size()) {
                    done = false;
                    break;
                }
                indices[idx] = 0;
            }
        }

        // Build add/sub trees
        for (const auto& combo : combos) {
            auto trees = build_add_sub_trees(combo);
            results.insert(results.end(), trees.begin(), trees.end());

            if (results.size() > static_cast<size_t>(config_.max_variants)) {
                break;
            }
        }

        if (results.size() > static_cast<size_t>(config_.max_variants)) {
            break;
        }
    }

    return results;
}

//--------------------------------------------------------------------------
// Unary/non-commutative operation fuzzing
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::fuzz_unary_op(
    AstPtr node,
    const std::set<mcode_t>& excluded_ops) {

    if (!node || node->is_leaf()) {
        return {node ? node->clone() : nullptr};
    }

    auto ast_node = std::static_pointer_cast<AstNode>(node);

    // Fuzz children
    auto left_variants = fuzz_recursive(ast_node->left, excluded_ops);
    std::vector<AstPtr> right_variants = {nullptr};
    if (ast_node->right) {
        right_variants = fuzz_recursive(ast_node->right, excluded_ops);
    }

    std::vector<AstPtr> results;

    for (const auto& left : left_variants) {
        for (const auto& right : right_variants) {
            auto new_node = std::make_shared<AstNode>(ast_node->opcode, left, right);
            new_node->dest_size = ast_node->dest_size;
            new_node->ea = ast_node->ea;
            results.push_back(new_node);

            if (results.size() > static_cast<size_t>(config_.max_variants)) {
                return results;
            }
        }
    }

    return results;
}

//--------------------------------------------------------------------------
// Operand extraction
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::get_flat_operands(AstPtr node, mcode_t op) {
    std::vector<AstPtr> operands;

    if (!node || node->is_leaf()) {
        if (node) operands.push_back(node);
        return operands;
    }

    auto ast_node = std::static_pointer_cast<AstNode>(node);

    if (ast_node->opcode == op) {
        // Same opcode - flatten
        auto left_ops = get_flat_operands(ast_node->left, op);
        auto right_ops = get_flat_operands(ast_node->right, op);
        operands.insert(operands.end(), left_ops.begin(), left_ops.end());
        operands.insert(operands.end(), right_ops.begin(), right_ops.end());
    } else {
        // Different opcode - treat as single operand
        operands.push_back(node);
    }

    return operands;
}

std::vector<PatternFuzzer::SignedOperand>
PatternFuzzer::get_add_sub_operands(AstPtr node) {
    std::vector<SignedOperand> operands;

    if (!node || node->is_leaf()) {
        if (node) operands.emplace_back(node, false);
        return operands;
    }

    auto ast_node = std::static_pointer_cast<AstNode>(node);

    if (ast_node->opcode == m_add) {
        auto left_ops = get_add_sub_operands(ast_node->left);
        auto right_ops = get_add_sub_operands(ast_node->right);
        operands.insert(operands.end(), left_ops.begin(), left_ops.end());
        operands.insert(operands.end(), right_ops.begin(), right_ops.end());
    } else if (ast_node->opcode == m_sub) {
        auto left_ops = get_add_sub_operands(ast_node->left);
        auto right_ops = get_add_sub_operands(ast_node->right);

        // Left operands keep their sign
        operands.insert(operands.end(), left_ops.begin(), left_ops.end());

        // Right operands get negated
        for (auto& rop : right_ops) {
            rop.is_negated = !rop.is_negated;
        }
        operands.insert(operands.end(), right_ops.begin(), right_ops.end());
    } else {
        // Not add/sub - single operand
        operands.emplace_back(node, false);
    }

    return operands;
}

//--------------------------------------------------------------------------
// Binary tree building
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::build_all_binary_trees(
    const std::vector<AstPtr>& operands, mcode_t op) {

    if (operands.empty()) {
        return {};
    }

    if (operands.size() == 1) {
        return {operands[0]};
    }

    if (operands.size() == 2) {
        return {make_node(op, operands[0], operands[1])};
    }

    // For 3+ operands, generate different tree structures
    // Left-associative and right-associative at minimum
    std::vector<AstPtr> results;

    // Left-associative: ((a op b) op c) op d
    AstPtr left_assoc = operands[0];
    for (size_t i = 1; i < operands.size(); i++) {
        left_assoc = make_node(op, left_assoc, operands[i]);
    }
    results.push_back(left_assoc);

    // Right-associative: a op (b op (c op d))
    AstPtr right_assoc = operands.back();
    for (int i = static_cast<int>(operands.size()) - 2; i >= 0; i--) {
        right_assoc = make_node(op, operands[i], right_assoc);
    }
    results.push_back(right_assoc);

    // For patterns we typically only need left-associative to match
    // IDA's representation, so limit tree variants

    return results;
}

std::vector<AstPtr> PatternFuzzer::build_add_sub_trees(
    const std::vector<SignedOperand>& operands) {

    if (operands.empty()) {
        return {};
    }

    if (operands.size() == 1) {
        if (operands[0].is_negated) {
            return {make_unary(m_neg, operands[0].operand)};
        }
        return {operands[0].operand};
    }

    std::vector<AstPtr> results;

    // Build left-associative tree
    // First operand
    AstPtr tree;
    if (operands[0].is_negated) {
        tree = make_unary(m_neg, operands[0].operand);
    } else {
        tree = operands[0].operand;
    }

    // Remaining operands
    for (size_t i = 1; i < operands.size(); i++) {
        if (operands[i].is_negated) {
            tree = make_node(m_sub, tree, operands[i].operand);
        } else {
            tree = make_node(m_add, tree, operands[i].operand);
        }
    }
    results.push_back(tree);

    // Also generate add/sub variations for each edge
    // This handles x + neg(y) <-> x - y
    for (size_t i = 1; i < operands.size(); i++) {
        auto variations = get_add_sub_variations(
            operands[i].is_negated ? m_sub : m_add,
            nullptr,  // Will be computed
            operands[i].operand);

        // Build tree with each variation for this position
        for (const auto& var : variations) {
            if (var && var != operands[i].operand) {
                // Create variant tree
                AstPtr var_tree;
                if (operands[0].is_negated) {
                    var_tree = make_unary(m_neg, operands[0].operand);
                } else {
                    var_tree = operands[0].operand;
                }

                for (size_t j = 1; j < operands.size(); j++) {
                    if (j == i) {
                        // Use variation
                        auto var_node = std::static_pointer_cast<AstNode>(var);
                        var_tree = make_node(var_node->opcode, var_tree, var_node->right);
                    } else if (operands[j].is_negated) {
                        var_tree = make_node(m_sub, var_tree, operands[j].operand);
                    } else {
                        var_tree = make_node(m_add, var_tree, operands[j].operand);
                    }
                }
                results.push_back(var_tree);
            }
        }
    }

    return results;
}

//--------------------------------------------------------------------------
// Add/Sub variations
//--------------------------------------------------------------------------
std::vector<AstPtr> PatternFuzzer::get_add_sub_variations(
    mcode_t op, AstPtr left, AstPtr right) {

    std::vector<AstPtr> results;

    if (!right) {
        return results;
    }

    // x + neg(y) -> x - y
    // x - neg(y) -> x + y
    if (right->is_node()) {
        auto right_node = std::static_pointer_cast<AstNode>(right);
        if (right_node->opcode == m_neg) {
            // Has negation - can convert
            mcode_t new_op = (op == m_add) ? m_sub : m_add;
            if (left) {
                results.push_back(make_node(new_op, left, right_node->left));
            } else {
                results.push_back(make_node(new_op, nullptr, right_node->left));
            }
        }
    }

    // Generate negation variant: x - y -> x + neg(y)
    if (op == m_sub && left) {
        results.push_back(make_node(m_add, left, make_unary(m_neg, right)));
    }

    return results;
}

//--------------------------------------------------------------------------
// Permutation utilities
//--------------------------------------------------------------------------
std::vector<std::vector<AstPtr>> PatternFuzzer::permute(
    const std::vector<AstPtr>& operands) {

    std::vector<std::vector<AstPtr>> results;

    if (operands.empty()) {
        return results;
    }

    // Generate indices
    std::vector<size_t> indices(operands.size());
    std::iota(indices.begin(), indices.end(), 0);

    // Generate all permutations
    do {
        std::vector<AstPtr> perm;
        for (size_t idx : indices) {
            perm.push_back(operands[idx]);
        }
        results.push_back(perm);

        // Limit to prevent explosion
        if (results.size() >= 24) {  // 4! = 24 (was 5! = 120)
            break;
        }
    } while (std::next_permutation(indices.begin(), indices.end()));

    return results;
}

std::vector<std::vector<PatternFuzzer::SignedOperand>>
PatternFuzzer::permute_signed(const std::vector<SignedOperand>& operands) {

    std::vector<std::vector<SignedOperand>> results;

    if (operands.empty()) {
        return results;
    }

    std::vector<size_t> indices(operands.size());
    std::iota(indices.begin(), indices.end(), 0);

    do {
        std::vector<SignedOperand> perm;
        for (size_t idx : indices) {
            perm.push_back(operands[idx]);
        }
        results.push_back(perm);

        if (results.size() >= 24) {  // 4! = 24 (was 5! = 120)
            break;
        }
    } while (std::next_permutation(indices.begin(), indices.end()));

    return results;
}

//--------------------------------------------------------------------------
// Deduplication - OPTIMIZED
// Uses hash-based comparison instead of expensive string generation
//--------------------------------------------------------------------------
static uint64_t compute_ast_hash(const AstBase* node) {
    if (!node) return 0;
    
    if (node->is_leaf()) {
        if (node->is_constant()) {
            auto c = static_cast<const AstConstant*>(node);
            return simd::hash_combine(simd::hash_u64(0xCAFE), simd::hash_u64(c->value));
        }
        auto leaf = static_cast<const AstLeaf*>(node);
        return simd::hash_bytes(leaf->name.data(), leaf->name.size());
    }
    
    auto n = static_cast<const AstNode*>(node);
    uint64_t h = simd::hash_u64(static_cast<uint64_t>(n->opcode));
    h = simd::hash_combine(h, compute_ast_hash(n->left.get()));
    h = simd::hash_combine(h, compute_ast_hash(n->right.get()));
    return h;
}

std::vector<AstPtr> PatternFuzzer::deduplicate(const std::vector<AstPtr>& variants) {
    std::vector<AstPtr> unique;
    std::unordered_set<uint64_t> seen;
    
    unique.reserve(variants.size());
    seen.reserve(variants.size());

    for (const auto& v : variants) {
        if (v) {
            uint64_t h = compute_ast_hash(v.get());
            if (seen.find(h) == seen.end()) {
                seen.insert(h);
                unique.push_back(v);
            }
        }
    }

    return unique;
}

} // namespace ast
} // namespace chernobog
