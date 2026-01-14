#include "chain_simplify.h"

namespace chernobog {
namespace chain {

//--------------------------------------------------------------------------
// Utility functions - OPTIMIZED
//--------------------------------------------------------------------------

// Fast operand equality check with early-out and SIMD hints
SIMD_FORCE_INLINE bool ChainSimplifier::operands_equal(const mop_t& a, const mop_t& b) {
    // Fast path: type and size must match
    // Combine checks into single comparison where possible
    if (SIMD_UNLIKELY(a.t != b.t)) return false;
    if (SIMD_UNLIKELY(a.size != b.size)) return false;

    // Type-specific comparison
    switch (a.t) {
        case mop_r:  // Register - single int comparison
            return a.r == b.r;

        case mop_n:  // Number constant
            // Null check first
            if (SIMD_UNLIKELY(!a.nnn || !b.nnn)) return a.nnn == b.nnn;
            return a.nnn->value == b.nnn->value;

        case mop_S:  // Stack variable
            if (SIMD_UNLIKELY(!a.s || !b.s)) return a.s == b.s;
            return a.s->off == b.s->off;

        case mop_v:  // Global variable - single uint64 comparison
            return a.g == b.g;

        case mop_l:  // Local variable
            if (SIMD_UNLIKELY(!a.l || !b.l)) return a.l == b.l;
            // Combine comparisons
            return (a.l->idx == b.l->idx) & (a.l->off == b.l->off);

        case mop_d:  // Result of another instruction
            // Compare instruction content (most expensive case)
            if (SIMD_UNLIKELY(!a.d || !b.d)) return a.d == b.d;
            return a.d->equal_insns(*b.d, EQ_IGNSIZE);

        default:
            return false;
    }
}

bool ChainSimplifier::is_not_of(const mop_t& a, const mop_t& b) {
    // Check if a = ~b
    if (a.t != mop_d || !a.d)
        return false;

    if (a.d->opcode != m_bnot)
        return false;

    return operands_equal(a.d->l, b);
}

bool ChainSimplifier::is_neg_of(const mop_t& a, const mop_t& b) {
    // Check if a = -b
    if (a.t != mop_d || !a.d)
        return false;

    if (a.d->opcode != m_neg)
        return false;

    return operands_equal(a.d->l, b);
}

bool ChainSimplifier::get_const_value(const mop_t& mop, uint64_t* out) {
    if (mop.t != mop_n)
        return false;

    *out = mop.nnn->value;
    return true;
}

uint64_t ChainSimplifier::get_identity_element(mcode_t op, int size) {
    switch (op) {
        case m_xor:
        case m_add:
        case m_or:
            return 0;

        case m_and:
            // All ones for the size
            if (size >= 8)
                return ~0ULL;
            return (1ULL << (size * 8)) - 1;

        default:
            return 0;
    }
}

bool ChainSimplifier::has_absorbing_element(mcode_t op, uint64_t* out, int size) {
    switch (op) {
        case m_and:
            *out = 0;
            return true;

        case m_or:
            // All ones for the size
            if (size >= 8)
                *out = ~0ULL;
            else
                *out = (1ULL << (size * 8)) - 1;
            return true;

        default:
            return false;
    }
}

//--------------------------------------------------------------------------
// Chain flattening
//--------------------------------------------------------------------------

void ChainSimplifier::flatten_operand(const mop_t& mop, mcode_t target_op,
                                      std::vector<chain_operand_t>& operands,
                                      std::vector<uint64_t>& constants,
                                      int size) {
    // Check for constant
    uint64_t const_val;
    if (get_const_value(mop, &const_val)) {
        constants.push_back(const_val);
        return;
    }

    // Check for nested same opcode
    if (mop.t == mop_d && mop.d && mop.d->opcode == target_op) {
        flatten_chain(mop.d, target_op, operands, constants, size);
        return;
    }

    // Handle special cases for XOR with negation
    if (target_op == m_xor && mop.t == mop_d && mop.d) {
        if (mop.d->opcode == m_bnot) {
            // ~x in XOR chain: treat as x ^ (-1)
            operands.push_back(chain_operand_t(mop.d->l, true));
            uint64_t all_ones = get_identity_element(m_and, size);
            constants.push_back(all_ones);
            return;
        }
    }

    // Handle special cases for ADD with negation
    if (target_op == m_add && mop.t == mop_d && mop.d) {
        if (mop.d->opcode == m_neg) {
            // -x in ADD chain
            operands.push_back(chain_operand_t(mop.d->l, true));
            return;
        }
    }

    // Regular operand
    operands.push_back(chain_operand_t(mop, false));
}

void ChainSimplifier::flatten_chain(const minsn_t* ins, mcode_t target_op,
                                    std::vector<chain_operand_t>& operands,
                                    std::vector<uint64_t>& constants,
                                    int size) {
    if (!ins || ins->opcode != target_op)
        return;

    flatten_operand(ins->l, target_op, operands, constants, size);
    flatten_operand(ins->r, target_op, operands, constants, size);
}

//--------------------------------------------------------------------------
// Identity removal - OPTIMIZED
// Uses prefetching and in-place removal to reduce allocations
//--------------------------------------------------------------------------

bool ChainSimplifier::remove_identity_pairs(std::vector<chain_operand_t>& operands,
                                            mcode_t op, int size) {
    const size_t n = operands.size();
    if (n < 2) return false;
    
    bool removed = false;
    
    // Use bit flags instead of vector<bool> for small sizes
    // This avoids heap allocation for typical chain sizes
    uint64_t removed_flags = 0;
    static_assert(TYPICAL_CHAIN_SIZE <= 64, "Flags must fit in uint64_t");
    
    const chain_operand_t* ops = operands.data();

    for (size_t i = 0; i < n && i < 64; i++) {
        if (removed_flags & (1ULL << i))
            continue;

        // Prefetch next operand for the inner loop
        if (i + 2 < n) {
            SIMD_PREFETCH_READ(&ops[i + 2].mop);
        }

        for (size_t j = i + 1; j < n && j < 64; j++) {
            if (removed_flags & (1ULL << j))
                continue;

            // Prefetch ahead in inner loop
            if (j + 1 < n) {
                SIMD_PREFETCH_READ(&ops[j + 1].mop);
            }

            bool is_pair = false;

            switch (op) {
                case m_xor:
                    // x ^ x = 0
                    if (operands_equal(ops[i].mop, ops[j].mop) &&
                        ops[i].is_negated == ops[j].is_negated) {
                        is_pair = true;
                    }
                    break;

                case m_and:
                    // x & ~x = 0
                    if (is_not_of(ops[i].mop, ops[j].mop) ||
                        is_not_of(ops[j].mop, ops[i].mop)) {
                        // This produces 0, which is absorbing for AND
                        operands.clear();
                        return true;
                    }
                    // x & x = x
                    if (operands_equal(ops[i].mop, ops[j].mop)) {
                        removed_flags |= (1ULL << j);
                        removed = true;
                    }
                    break;

                case m_or:
                    // x | ~x = -1
                    if (is_not_of(ops[i].mop, ops[j].mop) ||
                        is_not_of(ops[j].mop, ops[i].mop)) {
                        // This produces -1, which is absorbing for OR
                        operands.clear();
                        return true;
                    }
                    // x | x = x
                    if (operands_equal(ops[i].mop, ops[j].mop)) {
                        removed_flags |= (1ULL << j);
                        removed = true;
                    }
                    break;

                case m_add:
                    // x + (-x) = 0
                    if (ops[i].is_negated != ops[j].is_negated &&
                        operands_equal(ops[i].mop, ops[j].mop)) {
                        is_pair = true;
                    }
                    // Also check for actual neg instructions
                    if (!is_pair) {
                        if (is_neg_of(ops[i].mop, ops[j].mop) ||
                            is_neg_of(ops[j].mop, ops[i].mop)) {
                            is_pair = true;
                        }
                    }
                    break;
            }

            if (is_pair) {
                removed_flags |= (1ULL << i) | (1ULL << j);
                removed = true;
                break;
            }
        }
    }

    // In-place compaction instead of creating new vector
    if (removed && removed_flags != 0) {
        size_t write_idx = 0;
        for (size_t i = 0; i < n && i < 64; i++) {
            if (!(removed_flags & (1ULL << i))) {
                if (write_idx != i) {
                    operands[write_idx] = std::move(operands[i]);
                }
                write_idx++;
            }
        }
        operands.resize(write_idx);
    }

    return removed;
}

//--------------------------------------------------------------------------
// Chain analysis implementations
//--------------------------------------------------------------------------

chain_result_t ChainSimplifier::analyze_xor_chain(mblock_t* blk, minsn_t* ins) {
    chain_result_t result;

    if (!ins || ins->opcode != m_xor)
        return result;

    std::vector<chain_operand_t> operands;
    std::vector<uint64_t> constants;
    int size = ins->d.size;

    flatten_chain(ins, m_xor, operands, constants, size);

    // Fold constants: c1 ^ c2 ^ c3 = (c1 ^ c2 ^ c3)
    uint64_t const_result = 0;
    for (uint64_t c : constants) {
        const_result ^= c;
    }

    // Remove identity pairs (x ^ x = 0)
    bool changed = true;
    while (changed) {
        changed = remove_identity_pairs(operands, m_xor, size);
    }

    result.const_result = const_result;
    result.has_const = !constants.empty() && const_result != 0;
    result.operands = operands;

    // Determine simplification
    if (operands.empty()) {
        result.simplified = true;
        result.is_single_operand = false;
        if (const_result == 0) {
            result.is_zero = true;
        }
    } else if (operands.size() == 1 && const_result == 0) {
        result.simplified = true;
        result.is_single_operand = true;
    } else if (operands.size() + (const_result != 0 ? 1 : 0) <
               constants.size() + operands.size()) {
        result.simplified = true;
    }

    return result;
}

chain_result_t ChainSimplifier::analyze_and_chain(mblock_t* blk, minsn_t* ins) {
    chain_result_t result;

    if (!ins || ins->opcode != m_and)
        return result;

    std::vector<chain_operand_t> operands;
    std::vector<uint64_t> constants;
    int size = ins->d.size;

    flatten_chain(ins, m_and, operands, constants, size);

    // Fold constants: c1 & c2 & c3 = (c1 & c2 & c3)
    uint64_t all_ones = get_identity_element(m_and, size);
    uint64_t const_result = all_ones;
    for (uint64_t c : constants) {
        const_result &= c;
    }

    // Check for absorbing element (0)
    if (const_result == 0) {
        result.simplified = true;
        result.is_zero = true;
        result.const_result = 0;
        return result;
    }

    // Remove identity pairs (x & x = x, x & ~x = 0)
    bool changed = true;
    while (changed) {
        changed = remove_identity_pairs(operands, m_and, size);
        if (operands.empty() && changed) {
            // x & ~x was found - result is 0
            result.simplified = true;
            result.is_zero = true;
            result.const_result = 0;
            return result;
        }
    }

    result.const_result = const_result;
    result.has_const = !constants.empty() && const_result != all_ones;
    result.operands = operands;

    // Determine simplification
    if (operands.empty()) {
        result.simplified = true;
        result.is_single_operand = false;
    } else if (operands.size() == 1 && const_result == all_ones) {
        result.simplified = true;
        result.is_single_operand = true;
    }

    return result;
}

chain_result_t ChainSimplifier::analyze_or_chain(mblock_t* blk, minsn_t* ins) {
    chain_result_t result;

    if (!ins || ins->opcode != m_or)
        return result;

    std::vector<chain_operand_t> operands;
    std::vector<uint64_t> constants;
    int size = ins->d.size;

    flatten_chain(ins, m_or, operands, constants, size);

    // Fold constants: c1 | c2 | c3 = (c1 | c2 | c3)
    uint64_t const_result = 0;
    for (uint64_t c : constants) {
        const_result |= c;
    }

    // Check for absorbing element (-1)
    uint64_t all_ones = get_identity_element(m_and, size);
    if (const_result == all_ones) {
        result.simplified = true;
        result.is_all_ones = true;
        result.const_result = all_ones;
        return result;
    }

    // Remove identity pairs (x | x = x, x | ~x = -1)
    bool changed = true;
    while (changed) {
        changed = remove_identity_pairs(operands, m_or, size);
        if (operands.empty() && changed) {
            // x | ~x was found - result is -1
            result.simplified = true;
            result.is_all_ones = true;
            result.const_result = all_ones;
            return result;
        }
    }

    result.const_result = const_result;
    result.has_const = !constants.empty() && const_result != 0;
    result.operands = operands;

    // Determine simplification
    if (operands.empty()) {
        result.simplified = true;
        result.is_single_operand = false;
    } else if (operands.size() == 1 && const_result == 0) {
        result.simplified = true;
        result.is_single_operand = true;
    }

    return result;
}

chain_result_t ChainSimplifier::analyze_add_chain(mblock_t* blk, minsn_t* ins) {
    chain_result_t result;

    if (!ins || ins->opcode != m_add)
        return result;

    std::vector<chain_operand_t> operands;
    std::vector<uint64_t> constants;
    int size = ins->d.size;

    flatten_chain(ins, m_add, operands, constants, size);

    // Fold constants: c1 + c2 + c3 = (c1 + c2 + c3)
    uint64_t const_result = 0;
    for (uint64_t c : constants) {
        const_result += c;
    }

    // Mask to size
    if (size < 8) {
        const_result &= (1ULL << (size * 8)) - 1;
    }

    // Remove identity pairs (x + (-x) = 0)
    bool changed = true;
    while (changed) {
        changed = remove_identity_pairs(operands, m_add, size);
    }

    result.const_result = const_result;
    result.has_const = !constants.empty() && const_result != 0;
    result.operands = operands;

    // Determine simplification
    if (operands.empty()) {
        result.simplified = true;
        result.is_single_operand = false;
        if (const_result == 0) {
            result.is_zero = true;
        }
    } else if (operands.size() == 1 && const_result == 0) {
        result.simplified = true;
        result.is_single_operand = true;
    }

    return result;
}

//--------------------------------------------------------------------------
// Build simplified instruction
//--------------------------------------------------------------------------

minsn_t* ChainSimplifier::build_simplified(mblock_t* blk, minsn_t* orig,
                                           const chain_result_t& result,
                                           mcode_t op) {
    int size = orig->d.size;

    // Result is a constant
    if (result.operands.empty()) {
        minsn_t* new_ins = new minsn_t(orig->ea);
        new_ins->opcode = m_mov;
        new_ins->l.make_number(result.const_result, size);
        new_ins->d = orig->d;
        return new_ins;
    }

    // Result is a single operand (possibly with constant)
    if (result.is_single_operand && !result.has_const) {
        minsn_t* new_ins = new minsn_t(orig->ea);
        new_ins->opcode = m_mov;
        new_ins->l = result.operands[0].mop;
        new_ins->d = orig->d;
        return new_ins;
    }

    // Build chain from remaining operands
    // Start with first two operands (or first operand and constant)
    minsn_t* new_ins = new minsn_t(orig->ea);
    new_ins->opcode = op;
    new_ins->d = orig->d;

    if (result.operands.size() >= 2) {
        new_ins->l = result.operands[0].mop;
        new_ins->r = result.operands[1].mop;
    } else if (result.operands.size() == 1 && result.has_const) {
        new_ins->l = result.operands[0].mop;
        new_ins->r.make_number(result.const_result, size);
    } else {
        delete new_ins;
        return nullptr;
    }

    return new_ins;
}

//--------------------------------------------------------------------------
// Main simplification entry point
//--------------------------------------------------------------------------

int ChainSimplifier::simplify_chain(mblock_t* blk, minsn_t* ins) {
    if (!blk || !ins)
        return 0;

    chain_result_t result;

    switch (ins->opcode) {
        case m_xor:
            result = analyze_xor_chain(blk, ins);
            break;
        case m_and:
            result = analyze_and_chain(blk, ins);
            break;
        case m_or:
            result = analyze_or_chain(blk, ins);
            break;
        case m_add:
            result = analyze_add_chain(blk, ins);
            break;
        default:
            return 0;
    }

    if (!result.simplified)
        return 0;

    // Apply simplification
    int size = ins->d.size;

    if (result.is_zero) {
        ins->opcode = m_mov;
        ins->l.make_number(0, size);
        ins->r.erase();
        return 1;
    }

    if (result.is_all_ones) {
        uint64_t all_ones = get_identity_element(m_and, size);
        ins->opcode = m_mov;
        ins->l.make_number(all_ones, size);
        ins->r.erase();
        return 1;
    }

    if (result.is_single_operand && !result.has_const) {
        ins->opcode = m_mov;
        ins->l = result.operands[0].mop;
        ins->r.erase();
        return 1;
    }

    if (result.operands.empty() && result.has_const) {
        ins->opcode = m_mov;
        ins->l.make_number(result.const_result, size);
        ins->r.erase();
        return 1;
    }

    // More complex simplification - rebuild instruction
    if (result.operands.size() == 1 && result.has_const) {
        ins->l = result.operands[0].mop;
        ins->r.make_number(result.const_result, size);
        return 1;
    }

    return 0;
}

//--------------------------------------------------------------------------
// Handler implementation
//--------------------------------------------------------------------------

bool chain_simplify_handler_t::detect(mbl_array_t* mba) {
    if (!mba)
        return false;

    // Look for chains of same-opcode operations
    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk) continue;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            if (ins->opcode != m_xor && ins->opcode != m_and &&
                ins->opcode != m_or && ins->opcode != m_add)
                continue;

            // Check for nested same opcode
            if (ins->l.t == mop_d && ins->l.d &&
                ins->l.d->opcode == ins->opcode) {
                return true;
            }
            if (ins->r.t == mop_d && ins->r.d &&
                ins->r.d->opcode == ins->opcode) {
                return true;
            }
        }
    }

    return false;
}

int chain_simplify_handler_t::run(mbl_array_t* mba, deobf_ctx_t* ctx) {
    if (!mba || !ctx)
        return 0;

    int total_changes = 0;

    for (int i = 0; i < mba->qty; i++) {
        mblock_t* blk = mba->get_mblock(i);
        if (!blk) continue;

        for (minsn_t* ins = blk->head; ins; ins = ins->next) {
            int changes = ChainSimplifier::simplify_chain(blk, ins);
            total_changes += changes;
        }
    }

    if (total_changes > 0) {
        ctx->expressions_simplified += total_changes;
        deobf::log_verbose("[Chain] Simplified %d chains\n", total_changes);
    }

    return total_changes;
}

int chain_simplify_handler_t::simplify_insn(mblock_t* blk, minsn_t* ins,
                                            deobf_ctx_t* ctx) {
    int changes = ChainSimplifier::simplify_chain(blk, ins);

    if (changes > 0 && ctx) {
        ctx->expressions_simplified += changes;
    }

    return changes;
}

} // namespace chain
} // namespace chernobog
