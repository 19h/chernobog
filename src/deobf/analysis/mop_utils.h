#pragma once
#include "../deobf_types.h"
#include "../../common/simd.h"

//--------------------------------------------------------------------------
// Microcode Operand Utilities - OPTIMIZED
//
// Provides fast comparison and hashing for mop_t operands using SIMD
// acceleration where beneficial.
//
// Key optimizations:
//   - Branch-free comparison for common types
//   - Pre-computed hash for O(1) equality check
//   - Memory-aligned access patterns
//--------------------------------------------------------------------------

namespace chernobog {
namespace mop {

//--------------------------------------------------------------------------
// Fast mop_t equality check
// Ignores size differences for pattern matching compatibility
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE bool equal_ignore_size(const mop_t& a, const mop_t& b) {
    // Fast path: type must match
    if (SIMD_UNLIKELY(a.t != b.t)) return false;
    
    // Type-specific comparison with branch hints
    switch (a.t) {
        case mop_r:  // Register - single int comparison
            return a.r == b.r;
            
        case mop_n:  // Number constant
            if (SIMD_UNLIKELY(!a.nnn || !b.nnn)) return a.nnn == b.nnn;
            return a.nnn->value == b.nnn->value;
            
        case mop_S:  // Stack variable
            if (SIMD_UNLIKELY(!a.s || !b.s)) return a.s == b.s;
            return a.s->off == b.s->off;
            
        case mop_v:  // Global variable - single uint64 comparison
            return a.g == b.g;
            
        case mop_l:  // Local variable
            if (SIMD_UNLIKELY(!a.l || !b.l)) return a.l == b.l;
            return (a.l->idx == b.l->idx) & (a.l->off == b.l->off);
            
        case mop_d:  // Result of another instruction
            if (SIMD_UNLIKELY(!a.d || !b.d)) return a.d == b.d;
            return a.d->equal_insns(*b.d, EQ_IGNSIZE);
            
        case mop_b:  // Block reference
            return a.b == b.b;
            
        case mop_h:  // Helper function
            if (SIMD_UNLIKELY(!a.helper || !b.helper)) return a.helper == b.helper;
            return strcmp(a.helper, b.helper) == 0;
            
        case mop_str:  // String
            if (SIMD_UNLIKELY(!a.cstr || !b.cstr)) return a.cstr == b.cstr;
            return strcmp(a.cstr, b.cstr) == 0;
            
        case mop_a:  // Address operand - recurse
            if (SIMD_UNLIKELY(!a.a || !b.a)) return a.a == b.a;
            return equal_ignore_size(*a.a, *b.a);
            
        case mop_z:  // Empty
            return true;
            
        default:
            return false;
    }
}

//--------------------------------------------------------------------------
// Fast mop_t hash computation
// Used for hash tables and deduplication
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE uint64_t hash(const mop_t& m) {
    uint64_t h = simd::hash_u64(static_cast<uint64_t>(m.t));
    
    switch (m.t) {
        case mop_r:
            h = simd::hash_combine(h, simd::hash_u64(m.r));
            break;
            
        case mop_n:
            if (m.nnn) {
                h = simd::hash_combine(h, simd::hash_u64(m.nnn->value));
            }
            break;
            
        case mop_S:
            if (m.s) {
                h = simd::hash_combine(h, simd::hash_u64(static_cast<uint64_t>(m.s->off)));
            }
            break;
            
        case mop_v:
            h = simd::hash_combine(h, simd::hash_u64(m.g));
            break;
            
        case mop_l:
            if (m.l) {
                h = simd::hash_combine(h, simd::hash_u64(m.l->idx));
                h = simd::hash_combine(h, simd::hash_u64(m.l->off));
            }
            break;
            
        case mop_d:
            if (m.d) {
                // Hash based on opcode and operand structure
                h = simd::hash_combine(h, simd::hash_u64(m.d->opcode));
                h = simd::hash_combine(h, hash(m.d->l));
                h = simd::hash_combine(h, hash(m.d->r));
            }
            break;
            
        case mop_b:
            h = simd::hash_combine(h, simd::hash_u64(m.b));
            break;
            
        case mop_h:
            if (m.helper) {
                h = simd::hash_combine(h, simd::hash_bytes(m.helper, strlen(m.helper)));
            }
            break;
            
        case mop_str:
            if (m.cstr) {
                h = simd::hash_combine(h, simd::hash_bytes(m.cstr, strlen(m.cstr)));
            }
            break;
            
        case mop_a:
            if (m.a) {
                h = simd::hash_combine(h, hash(*m.a));
            }
            break;
            
        default:
            break;
    }
    
    return h;
}

//--------------------------------------------------------------------------
// Check if operand is constant
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE bool is_const(const mop_t& m) {
    return m.t == mop_n && m.nnn != nullptr;
}

//--------------------------------------------------------------------------
// Get constant value (returns 0 if not constant)
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE uint64_t get_const_value(const mop_t& m) {
    if (SIMD_LIKELY(m.t == mop_n && m.nnn)) {
        return m.nnn->value;
    }
    return 0;
}

//--------------------------------------------------------------------------
// Check if operand is a negation (~x) of another
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE bool is_bnot_of(const mop_t& a, const mop_t& b) {
    if (a.t != mop_d || !a.d) return false;
    if (a.d->opcode != m_bnot) return false;
    return equal_ignore_size(a.d->l, b);
}

//--------------------------------------------------------------------------
// Check if operand is arithmetic negation (-x) of another
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE bool is_neg_of(const mop_t& a, const mop_t& b) {
    if (a.t != mop_d || !a.d) return false;
    if (a.d->opcode != m_neg) return false;
    return equal_ignore_size(a.d->l, b);
}

//--------------------------------------------------------------------------
// Operand wrapper with pre-computed hash for use in hash containers
//--------------------------------------------------------------------------
struct MopWithHash {
    const mop_t* mop;
    uint64_t hash_value;
    
    MopWithHash() : mop(nullptr), hash_value(0) {}
    MopWithHash(const mop_t& m) : mop(&m), hash_value(hash(m)) {}
    
    bool operator==(const MopWithHash& other) const {
        // Fast path: hash mismatch
        if (hash_value != other.hash_value) return false;
        // Full comparison for collision resolution
        if (!mop || !other.mop) return mop == other.mop;
        return equal_ignore_size(*mop, *other.mop);
    }
    
    struct Hash {
        size_t operator()(const MopWithHash& m) const noexcept {
            return static_cast<size_t>(m.hash_value);
        }
    };
};

} // namespace mop
} // namespace chernobog
