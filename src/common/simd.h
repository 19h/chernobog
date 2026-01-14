// Portable SIMD utilities with alignment helpers
// Supports SSE2/SSE4.2, AVX2, NEON with graceful fallback
#ifndef CHERNOBOG_SIMD_H
#define CHERNOBOG_SIMD_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <type_traits>
#include <utility>
#include <algorithm>
#include <new>
#include <string>

//--------------------------------------------------------------------------
// Platform detection and SIMD capability
//--------------------------------------------------------------------------
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define CHERNOBOG_X86 1
    #if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
        #define CHERNOBOG_SSE2 1
        #include <emmintrin.h>
    #endif
    #if defined(__SSE4_2__) || defined(__AVX__)
        #define CHERNOBOG_SSE42 1
        #include <nmmintrin.h>
    #endif
    #if defined(__AVX2__)
        #define CHERNOBOG_AVX2 1
        #include <immintrin.h>
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define CHERNOBOG_ARM64 1
    #define CHERNOBOG_NEON 1
    #include <arm_neon.h>
#elif defined(__arm__) && defined(__ARM_NEON)
    #define CHERNOBOG_ARM32 1
    #define CHERNOBOG_NEON 1
    #include <arm_neon.h>
#endif

//--------------------------------------------------------------------------
// MSVC intrinsics header - must be included early for all bit operations
//--------------------------------------------------------------------------
#ifdef _MSC_VER
    #include <intrin.h>
    #pragma intrinsic(_BitScanForward, _BitScanReverse)
    #if defined(_M_X64)
        #pragma intrinsic(_BitScanForward64, _BitScanReverse64)
        #pragma intrinsic(__popcnt64)
    #endif
    #pragma intrinsic(__popcnt)
#endif

// Force inline macro
#ifdef _MSC_VER
    #define SIMD_FORCE_INLINE __forceinline
    #define SIMD_LIKELY(x) (x)
    #define SIMD_UNLIKELY(x) (x)
#else
    #define SIMD_FORCE_INLINE inline __attribute__((always_inline))
    #define SIMD_LIKELY(x) __builtin_expect(!!(x), 1)
    #define SIMD_UNLIKELY(x) __builtin_expect(!!(x), 0)
#endif

// Alignment specifier
#ifdef _MSC_VER
    #define SIMD_ALIGN(n) __declspec(align(n))
#else
    #define SIMD_ALIGN(n) __attribute__((aligned(n)))
#endif

// Prefetch hints
#ifdef _MSC_VER
    #define SIMD_PREFETCH_READ(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
    #define SIMD_PREFETCH_WRITE(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#elif defined(__GNUC__) || defined(__clang__)
    #define SIMD_PREFETCH_READ(addr) __builtin_prefetch((addr), 0, 3)
    #define SIMD_PREFETCH_WRITE(addr) __builtin_prefetch((addr), 1, 3)
#else
    #define SIMD_PREFETCH_READ(addr) ((void)0)
    #define SIMD_PREFETCH_WRITE(addr) ((void)0)
#endif

namespace chernobog {
namespace simd {

//--------------------------------------------------------------------------
// Alignment utilities
//--------------------------------------------------------------------------

// Check if pointer is aligned to N bytes
template<size_t N>
SIMD_FORCE_INLINE bool is_aligned(const void* ptr) {
    static_assert((N & (N - 1)) == 0, "N must be power of 2");
    return (reinterpret_cast<uintptr_t>(ptr) & (N - 1)) == 0;
}

// Align pointer up to N bytes
template<size_t N>
SIMD_FORCE_INLINE void* align_up(void* ptr) {
    static_assert((N & (N - 1)) == 0, "N must be power of 2");
    return reinterpret_cast<void*>(
        (reinterpret_cast<uintptr_t>(ptr) + (N - 1)) & ~(N - 1));
}

// Align pointer down to N bytes
template<size_t N>
SIMD_FORCE_INLINE void* align_down(void* ptr) {
    static_assert((N & (N - 1)) == 0, "N must be power of 2");
    return reinterpret_cast<void*>(
        reinterpret_cast<uintptr_t>(ptr) & ~(N - 1));
}

// Alignment constants
constexpr size_t CACHE_LINE_SIZE = 64;
constexpr size_t SIMD_ALIGNMENT = 
#if defined(CHERNOBOG_AVX2)
    32
#elif defined(CHERNOBOG_SSE2) || defined(CHERNOBOG_NEON)
    16
#else
    8
#endif
;

//--------------------------------------------------------------------------
// Fast memory comparison (SIMD accelerated)
//--------------------------------------------------------------------------

// Compare two memory blocks for equality (optimized for small sizes)
SIMD_FORCE_INLINE bool mem_eq(const void* a, const void* b, size_t n) {
    const uint8_t* pa = static_cast<const uint8_t*>(a);
    const uint8_t* pb = static_cast<const uint8_t*>(b);

    // Fast path for common small sizes
    switch (n) {
        case 0: return true;
        case 1: return *pa == *pb;
        case 2: return *reinterpret_cast<const uint16_t*>(pa) == 
                       *reinterpret_cast<const uint16_t*>(pb);
        case 4: return *reinterpret_cast<const uint32_t*>(pa) == 
                       *reinterpret_cast<const uint32_t*>(pb);
        case 8: return *reinterpret_cast<const uint64_t*>(pa) == 
                       *reinterpret_cast<const uint64_t*>(pb);
    }

#if defined(CHERNOBOG_AVX2)
    // AVX2: 32 bytes at a time
    while (n >= 32) {
        __m256i va = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pa));
        __m256i vb = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pb));
        __m256i cmp = _mm256_cmpeq_epi8(va, vb);
        if (_mm256_movemask_epi8(cmp) != -1) return false;
        pa += 32; pb += 32; n -= 32;
    }
#endif

#if defined(CHERNOBOG_SSE2)
    // SSE2: 16 bytes at a time
    while (n >= 16) {
        __m128i va = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pa));
        __m128i vb = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pb));
        __m128i cmp = _mm_cmpeq_epi8(va, vb);
        if (_mm_movemask_epi8(cmp) != 0xFFFF) return false;
        pa += 16; pb += 16; n -= 16;
    }
#elif defined(CHERNOBOG_NEON)
    // NEON: 16 bytes at a time
    while (n >= 16) {
        uint8x16_t va = vld1q_u8(pa);
        uint8x16_t vb = vld1q_u8(pb);
        uint8x16_t cmp = vceqq_u8(va, vb);
        // Check if all bytes match
        uint64x2_t cmp64 = vreinterpretq_u64_u8(cmp);
        if (vgetq_lane_u64(cmp64, 0) != ~0ULL || 
            vgetq_lane_u64(cmp64, 1) != ~0ULL) return false;
        pa += 16; pb += 16; n -= 16;
    }
#endif

    // Handle remaining bytes
    while (n >= 8) {
        if (*reinterpret_cast<const uint64_t*>(pa) != 
            *reinterpret_cast<const uint64_t*>(pb)) return false;
        pa += 8; pb += 8; n -= 8;
    }
    while (n > 0) {
        if (*pa++ != *pb++) return false;
        --n;
    }
    return true;
}

//--------------------------------------------------------------------------
// Fast hash computation (for hash tables) - SIMD ACCELERATED
//--------------------------------------------------------------------------

// FNV-1a hash constants
constexpr uint64_t FNV_OFFSET_BASIS = 14695981039346656037ULL;
constexpr uint64_t FNV_PRIME = 1099511628211ULL;

// xxHash-style constants for SIMD hashing
constexpr uint64_t XXH_PRIME64_1 = 0x9E3779B185EBCA87ULL;
constexpr uint64_t XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
constexpr uint64_t XXH_PRIME64_3 = 0x165667B19E3779F9ULL;
constexpr uint64_t XXH_PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
constexpr uint64_t XXH_PRIME64_5 = 0x27D4EB2F165667C5ULL;

// Rotate left (portable)
SIMD_FORCE_INLINE uint64_t rotl64(uint64_t x, int r) {
    return (x << r) | (x >> (64 - r));
}

// Mix function for hash finalization
SIMD_FORCE_INLINE uint64_t avalanche64(uint64_t h) {
    h ^= h >> 33;
    h *= XXH_PRIME64_2;
    h ^= h >> 29;
    h *= XXH_PRIME64_3;
    h ^= h >> 32;
    return h;
}

// Fast hash for small data - SIMD accelerated for larger inputs
SIMD_FORCE_INLINE uint64_t hash_bytes(const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint64_t h;

    // For very small inputs (common case), use simple FNV-1a
    if (SIMD_LIKELY(len < 32)) {
        h = FNV_OFFSET_BASIS;
        while (len >= 8) {
            uint64_t k = *reinterpret_cast<const uint64_t*>(p);
            h ^= k;
            h *= FNV_PRIME;
            p += 8;
            len -= 8;
        }
        while (len > 0) {
            h ^= *p++;
            h *= FNV_PRIME;
            --len;
        }
        return h;
    }

#if defined(CHERNOBOG_AVX2)
    // AVX2: Process 64 bytes at a time using parallel lanes
    if (len >= 64) {
        __m256i acc1 = _mm256_set1_epi64x(XXH_PRIME64_1);
        __m256i acc2 = _mm256_set1_epi64x(XXH_PRIME64_2);
        const __m256i prime2 = _mm256_set1_epi64x(XXH_PRIME64_2);
        const __m256i prime3 = _mm256_set1_epi64x(XXH_PRIME64_3);
        
        while (len >= 64) {
            __m256i data1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p));
            __m256i data2 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(p + 32));
            
            // Mixing step: multiply-accumulate
            acc1 = _mm256_add_epi64(acc1, _mm256_mul_epu32(data1, prime2));
            acc2 = _mm256_add_epi64(acc2, _mm256_mul_epu32(data2, prime2));
            
            // Rotate and mix
            acc1 = _mm256_xor_si256(acc1, _mm256_srli_epi64(data1, 33));
            acc2 = _mm256_xor_si256(acc2, _mm256_srli_epi64(data2, 33));
            
            p += 64;
            len -= 64;
        }
        
        // Combine lanes
        alignas(32) uint64_t lanes[8];
        _mm256_store_si256(reinterpret_cast<__m256i*>(lanes), acc1);
        _mm256_store_si256(reinterpret_cast<__m256i*>(lanes + 4), acc2);
        
        h = XXH_PRIME64_5;
        for (int i = 0; i < 8; i++) {
            h ^= rotl64(lanes[i] * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        }
    } else {
        h = XXH_PRIME64_5;
    }
#elif defined(CHERNOBOG_NEON)
    // NEON: Process 32 bytes at a time
    if (len >= 32) {
        uint64x2_t acc1 = vdupq_n_u64(XXH_PRIME64_1);
        uint64x2_t acc2 = vdupq_n_u64(XXH_PRIME64_2);
        
        while (len >= 32) {
            uint64x2_t data1 = vld1q_u64(reinterpret_cast<const uint64_t*>(p));
            uint64x2_t data2 = vld1q_u64(reinterpret_cast<const uint64_t*>(p + 16));
            
            // Mixing: add with multiply low 32 bits
            uint32x4_t d1_32 = vreinterpretq_u32_u64(data1);
            uint32x4_t d2_32 = vreinterpretq_u32_u64(data2);
            acc1 = vaddq_u64(acc1, vmull_u32(vget_low_u32(d1_32), vdup_n_u32(XXH_PRIME64_2 & 0xFFFFFFFF)));
            acc2 = vaddq_u64(acc2, vmull_u32(vget_low_u32(d2_32), vdup_n_u32(XXH_PRIME64_2 & 0xFFFFFFFF)));
            
            // XOR with shifted data
            acc1 = veorq_u64(acc1, vshrq_n_u64(data1, 33));
            acc2 = veorq_u64(acc2, vshrq_n_u64(data2, 33));
            
            p += 32;
            len -= 32;
        }
        
        // Combine lanes
        uint64_t lanes[4];
        vst1q_u64(lanes, acc1);
        vst1q_u64(lanes + 2, acc2);
        
        h = XXH_PRIME64_5;
        for (int i = 0; i < 4; i++) {
            h ^= rotl64(lanes[i] * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
            h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        }
    } else {
        h = XXH_PRIME64_5;
    }
#else
    h = XXH_PRIME64_5;
#endif

    // Process remaining 32-byte chunks (scalar)
    h += len;
    while (len >= 32) {
        uint64_t k1 = *reinterpret_cast<const uint64_t*>(p);
        uint64_t k2 = *reinterpret_cast<const uint64_t*>(p + 8);
        uint64_t k3 = *reinterpret_cast<const uint64_t*>(p + 16);
        uint64_t k4 = *reinterpret_cast<const uint64_t*>(p + 24);
        
        h ^= rotl64(k1 * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
        h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        h ^= rotl64(k2 * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
        h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        h ^= rotl64(k3 * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
        h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        h ^= rotl64(k4 * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
        h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        
        p += 32;
        len -= 32;
    }

    // Process remaining 8-byte chunks
    while (len >= 8) {
        uint64_t k = *reinterpret_cast<const uint64_t*>(p);
        h ^= rotl64(k * XXH_PRIME64_2, 31) * XXH_PRIME64_1;
        h = rotl64(h, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
        p += 8;
        len -= 8;
    }

    // Process remaining 4-byte chunk
    if (len >= 4) {
        h ^= static_cast<uint64_t>(*reinterpret_cast<const uint32_t*>(p)) * XXH_PRIME64_1;
        h = rotl64(h, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        p += 4;
        len -= 4;
    }

    // Process remaining bytes
    while (len > 0) {
        h ^= static_cast<uint64_t>(*p++) * XXH_PRIME64_5;
        h = rotl64(h, 11) * XXH_PRIME64_1;
        --len;
    }

    return avalanche64(h);
}

// Fast hash combine (for composite keys)
SIMD_FORCE_INLINE uint64_t hash_combine(uint64_t h1, uint64_t h2) {
    // Mix bits thoroughly
    h1 ^= h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2);
    return h1;
}

// Fast integer hash
SIMD_FORCE_INLINE uint64_t hash_u64(uint64_t x) {
    // Murmur3-like finalizer
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

SIMD_FORCE_INLINE uint32_t hash_u32(uint32_t x) {
    // Murmur3 finalizer
    x ^= x >> 16;
    x *= 0x85ebca6b;
    x ^= x >> 13;
    x *= 0xc2b2ae35;
    x ^= x >> 16;
    return x;
}

//--------------------------------------------------------------------------
// Portable popcount / bit operations
//--------------------------------------------------------------------------

SIMD_FORCE_INLINE int popcount32(uint32_t x) {
#if defined(_MSC_VER)
    return __popcnt(x);
#else
    return __builtin_popcount(x);
#endif
}

SIMD_FORCE_INLINE int popcount64(uint64_t x) {
#if defined(_MSC_VER)
    #if defined(_M_X64)
        return (int)__popcnt64(x);
    #else
        return __popcnt((uint32_t)x) + __popcnt((uint32_t)(x >> 32));
    #endif
#else
    return __builtin_popcountll(x);
#endif
}

SIMD_FORCE_INLINE int clz32(uint32_t x) {
    if (x == 0) return 32;
#if defined(_MSC_VER)
    unsigned long idx;
    _BitScanReverse(&idx, x);
    return 31 - (int)idx;
#else
    return __builtin_clz(x);
#endif
}

SIMD_FORCE_INLINE int clz64(uint64_t x) {
    if (x == 0) return 64;
#if defined(_MSC_VER)
    #if defined(_M_X64)
        unsigned long idx;
        _BitScanReverse64(&idx, x);
        return 63 - (int)idx;
    #else
        uint32_t hi = (uint32_t)(x >> 32);
        if (hi != 0) {
            unsigned long idx;
            _BitScanReverse(&idx, hi);
            return 31 - (int)idx;
        }
        unsigned long idx;
        _BitScanReverse(&idx, (uint32_t)x);
        return 63 - (int)idx;
    #endif
#else
    return __builtin_clzll(x);
#endif
}

SIMD_FORCE_INLINE int ctz32(uint32_t x) {
    if (x == 0) return 32;
#if defined(_MSC_VER)
    unsigned long idx;
    _BitScanForward(&idx, x);
    return (int)idx;
#else
    return __builtin_ctz(x);
#endif
}

SIMD_FORCE_INLINE int ctz64(uint64_t x) {
    if (x == 0) return 64;
#if defined(_MSC_VER)
    #if defined(_M_X64)
        unsigned long idx;
        _BitScanForward64(&idx, x);
        return (int)idx;
    #else
        uint32_t lo = (uint32_t)x;
        if (lo != 0) {
            unsigned long idx;
            _BitScanForward(&idx, lo);
            return (int)idx;
        }
        unsigned long idx;
        _BitScanForward(&idx, (uint32_t)(x >> 32));
        return 32 + (int)idx;
    #endif
#else
    return __builtin_ctzll(x);
#endif
}

// Log2 floor (for power-of-2 calculations)
SIMD_FORCE_INLINE int log2_floor(uint64_t x) {
    if (x == 0) return -1;
    return 63 - clz64(x);
}

SIMD_FORCE_INLINE int log2_floor32(uint32_t x) {
    if (x == 0) return -1;
    return 31 - clz32(x);
}

// Log2 ceiling (rounds up)
SIMD_FORCE_INLINE int log2_ceil(uint64_t x) {
    if (x <= 1) return 0;
    return 64 - clz64(x - 1);
}

// Next power of 2 (for capacity calculations)
SIMD_FORCE_INLINE uint64_t next_pow2(uint64_t x) {
    if (x == 0) return 1;
    return 1ULL << log2_ceil(x);
}

SIMD_FORCE_INLINE uint32_t next_pow2_32(uint32_t x) {
    if (x == 0) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    return x + 1;
}

// Check if value is power of 2
SIMD_FORCE_INLINE bool is_pow2(uint64_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

//--------------------------------------------------------------------------
// SIMD-accelerated pattern signature comparison
// Returns number of mismatches (0 = perfect match)
// Used for fast pattern rejection before full structural match
//--------------------------------------------------------------------------

// Compute pattern structural signature (opcode tree fingerprint)
// Returns a 64-bit signature that can be compared with SIMD
struct alignas(16) PatternSignature {
    uint64_t opcode_bits;    // Packed opcodes (5 bits each, up to 12 levels)
    uint64_t structure_bits; // Tree structure (1 = node, 0 = leaf, BFS order)
    uint16_t depth;          // Tree depth
    uint16_t node_count;     // Total number of nodes
    uint16_t leaf_count;     // Total number of leaves  
    uint16_t _pad;
    
    SIMD_FORCE_INLINE bool operator==(const PatternSignature& other) const {
        // Fast SIMD compare for aligned structures
#if defined(CHERNOBOG_SSE2)
        __m128i a = _mm_load_si128(reinterpret_cast<const __m128i*>(this));
        __m128i b = _mm_load_si128(reinterpret_cast<const __m128i*>(&other));
        __m128i cmp = _mm_cmpeq_epi8(a, b);
        return _mm_movemask_epi8(cmp) == 0xFFFF;
#elif defined(CHERNOBOG_NEON)
        uint8x16_t a = vld1q_u8(reinterpret_cast<const uint8_t*>(this));
        uint8x16_t b = vld1q_u8(reinterpret_cast<const uint8_t*>(&other));
        uint8x16_t cmp = vceqq_u8(a, b);
        uint64x2_t cmp64 = vreinterpretq_u64_u8(cmp);
        return vgetq_lane_u64(cmp64, 0) == ~0ULL && vgetq_lane_u64(cmp64, 1) == ~0ULL;
#else
        return opcode_bits == other.opcode_bits && 
               structure_bits == other.structure_bits &&
               depth == other.depth && 
               node_count == other.node_count &&
               leaf_count == other.leaf_count;
#endif
    }
    
    // Check if this signature could match (allowing wildcards in pattern)
    // Pattern wildcards are encoded as all-1s in relevant bit positions
    SIMD_FORCE_INLINE bool compatible_with(const PatternSignature& pattern) const {
        // Structure must be identical
        if (structure_bits != pattern.structure_bits) return false;
        if (depth != pattern.depth) return false;
        
        // For opcodes, pattern can have wildcards (0x1F = any)
        uint64_t diff = opcode_bits ^ pattern.opcode_bits;
        // Mask out positions that are wildcards in pattern (0x1F = 31)
        // Check each 5-bit group for wildcard
        uint64_t wildcard_mask = 0;
        uint64_t p = pattern.opcode_bits;
        for (int i = 0; i < 12; i++) {
            if ((p & 0x1F) == 0x1F) {
                wildcard_mask |= (0x1FULL << (i * 5));
            }
            p >>= 5;
        }
        return (diff & ~wildcard_mask) == 0;
    }
};

//--------------------------------------------------------------------------
// Fast SIMD memset (for clearing structures)
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE void memset_zero_16(void* dst) {
#if defined(CHERNOBOG_SSE2)
    _mm_store_si128(reinterpret_cast<__m128i*>(dst), _mm_setzero_si128());
#elif defined(CHERNOBOG_NEON)
    vst1q_u8(reinterpret_cast<uint8_t*>(dst), vdupq_n_u8(0));
#else
    memset(dst, 0, 16);
#endif
}

SIMD_FORCE_INLINE void memset_zero_32(void* dst) {
#if defined(CHERNOBOG_AVX2)
    _mm256_store_si256(reinterpret_cast<__m256i*>(dst), _mm256_setzero_si256());
#elif defined(CHERNOBOG_SSE2)
    __m128i zero = _mm_setzero_si128();
    _mm_store_si128(reinterpret_cast<__m128i*>(dst), zero);
    _mm_store_si128(reinterpret_cast<__m128i*>(static_cast<char*>(dst) + 16), zero);
#elif defined(CHERNOBOG_NEON)
    uint8x16_t zero = vdupq_n_u8(0);
    vst1q_u8(reinterpret_cast<uint8_t*>(dst), zero);
    vst1q_u8(reinterpret_cast<uint8_t*>(dst) + 16, zero);
#else
    memset(dst, 0, 32);
#endif
}

SIMD_FORCE_INLINE void memset_zero_64(void* dst) {
#if defined(CHERNOBOG_AVX2)
    __m256i zero = _mm256_setzero_si256();
    _mm256_store_si256(reinterpret_cast<__m256i*>(dst), zero);
    _mm256_store_si256(reinterpret_cast<__m256i*>(static_cast<char*>(dst) + 32), zero);
#elif defined(CHERNOBOG_SSE2)
    __m128i zero = _mm_setzero_si128();
    _mm_store_si128(reinterpret_cast<__m128i*>(dst), zero);
    _mm_store_si128(reinterpret_cast<__m128i*>(static_cast<char*>(dst) + 16), zero);
    _mm_store_si128(reinterpret_cast<__m128i*>(static_cast<char*>(dst) + 32), zero);
    _mm_store_si128(reinterpret_cast<__m128i*>(static_cast<char*>(dst) + 48), zero);
#elif defined(CHERNOBOG_NEON)
    uint8x16_t zero = vdupq_n_u8(0);
    vst1q_u8(reinterpret_cast<uint8_t*>(dst), zero);
    vst1q_u8(reinterpret_cast<uint8_t*>(dst) + 16, zero);
    vst1q_u8(reinterpret_cast<uint8_t*>(dst) + 32, zero);
    vst1q_u8(reinterpret_cast<uint8_t*>(dst) + 48, zero);
#else
    memset(dst, 0, 64);
#endif
}

//--------------------------------------------------------------------------
// SIMD-accelerated memcpy for aligned structures
//--------------------------------------------------------------------------
SIMD_FORCE_INLINE void memcpy_16(void* dst, const void* src) {
#if defined(CHERNOBOG_SSE2)
    _mm_store_si128(reinterpret_cast<__m128i*>(dst), 
                    _mm_load_si128(reinterpret_cast<const __m128i*>(src)));
#elif defined(CHERNOBOG_NEON)
    vst1q_u8(reinterpret_cast<uint8_t*>(dst), 
             vld1q_u8(reinterpret_cast<const uint8_t*>(src)));
#else
    memcpy(dst, src, 16);
#endif
}

SIMD_FORCE_INLINE void memcpy_32(void* dst, const void* src) {
#if defined(CHERNOBOG_AVX2)
    _mm256_store_si256(reinterpret_cast<__m256i*>(dst),
                       _mm256_load_si256(reinterpret_cast<const __m256i*>(src)));
#elif defined(CHERNOBOG_SSE2)
    _mm_store_si128(reinterpret_cast<__m128i*>(dst),
                    _mm_load_si128(reinterpret_cast<const __m128i*>(src)));
    _mm_store_si128(reinterpret_cast<__m128i*>(static_cast<char*>(dst) + 16),
                    _mm_load_si128(reinterpret_cast<const __m128i*>(static_cast<const char*>(src) + 16)));
#elif defined(CHERNOBOG_NEON)
    vst1q_u8(reinterpret_cast<uint8_t*>(dst),
             vld1q_u8(reinterpret_cast<const uint8_t*>(src)));
    vst1q_u8(reinterpret_cast<uint8_t*>(dst) + 16,
             vld1q_u8(reinterpret_cast<const uint8_t*>(src) + 16));
#else
    memcpy(dst, src, 32);
#endif
}

//--------------------------------------------------------------------------
// Small vector with inline storage (avoids heap for small collections)
//--------------------------------------------------------------------------

template<typename T, size_t InlineCapacity>
class SmallVector {
    static_assert(InlineCapacity > 0, "InlineCapacity must be > 0");
    
public:
    SmallVector() : size_(0), capacity_(InlineCapacity), data_(inline_storage()) {}
    
    ~SmallVector() {
        clear();
        if (data_ != inline_storage()) {
            ::operator delete(data_);
        }
    }
    
    SmallVector(const SmallVector& other) : size_(0), capacity_(InlineCapacity), data_(inline_storage()) {
        reserve(other.size_);
        for (size_t i = 0; i < other.size_; ++i) {
            new (&data_[i]) T(other.data_[i]);
        }
        size_ = other.size_;
    }
    
    SmallVector& operator=(const SmallVector& other) {
        if (this != &other) {
            clear();
            reserve(other.size_);
            for (size_t i = 0; i < other.size_; ++i) {
                new (&data_[i]) T(other.data_[i]);
            }
            size_ = other.size_;
        }
        return *this;
    }
    
    SmallVector(SmallVector&& other) noexcept : size_(0), capacity_(InlineCapacity), data_(inline_storage()) {
        if (other.data_ == other.inline_storage()) {
            // Move elements from inline storage
            for (size_t i = 0; i < other.size_; ++i) {
                new (&data_[i]) T(std::move(other.data_[i]));
                other.data_[i].~T();
            }
            size_ = other.size_;
            other.size_ = 0;
        } else {
            // Steal heap pointer
            data_ = other.data_;
            size_ = other.size_;
            capacity_ = other.capacity_;
            other.data_ = other.inline_storage();
            other.size_ = 0;
            other.capacity_ = InlineCapacity;
        }
    }
    
    void push_back(const T& val) {
        if (size_ >= capacity_) {
            grow(capacity_ * 2);
        }
        new (&data_[size_]) T(val);
        ++size_;
    }
    
    void push_back(T&& val) {
        if (size_ >= capacity_) {
            grow(capacity_ * 2);
        }
        new (&data_[size_]) T(std::move(val));
        ++size_;
    }
    
    template<typename... Args>
    T& emplace_back(Args&&... args) {
        if (size_ >= capacity_) {
            grow(capacity_ * 2);
        }
        new (&data_[size_]) T(std::forward<Args>(args)...);
        return data_[size_++];
    }
    
    void pop_back() {
        if (size_ > 0) {
            data_[--size_].~T();
        }
    }
    
    void clear() {
        for (size_t i = 0; i < size_; ++i) {
            data_[i].~T();
        }
        size_ = 0;
    }
    
    void reserve(size_t n) {
        if (n > capacity_) {
            grow(n);
        }
    }
    
    void resize(size_t n) {
        if (n > size_) {
            reserve(n);
            for (size_t i = size_; i < n; ++i) {
                new (&data_[i]) T();
            }
        } else {
            for (size_t i = n; i < size_; ++i) {
                data_[i].~T();
            }
        }
        size_ = n;
    }
    
    T& operator[](size_t i) { return data_[i]; }
    const T& operator[](size_t i) const { return data_[i]; }
    
    T* data() { return data_; }
    const T* data() const { return data_; }
    
    size_t size() const { return size_; }
    size_t capacity() const { return capacity_; }
    bool empty() const { return size_ == 0; }
    
    T* begin() { return data_; }
    T* end() { return data_ + size_; }
    const T* begin() const { return data_; }
    const T* end() const { return data_ + size_; }
    
    T& front() { return data_[0]; }
    T& back() { return data_[size_ - 1]; }
    const T& front() const { return data_[0]; }
    const T& back() const { return data_[size_ - 1]; }
    
private:
    T* inline_storage() { 
        return reinterpret_cast<T*>(&storage_); 
    }
    const T* inline_storage() const { 
        return reinterpret_cast<const T*>(&storage_); 
    }
    
    void grow(size_t new_cap) {
        T* new_data = static_cast<T*>(::operator new(new_cap * sizeof(T)));
        
        for (size_t i = 0; i < size_; ++i) {
            new (&new_data[i]) T(std::move(data_[i]));
            data_[i].~T();
        }
        
        if (data_ != inline_storage()) {
            ::operator delete(data_);
        }
        
        data_ = new_data;
        capacity_ = new_cap;
    }
    
    size_t size_;
    size_t capacity_;
    T* data_;
    typename std::aligned_storage<sizeof(T) * InlineCapacity, alignof(T)>::type storage_;
};

//--------------------------------------------------------------------------
// Arena allocator for temporary allocations
//--------------------------------------------------------------------------

class Arena {
public:
    static constexpr size_t DEFAULT_BLOCK_SIZE = 4096;
    
    explicit Arena(size_t block_size = DEFAULT_BLOCK_SIZE) 
        : block_size_(block_size), current_(nullptr), end_(nullptr) {}
    
    ~Arena() {
        for (void* block : blocks_) {
            ::operator delete(block);
        }
    }
    
    // Non-copyable, non-movable
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    
    void* allocate(size_t size, size_t align = 8) {
        // Align current pointer
        uintptr_t aligned = (reinterpret_cast<uintptr_t>(current_) + align - 1) & ~(align - 1);
        char* result = reinterpret_cast<char*>(aligned);
        
        if (result + size > end_) {
            // Need new block
            size_t alloc_size = std::max(block_size_, size + align);
            char* new_block = static_cast<char*>(::operator new(alloc_size));
            blocks_.push_back(new_block);
            current_ = new_block;
            end_ = new_block + alloc_size;
            
            aligned = (reinterpret_cast<uintptr_t>(current_) + align - 1) & ~(align - 1);
            result = reinterpret_cast<char*>(aligned);
        }
        
        current_ = result + size;
        return result;
    }
    
    template<typename T, typename... Args>
    T* create(Args&&... args) {
        void* mem = allocate(sizeof(T), alignof(T));
        return new (mem) T(std::forward<Args>(args)...);
    }
    
    void reset() {
        // Keep first block, release rest
        if (!blocks_.empty()) {
            for (size_t i = 1; i < blocks_.size(); ++i) {
                ::operator delete(blocks_[i]);
            }
            current_ = static_cast<char*>(blocks_[0]);
            end_ = current_ + block_size_;
            blocks_.resize(1);
        }
    }
    
    size_t bytes_allocated() const {
        size_t total = 0;
        for (size_t i = 0; i < blocks_.size(); ++i) {
            total += (i == blocks_.size() - 1) 
                ? static_cast<size_t>(current_ - static_cast<char*>(blocks_[i]))
                : block_size_;
        }
        return total;
    }
    
private:
    size_t block_size_;
    char* current_;
    char* end_;
    SmallVector<void*, 8> blocks_;
};

//--------------------------------------------------------------------------
// Fast string interning for variable names
//--------------------------------------------------------------------------

class StringInterner {
public:
    using StringId = uint32_t;
    static constexpr StringId INVALID_ID = ~0u;
    
    static StringInterner& instance() {
        static StringInterner inst;
        return inst;
    }
    
    StringId intern(const char* str, size_t len) {
        uint64_t h = hash_bytes(str, len);
        
        // Check if already interned
        for (size_t i = 0; i < entries_.size(); ++i) {
            if (entries_[i].hash == h && 
                entries_[i].len == len &&
                memcmp(entries_[i].str, str, len) == 0) {
                return static_cast<StringId>(i);
            }
        }
        
        // Add new entry
        char* copy = static_cast<char*>(arena_.allocate(len + 1));
        memcpy(copy, str, len);
        copy[len] = '\0';
        
        StringId id = static_cast<StringId>(entries_.size());
        entries_.push_back({h, copy, len});
        return id;
    }
    
    StringId intern(const std::string& str) {
        return intern(str.c_str(), str.size());
    }
    
    const char* get(StringId id) const {
        if (id >= entries_.size()) return nullptr;
        return entries_[id].str;
    }
    
    size_t length(StringId id) const {
        if (id >= entries_.size()) return 0;
        return entries_[id].len;
    }
    
    void clear() {
        entries_.clear();
        arena_.reset();
    }
    
private:
    StringInterner() = default;
    
    struct Entry {
        uint64_t hash;
        const char* str;
        size_t len;
    };
    
    SmallVector<Entry, 64> entries_;
    Arena arena_;
};

//--------------------------------------------------------------------------
// Object Pool for fixed-size allocations (like AST nodes)
// Thread-safe with per-thread free lists
//--------------------------------------------------------------------------

template<typename T, size_t BlockSize = 64>
class ObjectPool {
public:
    ObjectPool() = default;
    
    ~ObjectPool() {
        clear();
    }
    
    // Non-copyable
    ObjectPool(const ObjectPool&) = delete;
    ObjectPool& operator=(const ObjectPool&) = delete;
    
    template<typename... Args>
    T* allocate(Args&&... args) {
        T* obj;
        
        // Try free list first
        if (!free_list_.empty()) {
            obj = free_list_.back();
            free_list_.pop_back();
            new (obj) T(std::forward<Args>(args)...);
        } else {
            // Allocate new block if needed
            if (current_idx_ >= BlockSize || blocks_.empty()) {
                allocate_block();
            }
            obj = &blocks_.back()[current_idx_++];
            new (obj) T(std::forward<Args>(args)...);
        }
        
        return obj;
    }
    
    void deallocate(T* obj) {
        if (obj) {
            obj->~T();
            free_list_.push_back(obj);
        }
    }
    
    void clear() {
        for (T* block : blocks_) {
            ::operator delete(block);
        }
        blocks_.clear();
        free_list_.clear();
        current_idx_ = BlockSize;
    }
    
    size_t allocated_count() const {
        if (blocks_.empty()) return 0;
        return (blocks_.size() - 1) * BlockSize + current_idx_;
    }
    
private:
    void allocate_block() {
        T* block = static_cast<T*>(::operator new(BlockSize * sizeof(T)));
        blocks_.push_back(block);
        current_idx_ = 0;
    }
    
    SmallVector<T*, 16> blocks_;
    SmallVector<T*, 32> free_list_;
    size_t current_idx_ = BlockSize;
};

//--------------------------------------------------------------------------
// Scoped arena for temporary allocations that are freed in bulk
// Useful for per-instruction analysis allocations
//--------------------------------------------------------------------------

class ScopedArena {
public:
    explicit ScopedArena(Arena& arena) 
        : arena_(arena), saved_bytes_(arena.bytes_allocated()) {}
    
    ~ScopedArena() {
        // Note: Arena doesn't support partial deallocation
        // This is more of a marker for debugging/profiling
    }
    
    template<typename T, typename... Args>
    T* create(Args&&... args) {
        return arena_.create<T>(std::forward<Args>(args)...);
    }
    
    void* allocate(size_t size, size_t align = 8) {
        return arena_.allocate(size, align);
    }
    
private:
    Arena& arena_;
    size_t saved_bytes_;
};

} // namespace simd
} // namespace chernobog

#endif // CHERNOBOG_SIMD_H
