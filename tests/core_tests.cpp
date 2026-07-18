#include "common/arm64_branch.h"
#include "common/bitvector.h"
#include "common/simd.h"
#include "common/string_recovery.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>

namespace {

int failures = 0;

void check(bool condition, const char *description)
{
    if ( condition )
        return;
    std::fprintf(stderr, "FAIL: %s\n", description);
    ++failures;
}

void test_bitvectors()
{
    using namespace chernobog::bitvector;

    check(mask(1) == 0xFFULL, "8-bit mask");
    check(mask(3) == 0xFFFFFFULL, "24-bit mask");
    check(mask(8) == std::numeric_limits<uint64_t>::max(), "64-bit mask");
    check(truncate(0x1234, 1) == 0x34, "8-bit truncation");
    check(logical_not(0) == 1 && logical_not(2) == 0, "logical NOT");
    check(negate(0x80, 1) == 0x80, "8-bit minimum negation wraps");
    check(negate(1, 8) == std::numeric_limits<uint64_t>::max(),
          "64-bit negation");

    check(sign_extend(0x7F, 1) == 127, "positive 8-bit sign extension");
    check(sign_extend(0x80, 1) == -128, "negative 8-bit sign extension");
    check(sign_extend(0x800000, 3) == -8388608, "negative 24-bit sign extension");
    check(sign_extend(0xFFFFFFFFFFFFFFFFULL, 8) == -1,
          "negative 64-bit sign extension");
    check(sign_extend(0x8000000000000000ULL, 8) ==
              std::numeric_limits<int64_t>::min(),
          "64-bit minimum sign extension");

    check(shift_left(1, 7, 1) == 0x80, "8-bit left shift");
    check(shift_left(1, 8, 1) == 0, "oversized 8-bit left shift");
    check(shift_right_logical(0x80, 7, 1) == 1, "8-bit logical right shift");
    check(shift_right_arithmetic(0x80, 1, 1) == 0xC0,
          "8-bit arithmetic right shift");
    check(shift_right_arithmetic(0x80, 8, 1) == 0xFF,
          "oversized negative arithmetic shift");
    check(shift_right_arithmetic(0x7F, 8, 1) == 0,
          "oversized positive arithmetic shift");

    constexpr uint8_t bytes[] = {0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xAB, 0xCD, 0xEF};
    check(decode_bytes(bytes, 8, true) == 0x0123456789ABCDEFULL,
          "big-endian 64-bit decode");
    check(decode_bytes(bytes, 8, false) == 0xEFCDAB8967452301ULL,
          "little-endian 64-bit decode");
    check(decode_bytes(bytes, 3, true) == 0x012345ULL,
          "big-endian 24-bit decode");
    check(decode_bytes(bytes, 3, false) == 0x452301ULL,
          "little-endian 24-bit decode");
    check(decode_bytes(nullptr, 4, false) == 0,
          "null byte decode is rejected");
}

void test_arm64_direct_branch_encoding()
{
    using chernobog::arm64_branch::encode_b;
    using chernobog::arm64_branch::encode_b_cond;

    check(encode_b(0x100003034ULL, 0x100012DC8ULL) == 0x14003F65U,
          "ARM64 forward direct branch encoding");
    check(encode_b(0x1000ULL, 0x0ULL) == 0x17FFFC00U,
          "ARM64 backward direct branch encoding");
    check(encode_b(0, (uint64_t{1} << 27) - 4).has_value(),
          "ARM64 maximum forward branch displacement");
    check(!encode_b(0, uint64_t{1} << 27),
          "ARM64 out-of-range forward branch rejection");
    check(encode_b(uint64_t{1} << 27, 0).has_value(),
          "ARM64 maximum backward branch displacement");
    check(!encode_b((uint64_t{1} << 27) + 4, 0),
          "ARM64 out-of-range backward branch rejection");
    check(!encode_b(0x1000, 0x1002),
          "ARM64 unaligned branch target rejection");

    check(encode_b_cond(0x100012DD4ULL, 0x100012DDCULL, 0xAU)
              == 0x5400004AU,
          "ARM64 conditional branch encoding");
    check(encode_b_cond(uint64_t{1} << 20, 0, 0) == 0x54800000U,
          "ARM64 maximum backward conditional displacement");
    check(!encode_b_cond((uint64_t{1} << 20) + 4, 0, 0),
          "ARM64 out-of-range backward conditional rejection");
    check(!encode_b_cond(0, uint64_t{1} << 20, 0),
          "ARM64 out-of-range forward conditional rejection");
    check(!encode_b_cond(0x1000, 0x1000, 0xEU),
          "ARM64 reserved conditional predicate rejection");
}

void test_simd_utilities()
{
    using namespace chernobog::simd;

    check(rotl64(0x0123456789ABCDEFULL, 0) == 0x0123456789ABCDEFULL,
          "zero rotation");
    check(rotl64(1, 64) == 1, "full-width rotation");
    check(next_pow2(0) == 1 && next_pow2(9) == 16, "next 64-bit power of two");
    check(next_pow2(std::numeric_limits<uint64_t>::max()) == 0,
          "64-bit power-of-two overflow");
    check(next_pow2_32(std::numeric_limits<uint32_t>::max()) == 0,
          "32-bit power-of-two overflow");

    std::array<uint8_t, 192> source{};
    std::array<uint8_t, 192> copy{};
    for ( size_t i = 0; i < source.size(); ++i )
        source[i] = static_cast<uint8_t>((i * 131U + 17U) & 0xFFU);

    for ( size_t len = 0; len <= 128; ++len )
    {
        for ( size_t offset = 0; offset < 8; ++offset )
        {
            std::memcpy(copy.data() + offset, source.data() + 3, len);
            const uint64_t expected = hash_bytes(source.data() + 3, len);
            check(hash_bytes(copy.data() + offset, len) == expected,
                  "hash is independent of input alignment");
            check(mem_eq(source.data() + 3, copy.data() + offset, len),
                  "unaligned equal-memory comparison");
            if ( len > 0 )
            {
                copy[offset + len - 1] ^= 1;
                check(!mem_eq(source.data() + 3, copy.data() + offset, len),
                      "unaligned unequal-memory comparison");
                copy[offset + len - 1] ^= 1;
            }
        }
    }

    PatternSignature a{};
    PatternSignature b{};
    a.opcode_bits = b.opcode_bits = 1;
    a.structure_bits = b.structure_bits = 2;
    a.depth = 3;
    b.depth = 4;
    check(!(a == b), "pattern signature compares metadata beyond first 16 bytes");
}

void test_mba_identities()
{
    constexpr uint32_t width_mask = 0xFFU;
    const auto narrow = [](uint32_t value) { return value & 0xFFU; };
    const auto bnot = [&](uint32_t value) { return narrow(~value); };
    const auto neg = [&](uint32_t value) { return narrow(0U - value); };

    for ( uint32_t x = 0; x <= width_mask; ++x )
    {
        for ( uint32_t y = 0; y <= width_mask; ++y )
        {
            check(narrow(bnot(narrow(bnot(x) + bnot(y))) + 1U) ==
                      narrow(x + y + 2U),
                  "Add_OllvmRule_2 identity");
            check(narrow(bnot(bnot(x) | bnot(y)) +
                         bnot(x | bnot(y)) + 1U) == narrow(y + 1U),
                  "Add_OllvmRule_4 identity");
            check(narrow(bnot(x) + bnot(y) + 2U) == neg(narrow(x + y)),
                  "Add_FactorRule_1 identity");
            check(narrow((x ^ bnot(y)) + 2U * (x | y)) ==
                      narrow(x + y - 1U),
                  "Add_FactorRule_2 identity");
            check(neg(narrow(neg(x) - neg(y))) == narrow(x - y),
                  "Add_NegRule_2 identity");
            check(narrow((bnot(x) & y) + (x | y)) ==
                      narrow(x + 2U * (bnot(x) & y)),
                  "Add_ComplexRule_1 identity");
            check(narrow((x ^ y) - 2U * (bnot(x) & y)) ==
                      narrow(x - y),
                  "Sub_HackersDelightRule_3 identity");
            check(narrow(neg(narrow(2U * (bnot(x) & y))) + (x ^ y)) ==
                      narrow(x - y),
                  "Sub_HackersDelightRule_4 identity");
            check(narrow(bnot(bnot(x) | bnot(y)) | bnot(x | y)) ==
                      bnot(x ^ y),
                  "Xor_MbaRule_3 XNOR identity");
        }
    }
}

void test_branchless_select_identity()
{
    const auto select = [](uint64_t old_value, uint64_t candidate,
                           bool condition, int size) {
        const uint64_t width_mask = size == 8
            ? std::numeric_limits<uint64_t>::max()
            : (uint64_t{1} << (size * 8)) - 1;
        const uint64_t mask = (uint64_t{0} - uint64_t{condition}) & width_mask;
        return (old_value ^ ((old_value ^ candidate) & mask)) & width_mask;
    };

    // Exhaust the complete 8-bit domain for both predicate values.
    for ( uint64_t old_value = 0; old_value <= 0xFF; ++old_value )
    {
        for ( uint64_t candidate = 0; candidate <= 0xFF; ++candidate )
        {
            check(select(old_value, candidate, false, 1) == old_value,
                  "branchless select retains the old 8-bit value");
            check(select(old_value, candidate, true, 1) == candidate,
                  "branchless select takes the candidate 8-bit value");
        }
    }

    constexpr uint64_t values[] = {
        0,
        1,
        0x7FFFFFFFULL,
        0x80000000ULL,
        0x0123456789ABCDEFULL,
        std::numeric_limits<uint64_t>::max(),
    };
    for ( int size : {2, 4, 8} )
    {
        const uint64_t width_mask = size == 8
            ? std::numeric_limits<uint64_t>::max()
            : (uint64_t{1} << (size * 8)) - 1;
        for ( uint64_t old_value : values )
        {
            for ( uint64_t candidate : values )
            {
                check(select(old_value, candidate, false, size) ==
                          (old_value & width_mask),
                      "branchless select retains the old wide value");
                check(select(old_value, candidate, true, size) ==
                          (candidate & width_mask),
                      "branchless select takes the candidate wide value");
            }
        }
    }
}

void test_hikari_string_recovery()
{
    using chernobog::string_recovery::recover_hikari_xor_ascii;

    const std::vector<uint8_t> separate_terminator = {
        0x09, 0x3F, 0x39, 0x28, 0x3F, 0x2E, 0x00};
    const std::vector<uint8_t> six_keys(6, 0x5A);
    check(recover_hikari_xor_ascii(separate_terminator, six_keys) == "Secret",
          "Hikari separate destination terminator");

    const std::vector<uint8_t> encrypted_terminator = {
        0x09, 0x3F, 0x39, 0x28, 0x3F, 0x2E, 0x5A};
    const std::vector<uint8_t> seven_keys(7, 0x5A);
    check(recover_hikari_xor_ascii(encrypted_terminator, seven_keys) == "Secret",
          "Hikari XOR-encrypted terminator");

    std::vector<uint8_t> corrupted = separate_terminator;
    corrupted[2] = 0x5B; // Decrypts to byte 0x01.
    check(recover_hikari_xor_ascii(corrupted, six_keys).empty(),
          "Hikari non-printable plaintext rejection");

    const std::vector<uint8_t> unterminated(
        separate_terminator.begin(), separate_terminator.end() - 1);
    check(recover_hikari_xor_ascii(unterminated, six_keys).empty(),
          "Hikari unterminated plaintext rejection");

    using chernobog::string_recovery::recover_static_text;
    const std::vector<uint8_t> ascii = {'N', 'h', 0};
    const auto recovered_ascii = recover_static_text(ascii, 1, false, false);
    check(recovered_ascii && recovered_ascii->utf8 == "Nh"
          && recovered_ascii->characters == 2
          && recovered_ascii->explicitly_terminated,
          "terminated static UTF-8 recovery");
    const std::vector<uint8_t> one_character = {'-', 0};
    const auto recovered_one = recover_static_text(
        one_character, 1, false, false);
    check(recovered_one && recovered_one->utf8 == "-"
          && recovered_one->explicitly_terminated,
          "single-character explicitly terminated static UTF-8 recovery");

    const std::vector<uint8_t> length_delimited = {'A', 'E', 'S', '-', '2', '5', '6'};
    const auto recovered_length = recover_static_text(
        length_delimited, 1, false, true);
    check(recovered_length && recovered_length->utf8 == "AES-256"
          && !recovered_length->explicitly_terminated,
          "length-delimited static UTF-8 recovery");
    check(!recover_static_text(length_delimited, 1, false, false),
          "unterminated static text requires explicit admission");

    const std::vector<uint8_t> utf16le = {
        0xA9, 0x03, 0x3D, 0xD8, 0x80, 0xDE, 0x00, 0x00}; // Omega + U+1F680
    const auto recovered_utf16 = recover_static_text(utf16le, 2, false, false);
    check(recovered_utf16 && recovered_utf16->utf8 == "\xCE\xA9\xF0\x9F\x9A\x80"
          && recovered_utf16->characters == 2,
          "strict UTF-16LE recovery with surrogate pair");
    const std::vector<uint8_t> utf16be = {
        0x03, 0xA9, 0xD8, 0x3D, 0xDE, 0x80, 0x00, 0x00};
    const auto recovered_utf16be = recover_static_text(
        utf16be, 2, true, false);
    check(recovered_utf16be
          && recovered_utf16be->utf8 == "\xCE\xA9\xF0\x9F\x9A\x80",
          "strict UTF-16BE recovery with surrogate pair");
    const std::vector<uint8_t> utf32le = {
        0x80, 0xF6, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    const auto recovered_utf32 = recover_static_text(
        utf32le, 4, false, false);
    check(recovered_utf32 && recovered_utf32->utf8 == "\xF0\x9F\x9A\x80",
          "strict UTF-32LE recovery");

    const std::vector<uint8_t> invalid_utf8 = {0xC0, 0xAF, 0};
    check(!recover_static_text(invalid_utf8, 1, false, false),
          "overlong UTF-8 rejection");
    const std::vector<uint8_t> embedded_control = {'A', 0x01, 'B', 0};
    check(!recover_static_text(embedded_control, 1, false, false),
          "static text control-code rejection");
    const std::vector<uint8_t> unpaired_surrogate = {
        0x00, 0xD8, 0x41, 0x00, 0x00, 0x00};
    check(!recover_static_text(unpaired_surrogate, 2, false, false),
          "unpaired UTF-16 surrogate rejection");
}

} // namespace

int main()
{
    test_bitvectors();
    test_arm64_direct_branch_encoding();
    test_simd_utilities();
    test_mba_identities();
    test_branchless_select_identity();
    test_hikari_string_recovery();
    if ( failures != 0 )
        std::fprintf(stderr, "%d core test(s) failed\n", failures);
    return failures == 0 ? 0 : 1;
}
