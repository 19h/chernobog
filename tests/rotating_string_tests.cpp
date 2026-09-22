#include "common/rotating_string_transform.h"
#include <cstdlib>
#include <iostream>
#include <random>

using namespace chernobog::rotating_string;
using chernobog::string_recovery::text_encoding_t;

static void check(bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

static Program program(uint32_t key, uint8_t unit_bytes)
{
    Program result;
    result.nodes = {{Operation::CONSTANT, 32, false, 0, 0, key, 0},
                    {Operation::INDEX, 64, true, 0, 0, 0, 1},
                    {Operation::ROL32, 32, false, 0, 1, 0, 0},
                    {Operation::ADD, 64, true, 1, 2, 0, 0},
                    {Operation::INPUT, uint8_t(8 * unit_bytes), false, 0, 0, 0, 0},
                    {Operation::XOR, 64, true, 4, 3, 0, 0},
                    {Operation::CAST, uint8_t(8 * unit_bytes), false, 5, 0, 0, 0}};
    result.result = 6;
    return result;
}

// Independent rotate oracle: apply count one-bit rotations, avoiding the
// production shift/or implementation. It also covers counts >= 32.
static uint32_t reference_rotate(uint32_t value, uint64_t count)
{
    for (uint64_t step = 0; step < count % 32; ++step)
        value = uint32_t(value * 2u) + uint32_t((value & UINT32_C(0x80000000)) != 0);
    return value;
}

static std::vector<uint8_t> reference_encrypt(const std::vector<uint8_t> &plain, uint32_t key,
                                              uint8_t unit_bytes, bool big_endian)
{
    auto encrypted = plain;
    for (size_t index = 0; index < plain.size() / unit_bytes; ++index)
    {
        const uint32_t key_unit = reference_rotate(key, index) + uint32_t(index);
        for (size_t byte = 0; byte < unit_bytes; ++byte)
        {
            const size_t shift = big_endian ? unit_bytes - 1 - byte : byte;
            encrypted[index * unit_bytes + byte] ^= uint8_t(key_unit >> (shift * 8));
        }
    }
    return encrypted;
}

int main()
{
    std::mt19937 random(0x845719u);
    size_t checked_indices = 0;
    for (unsigned trial = 0; trial < 64; ++trial)
    {
        const uint32_t key = trial == 0 ? 0 : trial == 1 ? UINT32_MAX : uint32_t(random());
        for (uint8_t width : {uint8_t(1), uint8_t(2)})
        {
            const auto expression = program(key, width);
            const Contract contract{key, 257, width, false};
            const auto proof = prove(expression, contract);
            check(proof && proof->indices_proved == 257 &&
                      proof->symbolic_input_bits == size_t(width * 8),
                  "typed transform must prove every bounded index for all input bits");
            for (size_t index = 0; index < contract.units; ++index)
            {
                const auto value = evaluate(expression, index, uint8_t(width * 8));
                const auto expected =
                    (uint64_t(reference_rotate(key, index)) + index) & mask(uint8_t(width * 8));
                check(value && value->constant == expected,
                      "schedule disagrees with independent rotate oracle");
                ++checked_indices;
            }
        }
    }
    const uint32_t key = UINT32_C(0xA17E395B);
    const std::vector<uint8_t> utf8{'V', 'M', 'P', ' ', 0xCE, 0xA9, 0};
    const std::vector<uint8_t> utf16le{'W', 0, 'i', 0, 'd', 0, 'e', 0, 0, 0};
    const std::vector<uint8_t> utf16be{0, 'W', 0, 'i', 0, 'd', 0, 'e', 0, 0};
    for (const auto &plain : {utf8, utf16le, utf16be})
    {
        for (uint8_t width : {uint8_t(1), uint8_t(2)})
        {
            if (plain.size() % width)
                continue;
            for (bool big_endian : {false, true})
            {
                const auto encrypted = reference_encrypt(plain, key, width, big_endian);
                const auto decoded =
                    decode_bytes(program(key, width),
                                 Contract{key, plain.size() / width, width, big_endian}, encrypted);
                check(decoded && *decoded == plain,
                      "typed byte/word endian transform must recover exact bytes");
            }
        }
    }
    const auto byte_utf16_cipher = reference_encrypt(utf16le, key, 1, false);
    const auto byte_decoded =
        decode_bytes(program(key, 1), Contract{key, 10, 1, false}, byte_utf16_cipher);
    check(byte_decoded && decode_text(*byte_decoded, text_encoding_t::utf16_le)->utf8 == "Wide",
          "UTF-16 decoding must remain independent of the byte transform");
    const auto wrong_unit =
        decode_bytes(program(key, 2), Contract{key, 5, 2, false}, byte_utf16_cipher);
    check(wrong_unit && *wrong_unit != utf16le,
          "UTF-16 content must not select the wide-unit schedule");
    check(decode_text(utf8, text_encoding_t::utf8)->utf8 == u8"VMP \u03A9",
          "UTF-8 validation must preserve non-ASCII scalars");
    check(decode_text(utf16be, text_encoding_t::utf16_be)->utf8 == "Wide",
          "explicit UTF-16BE decode");
    auto invalid = utf16le;
    invalid[0] = 0;
    invalid[1] = 0xD8;
    check(!decode_text(invalid, text_encoding_t::utf16_le),
          "unpaired UTF-16 surrogate must reject text");
    invalid = utf8;
    invalid.pop_back();
    check(!decode_text(invalid, text_encoding_t::utf8),
          "unterminated output must not become a string");

    for (unsigned negative = 0; negative < 10; ++negative)
    {
        auto expression = program(key, 1);
        Contract contract{key, 80, 1, false};
        switch (negative)
        {
        case 0:
            expression.nodes[2].operation = Operation::ROR32;
            break;
        case 1:
            expression.nodes[1].step = 2;
            break;
        case 2:
            expression.nodes[0].value ^= 1;
            break;
        case 3:
            expression.nodes[2].bits = 64;
            break;
        case 4:
            expression.nodes[5].operation = Operation::ADD;
            break;
        case 5:
            expression.nodes[4].bits = 16;
            break;
        case 6:
            expression.nodes[5].left = 5;
            break;
        case 7:
            contract.units = maximum_bytes + 1;
            break;
        case 8:
            expression.nodes[1].value = 1;
            break;
        case 9:
            expression.nodes[2].bits = 8;
            break;
        }
        check(!prove(expression, contract),
              "wrong direction/index/key/width/input/cycle/bounds must abstain");
    }
    auto signed_input = program(key, 1);
    signed_input.nodes[4].is_signed = true;
    check(bool(prove(signed_input, Contract{key, 80, 1, false})),
          "sign extension followed by byte truncation preserves low-byte XOR semantics");
    // Instantiate every byte input against an independently evaluated scalar
    // result, including sign extension through the 64-bit XOR expression.
    for (uint64_t index = 0; index < 65; ++index)
    {
        const auto symbolic = evaluate(signed_input, index, 8);
        check(bool(symbolic), "signed input expression must evaluate");
        for (uint32_t input = 0; input < 256; ++input)
        {
            uint64_t actual = symbolic->constant;
            for (unsigned bit = 0; bit < symbolic->bits; ++bit)
            {
                uint16_t terms = uint16_t(symbolic->coefficients[bit] & input);
                unsigned parity = 0;
                while (terms)
                {
                    parity ^= terms & 1;
                    terms >>= 1;
                }
                actual ^= uint64_t(parity) << bit;
            }
            const uint8_t expected =
                uint8_t(input ^ (uint64_t(reference_rotate(key, index)) + index));
            check(uint8_t(actual) == expected,
                  "symbolic input coefficients disagree with scalar truth table");
        }
    }
    auto narrow_counter = program(key, 1);
    narrow_counter.nodes[1].bits = 8;
    check(!prove(narrow_counter, Contract{key, 129, 1, false}),
          "signed induction overflow must reject proof");
    std::cout << "rotating string tests passed; oracle indices=" << checked_indices << '\n';
}
