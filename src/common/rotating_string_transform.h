/* Typed proof for bounded rotate/add/XOR string transforms.
 * Each input bit is a symbolic Boolean variable. XOR/casts are evaluated
 * exactly; arithmetic/rotates require constant operands after substituting
 * the bounded index. Unsupported expressions abstain, never sample input.
 */
#pragma once

#include "string_recovery.h"
#include <array>
#include <limits>

namespace chernobog::rotating_string
{

enum class Operation : uint8_t
{
    CONSTANT,
    INDEX,
    INPUT,
    CAST,
    ADD,
    SUB,
    XOR,
    ROL32,
    ROR32
};
struct Node
{
    Operation operation = Operation::CONSTANT;
    uint8_t bits = 0;
    bool is_signed = false;
    size_t left = 0, right = 0;
    uint64_t value = 0, step = 0;
};
struct Program
{
    std::vector<Node> nodes;
    size_t result = 0;
};
struct Contract
{
    uint32_t key = 0;
    size_t units = 0;
    uint8_t unit_bytes = 0;
    bool big_endian = false;
};
struct Proof
{
    Contract contract;
    size_t indices_proved = 0;
    size_t symbolic_input_bits = 0;
};
inline constexpr size_t maximum_nodes = 128;
inline constexpr size_t maximum_bytes = 8192;

inline bool supported_width(uint8_t bits)
{
    return bits == 8 || bits == 16 || bits == 32 || bits == 64;
}
inline uint64_t mask(uint8_t bits) { return bits == 64 ? ~uint64_t(0) : (uint64_t(1) << bits) - 1; }
inline uint32_t rotate_left(uint32_t key, uint64_t count)
{
    const unsigned shift = unsigned(count & 31);
    return (key << shift) | (key >> ((32 - shift) & 31));
}

struct SymbolicValue
{
    uint64_t constant = 0;
    std::array<uint16_t, 64> coefficients{};
    uint8_t bits = 0;
    bool is_signed = false;
    bool is_constant() const
    {
        return std::all_of(coefficients.begin(), coefficients.end(),
                           [](uint16_t coefficient) { return coefficient == 0; });
    }
};

inline SymbolicValue resize(SymbolicValue value, uint8_t bits)
{
    if (bits > value.bits && value.is_signed)
    {
        const bool sign = ((value.constant >> (value.bits - 1)) & 1) != 0;
        for (uint8_t bit = value.bits; bit < bits; ++bit)
        {
            value.coefficients[bit] = value.coefficients[value.bits - 1];
            if (sign)
                value.constant |= uint64_t(1) << bit;
        }
    }
    for (uint8_t bit = bits; bit < 64; ++bit)
        value.coefficients[bit] = 0;
    value.constant &= mask(bits);
    value.bits = bits;
    return value;
}

inline std::optional<SymbolicValue> evaluate(const Program &program, uint64_t index,
                                             uint8_t input_bits)
{
    if (program.nodes.empty() || program.nodes.size() > maximum_nodes ||
        program.result >= program.nodes.size() || (input_bits != 8 && input_bits != 16))
        return std::nullopt;
    std::vector<SymbolicValue> values;
    values.reserve(program.nodes.size());
    for (size_t position = 0; position < program.nodes.size(); ++position)
    {
        const Node &node = program.nodes[position];
        if (!supported_width(node.bits))
            return std::nullopt;
        SymbolicValue value;
        value.bits = node.bits;
        value.is_signed = node.is_signed;
        switch (node.operation)
        {
        case Operation::CONSTANT:
            value.constant = node.value & mask(node.bits);
            break;
        case Operation::INDEX:
            if (node.step != 0 &&
                index > (mask(node.bits) - (node.value & mask(node.bits))) / node.step)
                return std::nullopt;
            value.constant = (node.value + index * node.step) & mask(node.bits);
            if (node.is_signed && value.constant > (mask(node.bits) >> 1))
                return std::nullopt;
            break;
        case Operation::INPUT:
            if (node.bits != input_bits)
                return std::nullopt;
            for (uint8_t bit = 0; bit < input_bits; ++bit)
                value.coefficients[bit] = uint16_t(uint32_t(1) << bit);
            break;
        case Operation::CAST:
            if (node.left >= position)
                return std::nullopt;
            value = resize(values[node.left], node.bits);
            value.is_signed = node.is_signed;
            break;
        case Operation::ADD:
        case Operation::SUB:
        case Operation::XOR:
        case Operation::ROL32:
        case Operation::ROR32:
        {
            if (node.left >= position || node.right >= position)
                return std::nullopt;
            const auto left = resize(values[node.left], node.bits);
            const auto right = resize(values[node.right], node.bits);
            if (node.operation == Operation::XOR)
            {
                value.constant = left.constant ^ right.constant;
                for (uint8_t bit = 0; bit < node.bits; ++bit)
                    value.coefficients[bit] = left.coefficients[bit] ^ right.coefficients[bit];
            }
            else
            {
                if (!left.is_constant() || !right.is_constant())
                    return std::nullopt;
                if (node.operation == Operation::ADD || node.operation == Operation::SUB)
                    value.constant =
                        (node.operation == Operation::ADD ? left.constant + right.constant
                                                          : left.constant - right.constant) &
                        mask(node.bits);
                else
                {
                    if (node.bits != 32)
                        return std::nullopt;
                    const uint64_t count = node.operation == Operation::ROL32
                                               ? right.constant
                                               : (32 - (right.constant & 31));
                    value.constant = rotate_left(uint32_t(left.constant), count);
                }
            }
            break;
        }
        default:
            return std::nullopt;
        }
        values.push_back(value);
    }
    return values[program.result];
}

inline std::optional<Proof> prove(const Program &program, const Contract &contract)
{
    if ((contract.unit_bytes != 1 && contract.unit_bytes != 2) || contract.units == 0 ||
        contract.units > maximum_bytes / contract.unit_bytes)
        return std::nullopt;
    const uint8_t bits = uint8_t(contract.unit_bytes * 8);
    for (size_t index = 0; index < contract.units; ++index)
    {
        const auto evaluated = evaluate(program, index, bits);
        if (!evaluated)
            return std::nullopt;
        const auto output = resize(*evaluated, bits);
        const uint64_t expected = (uint64_t(rotate_left(contract.key, index)) + index) & mask(bits);
        if (output.constant != expected)
            return std::nullopt;
        for (uint8_t bit = 0; bit < bits; ++bit)
            if (output.coefficients[bit] != uint16_t(uint32_t(1) << bit))
                return std::nullopt;
    }
    return Proof{contract, contract.units, size_t(bits)};
}

// Encoding is independent of the proven transform unit. In particular,
// byte-transformed UTF-16 remains a byte transform.
inline std::optional<std::vector<uint8_t>> decode_bytes(const Program &program,
                                                        const Contract &contract,
                                                        const std::vector<uint8_t> &ciphertext)
{
    if (!prove(program, contract) || ciphertext.size() != contract.units * contract.unit_bytes)
        return std::nullopt;
    auto output = ciphertext;
    for (size_t index = 0; index < contract.units; ++index)
    {
        const uint32_t schedule = rotate_left(contract.key, index) + uint32_t(index);
        for (size_t byte = 0; byte < contract.unit_bytes; ++byte)
        {
            const size_t shift = contract.big_endian ? contract.unit_bytes - 1 - byte : byte;
            output[index * contract.unit_bytes + byte] ^= uint8_t(schedule >> (8 * shift));
        }
    }
    return output;
}

inline std::optional<string_recovery::recovered_text_t>
decode_text(const std::vector<uint8_t> &plaintext, string_recovery::text_encoding_t encoding)
{
    using namespace string_recovery;
    recovered_text_t text;
    bool valid = false;
    if (encoding == text_encoding_t::utf8)
    {
        valid =
            plaintext.size() > 1 && plaintext.back() == 0 &&
            std::find(plaintext.begin(), plaintext.end() - 1, uint8_t(0)) == plaintext.end() - 1 &&
            decode_utf8_payload(plaintext, plaintext.size() - 1, &text);
    }
    else if (encoding == text_encoding_t::utf16_le || encoding == text_encoding_t::utf16_be)
    {
        const bool big_endian = encoding == text_encoding_t::utf16_be;
        valid = plaintext.size() >= 4 && plaintext.size() % 2 == 0 &&
                decode_unit(plaintext.data() + plaintext.size() - 2, 2, big_endian) == 0 &&
                decode_wide_payload(plaintext, plaintext.size() - 2, 2, big_endian, &text);
    }
    if (!valid || text.characters < 4)
        return std::nullopt;
    text.explicitly_terminated = true;
    return text;
}

} // namespace chernobog::rotating_string
