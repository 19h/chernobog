#include "common/arm64_branch.h"
#include "common/finite_domain.h"

#include <array>
#include <cstdlib>
#include <iostream>
#include <map>

using namespace chernobog::finite_domain;

static void require(bool condition, const char *message)
{
    if (!condition)
    {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

struct Fixture
{
    std::map<uint64_t, uint8_t> memory;
    bool writable = false;

    Fixture()
    {
        for (unsigned input = 0; input < 256; ++input)
        {
            const uint8_t first = uint8_t(input * 13 + 37);
            memory[0x1000 + input] = first;
            memory[0x2000 + (first ^ 0x9A)] = uint8_t(input ^ 0xE5);
        }
    }

    std::optional<uint64_t> read(uint64_t address, int bytes) const
    {
        if (writable)
            return std::nullopt;
        uint64_t value = 0;
        for (int byte = 0; byte < bytes; ++byte)
        {
            const auto it = memory.find(address + uint64_t(byte));
            if (it == memory.end())
                return std::nullopt;
            value |= uint64_t(it->second) << (byte * 8);
        }
        return value;
    }

    void qword(uint64_t address, uint64_t value)
    {
        for (unsigned byte = 0; byte < 8; ++byte)
            memory[address + byte] = uint8_t(value >> (byte * 8));
    }
};

static Id lookup(Graph &g, Id input)
{
    const Id first = g.make(Op::load, 1, g.make(Op::add, 8, g.constant(0x1000, 8), input));
    const Id second_index = g.make(Op::bit_xor, 4, first, g.constant(0x9A, 4));
    const Id second = g.make(Op::load, 1, g.make(Op::add, 8, g.constant(0x2000, 8), second_index));
    return g.make(Op::bit_xor, 1, input, second);
}

int main()
{
    Fixture fixture;
    Graph graph([&](uint64_t a, int b) { return fixture.read(a, b); });
    const Id a = graph.variable(1, 4, 32);
    const Id b = graph.variable(2, 4, 32);
    const Id mixed =
        graph.make(Op::mul, 4, graph.make(Op::sub, 4, a, b), graph.constant(0xA5CD4CF, 4));
    const Id byte = graph.make(Op::low, 1, mixed);
    const Id result = lookup(graph, byte);
    require(graph.literal(result) == 0xE5, "correlated lookup must be universally constant");

    const Id masked = graph.make(Op::bit_and, 4, mixed, graph.constant(255, 4));
    require(graph.literal(lookup(graph, masked)) == 0xE5,
            "wide masked byte lookups must remain correlated and bounded");
    const auto domain = graph.enumerate(masked);
    require(domain && domain->results.size() == 256 && domain->results.back() == 255,
            "a zero-extended masked byte must cover all 256 values");
    require(graph.literal(graph.make(Op::bit_and, 4, a, graph.constant(0, 4))) == 0,
            "zero mask has exactly one value");
    require(!graph.enumerate(graph.make(Op::bit_and, 4, a, graph.constant(0x100, 4))),
            "a mask above the byte domain must not be silently truncated");
    require(!graph.enumerate(graph.make(Op::bit_xor, 4, a, masked)),
            "a full-width input must not alias its masked byte");
    const Id byte_condition = graph.variable(40, 1, 1);
    const Id narrow_dispatch =
        graph.make(Op::bit_xor, 1, graph.make(Op::mul, 1, byte_condition, graph.constant(0x4A, 1)),
                   graph.constant(0x7F, 1));
    const auto narrow_targets = graph.enumerate(narrow_dispatch);
    require(narrow_targets && narrow_targets->inputs.size() == 1 &&
                narrow_targets->results == std::vector<uint64_t>{0x7F, 0x35},
            "byte-sized Boolean arithmetic must retain its two outcomes");
    const auto masked_targets =
        graph.enumerate(graph.make(Op::bit_and, 4, narrow_dispatch, graph.constant(255, 4)));
    require(masked_targets && masked_targets->inputs == narrow_targets->inputs &&
                masked_targets->results == narrow_targets->results,
            "a wide byte mask must preserve an already bounded Boolean relation");

    const Id condition = graph.variable(3, 4, 1);
    const Id index =
        graph.make(Op::bit_xor, 4, graph.make(Op::mul, 4, condition, graph.constant(0x5DC0, 4)),
                   graph.constant(0x38E4, 4));
    fixture.qword(0x3000 + 8 * 0x38E4, 0x4000);
    fixture.qword(0x3000 + 8 * 0x6524, 0x5000);
    const Id target = graph.make(Op::load, 8,
                                 graph.make(Op::add, 8, graph.constant(0x3000, 8),
                                            graph.make(Op::mul, 8, index, graph.constant(8, 8))));
    const auto targets = graph.enumerate(target);
    require(targets && targets->inputs.size() == 1 && targets->results.size() == 2 &&
                targets->results[0] == 0x4000 && targets->results[1] == 0x5000,
            "Boolean target mapping must retain false/true order");

    Fixture changed;
    changed.memory[0x2000] ^= 1;
    Graph nonconstant([&](uint64_t x, int n) { return changed.read(x, n); });
    const Id varying = lookup(nonconstant, nonconstant.variable(1, 1, 8));
    require(!nonconstant.literal(varying), "one differing row must prevent constant proof");
    const auto alternatives = nonconstant.enumerate(varying);
    require(alternatives && alternatives->results.size() == 256,
            "all byte assignments must remain represented");

    Fixture missing;
    missing.memory.erase(0x1000 + 255);
    Graph incomplete([&](uint64_t x, int n) { return missing.read(x, n); });
    const Id hole = lookup(incomplete, incomplete.variable(1, 1, 8));
    require(!incomplete.enumerate(hole), "missing final row must invalidate the whole proof");

    fixture.writable = true;
    Graph mutable_memory([&](uint64_t x, int n) { return fixture.read(x, n); });
    require(!mutable_memory.enumerate(lookup(mutable_memory, mutable_memory.variable(1, 1, 8))),
            "untrusted memory must not be folded");

    Graph widths([](uint64_t, int) { return std::optional<uint64_t>(); });
    require(widths.literal(widths.make(Op::add, 4, widths.constant(0xFFFFFFFF, 4),
                                       widths.constant(1, 4))) == 0,
            "32-bit addition must wrap");
    require(widths.literal(widths.make(Op::sign_extend, 8, widths.constant(0x80, 1), invalid, 1)) ==
                0xFFFFFFFFFFFFFF80ULL,
            "signed extensions must retain the source width");
    require(!widths.enumerate(widths.variable(1, 2, 16)), "unbounded enumeration must fail closed");

    using chernobog::arm64_branch::decode_indirect;
    for (uint32_t word : {0xD71F0931U, 0xD73F0911U, 0xD61F093FU, 0xD63F0D3FU})
    {
        const auto branch = decode_indirect(word);
        require(branch && branch->authenticated, "authenticated branch encoding");
    }
    require(decode_indirect(0xD61F0120U) && !decode_indirect(0xD61F0120U)->authenticated,
            "plain BR encoding");
    require(!decode_indirect(0xD503201FU), "NOP must not be a branch");
    require(!decode_indirect(0xD61F0920U), "invalid zero-modifier encoding must be rejected");
    std::cout << "finite domain tests passed\n";
}
