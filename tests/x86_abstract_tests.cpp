#include "common/x86_abstract.h"
#include "common/bounded_dataflow.h"

#include <array>
#include <cstdio>
#include <cstdlib>

using namespace chernobog::x86_abstract;

namespace
{
int failures = 0;
void check(bool ok, const char *what)
{
    if (ok)
        return;
    if (failures < 20)
        std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

struct FlowState
{
    Word word;
    Flags flags;
    void join(const FlowState &other)
    {
        word.join(other.word);
        flags.join(other.flags);
    }
    bool operator==(const FlowState &other) const
    {
        return word.known == other.word.known && word.value == other.word.value &&
               flags.known == other.flags.known && flags.value == other.flags.value;
    }
};

void dataflow_regressions()
{
    using chernobog::FlowNode;
    using chernobog::bounded_dataflow;
    // Enumerate concretizations independently: a join may retain exactly the
    // bits common to every member of the union of both abstract input sets.
    for (unsigned ak = 0; ak < 16; ++ak)
        for (unsigned av = 0; av < 16; ++av)
            for (unsigned bk = 0; bk < 16; ++bk)
                for (unsigned bv = 0; bv < 16; ++bv)
                {
                    unsigned all_one = 15, all_zero = 15;
                    for (unsigned v = 0; v < 16; ++v)
                        if ((v & ak) == (av & ak) || (v & bk) == (bv & bk))
                        {
                            all_one &= v;
                            all_zero &= ~v;
                        }
                    Word word{ak, av & ak};
                    word.join(Word{bk, bv & bk});
                    Flags flags{uint8_t(ak), uint8_t(av & ak)};
                    flags.join(Flags{uint8_t(bk), uint8_t(bv & bk)});
                    check(word.known == (all_one | all_zero) && word.value == all_one &&
                              flags.known == word.known && flags.value == word.value,
                          "known-bit joins match independent concrete-set union");
                }
    const std::vector<FlowNode> diamond = {{{}, true}, {{0}, false}, {{0}, false}, {{1, 2}, false}};
    const auto solve = [&](bool disagree, size_t rounds)
    {
        return bounded_dataflow<FlowState>(diamond, 4, rounds,
                                           [&](size_t i, FlowState state)
                                           {
                                               if (i == 1 || i == 2)
                                               {
                                                   state.word.write(
                                                       32, 0, i == 2 && disagree ? 8 : 7, true);
                                                   state.flags.set(CF, !(i == 2 && disagree));
                                               }
                                               return state;
                                           });
    };
    auto result = solve(false, 8);
    check(result && (*result)[3].word.read(64) == 7 && (*result)[3].flags.get(CF) == true,
          "equal diamond predecessors establish exact register and flag facts");
    result = solve(true, 8);
    check(result && !(*result)[3].word.read(64) && !(*result)[3].flags.get(CF),
          "disagreeing branch inputs remain unknown");
    check(!solve(false, 2), "unfinished iterations cannot publish provisional facts");
    auto graph = diamond;
    graph[3].unknown_entry = true;
    result = bounded_dataflow<FlowState>(graph, 4, 8,
                                         [](size_t i, FlowState state)
                                         {
                                             if (i == 1 || i == 2)
                                                 state.flags.set(CF, true);
                                             return state;
                                         });
    check(result && !(*result)[3].flags.get(CF), "external join entries contribute unknown state");
    graph = {{{}, true}, {{0, 2}, false}, {{1}, false}, {{1}, false}};
    for (bool clobber : {false, true})
    {
        result = bounded_dataflow<FlowState>(graph, 4, 16,
                                             [=](size_t i, FlowState state)
                                             {
                                                 if (i == 0)
                                                     state.flags.set(CF, true);
                                                 if (i == 2 && clobber)
                                                     state.flags.set(CF, false);
                                                 return state;
                                             });
        check(result &&
                  (clobber ? !(*result)[3].flags.get(CF) : (*result)[3].flags.get(CF) == true),
              "loop fixed point preserves invariants but rejects back-edge disagreement");
    }
    const auto identity = [](size_t, FlowState state) { return state; };
    check(!bounded_dataflow<FlowState>(graph, 3, 16, identity), "graph node cap rejects overflow");
    check(!bounded_dataflow<FlowState>(graph, 4, 0, identity), "zero iteration cap rejects");
    graph[0].predecessors = {4};
    check(!bounded_dataflow<FlowState>(graph, 4, 16, identity), "foreign predecessor rejects");
    graph[0].predecessors = {0, 0, 0, 0, 0};
    check(!bounded_dataflow<FlowState>(graph, 4, 16, identity), "predecessor cap rejects overflow");
    graph = {{{1}, false}, {{0}, false}};
    result = bounded_dataflow<FlowState>(graph, 2, 8,
                                         [](size_t, FlowState state)
                                         {
                                             state.flags.set(CF, true);
                                             return state;
                                         });
    check(result && !(*result)[0].flags.known && !(*result)[1].flags.known,
          "unreached cycles cannot manufacture input facts");
    std::puts("dataflow join concretizations: 65536; graph controls passed");
}

uint8_t arithmetic_oracle(unsigned a, unsigned b, unsigned carry, bool sub)
{
    const int exact = sub ? int(a) - int(b) - int(carry) : int(a + b + carry);
    const int sa = a < 128 ? int(a) : int(a) - 256;
    const int sb = b < 128 ? int(b) : int(b) - 256;
    const int signed_exact = sub ? sa - sb - int(carry) : sa + sb + int(carry);
    const unsigned byte = unsigned(exact) & 255;
    const int nibble = sub ? int(a % 16) - int(b % 16) - int(carry) : int(a % 16 + b % 16 + carry);
    unsigned ones = 0;
    for (unsigned v = byte; v; v /= 2)
        ones += v % 2;
    return uint8_t((exact < 0 || exact > 255 ? CF : 0) | (ones % 2 == 0 ? PF : 0) |
                   (nibble < 0 || nibble > 15 ? AF : 0) | (byte == 0 ? ZF : 0) |
                   (byte >= 128 ? SF : 0) | (signed_exact < -128 || signed_exact > 127 ? OF : 0));
}

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
uint8_t architectural_flags(uint64_t flags)
{
    return uint8_t(((flags & 1) ? CF : 0) | ((flags & 4) ? PF : 0) | ((flags & 16) ? AF : 0) |
                   ((flags & 64) ? ZF : 0) | ((flags & 128) ? SF : 0) | ((flags & 2048) ? OF : 0));
}

std::pair<uint8_t, uint8_t> native_arithmetic(uint8_t a, uint8_t b, uint64_t carry, Operation op)
{
    uint64_t flags = 0;
#define NATIVE(binary)                                                                             \
    asm volatile("btq $0, %3; " binary " %b2, %b0; pushfq; popq %1"                                \
                 : "+q"(a), "=r"(flags)                                                            \
                 : "q"(b), "r"(carry)                                                              \
                 : "cc", "memory")
    switch (op)
    {
    case Operation::add:
        NATIVE("addb");
        break;
    case Operation::adc:
        NATIVE("adcb");
        break;
    case Operation::sub:
        NATIVE("subb");
        break;
    case Operation::sbb:
        NATIVE("sbbb");
        break;
    default:
        std::abort();
    }
#undef NATIVE
    return {a, architectural_flags(flags)};
}

std::pair<uint8_t, uint8_t> native_shift(uint8_t a, uint8_t count, uint64_t initial, Operation op)
{
    uint64_t flags = 0;
#define SHIFT(binary)                                                                              \
    asm volatile("pushq %3; popfq; " binary " %%cl, %b0; pushfq; popq %1"                          \
                 : "+q"(a), "=r"(flags)                                                            \
                 : "c"(count), "r"(initial)                                                        \
                 : "cc", "memory")
    switch (op)
    {
    case Operation::shift_left:
        SHIFT("shlb");
        break;
    case Operation::shift_right:
        SHIFT("shrb");
        break;
    case Operation::arithmetic_right:
        SHIFT("sarb");
        break;
    default:
        std::abort();
    }
#undef SHIFT
    return {a, architectural_flags(flags)};
}

void native_shift_and_partial_writes()
{
    size_t cases = 0;
    for (Operation op :
         {Operation::shift_left, Operation::shift_right, Operation::arithmetic_right})
        for (unsigned a = 0; a < 256; ++a)
            for (unsigned count = 0; count < 256; ++count)
                for (const uint64_t initial : {UINT64_C(0x202), UINT64_C(0xad7)})
                {
                    Flags f{ALL, architectural_flags(initial)};
                    const auto value = transfer(op, 8, a, count, false, f);
                    const auto native = native_shift(uint8_t(a), uint8_t(count), initial, op);
                    check(value == native.first && (f.value & f.known) == (native.second & f.known),
                          "shift result and every claimed defined flag match x86 execution");
                    ++cases;
                }
    uint64_t a = UINT64_MAX, source = 0;
    asm volatile("cmpq %1, %1; cmovnel %k1, %k0" : "+r"(a) : "r"(source) : "cc");
    check(a == UINT32_MAX, "false CMOV r32 clears high register bits on x86 execution");
    a = UINT64_MAX;
    asm volatile("cmpq %1, %1; setne %b0" : "+q"(a) : "r"(source) : "cc");
    check(a == UINT64_C(0xffffffffffffff00), "false SETcc stores zero and preserves other bytes");
    std::printf("native shift cases: %zu; CMOV/SET partial-write controls passed\n", cases);
}
#endif

void exhaustive_arithmetic()
{
    constexpr std::array<Operation, 4> ops = {Operation::add, Operation::adc, Operation::sub,
                                              Operation::sbb};
    size_t cases = 0;
    for (Operation op : ops)
        for (unsigned a = 0; a < 256; ++a)
            for (unsigned b = 0; b < 256; ++b)
                for (unsigned carry = 0; carry < 2; ++carry)
                {
                    Flags flags;
                    flags.set(CF, carry != 0);
                    const auto value = transfer(op, 8, a, b, false, flags);
                    const unsigned c = op == Operation::adc || op == Operation::sbb ? carry : 0;
                    const bool sub = op == Operation::sub || op == Operation::sbb;
                    const auto expected = uint8_t(sub ? a - b - c : a + b + c);
                    const uint8_t expected_flags = arithmetic_oracle(a, b, c, sub);
                    check(value == expected && flags.known == ALL && flags.value == expected_flags,
                          "exhaustive 8-bit arithmetic versus integer oracle");
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
                    const auto native = native_arithmetic(uint8_t(a), uint8_t(b), carry, op);
                    check(value == native.first && flags.value == native.second,
                          "exhaustive 8-bit arithmetic versus x86 execution");
#endif
                    ++cases;
                }
    std::printf("arithmetic cases: %zu; ", cases);
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    std::puts("x86 execution oracle active");
#else
    std::puts("portable integer oracle (native x86 oracle not compiled on this architecture)");
#endif
}

bool condition_oracle(unsigned code, unsigned f)
{
    const bool c = f & CF, z = f & ZF, s = f & SF, o = f & OF, p = f & PF;
    const bool base[8] = {o, c, z, c || z, s, p, s != o, z || s != o};
    return base[code / 2] != ((code % 2) != 0);
}

void exhaustive_conditions()
{
    for (unsigned profile = 0; profile < 729; ++profile)
    {
        Flags flags;
        unsigned encoded = profile;
        for (unsigned bit = 0; bit < 6; ++bit, encoded /= 3)
            if (encoded % 3 != 0)
                flags.set(uint8_t(1u << bit), encoded % 3 == 2);
        for (unsigned code = 0; code < 16; ++code)
        {
            bool yes = false, no = false;
            for (unsigned f = 0; f < 64; ++f)
                if ((f & flags.known) == flags.value)
                {
                    if (condition_oracle(code, f))
                        yes = true;
                    else
                        no = true;
                }
            const auto result = evaluate(Condition(code), flags);
            check(result.has_value() == (yes != no),
                  "condition defined exactly when every completion agrees");
            if (result)
                check(*result == yes, "condition truth value");
        }
    }
    std::puts("condition profiles: 729 x 16");
}

void boundaries()
{
    for (unsigned bits : {8u, 16u, 32u, 64u})
    {
        const uint64_t m = mask(bits), s = uint64_t{1} << (bits - 1);
        Flags f;
        check(transfer(Operation::add, bits, m, 1, false, f) == 0 && f.get(CF) == true &&
                  f.get(ZF) == true && f.get(OF) == false,
              "all widths wrap unsigned addition");
        check(transfer(Operation::add, bits, s - 1, 1, false, f) == s && f.get(OF) == true &&
                  f.get(SF) == true && f.get(CF) == false,
              "all widths signed addition overflow");
        check(transfer(Operation::sub, bits, s, 1, false, f) == s - 1 && f.get(OF) == true &&
                  f.get(SF) == false,
              "all widths signed subtraction overflow");
        f.set(CF, true);
        check(transfer(Operation::increment, bits, m, {}, false, f) == 0 && f.get(CF) == true,
              "INC preserves known carry");
        f.forget(CF);
        transfer(Operation::decrement, bits, 0, {}, false, f);
        check(!f.get(CF) && f.get(SF) == true, "DEC preserves unknown carry");
        check(transfer(Operation::sub, bits, {}, {}, true, f) == 0 && f.get(CF) == false &&
                  f.get(ZF) == true,
              "SUB self known zero");
        transfer(Operation::bit_xor, bits, {}, {}, true, f);
        check(f.get(ZF) == true && f.get(PF) == true && !f.get(AF), "XOR self undefined AF");
        const Flags before = f;
        transfer(Operation::shift_left, bits, {}, 0, false, f);
        check(f.known == before.known && f.value == before.value, "zero shift preserves all flags");
        transfer(Operation::shift_right, bits, s, 1, false, f);
        check(f.get(OF) == true && f.get(CF) == false, "SHR one overflow from original sign");
        transfer(Operation::arithmetic_right, bits, s, 2, false, f);
        check(!f.get(OF) && !f.get(AF) && f.get(SF) == true,
              "SAR multi-count defined and undefined flags");
        transfer(Operation::shift_left, bits, 1, {}, false, f);
        check(f.known == 0, "unknown shift count invalidates flags");
    }
    Flags f;
    f.set(CF, true);
    f.set(ZF, true);
    transfer(Operation::complement_carry, 0, {}, {}, false, f);
    check(f.get(CF) == false && f.get(ZF) == true, "CMC preserves ZF while inverting CF");
    f.forget(CF);
    transfer(Operation::complement_carry, 0, {}, {}, false, f);
    check(!f.get(CF) && f.get(ZF) == true, "CMC unknown remains unknown");
    transfer(Operation::adc, 32, 1, 1, false, f);
    check(f.known == 0, "ADC unknown carry is not zero");
    transfer(Operation::unknown, 32, 0, 0, true, f);
    check(f.known == 0, "unsupported semantics never inherit known flags");

    Word w;
    w.write(64, 0, UINT64_MAX, true);
    w.write(8, 8, 0, true);
    check(w.read(64) == UINT64_C(0xffffffffffff00ff), "AH writes preserve other bits");
    w.write(8, 0, {}, true);
    check(!w.read(16) && w.read(8, 8) == 0, "unknown AL only invalidates AL");
    w.write(32, 0, 7, true);
    check(w.read(64) == 7, "EAX clears upper RAX");
    w.write(32, 0, {}, true);
    check(!w.read(64) && w.read(32, 32) == 0, "unknown EAX still clears upper RAX");
    w.write(64, 1, 0, true);
    check(w.known == 0, "invalid register slice invalidates rather than shifts out of range");
}

void mapping_counterexamples()
{
    for (unsigned x = 0; x < 256; ++x)
        for (unsigned c = 0; c < 256; ++c)
        {
            const unsigned a = x & c, o = x | c;
            check(((~(~(~a))) & 255) != a && ((~(~(~o))) & 255) != o,
                  "reject incorrect triple-NOT identities");
            check(((~(~a)) & 255) == a && ((~(~o)) & 255) == o, "correct double-NOT identities");
        }
    const uint32_t a = 0x1000, b = 0x10ff, k = 1;
    check(((a & ~k) + (b & k)) == 0x1001 && ((a & ~k) + (b & k)) != (k ? b : a),
          "constant target is not an exemption from full-width mask proof");
}
} // namespace

int main()
{
    dataflow_regressions();
    exhaustive_arithmetic();
    exhaustive_conditions();
    boundaries();
    mapping_counterexamples();
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    native_shift_and_partial_writes();
#endif
    if (failures)
        std::fprintf(stderr, "%d failures\n", failures);
    return failures ? 1 : 0;
}
