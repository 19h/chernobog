#include "common/x86_abstract.h"
#include "common/bounded_dataflow.h"
#include "common/x86_string_memory.h"

#include <array>
#include <cstdio>
#include <cstdlib>

using namespace chernobog::x86_abstract;

namespace
{
int failures = 0;
uint64_t assertions = 0, native_repeat_cases = 0;
void check(bool ok, const char *what)
{
    ++assertions;
    if (ok)
        return;
    if (failures < 20)
        std::fprintf(stderr, "FAIL: %s\n", what);
    ++failures;
}

#ifdef CHERNOBOG_NATIVE_REPEAT_ORACLE
void native_repeat(std::array<uint8_t, 512> &memory, unsigned bytes, bool move, unsigned count,
                   int direction, unsigned destination, unsigned source, uint64_t accumulator)
{
    auto *d = memory.data() + destination;
    auto *s = memory.data() + source;
    const auto *initial_d = d, *initial_s = s;
    size_t remaining = count, flags = 0;
    const unsigned pattern = (count + destination + source + bytes + unsigned(move)) & 63;
    size_t seed = 0x202;
    const unsigned status_bits[] = {1, 4, 16, 64, 128, 2048};
    for (unsigned i = 0; i < 6; ++i)
        if (pattern & (1u << i))
            seed |= status_bits[i];
    ++native_repeat_cases;
#if defined(__x86_64__)
#define INIT_STRING_FLAGS "pushq %[seed]; popfq; "
#define READ_STRING_FLAGS "pushfq; popq %[flags]; cld"
#elif defined(__i386__)
#define INIT_STRING_FLAGS "pushl %[seed]; popfl; "
#define READ_STRING_FLAGS "pushfl; popl %[flags]; cld"
#else
#error Native repeat oracle requires an x86 target
#endif
#define REPEAT_ASM(OP, DF)                                                                         \
    asm volatile(INIT_STRING_FLAGS DF "; rep " OP "; " READ_STRING_FLAGS                           \
                 : "+D"(d), "+S"(s), "+c"(remaining), [flags] "=r"(flags)                          \
                 : "a"(size_t(accumulator)), [seed] "r"(seed)                                      \
                 : "memory", "cc")
#define RUN_REPEAT(OP)                                                                             \
    do                                                                                             \
    {                                                                                              \
        if (direction < 0)                                                                         \
            REPEAT_ASM(OP, "std");                                                                 \
        else                                                                                       \
            REPEAT_ASM(OP, "cld");                                                                 \
    } while (false)
    if (move)
        switch (bytes)
        {
        case 1:
            RUN_REPEAT("movsb");
            break;
        case 2:
            RUN_REPEAT("movsw");
            break;
        case 4:
            RUN_REPEAT("movsl");
            break;
#if defined(__x86_64__)
        case 8:
            RUN_REPEAT("movsq");
            break;
#endif
        default:
            check(false, "native repeat width is supported");
            return;
        }
    else
        switch (bytes)
        {
        case 1:
            RUN_REPEAT("stosb");
            break;
        case 2:
            RUN_REPEAT("stosw");
            break;
        case 4:
            RUN_REPEAT("stosl");
            break;
#if defined(__x86_64__)
        case 8:
            RUN_REPEAT("stosq");
            break;
#endif
        default:
            check(false, "native repeat width is supported");
            return;
        }
#undef RUN_REPEAT
#undef REPEAT_ASM
#undef READ_STRING_FLAGS
#undef INIT_STRING_FLAGS
    check(remaining == 0, "native repeat normal completion clears count");
    check(d == initial_d + direction * int(count * bytes), "native repeat advances DI");
    check(s == initial_s + (move ? direction * int(count * bytes) : 0),
          "native repeat advances SI only for MOVS");
    check((flags & 0x8d5) == (seed & 0x8d5), "native MOVS/STOS preserve six status flags");
    check(bool(flags & 0x400) == (direction < 0), "native repeat preserves DF");
}
#endif

void repeated_memory_regressions()
{
    // Independent enumeration of all 3^8 low-byte known-bit domains. The
    // other count bits are zero; poisoned unknown value bits are irrelevant.
    for (unsigned encoding = 0; encoding < 6561; ++encoding)
    {
        unsigned known = 0, value = 0, digits = encoding;
        for (unsigned bit = 0; bit < 8; ++bit, digits /= 3)
            if (digits % 3)
            {
                known |= 1u << bit;
                if (digits % 3 == 2)
                    value |= 1u << bit;
            }
        std::array<unsigned, 256> concrete{};
        unsigned size = 0;
        for (unsigned i = 0; i < 256; ++i)
            if ((i & known) == value)
                concrete[size++] = i;
        Flags partial_flags;
        partial_flags.set(CF | OF, false);
        partial_flags.set(AF, true);
        partial_result_flags(partial_flags, Word{known, value | (uint64_t{255} & ~known)}, 8);
        unsigned all_one_flags = ZF | SF | PF, all_zero_flags = ZF | SF | PF;
        for (unsigned i = 0; i < size; ++i)
        {
            const unsigned byte = concrete[i];
            unsigned parity = 0;
            for (unsigned bit = 0; bit < 8; ++bit)
                parity ^= (byte >> bit) & 1;
            const unsigned status =
                (byte == 0 ? ZF : 0) | (byte & 128 ? SF : 0) | (parity == 0 ? PF : 0);
            all_one_flags &= status;
            all_zero_flags &= ~status;
        }
        check(partial_flags.known == (CF | OF | AF | all_one_flags | all_zero_flags) &&
                  partial_flags.value == (AF | all_one_flags),
              "partial result flags match every concrete byte completion");
        for (unsigned bits : {32u, 64u})
        {
            const Word count{(mask(bits) & ~uint64_t{255}) | known,
                             value | (uint64_t{255} & ~known)};
            const auto actual = repeat_counts(count, bits);
            const bool bounded = concrete[size - 1] <= 8;
            check(bool(actual) == bounded, "repeat domain never clips counts above eight");
            if (actual)
            {
                check(actual->size == size, "repeat domain includes every compatible count");
                for (unsigned i = 0; i < size; ++i)
                    check(actual->values[i] == concrete[i], "repeat domain exact enumeration");
            }
        }
        for (unsigned immediate : {0u, 1u, 3u, 7u, 8u, 15u, 127u, 255u})
        {
            Word actual{known, value | (uint64_t{255} & ~known)};
            and_constant(actual, 8, 0, immediate, false);
            unsigned all_one = 255, all_zero = 255;
            for (unsigned i = 0; i < size; ++i)
            {
                all_one &= concrete[i] & immediate;
                all_zero &= ~(concrete[i] & immediate);
            }
            check(actual.known == ((all_one | all_zero) & 255) && actual.value == all_one,
                  "immediate AND known bits match every concretization");
            for (unsigned operation = 0; operation < 2; ++operation)
            {
                Word bits{known, value | (uint64_t{255} & ~known)};
                if (operation == 0)
                    or_constant(bits, 8, 0, immediate, false);
                else
                    xor_constant(bits, 8, 0, immediate, false);
                all_one = all_zero = 255;
                for (unsigned i = 0; i < size; ++i)
                {
                    const unsigned result =
                        operation == 0 ? concrete[i] | immediate : concrete[i] ^ immediate;
                    all_one &= result;
                    all_zero &= ~result;
                }
                check(bits.known == ((all_one | all_zero) & 255) && bits.value == all_one,
                      "immediate OR/XOR known bits match every concretization");
            }
        }
    }
    Word partial{UINT64_MAX, UINT64_MAX};
    and_constant(partial, 8, 8, 0x12, true);
    check(partial.read(64) == UINT64_C(0xffffffffffff12ff),
          "AH immediate AND preserves every other register byte");
    partial = {};
    and_constant(partial, 32, 0, 1, true);
    check(partial.known == (UINT64_MAX - 1) && partial.value == 0,
          "masked ECX has only its low bit unknown and zero-extends RCX");
    and_constant(partial, 64, 1, 0, true);
    check(partial.known == 0, "invalid immediate AND slice rejects register fact");
    partial = {UINT64_MAX ^ UINT64_C(0xff00), UINT64_MAX ^ UINT64_C(0xff00)};
    or_constant(partial, 8, 8, 0x12, true);
    check(partial.known == ((UINT64_MAX ^ UINT64_C(0xff00)) | UINT64_C(0x1200)) &&
              partial.value == ((UINT64_MAX ^ UINT64_C(0xff00)) | UINT64_C(0x1200)),
          "AH immediate OR fixes ones and preserves other register bytes");
    xor_constant(partial, 8, 8, 0x12, true);
    check(partial.known == ((UINT64_MAX ^ UINT64_C(0xff00)) | UINT64_C(0x1200)) &&
              partial.value == (UINT64_MAX ^ UINT64_C(0xff00)),
          "AH immediate XOR toggles only known source bits");
    partial = {};
    or_constant(partial, 32, 0, UINT64_C(0xffff0000), true);
    check(partial.known == UINT64_C(0xffffffffffff0000) && partial.value == UINT64_C(0xffff0000),
          "immediate OR fixes low 32-bit ones and zero-extends high 32 bits");
    xor_constant(partial, 32, 0, UINT64_C(0x00ff0000), true);
    check(partial.known == UINT64_C(0xffffffffffff0000) && partial.value == UINT64_C(0xff000000),
          "immediate XOR changes only known low 32-bit values");
    or_constant(partial, 64, 1, 0, true);
    check(partial.known == 0, "invalid immediate OR slice rejects register fact");
    xor_constant(partial, 64, 1, 0, true);
    check(partial.known == 0, "invalid immediate XOR slice rejects register fact");
    Flags wide_flags;
    partial_result_flags(wide_flags,
                         Word{UINT64_C(0xfffffffffffffeff), UINT64_C(0x8000000000000003)}, 64);
    check(wide_flags.get(ZF) == false && wide_flags.get(SF) == true && wide_flags.get(PF) == true,
          "partial 64-bit result fixes zero, sign and low-byte parity independently");
    partial_result_flags(wide_flags, Word{UINT64_C(0xff00), UINT64_C(0x0200)}, 8, 8);
    check(wide_flags.get(ZF) == false && wide_flags.get(SF) == false && wide_flags.get(PF) == false,
          "partial AH result uses its own byte for status flags");
    partial_result_flags(wide_flags, Word{}, 64, 1);
    check(!wide_flags.get(ZF) && !wide_flags.get(SF) && !wide_flags.get(PF),
          "invalid result slice establishes no status fact");
    check(!repeat_counts(Word{}, 64), "unknown high count bits reject finite model");
    check(!repeat_counts(Word{UINT64_MAX, 0}, 16), "unsupported count width rejects model");
    const auto range = [](uint64_t a, unsigned n) { return a < 512 && n <= 512 - a; };
    for (unsigned bits : {32u, 64u})
        for (unsigned bytes : {1u, 2u, 4u, 8u})
            for (bool move : {false, true})
                for (int delta : {-16, -1, 0, 1, 16, 64})
                    for (unsigned domain = 0; domain < 13; ++domain)
                        for (unsigned direction_domain = 0; direction_domain < 3;
                             ++direction_domain)
                            for (bool unknown : {false, true})
                            {
                                const unsigned low_unknown = domain == 9    ? 1
                                                             : domain == 10 ? 3
                                                             : domain == 11 ? 2
                                                             : domain == 12 ? 7
                                                                            : 0;
                                const unsigned fixed = domain == 11 ? 1 : domain < 9 ? domain : 0;
                                const Word count{mask(bits) & ~uint64_t(low_unknown), fixed};
                                std::array<uint8_t, 512> initial{};
                                for (unsigned i = 0; i < initial.size(); ++i)
                                    initial[i] = uint8_t(i * 37 + (i / 7));
                                StringMemory memory;
                                for (unsigned i = 96; i < 192; ++i)
                                    memory[i] = initial[i];
                                memory[450] = initial[450];
                                const StringRepeat repeat{
                                    bits,
                                    bytes,
                                    move,
                                    uint64_t(128 + delta),
                                    unknown ? std::nullopt : std::optional<uint64_t>{128},
                                    unknown ? std::nullopt
                                            : std::optional<uint64_t>{UINT64_C(0x8877665544332211)},
                                    direction_domain ? std::optional<bool>{direction_domain == 2}
                                                     : std::nullopt};
                                check(repeat_string_memory(memory, count, repeat, range, range),
                                      "bounded repeat with mapped destinations is admitted");
                                check(memory.count(450) && memory.at(450) == initial[450],
                                      "repeat preserves unrelated local memory");
                                check(memory.size() <= 128, "repeat obeys retained-byte cap");
                                const Word destination_index = repeat_index(
                                    count, repeat.destination, bits, bytes, repeat.reverse);
                                const Word source_index =
                                    repeat_index(count, repeat.source, bits, bytes, repeat.reverse);
                                uint64_t destination_ones = mask(bits),
                                         destination_zeros = mask(bits);
                                uint64_t source_ones = mask(bits), source_zeros = mask(bits);
                                // A concrete byte-array machine does not use the helper,
                                // its count enumerator, memory map or join operation.
                                for (unsigned n = 0; n < 256; ++n)
                                    if ((uint64_t(n) & count.known) == count.value)
                                        for (int direction : {-1, 1})
                                            for (unsigned hidden = 0; hidden < 2; ++hidden)
                                            {
                                                if (direction_domain &&
                                                    (direction < 0) != (direction_domain == 2))
                                                    continue;
                                                const uint64_t ending_destination = uint64_t(
                                                    128 + delta + direction * int(n * bytes));
                                                const uint64_t ending_source =
                                                    uint64_t(128 + direction * int(n * bytes));
                                                check(
                                                    (ending_destination &
                                                     destination_index.known) ==
                                                        destination_index.value,
                                                    "retained DI bits agree with concrete machine");
                                                check(
                                                    unknown
                                                        ? source_index.known == 0
                                                        : (ending_source & source_index.known) ==
                                                              source_index.value,
                                                    "retained SI bits agree with concrete machine");
                                                destination_ones &= ending_destination;
                                                destination_zeros &= ~ending_destination;
                                                source_ones &= ending_source;
                                                source_zeros &= ~ending_source;
                                                auto concrete = initial;
                                                for (unsigned i = 0; i < n; ++i)
                                                {
                                                    const int destination =
                                                        128 + delta + direction * int(i * bytes);
                                                    const int source = (unknown ? 320 : 128) +
                                                                       direction * int(i * bytes);
                                                    std::array<uint8_t, 8> payload{};
                                                    for (unsigned j = 0; j < bytes; ++j)
                                                        payload[j] =
                                                            move ? concrete[size_t(source) + j]
                                                            : unknown
                                                                ? uint8_t(hidden * 255)
                                                                : uint8_t(UINT64_C(
                                                                              0x8877665544332211) >>
                                                                          (j * 8));
                                                    for (unsigned j = 0; j < bytes; ++j)
                                                        concrete[size_t(destination) + j] =
                                                            payload[j];
                                                }
                                                for (const auto &byte : memory)
                                                    check(
                                                        byte.second == concrete[size_t(byte.first)],
                                                        "retained repeat byte agrees with concrete machine");
#ifdef CHERNOBOG_NATIVE_REPEAT_ORACLE
                                                auto native = initial;
                                                native_repeat(
                                                    native, bytes, move, n, direction,
                                                    unsigned(128 + delta), unknown ? 320 : 128,
                                                    unknown ? hidden ? UINT64_MAX : 0
                                                            : UINT64_C(0x8877665544332211));
                                                check(
                                                    native == concrete,
                                                    "native repeat agrees with full-buffer concrete oracle");
#endif
                                            }
                                check(
                                    destination_index.known ==
                                            ((destination_ones | destination_zeros) & mask(bits)) &&
                                        destination_index.value == destination_ones,
                                    "DI join retains exactly the common concrete bits");
                                check(unknown
                                          ? source_index.known == 0
                                          : source_index.known ==
                                                    ((source_ones | source_zeros) & mask(bits)) &&
                                                source_index.value == source_ones,
                                      "SI join retains exactly the common concrete bits");
                            }
    const Word eight{UINT64_MAX, 8}, zero{UINT64_MAX, 0}, one{UINT64_MAX, 1};
    for (unsigned bits : {32u, 64u})
        for (unsigned bytes : {1u, 2u, 4u, 8u})
            for (unsigned count = 0; count <= 8; ++count)
                for (uint64_t base : {uint64_t{0}, uint64_t{1}, mask(bits) - 1, mask(bits)})
                    for (bool reverse : {false, true})
                    {
                        uint64_t concrete = base;
                        for (unsigned i = 0; i < count; ++i)
                            for (unsigned j = 0; j < bytes; ++j)
                                concrete = (reverse ? concrete - 1 : concrete + 1) & mask(bits);
                        const Word result =
                            repeat_index(Word{mask(bits), count}, base, bits, bytes, reverse);
                        check(result.known == mask(bits) && result.value == concrete,
                              "index wrap agrees with independent byte-step machine");
                    }
    check(repeat_index(one, {}, 64, 1, false).known == 0, "unknown index remains unknown");
    check(repeat_index(Word{}, 100, 64, 1, false).known == 0,
          "unbounded count cannot establish index bits");
    check(repeat_index(Word{UINT64_MAX, 9}, 100, 64, 1, false).known == 0,
          "count nine cannot establish index bits");
    check(repeat_index(one, 100, 16, 1, false).known == 0,
          "unsupported address width cannot establish index bits");
    check(repeat_index(one, UINT64_MAX, 32, 1, false).known == 0,
          "index outside address width cannot establish index bits");
    for (unsigned bytes : {0u, 3u, 16u})
        check(repeat_index(one, 100, 64, bytes, false).known == 0,
              "unsupported element width cannot establish index bits");
    StringMemory memory{{100, 42}, {450, 19}};
    const auto before = memory;
    check(repeat_string_memory(memory, zero, {64, 8, true, {}, {}, {}}, range, range) &&
              memory == before,
          "zero repeats preserve all bytes without known pointers");
    check(!repeat_string_memory(memory, Word{UINT64_MAX, 9}, {64, 1, false, 100, {}, 7}, range,
                                range) &&
              memory == before,
          "nine iterations reject without dropping a state or changing input");
    check(!repeat_string_memory(memory, eight, {64, 1, false, 100, {}, 7}, range,
                                [](uint64_t a, unsigned) { return a >= 100; }) &&
              memory == before,
          "one invalid DF direction rejects the whole repeat");
    check(repeat_string_memory(memory, eight, {64, 1, false, 100, {}, 7, false}, range,
                               [](uint64_t a, unsigned) { return a >= 100; }) &&
              memory.at(107) == 7 && memory.at(450) == 19,
          "known forward DF excludes invalid reverse destinations");
    memory = before;
    check(!repeat_string_memory(memory, eight, {64, 1, false, 100, {}, 7, true}, range,
                                [](uint64_t a, unsigned) { return a >= 100; }) &&
              memory == before,
          "known reverse DF rejects its invalid destination without mutation");
    check(!repeat_string_memory(memory, one, {32, 8, false, UINT32_MAX - 3, {}, 7}, range,
                                [](uint64_t, unsigned) { return true; }) &&
              memory == before,
          "element spanning the address boundary rejects repeat");
    check(!repeat_string_memory(memory, one, {64, 1, false, {}, {}, 7}, range, range) &&
              memory == before,
          "unknown destination rejects nonzero repeat");
    check(repeat_string_memory(
              memory, one, {64, 1, true, 100, 450, {}}, [](uint64_t, unsigned) { return false; },
              range) &&
              !memory.count(100) && memory.at(450) == 19,
          "unreadable source forgets written byte and preserves disjoint source");
    memory.clear();
    for (unsigned i = 0; i < 128; ++i)
        memory[i] = uint8_t(i);
    check(repeat_string_memory(memory, eight, {64, 8, false, 200, {}, UINT64_MAX}, range, range) &&
              memory.size() <= 128,
          "repeat store evictions retain bounded memory");
}

void repeat_compare_early_stop_regressions()
{
    using namespace chernobog::x86_abstract;
    for (unsigned width : {8u, 16u, 32u, 64u})
        for (uint64_t count : {uint64_t{2}, uint64_t{3}, UINT64_MAX})
        {
            const Flags prior{ALL, ALL};
            const auto repe =
                first_compare_early_stop(width, count, true, 0x10, 0x20, false, prior);
            check(repe && repe->remaining == count - 1 && repe->flags.get(ZF) == false &&
                      repe->flags.get(CF) == true,
                  "REPE unequal first comparison stops with one decrement and new flags");
            const auto repne = first_compare_early_stop(width, count, false, {}, {}, true, prior);
            check(repne && repne->remaining == count - 1 && repne->flags.get(ZF) == true &&
                      repne->flags.get(CF) == false,
                  "REPNE equal first comparison stops with one decrement and new flags");
            check(!first_compare_early_stop(width, count, true, {}, {}, true, prior),
                  "REPE equal first comparison must continue");
            check(!first_compare_early_stop(width, count, false, 0x10, 0x20, false, prior),
                  "REPNE unequal first comparison must continue");
            check(!first_compare_early_stop(width, count, true, {}, {}, false, prior),
                  "prior known ZF cannot replace unknown first comparison");
        }
    check(!first_compare_early_stop(8, 0, true, 0x10, 0x20, false, {}),
          "zero-count comparison does not execute");
    check(!first_compare_early_stop(8, 1, true, 0x10, 0x20, false, {}),
          "single-count comparison uses the existing exact-one path");
    check(!first_compare_early_stop(24, 2, true, 0x10, 0x20, false, {}),
          "unsupported comparison width abstains");
}

void repeat_compare_bounded_regressions()
{
    using namespace chernobog::x86_abstract;
    for (unsigned width : {8u, 16u, 32u, 64u})
    {
        const auto repe =
            bounded_compare_repeat(width, 3, true, false, Flags{ALL, ALL},
                                   [](uint64_t iteration, bool) -> std::optional<CompareOperands>
                                   {
                                       return iteration == 0 ? CompareOperands{0x10, 0x10, false}
                                                             : CompareOperands{0x10, 0x20, false};
                                   });
        check(repe && repe->remaining == 1 && repe->flags.get(ZF) == false &&
                  repe->flags.get(CF) == true,
              "REPE second unequal comparison stops with count one and second flags");
        const auto repne =
            bounded_compare_repeat(width, 3, false, true, Flags{ALL, ALL},
                                   [](uint64_t iteration, bool) -> std::optional<CompareOperands>
                                   {
                                       return iteration == 0 ? CompareOperands{0x10, 0x20, false}
                                                             : CompareOperands{{}, {}, true};
                                   });
        check(repne && repne->remaining == 1 && repne->flags.get(ZF) == true &&
                  repne->flags.get(CF) == false,
              "REPNE second equal comparison stops with count one and second flags");
    }
    const auto exhausted = bounded_compare_repeat(
        8, 3, true, {}, {}, [](uint64_t, bool) -> std::optional<CompareOperands>
        { return CompareOperands{{}, {}, true}; });
    check(exhausted && exhausted->remaining == 0 && exhausted->flags.get(ZF) == true &&
              exhausted->flags.get(CF) == false,
          "both direction completions exhaust a three-iteration REPE CMPS count");
    const auto last_unknown = bounded_compare_repeat(
        8, 2, true, false, {},
        [](uint64_t iteration, bool) -> std::optional<CompareOperands>
        {
            return iteration == 0 ? CompareOperands{{}, {}, true} : CompareOperands{{}, {}, false};
        });
    check(last_unknown && last_unknown->remaining == 0 && last_unknown->flags.known == 0,
          "unknown final comparison preserves exact exhausted count but no flags");
    check(!bounded_compare_repeat(
              8, 3, true, {}, {},
              [](uint64_t iteration, bool reverse) -> std::optional<CompareOperands>
              {
                  return iteration == 1 && reverse ? CompareOperands{0x10, 0x20, false}
                                                   : CompareOperands{{}, {}, true};
              }),
          "different direction counts cannot yield one exact repeat result");
    check(!bounded_compare_repeat(8, 3, true, false, {},
                                  [](uint64_t iteration, bool) -> std::optional<CompareOperands>
                                  {
                                      return iteration == 1
                                                 ? std::nullopt
                                                 : std::optional<CompareOperands>{{{}, {}, true}};
                                  }),
          "missing second comparison cannot establish repeat continuation");
    check(!bounded_compare_repeat(8, 129, true, false, {},
                                  [](uint64_t, bool) -> std::optional<CompareOperands>
                                  { return CompareOperands{{}, {}, true}; }),
          "repeat beyond the finite replay budget abstains without a stop");
    const auto huge_first = bounded_compare_repeat(
        8, UINT64_MAX, true, {}, {}, [](uint64_t, bool) -> std::optional<CompareOperands>
        { return CompareOperands{0x10, 0x20, false}; });
    check(huge_first && huge_first->remaining == UINT64_MAX - 1,
          "first-iteration stop does not unroll a huge initial count");
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

void backward_slice_regressions()
{
    using chernobog::FlowNode;
    using chernobog::backward_flow_slice;
    uint64_t comparisons = 0;
    // Independently enumerate concrete Boolean inputs over every five-node
    // acyclic topology. Every cut edge must add both Boolean completions.
    for (unsigned topology = 0; topology < 1024; ++topology)
        for (unsigned operations = 0; operations < 16; ++operations)
        {
            std::vector<FlowNode> graph(5);
            unsigned edge = 0;
            for (size_t i = 0; i < graph.size(); ++i)
                for (size_t p = 0; p < i; ++p, ++edge)
                    if (topology & (1u << edge))
                        graph[i].predecessors.push_back(p);
            graph[0].unknown_entry = true;
            std::array<unsigned, 5> inputs{}, outputs{};
            const auto operation = [&](size_t i) { return (operations >> (i % 4)) & 3u; };
            for (size_t i = 0; i < graph.size(); ++i)
            {
                unsigned input = graph[i].predecessors.empty() ? 3 : 0;
                for (size_t p : graph[i].predecessors)
                    input |= outputs[p];
                inputs[i] = input;
                const unsigned op = operation(i);
                outputs[i] = op == 0   ? input
                             : op == 1 ? 1
                             : op == 2 ? 2
                                       : ((input & 1) << 1) | ((input & 2) >> 1);
            }
            for (size_t budget = 1; budget <= 5; ++budget)
            {
                const auto slice = backward_flow_slice(graph, 4, budget);
                check(slice && slice->graph.size() <= budget &&
                          slice->original_indices[slice->query] == 4,
                      "backward slice keeps the query within its node budget");
                if (!slice)
                    continue;
                const auto result = chernobog::bounded_dataflow<FlowState>(
                    slice->graph, budget, 16,
                    [&](size_t i, FlowState state)
                    {
                        const unsigned op = operation(slice->original_indices[i]);
                        if (op == 1 || op == 2)
                            state.flags.set(CF, op == 2);
                        else if (op == 3)
                            if (const auto value = state.flags.get(CF))
                                state.flags.set(CF, !*value);
                        return state;
                    });
                check(result.has_value(), "acyclic slice reaches a fixed point");
                if (!result)
                    continue;
                const auto value = (*result)[slice->query].flags.get(CF);
                check(!value || inputs[4] == (*value ? 2u : 1u),
                      "every sliced Boolean fact agrees with every concrete original input");
                ++comparisons;
            }
        }
    std::vector<FlowNode> loop = {{{}, true}, {{0, 2}, false}, {{1}, false}, {{1}, false}};
    for (size_t budget : {1u, 2u, 3u, 4u})
    {
        const auto slice = backward_flow_slice(loop, 3, budget);
        const auto result =
            chernobog::bounded_dataflow<FlowState>(slice->graph, budget, 16,
                                                   [&](size_t i, FlowState state)
                                                   {
                                                       if (slice->original_indices[i] == 0)
                                                           state.flags.set(CF, true);
                                                       return state;
                                                   });
        check(result && (budget == 4 ? (*result)[slice->query].flags.get(CF) == true
                                     : !(*result)[slice->query].flags.get(CF)),
              "a cut loop entry stays unknown until its establishing predecessor is retained");
    }
    check(!backward_flow_slice(loop, 4, 4), "foreign slice query rejects");
    check(!backward_flow_slice(loop, 3, 0), "zero slice budget rejects");
    loop[0].predecessors = {4};
    check(!backward_flow_slice(loop, 3, 2), "even an unselected malformed predecessor rejects");
    std::printf("backward slice concrete Boolean comparisons: %llu; controls passed\n",
                static_cast<unsigned long long>(comparisons));
}

void alternative_regressions()
{
    struct Pair
    {
        Word left, right;
        void join(const Pair &other)
        {
            left.join(other.left);
            right.join(other.right);
        }
        bool operator==(const Pair &other) const
        {
            return left.known == other.left.known && left.value == other.left.value &&
                   right.known == other.right.known && right.value == other.right.value;
        }
    };
    using Domain = chernobog::BoundedAlternatives<Pair, 2>;
    const auto exact = [](unsigned a, unsigned b) { return Pair{Word{255, a}, Word{255, b}}; };
    const auto product = [](Pair state)
    {
        const auto a = state.left.read(8), b = state.right.read(8);
        state.left = a && b ? Word{255, (*a * *b) & 255} : Word{};
        return state;
    };
    size_t cases = 0;
    for (unsigned a = 0; a < 16; ++a)
        for (unsigned b = 0; b < 16; ++b)
            for (unsigned c = 0; c < 16; ++c)
                for (unsigned d = 0; d < 16; ++d)
                {
                    Domain input(exact(a, b));
                    input.join(Domain(exact(c, d)));
                    const auto result = input.apply(product).common().left;
                    const unsigned first = (a * b) & 255, second = (c * d) & 255;
                    check((first & result.known) == result.value &&
                              (second & result.known) == result.value &&
                              (first == second ? result.read(8) == first : !result.read(8)),
                          "correlated multiplication agrees with independent concrete outcomes");
                    Domain reversed(exact(c, d));
                    reversed.join(Domain(exact(a, b)));
                    reversed.join(Domain(exact(a, b)));
                    check(input == reversed,
                          "alternative equality ignores ordering and duplicate paths");
                    ++cases;
                }
    Domain input(exact(0, 7));
    input.join(Domain(exact(7, 0)));
    check(input.apply(product).common().left.read(8) == 0,
          "alternatives retain correlations discarded by a product of independent joins");
    input.join(Domain(exact(0, 0)));
    check(input.widened() && input.states().size() == 1 &&
              !input.apply(product).common().left.read(8),
          "overflow widens every path instead of keeping a favorable subset");
    const auto widened = input.common();
    for (const auto &actual : {exact(0, 7), exact(7, 0), exact(0, 0)})
        check((actual.left.value & widened.left.known) == widened.left.value &&
                  (actual.right.value & widened.right.known) == widened.right.value,
              "widened state covers all concrete predecessors");
    input = input.apply(
        [](Pair state)
        {
            state.left = Word{255, 9};
            return state;
        });
    check(input.widened() && input.common().left.read(8) == 9,
          "an unconditional overwrite establishes a fact after widening");
    input.join(Domain{});
    check(!input.common().left.read(8), "unknown external entry is retained after widening");
    using chernobog::FlowNode;
    const std::vector<FlowNode> graph = {
        {{}, true}, {{0}, false}, {{0}, false}, {{1, 2}, false}, {{3}, false}};
    const auto transfer = [&](size_t i, Domain state)
    {
        if (i == 1)
            return Domain(exact(0, 7));
        if (i == 2)
            return Domain(exact(7, 0));
        if (i == 3)
            return state.apply(product);
        return state;
    };
    auto result = chernobog::bounded_dataflow<Domain>(graph, 5, 16, transfer);
    check(result && (*result)[4].common().left.read(8) == 0,
          "fixed-point graph propagates correlated values through a join");
    check(!chernobog::bounded_dataflow<Domain>(graph, 5, 3, transfer),
          "unfinished alternative analysis cannot return provisional values");
    auto external = graph;
    external[3].unknown_entry = true;
    result = chernobog::bounded_dataflow<Domain>(external, 5, 16, transfer);
    check(result && !(*result)[4].common().left.read(8),
          "external entry prevents a correlated graph proof");
    const std::vector<FlowNode> loop = {{{}, true}, {{0, 2}, false}, {{1}, false}, {{1}, false}};
    result = chernobog::bounded_dataflow<Domain>(
        loop, 4, 32,
        [&](size_t i, Domain state)
        {
            if (i == 0)
                return Domain(exact(0, 9));
            if (i == 2)
                return state.apply(
                    [](Pair next)
                    {
                        const auto value = next.left.read(8);
                        next.left = value ? Word{255, (*value + 1) & 255} : Word{};
                        return next;
                    });
            return state;
        });
    check(result && (*result)[3].widened() && !(*result)[3].common().left.read(8) &&
              (*result)[3].common().right.read(8) == 9,
          "changing loop widens while retaining its independent invariant");
    std::printf("alternative concrete pairs: %zu; cap, entry, loop and budget controls passed\n",
                cases);
}

void explicit_entry_regressions()
{
    using chernobog::FlowNode;
    using chernobog::bounded_reachable_dataflow;
    // Node 2 is an orphan after a proved edge exclusion, not an unknown entry.
    std::vector<FlowNode> graph = {{{}, true}, {{0}, false}, {{}, false}, {{1, 2}, false}};
    const auto transfer = [](size_t i, FlowState state)
    {
        if (i == 1 || i == 2)
            state.word.write(32, 0, i == 1 ? 7 : 8, true);
        return state;
    };
    auto result = bounded_reachable_dataflow<FlowState>(graph, 4, 16, transfer);
    check(result && !(*result)[2] && (*result)[3] && (*result)[3]->word.read(64) == 7,
          "a newly orphaned block cannot manufacture an unknown entry or overwrite a target");
    graph[2].unknown_entry = true;
    result = bounded_reachable_dataflow<FlowState>(graph, 4, 16, transfer);
    check(result && (*result)[2] && (*result)[3] && !(*result)[3]->word.read(64),
          "an actual external entry restores the excluded destination");
    check(!bounded_reachable_dataflow<FlowState>(graph, 4, 2, transfer),
          "a provisional refined solve cannot return a value");
    graph = {{{1}, false}, {{0}, false}};
    result = bounded_reachable_dataflow<FlowState>(graph, 2, 16, transfer);
    check(result && !(*result)[0] && !(*result)[1], "an unentered cycle remains lattice bottom");
    graph = {{{}, true}, {{0, 2}, false}, {{1}, false}, {{1}, false}};
    const auto loop = [](size_t i, FlowState state)
    {
        if (i == 0)
            state.flags.set(CF, true);
        if (i == 2)
            state.flags.set(CF, false);
        return state;
    };
    check(!bounded_reachable_dataflow<FlowState>(graph, 4, 2, loop),
          "initial loop carry is not a converged predicate proof");
    result = bounded_reachable_dataflow<FlowState>(graph, 4, 16, loop);
    check(result && (*result)[1] && !(*result)[1]->flags.get(CF),
          "a back-edge clobber prevents a universal branch outcome");
    graph[0].predecessors = {4};
    check(!bounded_reachable_dataflow<FlowState>(graph, 4, 16, loop),
          "explicit-entry solver rejects a foreign predecessor");
    std::puts(
        "explicit-entry dataflow: orphan, external entry, cycle, loop and budget controls passed");
}

void status_ah_regressions()
{
    const auto encoded = [](unsigned flags)
    {
        return unsigned((flags & CF ? 0x01 : 0) | (flags & PF ? 0x04 : 0) |
                        (flags & AF ? 0x10 : 0) | (flags & ZF ? 0x40 : 0) |
                        (flags & SF ? 0x80 : 0));
    };
    const auto decoded = [](unsigned ah)
    {
        return unsigned((ah & 0x01 ? CF : 0) | (ah & 0x04 ? PF : 0) | (ah & 0x10 ? AF : 0) |
                        (ah & 0x40 ? ZF : 0) | (ah & 0x80 ? SF : 0));
    };
    for (unsigned known = 0; known <= ALL; ++known)
        for (unsigned value = 0; value <= ALL; ++value)
        {
            const Flags flags{uint8_t(known), uint8_t(value & known)};
            Word accumulator{UINT64_MAX, UINT64_C(0x1234567890abcdef)};
            load_status_into_ah(accumulator, flags);
            check(((accumulator.known >> 8) & 255) == (0x2a | encoded(known)) &&
                      ((accumulator.value >> 8) & 255) == (0x02 | encoded(value & known)) &&
                      (accumulator.known & ~UINT64_C(0xff00)) == ~UINT64_C(0xff00) &&
                      (accumulator.value & ~UINT64_C(0xff00)) ==
                          (UINT64_C(0x1234567890abcdef) & ~UINT64_C(0xff00)),
                  "LAHF maps each known flag into AH and preserves other accumulator bits");
            Flags restored{ALL, OF};
            store_ah_into_status(restored, accumulator);
            check(restored.known == ((known & ~unsigned(OF)) | OF) &&
                      restored.value == (((value & known) & ~unsigned(OF)) | OF),
                  "SAHF restores only known AH status bits and preserves OF");
        }
    for (unsigned ah = 0; ah < 256; ++ah)
    {
        Word accumulator;
        accumulator.write(8, 8, ah, false);
        Flags flags{ALL, OF};
        store_ah_into_status(flags, accumulator);
        check(flags.known == ALL && flags.value == (OF | decoded(ah)),
              "SAHF ignores reserved AH bits and leaves OF unchanged");
    }
    std::puts("LAHF/SAHF partial profiles: 4096; concrete AH values: 256");
}

void accumulator_extension_regressions()
{
    constexpr uint64_t initial = UINT64_C(0x123456789abcdef0);
    // Intersect every compatible concrete byte completion independently of the
    // abstract transfer. This covers all 3^8 partial byte states, including an
    // unknown sign bit and low bits whose values are known separately.
    for (unsigned profile = 0; profile < 6561; ++profile)
    {
        unsigned encoded = profile;
        Word input{UINT64_C(0xffffffffffffff00), initial & ~UINT64_C(0xff)};
        for (unsigned bit = 0; bit < 8; ++bit, encoded /= 3)
            if (encoded % 3)
            {
                input.known |= uint64_t{1} << bit;
                if (encoded % 3 == 2)
                    input.value |= uint64_t{1} << bit;
            }
        Word expected;
        bool first = true;
        for (unsigned byte = 0; byte < 256; ++byte)
        {
            if ((byte & input.known & 255) != (input.value & 255))
                continue;
            const int signed_byte = byte < 128 ? int(byte) : int(byte) - 256;
            Word concrete{UINT64_MAX,
                          (initial & ~UINT64_C(0xffff)) | uint64_t(uint16_t(signed_byte))};
            if (first)
                expected = concrete;
            else
                expected.join(concrete);
            first = false;
        }
        Word result = input;
        sign_extend_accumulator(result, result, 8, false, true);
        check(!first && result.known == expected.known && result.value == expected.value,
              "CBW partial bits equal the intersection of all concrete completions");
    }
    for (unsigned value = 0; value < 65536; ++value)
        for (bool mode64 : {false, true})
        {
            Word source{UINT64_MAX, (initial & ~UINT64_C(0xffff)) | value};
            Word low = source, high{UINT64_MAX, initial};
            sign_extend_accumulator(low, low, 16, false, mode64);
            sign_extend_accumulator(high, source, 16, true, mode64);
            const int signed_word = value < 32768 ? int(value) : int(value) - 65536;
            const uint64_t expected_low =
                uint32_t(signed_word) | (mode64 ? 0 : (initial & ~UINT64_C(0xffffffff)));
            const uint64_t expected_high =
                (initial & ~UINT64_C(0xffff)) | (signed_word < 0 ? UINT64_C(0xffff) : 0);
            check(low.known == UINT64_MAX && low.value == expected_low &&
                      high.known == UINT64_MAX && high.value == expected_high &&
                      source.value == ((initial & ~UINT64_C(0xffff)) | value),
                  "CWDE and CWD exhaust signed words, aliases and preserved register slices");
        }
    for (unsigned bits : {16u, 32u, 64u})
        for (unsigned sign_state = 0; sign_state < 3; ++sign_state)
            for (bool mode64 : {false, true})
            {
                const uint64_t sign = uint64_t{1} << (bits - 1);
                Word source{sign_state ? sign : 0, sign_state == 2 ? sign : 0};
                Word high{UINT64_MAX, initial};
                sign_extend_accumulator(high, source, bits, true, mode64);
                const uint64_t upper_zero = mode64 && bits == 32 ? ~mask(32) : 0;
                const uint64_t expected_known = ~mask(bits) | (sign_state ? mask(bits) : 0);
                check(high.known == expected_known &&
                          high.value ==
                              (((initial & ~mask(bits)) | (sign_state == 2 ? mask(bits) : 0)) &
                               ~upper_zero),
                      "high-half extension needs only the sign bit and models EDX zero extension");
                if (bits == 32)
                {
                    Word low = source;
                    sign_extend_accumulator(low, low, 32, false, true);
                    check(low.known == (source.known | (sign_state ? ~mask(32) : 0)) &&
                              low.value == (source.value | (sign_state == 2 ? ~mask(32) : 0)),
                          "CDQE preserves partial low bits and extends only a known sign");
                }
            }
    std::puts("Accumulator extension partial bytes: 6561; signed words: 65536 per mode");
}

std::pair<uint64_t, uint64_t> product_oracle(unsigned width, bool is_signed, uint64_t a, uint64_t b)
{
    const uint64_t m = mask(width), sign = uint64_t{1} << (width - 1);
    a &= m;
    b &= m;
    const bool negative = is_signed && ((a & sign) != 0) != ((b & sign) != 0);
    if (is_signed && (a & sign))
        a = (~a + 1) & m;
    if (is_signed && (b & sign))
        b = (~b + 1) & m;
    std::array<bool, 128> bits{};
    // Independently add shifted magnitude bits, then negate the entire 2w-bit
    // vector when needed. No word products or high-half correction formula.
    for (unsigned i = 0; i < width; ++i)
        if ((b >> i) & 1)
        {
            bool carry = false;
            for (unsigned j = i; j < 2 * width; ++j)
            {
                const unsigned sum = unsigned(bits[j]) + unsigned(carry) +
                                     unsigned(j - i < width && ((a >> (j - i)) & 1));
                bits[j] = sum & 1;
                carry = sum > 1;
            }
        }
    if (negative)
    {
        bool carry = true;
        for (unsigned j = 0; j < 2 * width; ++j)
        {
            const unsigned sum = unsigned(!bits[j]) + unsigned(carry);
            bits[j] = sum & 1;
            carry = sum > 1;
        }
    }
    uint64_t low = 0, high = 0;
    for (unsigned j = 0; j < width; ++j)
    {
        low |= uint64_t(bits[j]) << j;
        high |= uint64_t(bits[width + j]) << j;
    }
    return {low, high};
}

void multiply_regressions()
{
    size_t byte_cases = 0, wide_cases = 0, flag_cases = 0;
    const auto compare = [](unsigned width, bool is_signed, uint64_t a, uint64_t b, Flags initial)
    {
        const auto expected = product_oracle(width, is_signed, a, b);
        const bool overflow =
            is_signed ? expected.second != ((expected.first >> (width - 1)) ? mask(width) : 0)
                      : expected.second != 0;
        const Product result = multiply(width, is_signed, a, b, initial);
        check(result.low == expected.first && result.high == expected.second &&
                  initial.known == (CF | OF) && initial.value == (overflow ? (CF | OF) : 0),
              "full multiply agrees with independent bit-serial signed/unsigned oracle");
    };
    for (bool is_signed : {false, true})
        for (unsigned a = 0; a < 256; ++a)
            for (unsigned b = 0; b < 256; ++b)
            {
                compare(8, is_signed, a, b, Flags{ALL, uint8_t((a ^ b) & ALL)});
                ++byte_cases;
            }
    constexpr uint64_t values[] = {0,
                                   1,
                                   127,
                                   128,
                                   255,
                                   32767,
                                   32768,
                                   65535,
                                   UINT64_C(0x7fffffff),
                                   UINT64_C(0x80000000),
                                   UINT64_C(0xffffffff),
                                   UINT64_C(0x7fffffffffffffff),
                                   UINT64_C(0x8000000000000000),
                                   UINT64_MAX,
                                   UINT64_C(0x123456789abcdef0)};
    for (unsigned width : {16u, 32u, 64u})
        for (bool is_signed : {false, true})
            for (uint64_t a : values)
                for (uint64_t b : values)
                {
                    compare(width, is_signed, a, b, Flags{ALL, ALL});
                    ++wide_cases;
                }
    for (unsigned profile = 0; profile < 729; ++profile)
        for (unsigned width : {8u, 16u, 32u, 64u})
            for (bool is_signed : {false, true})
            {
                Flags flags;
                unsigned encoded = profile;
                for (unsigned bit = 0; bit < 6; ++bit, encoded /= 3)
                    if (encoded % 3)
                        flags.set(uint8_t(1u << bit), encoded % 3 == 2);
                compare(width, is_signed, mask(width), 2, flags);
                ++flag_cases;
                const Product zero = multiply(width, is_signed, {}, 0, flags);
                check(zero.low == 0 && zero.high == 0 && flags.known == (CF | OF) && !flags.value,
                      "unknown source times zero has exact halves and cleared overflow");
                const Product one = multiply(width, is_signed, 1, {}, flags);
                check(!one.low &&
                          one.high == (is_signed ? std::nullopt : std::optional<uint64_t>{0}) &&
                          flags.known == (CF | OF) && !flags.value,
                      "unknown source times one retains exact overflow and unsigned high half");
                const Product unknown = multiply(width, is_signed, {}, 3, flags);
                check(!unknown.low && !unknown.high && !flags.known && !flags.value,
                      "unknown nontrivial product leaves all status bits and halves unknown");
            }
    Flags flags{ALL, ALL};
    const Product invalid = multiply(0, false, 0, 0, flags);
    check(!invalid.low && !invalid.high && !flags.known, "invalid multiply width abstains");
    std::printf("multiply bytes: %zu; wide pairs: %zu; partial flag profiles: %zu\n", byte_cases,
                wide_cases, flag_cases);
}

std::pair<uint64_t, Flags> rotate_oracle(Operation op, unsigned width, uint64_t input,
                                         unsigned raw_count, Flags flags)
{
    const bool through = op == Operation::carry_left || op == Operation::carry_right;
    const bool to_left = op == Operation::rotate_left || op == Operation::carry_left;
    const unsigned count = raw_count & (width == 64 ? 63 : 31);
    if (count == 0)
        return {input & mask(width), flags};
    const unsigned length = width + unsigned(through);
    std::array<bool, 65> bits{};
    for (unsigned i = 0; i < width; ++i)
        bits[i] = (input >> i) & 1;
    if (through)
        bits[width] = *flags.get(CF);
    // Independently rotate an explicit bit vector, avoiding the implementation's
    // word-shift formulas and its special wraparound terms.
    for (unsigned step = 0; step < count % length; ++step)
    {
        const auto old = bits;
        for (unsigned i = 0; i < length; ++i)
            bits[i] = old[(i + (to_left ? length - 1 : 1)) % length];
    }
    uint64_t result = 0;
    for (unsigned i = 0; i < width; ++i)
        result |= uint64_t(bits[i]) << i;
    flags.set(CF, through ? bits[width] : bits[to_left ? 0 : width - 1]);
    flags.forget(OF);
    if (count == 1)
        flags.set(OF, bits[width - 1] != (to_left ? *flags.get(CF) : bits[width - 2]));
    return {result, flags};
}

void rotate_regressions()
{
    constexpr Operation ops[] = {Operation::rotate_left, Operation::rotate_right,
                                 Operation::carry_left, Operation::carry_right};
    size_t cases = 0;
    for (unsigned width : {8u, 16u, 32u, 64u})
        for (Operation op : ops)
            for (unsigned profile = 0; profile < 729; ++profile)
                for (unsigned count : {0u, 1u, 2u, 8u, 9u, 17u, 32u, 64u, 255u})
                {
                    Flags initial;
                    unsigned encoded = profile;
                    for (unsigned bit = 0; bit < 6; ++bit, encoded /= 3)
                        if (encoded % 3)
                            initial.set(uint8_t(1u << bit), encoded % 3 == 2);
                    const uint64_t input = (uint64_t{1} << (width - 1)) | 5;
                    Flags expected;
                    std::optional<uint64_t> expected_value;
                    bool first = true;
                    for (bool carry : {false, true})
                    {
                        if (initial.get(CF) && *initial.get(CF) != carry)
                            continue;
                        Flags concrete = initial;
                        concrete.set(CF, carry);
                        const auto result = rotate_oracle(op, width, input, count, concrete);
                        if (first)
                        {
                            expected = result.second;
                            expected_value = result.first;
                        }
                        else
                        {
                            expected.join(result.second);
                            if (expected_value != result.first)
                                expected_value.reset();
                        }
                        first = false;
                    }
                    Flags actual = initial;
                    const auto result = transfer(op, width, input, count, false, actual);
                    check(result == expected_value && actual.known == expected.known &&
                              actual.value == expected.value,
                          "all partial flag profiles agree with explicit rotate bit vectors");
                    ++cases;
                }
    for (unsigned width : {8u, 16u, 32u, 64u})
        for (Operation op : ops)
        {
            Flags flags{ALL, ALL};
            transfer(op, width, {}, {}, false, flags);
            check(flags.known == (ALL & ~(CF | OF)) && flags.value == flags.known,
                  "unknown rotate operand/count retains exactly SF/ZF/AF/PF");
            flags = {ALL, ALL};
            transfer(op, width, {}, 0, false, flags);
            check(flags.known == ALL && flags.value == ALL,
                  "masked-zero rotate preserves flags without a known operand");
            flags = {ALL, 0};
            const auto zero = transfer(op, width, 0, {}, false, flags);
            check(zero == 0 && flags.get(CF) == false && !flags.get(OF),
                  "zero word and matching carry remain invariant for an unknown count");
        }
    std::printf("rotate partial profiles: %zu; unknown-count and operand controls passed\n", cases);
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

void alternative_condition_regressions()
{
    size_t cases = 0;
    const auto identity = [](Flags flags) { return flags; };
    for (unsigned profile = 0; profile < 729; ++profile)
    {
        Flags partial;
        unsigned encoded = profile;
        for (unsigned bit = 0; bit < 6; ++bit, encoded /= 3)
            if (encoded % 3)
                partial.set(uint8_t(1u << bit), encoded % 3 == 2);
        for (unsigned other = 0; other < 64; ++other)
            for (unsigned code = 0; code < 16; ++code)
            {
                bool yes = false, no = false;
                for (unsigned concrete = 0; concrete < 64; ++concrete)
                    if ((concrete & partial.known) == partial.value || concrete == other)
                        (condition_oracle(code, concrete) ? yes : no) = true;
                const std::array<Flags, 2> inputs = {partial, Flags{ALL, uint8_t(other)}};
                const auto result = evaluate_alternatives(Condition(code), inputs, identity);
                check(result.has_value() == (yes != no) && (!result || *result == yes),
                      "universal alternative condition matches independent concrete union");
                ++cases;
            }
    }
    const std::array<Flags, 2> disjunction = {Flags{ALL, CF}, Flags{ALL, ZF}};
    Flags common = disjunction[0];
    common.join(disjunction[1]);
    check(!evaluate(Condition::below_equal, common) &&
              evaluate_alternatives(Condition::below_equal, disjunction, identity) == true,
          "a universal condition can retain a relation lost by individual flag joins");
    check(!evaluate_alternatives(Condition::equal, std::array<Flags, 0>{}, identity),
          "empty inputs cannot produce a vacuous branch fact");
    check(!evaluate_alternatives(Condition(16), disjunction, identity),
          "invalid condition codes cannot justify edge filtering");
    FlowState first;
    first.word.write(32, 0, 0, true);
    first.flags = {ALL, CF};
    chernobog::BoundedAlternatives<FlowState> domain(first);
    const auto flags_at = [](const FlowState &state) { return state.flags; };
    for (unsigned i = 1; i < 8; ++i)
    {
        FlowState next;
        next.word.write(32, 0, i, true);
        next.flags = {ALL, uint8_t(i & 1 ? ZF : CF)};
        domain.join(chernobog::BoundedAlternatives<FlowState>(next));
    }
    check(!domain.widened() &&
              evaluate_alternatives(Condition::below_equal, domain.states(), flags_at) == true &&
              evaluate_alternatives(Condition::above, domain.states(), flags_at) == false,
          "eight distinct states retain universal true and false compound predicates");
    FlowState ninth;
    ninth.word.write(32, 0, 8, true);
    ninth.flags = {ALL, CF};
    domain.join(chernobog::BoundedAlternatives<FlowState>(ninth));
    check(domain.widened() &&
              !evaluate_alternatives(Condition::below_equal, domain.states(), flags_at),
          "nine-state widening conservatively loses a universally true relation");
    std::printf(
        "alternative condition unions: %zu; correlated, empty and invalid controls passed\n",
        cases);
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
    repeated_memory_regressions();
    repeat_compare_early_stop_regressions();
    repeat_compare_bounded_regressions();
    const uint64_t repeat_assertions = assertions;
    dataflow_regressions();
    backward_slice_regressions();
    alternative_regressions();
    explicit_entry_regressions();
    status_ah_regressions();
    accumulator_extension_regressions();
    multiply_regressions();
    rotate_regressions();
    exhaustive_arithmetic();
    exhaustive_conditions();
    alternative_condition_regressions();
    boundaries();
    mapping_counterexamples();
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    native_shift_and_partial_writes();
#endif
    if (failures)
        std::fprintf(stderr, "%d failures\n", failures);
    std::printf("{\"repeat_assertions\": %llu, \"native_repeat_cases\": %llu, \"passed\": %s}\n",
                static_cast<unsigned long long>(repeat_assertions),
                static_cast<unsigned long long>(native_repeat_cases), failures ? "false" : "true");
    return failures ? 1 : 0;
}
