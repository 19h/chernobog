// Execute the independent x64 fixture; capture SP, dead-slot bytes, and flags.
// Compile with -mno-red-zone because the inline assembly performs real CALLs.
#include <cstdint>
#include <cstdio>

extern "C" int gp_call();
extern "C" int gp_adjust();

struct Effects
{
    uint64_t result, before_sp, after_sp, slot, before_flags, after_flags;
};

static Effects execute(int (*function)())
{
    Effects e{};
    asm volatile("movq %%rsp, %[before]\n\t"
                 "pushfq\n\tpopq %[before_flags]\n\t"
                 "callq *%[function]\n\t"
                 "movq %%rsp, %[after]\n\t"
                 "movq -16(%%rsp), %[slot]\n\t"
                 "pushfq\n\tpopq %[after_flags]"
                 : [result] "=&a"(e.result), [before] "=&r"(e.before_sp), [after] "=&r"(e.after_sp),
                   [slot] "=&r"(e.slot), [before_flags] "=&r"(e.before_flags),
                   [after_flags] "=&r"(e.after_flags)
                 : [function] "r"(function)
                 : "r11", "cc", "memory");
    return e;
}

static uint64_t add_three_flags(uint64_t value)
{
    const uint64_t sum = value + 3;
    unsigned ones = 0;
    for (unsigned bit = 0; bit < 8; ++bit)
        ones += unsigned((sum >> bit) & 1);
    return uint64_t(sum < value) | (uint64_t((ones & 1) == 0) << 2) |
           (uint64_t((value & 15) + 3 > 15) << 4) | (uint64_t(sum == 0) << 6) | ((sum >> 63) << 7) |
           (((~(value ^ 3) & (value ^ sum)) >> 63) << 11);
}

int main()
{
    const auto call = execute(gp_call);
    const auto adjust = execute(gp_adjust);
    const uint64_t call_pc = uint64_t(reinterpret_cast<uintptr_t>(gp_call)) + 5;
    const uint64_t adjust_pc = uint64_t(reinterpret_cast<uintptr_t>(gp_adjust)) + 5;
    constexpr uint64_t status_flags = 0x8d5;
    const bool ok = call.result == 7 && adjust.result == 7 && call.before_sp == call.after_sp &&
                    adjust.before_sp == adjust.after_sp && call.slot == call_pc &&
                    adjust.slot == adjust_pc + 3 &&
                    ((call.before_flags ^ call.after_flags) & status_flags) == 0 &&
                    (adjust.after_flags & status_flags) == add_three_flags(adjust_pc);
    std::puts(ok ? "PASS call_context_effects=2 result,SP,memory,defined_flags"
                 : "FAIL call-context architectural effects");
    return ok ? 0 : 1;
}
