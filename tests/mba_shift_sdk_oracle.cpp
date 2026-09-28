#include <hexrays.hpp>

#include <cstdint>
#include <cstdio>
#include <initializer_list>

int main()
{
    for (const int width : {1, 2, 4, 8})
    {
        const int bits = width * 8;
        const uint64_t mask = width == 8 ? UINT64_MAX : (uint64_t(1) << bits) - 1;
        const uint64_t values[] = {0, 1, uint64_t(1) << (bits - 1), mask};
        const int counts[] = {0, bits - 1, bits, 255};
        for (const uint64_t value : values)
        {
            for (const int count : counts)
            {
                const intval64_t left(value, width), right(count, 1);
                const uint64_t shl = (left << right).val;
                const uint64_t shr = (left >> right).val;
                const uint64_t sar = left.sar(right).val;
                std::printf(
                    "%d,%llu,%d,%llu,%llu,%llu\n", width, static_cast<unsigned long long>(value),
                    count, static_cast<unsigned long long>(shl),
                    static_cast<unsigned long long>(shr), static_cast<unsigned long long>(sar));
            }
        }
    }
}
