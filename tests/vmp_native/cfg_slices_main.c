#include <stdint.h>
#include <stdio.h>

extern int slice_equal192(int), slice_different192(int), slice_flags192(int), slice_loop192(int),
    slice_cut192(int), slice_target192(int), slice_memory192(int), slice_inventory4096(int),
    slice_inventory4097(int), slice_destination(int), slice_prefix8(int);
extern uintptr_t slice_cell;

int main(void)
{
    uint32_t random_state = UINT32_C(0x713ec0a5);
    unsigned checks = 0;
    for (unsigned i = 0; i < 1024; ++i)
    {
        random_state ^= random_state << 13;
        random_state ^= random_state >> 17;
        random_state ^= random_state << 5;
        const int input = i < 256 ? (int)i : (int)(random_state & UINT32_C(0x7fffffff));
        if (slice_equal192(input) != 1 || slice_different192(input) != (input != 0) ||
            slice_flags192(input) != 1 || slice_cut192(input) != 1 || slice_target192(input) != 7 ||
            slice_memory192(input) != 7 || slice_cell != (uintptr_t)&slice_destination ||
            slice_inventory4096(input) != 1 || slice_inventory4097(input) != 1 ||
            slice_prefix8(input) != 1)
            return 1;
        checks += 10;
        if (slice_loop192((input & 31) + 1) != 1)
            return 2;
        ++checks;
    }
    printf("{\"passed\":true,\"checks\":%u,\"seed\":\"0x713ec0a5\"}\n", checks);
    return 0;
}
