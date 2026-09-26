#include <stdint.h>
#include <stdio.h>

extern int df_stack_top_dynamic(int), df_memory_conflicting_byte(int),
    df_memory_conflicting_store(int);
extern int jc_register(int), jc_memory(int), jc_stack(int), jc_dynamic(int), jc_cap(int);
extern int cv_partial(int, int (*)(void)), cv_alias(int, uint64_t *), cv_multi_address(int),
    cv_infeasible(int), cv_call(int), cv_nine(void);

int main(void)
{
    unsigned checks = 0;
    uint64_t disjoint = 0;
    for (int input = -256; input <= 255; ++input)
    {
        const int dynamic = input ? 8 : 7;
        if (df_stack_top_dynamic(input) != dynamic ||
            df_memory_conflicting_byte(input) != dynamic ||
            df_memory_conflicting_store(input) != dynamic || jc_register(input) != 7 ||
            jc_memory(input) != 7 || jc_stack(input) != 7 || jc_dynamic(input) != dynamic ||
            jc_cap(input) != 7 || cv_partial(input, cv_nine) != (input ? 9 : 7) ||
            cv_alias(input, &disjoint) != 7 || cv_multi_address(input) != dynamic ||
            cv_infeasible(input) != 7 || cv_call(input) != 7)
            return 1;
        checks += 13;
    }
    printf("{\"passed\":true,\"checks\":%u}\n", checks);
    return 0;
}
