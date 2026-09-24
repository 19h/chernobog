#include <stdio.h>

extern int df_equal(int), df_different(int), df_flags(int), df_direction(int), df_loop(int),
    df_loop_changes(int), df_stack(int), df_stack_changes(int), df_jump(int), df_target(int),
    df_target_changes(int), df_direction_status(int);

int main(void)
{
    unsigned checks = 0;
    for (int input = 0; input < 256; ++input)
    {
        if (df_equal(input) != 1 || df_different(input) != (input == 0) || df_flags(input) != 1 ||
            df_direction(input) != 1 || df_direction_status(input) != 0 || df_stack(input) != 1 ||
            df_stack_changes(input) != (input == 0) || df_jump(input) != 1 ||
            df_target(input) != 7 || df_target_changes(input) != (input == 0 ? 9 : 7))
            return 1;
        checks += 10;
        if (input > 0)
        {
            if (df_loop(input) != 1 || df_loop_changes(input) != ((input & 1) == 0))
                return 2;
            checks += 2;
        }
    }
    printf("{\"checks\":%u,\"passed\":true}\n", checks);
    return 0;
}
