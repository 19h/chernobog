#include <stdio.h>

extern int od_equal(int), od_conflict(int), od_budget64(int), od_budget65(int),
    od_adjacent_root(int), od_adjacent_external(int), od_call_root(int);
extern int df_equal(int), df_loop(int), df_loop_changes(int), df_target(int),
    df_target_changes(int);

static int expect(const char *name, int actual, int expected, unsigned *checks)
{
    if (actual != expected)
    {
        printf("{\"checks\":%u,\"passed\":false,\"case\":\"%s\",\"actual\":%d,\"expected\":%d}\n",
               *checks, name, actual, expected);
        return 0;
    }
    ++*checks;
    return 1;
}

int main(void)
{
    unsigned checks = 0;
#ifdef OWNERLESS_CORRUPT_EXPECTATION
    const int equal_expected = 0;
#else
    const int equal_expected = 1;
#endif
    for (int input = 0; input < 256; ++input)
    {
        if (!expect("od_equal", od_equal(input), equal_expected, &checks) ||
            !expect("od_conflict", od_conflict(input), input != 0, &checks) ||
            !expect("od_budget64", od_budget64(input), 1, &checks) ||
            !expect("od_budget65", od_budget65(input), 1, &checks) ||
            !expect("od_adjacent_root", od_adjacent_root(input), 1, &checks) ||
            !expect("od_adjacent_external", od_adjacent_external(input), 0, &checks) ||
            !expect("od_call_root", od_call_root(input), 0, &checks) ||
            !expect("df_equal", df_equal(input), 1, &checks) ||
            !expect("df_target", df_target(input), 7, &checks) ||
            !expect("df_target_changes", df_target_changes(input), input == 0 ? 9 : 7, &checks))
            return 1;
        /* Zero would take 2^32 DEC iterations and is outside this bounded oracle. */
        if (input > 0 &&
            (!expect("df_loop", df_loop(input), 1, &checks) ||
             !expect("df_loop_changes", df_loop_changes(input), (input & 1) == 0, &checks)))
            return 1;
    }
    printf("{\"checks\":%u,\"passed\":true}\n", checks);
    return 0;
}
