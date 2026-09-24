#include <stdio.h>

extern int df_equal(int), df_different(int), df_flags(int), df_direction(int), df_loop(int),
    df_loop_changes(int), df_stack(int), df_stack_changes(int), df_jump(int), df_target(int),
    df_target_changes(int), df_direction_status(int);
extern int df_flags_saved(int), df_flags_literal(int), df_flags_overwrite(int),
    df_flags_dynamic(int), df_flags_full(int), df_flags_status(int);
extern int df_stack_top_transfer(int), df_stack_top_overwrite(int);
extern int df_stack_top_dynamic(int);
extern int df_memory_store_transfer(int), df_memory_disjoint_store(int);
extern int df_memory_overlapping_store(int), df_memory_unknown_alias(int, int *);
extern int df_memory_conflicting_store(int);
extern int df_memory_initial_word(int), df_memory_equal_stores(int);
extern int df_memory_direct_store(int);
extern int df_memory_split_store(int), df_memory_known_byte_overwrite(int);
extern int df_memory_repaired_byte(int), df_memory_missing_byte(int);
extern int df_memory_conflicting_byte(int);
extern int df_memory_stack_round_trip(int);

int main(void)
{
    unsigned checks = 0;
    int disjoint = 0;
    for (int input = 0; input < 256; ++input)
    {
        if (df_equal(input) != 1 || df_different(input) != (input == 0) || df_flags(input) != 1 ||
            df_direction(input) != 1 || df_direction_status(input) != 0 || df_stack(input) != 1 ||
            df_stack_changes(input) != (input == 0) || df_jump(input) != 1 ||
            df_target(input) != 7 || df_target_changes(input) != (input == 0 ? 9 : 7) ||
            df_flags_saved(input) != 1 || df_flags_full(input) != 1 ||
            df_flags_status(input) != 0 || df_flags_literal(input) != 1 ||
            df_flags_overwrite(input) != 0 || df_flags_dynamic(input) != (input & 1) ||
            df_stack_top_transfer(input) != 7 || df_stack_top_overwrite(input) != 8 ||
            df_stack_top_dynamic(input) != (input == 0 ? 7 : 8) ||
            df_memory_store_transfer(input) != 7 || df_memory_disjoint_store(input) != 7 ||
            df_memory_overlapping_store(input) != 7 ||
            df_memory_unknown_alias(input, &disjoint) != 7 ||
            df_memory_conflicting_store(input) != (input == 0 ? 7 : 8) ||
            df_memory_initial_word(input) != 7 || df_memory_equal_stores(input) != 7 ||
            df_memory_direct_store(input) != 7 || df_memory_split_store(input) != 7 ||
            df_memory_known_byte_overwrite(input) != 7 || df_memory_repaired_byte(input) != 7 ||
            df_memory_missing_byte(input) != 7 ||
            df_memory_conflicting_byte(input) != (input == 0 ? 7 : 8) ||
            df_memory_stack_round_trip(input) != 7)
            return 1;
        checks += 33;
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
