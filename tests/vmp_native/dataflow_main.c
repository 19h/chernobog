#include <stdio.h>
#include <stdint.h>

extern int df_equal(int), df_different(int), df_flags(int), df_direction(int), df_loop(int),
    df_loop_changes(int), df_stack(int), df_stack_changes(int), df_jump(int), df_target(int),
    df_target_changes(int), df_direction_status(int);
extern int df_flags_saved(int), df_flags_literal(int), df_flags_overwrite(int),
    df_flags_dynamic(int), df_flags_full(int), df_flags_status(int);
extern int df_stack_top_transfer(int), df_stack_top_overwrite(int);
extern int df_stack_top_dynamic(int);
extern int df_memory_store_transfer(int), df_memory_disjoint_store(int);
extern int df_memory_overlapping_store(int), df_memory_unknown_alias(int, void *);
extern int df_memory_conflicting_store(int);
extern int df_memory_initial_word(int), df_memory_equal_stores(int);
extern int df_memory_direct_store(int);
extern int df_memory_split_store(int), df_memory_known_byte_overwrite(int);
extern int df_memory_repaired_byte(int), df_memory_missing_byte(int);
extern int df_memory_conflicting_byte(int);
extern int df_memory_stack_round_trip(int);
extern int df_memory_xchg_store(int), df_memory_xchg_partial(int), df_memory_xchg_load(int);
extern int df_memory_xchg_byte(int);
extern int df_memory_xchg_unknown_source(int, int (*)(void));
extern int df_memory_mov_load(int), df_memory_mov_load_byte(int);
extern int df_memory_mov_load_initial(int), df_memory_mov_load_alias(int, void *);
extern int df_memory_movzx_byte(int), df_memory_movsx_byte(int);
extern int df_memory_movzx_word(int), df_memory_movsx_word(int);
extern int df_memory_movzx_initial(int), df_memory_movzx_alias(int, void *);
extern int df_memory_movsx_negative(int), df_memory_movsx_initial_negative(int);
extern int df_memory_movsxd_negative(int), df_memory_movsxd_initial_negative(int);
extern int df_memory_movsx_word_negative(int), df_memory_movsx_initial_word_negative(int);
extern int df_memory_alu_add(int), df_memory_alu_xor_byte(int), df_memory_alu_source(int);
extern int df_memory_alu_initial(int), df_memory_alu_alias(int, void *);
extern int df_memory_alu_compare(int);
extern int df_memory_alu_rmw_initial(int), df_memory_alu_rmw_alias(int, void *);
extern int df_memory_alu_compare_initial(int);
extern int df_memory_alu_flags(int), df_memory_alu_flags_initial(int);
extern int df_rep_movs_cf(int), df_rep_movs_zf(int), df_movs_plain_cf(int);
extern int df_cmps_flags_changed(int);
extern int df_rep_stos_cf(int), df_lods_plain_cf(int), df_rep_lods_zf(int);
extern int df_scas_flags_changed(int), df_stos_alias(int, void *);
extern int df_stos_register_target(int), df_lods_memory_target(int);
extern int df_rep_movs_alias(int, void *);
extern int df_rep_movs_register_target(int), df_movs_plain_count_target(int);
extern int df_rep_movs_count_unknown(int);
extern int df_memory_target(void);

int main(void)
{
    unsigned checks = 0;
    uint64_t disjoint = 0;
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
            df_memory_stack_round_trip(input) != 7 || df_memory_xchg_store(input) != 7 ||
            df_memory_xchg_partial(input) != 7 || df_memory_xchg_load(input) != 7 ||
            df_memory_xchg_byte(input) != 7 ||
            df_memory_xchg_unknown_source(input, df_memory_target) != 7 ||
            df_memory_mov_load(input) != 7 || df_memory_mov_load_byte(input) != 7 ||
            df_memory_mov_load_initial(input) != 7 ||
            df_memory_mov_load_alias(input, &disjoint) != 7 || df_memory_movzx_byte(input) != 7 ||
            df_memory_movsx_byte(input) != 7 || df_memory_movzx_initial(input) != 7 ||
            df_memory_movzx_alias(input, &disjoint) != 7 || df_memory_movsx_negative(input) != 1 ||
            df_memory_movsx_initial_negative(input) != 1 || df_memory_movsxd_negative(input) != 1 ||
            df_memory_movsxd_initial_negative(input) != 1 || df_memory_movzx_word(input) != 7 ||
            df_memory_movsx_word(input) != 7 || df_memory_movsx_word_negative(input) != 1 ||
            df_memory_movsx_initial_word_negative(input) != 1 || df_memory_alu_add(input) != 7 ||
            df_memory_alu_xor_byte(input) != 7 || df_memory_alu_source(input) != 7 ||
            df_memory_alu_initial(input) != 7 || df_memory_alu_alias(input, &disjoint) != 7 ||
            df_memory_alu_compare(input) != 1 || df_memory_alu_rmw_initial(input) != 7 ||
            df_memory_alu_rmw_alias(input, &disjoint) != 7 ||
            df_memory_alu_compare_initial(input) != 1 || df_memory_alu_flags(input) != 1 ||
            df_memory_alu_flags_initial(input) != 1 || df_rep_movs_cf(input) != 1 ||
            df_rep_movs_zf(input) != 1 || df_movs_plain_cf(input) != 1 ||
            df_cmps_flags_changed(input) != 0 || df_rep_movs_alias(input, &disjoint) != 7 ||
            df_rep_movs_register_target(input) != 7 || df_movs_plain_count_target(input) != 7 ||
            df_rep_movs_count_unknown(input) != 7 || df_rep_stos_cf(input) != 1 ||
            df_lods_plain_cf(input) != 1 || df_rep_lods_zf(input) != 1 ||
            df_scas_flags_changed(input) != 0 || df_stos_alias(input, &disjoint) != 7 ||
            df_stos_register_target(input) != 7 || df_lods_memory_target(input) != 7)
            return 1;
        checks += 80;
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
