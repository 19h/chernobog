#include <stdio.h>

extern int rep_lods_two_forward(int input);
extern int rep_lods_three_reverse(int input);
extern int rep_lods_unknown_df_forward(int input);
extern int rep_lods_unknown_df_reverse(int input);
extern int rep_lods_ambiguous_count(int input);
extern int rep_lods_eight(int input);
extern int rep_lods_two_word(int input);
extern int rep_lods_two_qword(int input);
extern int rep_lods_two_dword_value(int input);
extern int rep_lods_nine(int input);

int main(void)
{
    unsigned checks = 0;
    for (int input = 0; input < 256; ++input)
    {
        if (rep_lods_two_forward(input) != 73 || rep_lods_three_reverse(input) != 73 ||
            rep_lods_unknown_df_forward(input) != 73 || rep_lods_unknown_df_reverse(input) != 73 ||
            rep_lods_ambiguous_count(input) != 73 || rep_lods_eight(input) != 73 ||
            rep_lods_two_word(input) != 73 || rep_lods_two_qword(input) != 73 ||
            rep_lods_nine(input) != 73 || rep_lods_two_dword_value(input) != 1)
            return 1;
        checks += 10;
    }
    printf("{\"passed\":true,\"checks\":%u}\n", checks);
    return 0;
}
