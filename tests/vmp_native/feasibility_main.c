#include <stdio.h>

extern int bf_o_false(int), bf_o_true(int), bf_o_dynamic(int);
extern int bf_no_false(int), bf_no_true(int), bf_no_dynamic(int);
extern int bf_b_false(int), bf_b_true(int), bf_b_dynamic(int);
extern int bf_ae_false(int), bf_ae_true(int), bf_ae_dynamic(int);
extern int bf_e_false(int), bf_e_true(int), bf_e_dynamic(int);
extern int bf_ne_false(int), bf_ne_true(int), bf_ne_dynamic(int);
extern int bf_be_false(int), bf_be_true(int), bf_be_dynamic(int);
extern int bf_a_false(int), bf_a_true(int), bf_a_dynamic(int);
extern int bf_s_false(int), bf_s_true(int), bf_s_dynamic(int);
extern int bf_ns_false(int), bf_ns_true(int), bf_ns_dynamic(int);
extern int bf_p_false(int), bf_p_true(int), bf_p_dynamic(int);
extern int bf_np_false(int), bf_np_true(int), bf_np_dynamic(int);
extern int bf_l_false(int), bf_l_true(int), bf_l_dynamic(int);
extern int bf_ge_false(int), bf_ge_true(int), bf_ge_dynamic(int);
extern int bf_le_false(int), bf_le_true(int), bf_le_dynamic(int);
extern int bf_g_false(int), bf_g_true(int), bf_g_dynamic(int);
extern int bf_memory_false(int), bf_memory_true(int), bf_stack_false(int), bf_stack_true(int),
    bf_compound(int), bf_compound_dynamic(int), bf_loop(int);

static int condition(unsigned kind, unsigned bits)
{
    const int c = bits & 1, p = bits & 2, z = bits & 8, s = bits & 16, o = bits & 32;
    switch (kind)
    {
    case 0:
        return !!o;
    case 1:
        return !o;
    case 2:
        return !!c;
    case 3:
        return !c;
    case 4:
        return !!z;
    case 5:
        return !z;
    case 6:
        return c || z;
    case 7:
        return !c && !z;
    case 8:
        return !!s;
    case 9:
        return !s;
    case 10:
        return !!p;
    case 11:
        return !p;
    case 12:
        return !!s != !!o;
    case 13:
        return !!s == !!o;
    case 14:
        return z || (!!s != !!o);
    case 15:
        return !z && (!!s == !!o);
    }
    return -1;
}

int main(void)
{
#define PAIR(name) bf_##name##_false, bf_##name##_true,
    int (*fixed[])(int) = {PAIR(o) PAIR(no) PAIR(b) PAIR(ae) PAIR(e) PAIR(ne) PAIR(be) PAIR(a)
                               PAIR(s) PAIR(ns) PAIR(p) PAIR(np) PAIR(l) PAIR(ge) PAIR(le) PAIR(g)
                                   bf_memory_false,
                           bf_memory_true, bf_stack_false, bf_stack_true, bf_compound};
#undef PAIR
    int (*dynamic[])(int) = {bf_o_dynamic, bf_no_dynamic, bf_b_dynamic,  bf_ae_dynamic,
                             bf_e_dynamic, bf_ne_dynamic, bf_be_dynamic, bf_a_dynamic,
                             bf_s_dynamic, bf_ns_dynamic, bf_p_dynamic,  bf_np_dynamic,
                             bf_l_dynamic, bf_ge_dynamic, bf_le_dynamic, bf_g_dynamic};
    unsigned checks = 0;
    for (int input = -256; input <= 255; ++input)
    {
        for (unsigned i = 0; i < sizeof(fixed) / sizeof(fixed[0]); ++i)
        {
            if (fixed[i](input) != 7)
                return 1;
            ++checks;
        }
        if (bf_compound_dynamic(input) != (input ? 7 : 8) || bf_loop(input) != 8)
            return 2;
        checks += 2;
    }
    for (unsigned profile = 0; profile < 64; ++profile)
    {
        const unsigned encoded = (profile & 1) | ((profile & 2) << 1) | ((profile & 4) << 2) |
                                 ((profile & 8) << 3) | ((profile & 16) << 3) |
                                 ((profile & 32) << 6) | 2;
        for (unsigned kind = 0; kind < 16; ++kind)
        {
            if (dynamic[kind](encoded) != (condition(kind, profile) ? 7 : 8))
                return 3;
            ++checks;
        }
    }
    printf("{\"passed\":true,\"checks\":%u}\n", checks);
    return 0;
}
