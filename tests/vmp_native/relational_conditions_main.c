#include <stdio.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

extern int rc_be_true_branch(int);
extern int rc_be_true_branch_dynamic(int);
extern int rc_be_true_set(int);
extern int rc_be_true_set_dynamic(int);
extern int rc_be_true_move(int);
extern int rc_be_true_move_dynamic(int);
extern int rc_be_true_memory(int);
extern int rc_be_true_memory_dynamic(int);
extern int rc_a_false_branch(int);
extern int rc_a_false_branch_dynamic(int);
extern int rc_a_false_set(int);
extern int rc_a_false_set_dynamic(int);
extern int rc_a_false_move(int);
extern int rc_a_false_move_dynamic(int);
extern int rc_a_false_memory(int);
extern int rc_a_false_memory_dynamic(int);
extern int rc_l_true_branch(int);
extern int rc_l_true_branch_dynamic(int);
extern int rc_l_true_set(int);
extern int rc_l_true_set_dynamic(int);
extern int rc_l_true_move(int);
extern int rc_l_true_move_dynamic(int);
extern int rc_l_true_memory(int);
extern int rc_l_true_memory_dynamic(int);
extern int rc_l_false_branch(int);
extern int rc_l_false_branch_dynamic(int);
extern int rc_l_false_set(int);
extern int rc_l_false_set_dynamic(int);
extern int rc_l_false_move(int);
extern int rc_l_false_move_dynamic(int);
extern int rc_l_false_memory(int);
extern int rc_l_false_memory_dynamic(int);
extern int rc_ge_true_branch(int);
extern int rc_ge_true_branch_dynamic(int);
extern int rc_ge_true_set(int);
extern int rc_ge_true_set_dynamic(int);
extern int rc_ge_true_move(int);
extern int rc_ge_true_move_dynamic(int);
extern int rc_ge_true_memory(int);
extern int rc_ge_true_memory_dynamic(int);
extern int rc_ge_false_branch(int);
extern int rc_ge_false_branch_dynamic(int);
extern int rc_ge_false_set(int);
extern int rc_ge_false_set_dynamic(int);
extern int rc_ge_false_move(int);
extern int rc_ge_false_move_dynamic(int);
extern int rc_ge_false_memory(int);
extern int rc_ge_false_memory_dynamic(int);
extern int rc_le_true_branch(int);
extern int rc_le_true_branch_dynamic(int);
extern int rc_le_true_set(int);
extern int rc_le_true_set_dynamic(int);
extern int rc_le_true_move(int);
extern int rc_le_true_move_dynamic(int);
extern int rc_le_true_memory(int);
extern int rc_le_true_memory_dynamic(int);
extern int rc_le_false_branch(int);
extern int rc_le_false_branch_dynamic(int);
extern int rc_le_false_set(int);
extern int rc_le_false_set_dynamic(int);
extern int rc_le_false_move(int);
extern int rc_le_false_move_dynamic(int);
extern int rc_le_false_memory(int);
extern int rc_le_false_memory_dynamic(int);
extern int rc_g_true_branch(int);
extern int rc_g_true_branch_dynamic(int);
extern int rc_g_true_set(int);
extern int rc_g_true_set_dynamic(int);
extern int rc_g_true_move(int);
extern int rc_g_true_move_dynamic(int);
extern int rc_g_true_memory(int);
extern int rc_g_true_memory_dynamic(int);
extern int rc_g_false_branch(int);
extern int rc_g_false_branch_dynamic(int);
extern int rc_g_false_set(int);
extern int rc_g_false_set_dynamic(int);
extern int rc_g_false_move(int);
extern int rc_g_false_move_dynamic(int);
extern int rc_g_false_memory(int);
extern int rc_g_false_memory_dynamic(int);
extern int rc_cap(int);
extern int rc_lock_branch(int), rc_lock_set(int), rc_lock_move(int), rc_lock_memory(int);

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
    const struct
    {
        int (*function)(int);
        unsigned kind, condition, first, second;
    } cases[] = {
        {rc_be_true_branch, 0, 6, 1, 8},     {rc_be_true_branch_dynamic, 0, 6, 1, 0},
        {rc_be_true_set, 1, 6, 1, 8},        {rc_be_true_set_dynamic, 1, 6, 1, 0},
        {rc_be_true_move, 2, 6, 1, 8},       {rc_be_true_move_dynamic, 2, 6, 1, 0},
        {rc_be_true_memory, 3, 6, 1, 8},     {rc_be_true_memory_dynamic, 3, 6, 1, 0},
        {rc_a_false_branch, 0, 7, 1, 8},     {rc_a_false_branch_dynamic, 0, 7, 1, 0},
        {rc_a_false_set, 1, 7, 1, 8},        {rc_a_false_set_dynamic, 1, 7, 1, 0},
        {rc_a_false_move, 2, 7, 1, 8},       {rc_a_false_move_dynamic, 2, 7, 1, 0},
        {rc_a_false_memory, 3, 7, 1, 8},     {rc_a_false_memory_dynamic, 3, 7, 1, 0},
        {rc_l_true_branch, 0, 12, 16, 32},   {rc_l_true_branch_dynamic, 0, 12, 16, 0},
        {rc_l_true_set, 1, 12, 16, 32},      {rc_l_true_set_dynamic, 1, 12, 16, 0},
        {rc_l_true_move, 2, 12, 16, 32},     {rc_l_true_move_dynamic, 2, 12, 16, 0},
        {rc_l_true_memory, 3, 12, 16, 32},   {rc_l_true_memory_dynamic, 3, 12, 16, 0},
        {rc_l_false_branch, 0, 12, 0, 48},   {rc_l_false_branch_dynamic, 0, 12, 0, 16},
        {rc_l_false_set, 1, 12, 0, 48},      {rc_l_false_set_dynamic, 1, 12, 0, 16},
        {rc_l_false_move, 2, 12, 0, 48},     {rc_l_false_move_dynamic, 2, 12, 0, 16},
        {rc_l_false_memory, 3, 12, 0, 48},   {rc_l_false_memory_dynamic, 3, 12, 0, 16},
        {rc_ge_true_branch, 0, 13, 0, 48},   {rc_ge_true_branch_dynamic, 0, 13, 0, 16},
        {rc_ge_true_set, 1, 13, 0, 48},      {rc_ge_true_set_dynamic, 1, 13, 0, 16},
        {rc_ge_true_move, 2, 13, 0, 48},     {rc_ge_true_move_dynamic, 2, 13, 0, 16},
        {rc_ge_true_memory, 3, 13, 0, 48},   {rc_ge_true_memory_dynamic, 3, 13, 0, 16},
        {rc_ge_false_branch, 0, 13, 16, 32}, {rc_ge_false_branch_dynamic, 0, 13, 16, 0},
        {rc_ge_false_set, 1, 13, 16, 32},    {rc_ge_false_set_dynamic, 1, 13, 16, 0},
        {rc_ge_false_move, 2, 13, 16, 32},   {rc_ge_false_move_dynamic, 2, 13, 16, 0},
        {rc_ge_false_memory, 3, 13, 16, 32}, {rc_ge_false_memory_dynamic, 3, 13, 16, 0},
        {rc_le_true_branch, 0, 14, 16, 32},  {rc_le_true_branch_dynamic, 0, 14, 16, 0},
        {rc_le_true_set, 1, 14, 16, 32},     {rc_le_true_set_dynamic, 1, 14, 16, 0},
        {rc_le_true_move, 2, 14, 16, 32},    {rc_le_true_move_dynamic, 2, 14, 16, 0},
        {rc_le_true_memory, 3, 14, 16, 32},  {rc_le_true_memory_dynamic, 3, 14, 16, 0},
        {rc_le_false_branch, 0, 14, 0, 48},  {rc_le_false_branch_dynamic, 0, 14, 0, 16},
        {rc_le_false_set, 1, 14, 0, 48},     {rc_le_false_set_dynamic, 1, 14, 0, 16},
        {rc_le_false_move, 2, 14, 0, 48},    {rc_le_false_move_dynamic, 2, 14, 0, 16},
        {rc_le_false_memory, 3, 14, 0, 48},  {rc_le_false_memory_dynamic, 3, 14, 0, 16},
        {rc_g_true_branch, 0, 15, 0, 48},    {rc_g_true_branch_dynamic, 0, 15, 0, 16},
        {rc_g_true_set, 1, 15, 0, 48},       {rc_g_true_set_dynamic, 1, 15, 0, 16},
        {rc_g_true_move, 2, 15, 0, 48},      {rc_g_true_move_dynamic, 2, 15, 0, 16},
        {rc_g_true_memory, 3, 15, 0, 48},    {rc_g_true_memory_dynamic, 3, 15, 0, 16},
        {rc_g_false_branch, 0, 15, 16, 32},  {rc_g_false_branch_dynamic, 0, 15, 16, 0},
        {rc_g_false_set, 1, 15, 16, 32},     {rc_g_false_set_dynamic, 1, 15, 16, 0},
        {rc_g_false_move, 2, 15, 16, 32},    {rc_g_false_move_dynamic, 2, 15, 16, 0},
        {rc_g_false_memory, 3, 15, 16, 32},  {rc_g_false_memory_dynamic, 3, 15, 16, 0},
    };
    unsigned checks = 0;
    for (int input = -256; input <= 255; ++input)
    {
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        {
            const int truth =
                condition(cases[i].condition, input ? cases[i].first : cases[i].second);
            const int expected = cases[i].kind == 1 ? 0x123400 | truth : truth ? 7 : 8;
            if (cases[i].function(input) != expected)
                return 1;
            ++checks;
        }
        if (rc_cap(input) != 0x123401)
            return 2;
        ++checks;
    }
    const struct rlimit core_limit = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core_limit) != 0)
        return 3;
    int (*invalid[])(int) = {rc_lock_branch, rc_lock_set, rc_lock_move, rc_lock_memory};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        const pid_t child = fork();
        if (child < 0)
            return 4;
        if (child == 0)
        {
            (void)invalid[i](0);
            _exit(99);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
            WTERMSIG(status) != SIGILL)
            return 5;
        ++checks;
    }
    printf("{\"passed\":true,\"checks\":%u}\n", checks);
    return 0;
}
