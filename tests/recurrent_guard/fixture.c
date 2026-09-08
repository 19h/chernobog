/* Native reference for fixture.S. Build:
 * xcrun clang -arch x86_64 -O1 -g0 -fno-builtin \
 *   tests/recurrent_guard/fixture.c tests/recurrent_guard/fixture.S \
 *   -o /tmp/recurrent_guard_fixture
 * The seven nonreturning cases are bounded by a child-process alarm (1 s).
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

typedef int (*fixture_fn)(uint32_t);
#define DECLARE(name) extern int name(uint32_t)
DECLARE(rg_positive);
DECLARE(rg_late_guard);
DECLARE(rg_unknown_guard);
DECLARE(rg_global_effect);
DECLARE(rg_escaped_state);
DECLARE(rg_recurrence_register);
DECLARE(rg_middle_entry);
DECLARE(rg_register_effect);
DECLARE(rg_entry_cycle);
DECLARE(rg_restored_selector);
DECLARE(rg_corrupted_restore);
extern volatile uint32_t rg_guard_hits;

static uint32_t encode(uint32_t value)
{
    return ((value ^ UINT32_C(0x2468ace0)) - UINT32_C(0x13579bdf))
           ^ UINT32_C(0x9e3779b9);
}

static void require_result(const char *name, fixture_fn function,
                           uint32_t argument, int expected)
{
    int observed = function(argument);
    if (observed != expected) {
        fprintf(stderr, "%s: observed %d, expected %d\n", name, observed, expected);
        exit(1);
    }
    printf("%s(%u) = %d\n", name, argument, observed);
}

static void require_loop(const char *name, fixture_fn function, uint32_t argument)
{
    fflush(NULL);
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        exit(2);
    }
    if (child == 0) {
        alarm(1);
        (void)function(argument);
        _exit(3);
    }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) {
            perror("waitpid");
            exit(4);
        }
    }
    if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGALRM) {
        fprintf(stderr, "%s: expected SIGALRM, wait status=%d\n", name, status);
        exit(5);
    }
    printf("%s(%u): SIGALRM after 1 s\n", name, argument);
}

int main(void)
{
    require_result("positive", rg_positive, 0, 255);
    require_result("unknown_guard_safe", rg_unknown_guard, encode(4), 255);
    rg_guard_hits = 0;
    require_result("global_effect", rg_global_effect, 0, 255);
    if (rg_guard_hits != 8)
        return 6;
    printf("global_effect: dispatcher updates = %u\n", rg_guard_hits);
    require_result("escaped_state", rg_escaped_state, 0, 255);
    require_result("recurrence_register", rg_recurrence_register, 0, 255);
    require_result("register_effect", rg_register_effect, 0, 36);
    require_result("entry_cycle_safe", rg_entry_cycle, 1, 255);
    require_result("restored_selector_zero", rg_restored_selector, 0, 256);
    require_result("restored_selector_nonzero", rg_restored_selector, 1, 257);
    require_loop("late_guard", rg_late_guard, 0);
    require_loop("unknown_guard_reachable", rg_unknown_guard, encode(9));
    require_loop("unknown_table_default", rg_unknown_guard, encode(8));
    require_loop("middle_entry", rg_middle_entry, 0);
    require_loop("entry_cycle_reachable", rg_entry_cycle, 2);
    require_loop("corrupted_restore_zero", rg_corrupted_restore, 0);
    require_loop("corrupted_restore_nonzero", rg_corrupted_restore, 1);
    puts("PASS recurrent guard native reference");
    return 0;
}
