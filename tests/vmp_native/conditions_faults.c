/* Observe CMOV's unconditional read and architectural state at a read fault.
 * The process owns both pages. No signal is raised against another process. */
#define _GNU_SOURCE 1
#include <inttypes.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#if defined(__APPLE__)
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif
#include <unistd.h>

typedef uintptr_t word_t;
typedef word_t (*function_t)(word_t, word_t, uint64_t *);
#define DECLARE(n) extern word_t n(word_t, word_t, uint64_t *);
DECLARE(vc_cm_mem_true)
DECLARE(vc_cm_mem_false)
DECLARE(vc_cm_mem16_true)
DECLARE(vc_cm_mem16_false)
DECLARE(vc_cm_mem32_true)
DECLARE(vc_cm_mem32_false)
extern word_t vc_invoke(function_t, word_t, word_t, uint64_t *, uint64_t *);
static const struct
{
    const char *name;
    function_t function;
    unsigned width;
} cases[] = {
    {"vc_cm_mem_true", vc_cm_mem_true, sizeof(word_t)},
    {"vc_cm_mem_false", vc_cm_mem_false, sizeof(word_t)},
    {"vc_cm_mem16_true", vc_cm_mem16_true, 2},
    {"vc_cm_mem16_false", vc_cm_mem16_false, 2},
    {"vc_cm_mem32_true", vc_cm_mem32_true, 4},
    {"vc_cm_mem32_false", vc_cm_mem32_false, 4},
};
static sigjmp_buf recovery;
static volatile sig_atomic_t observed_signal;
static volatile uintptr_t fault_address, fault_pc;
static volatile uint64_t observed_ax, observed_flags;

static void fault_handler(int signal, siginfo_t *info, void *context)
{
    const ucontext_t *state = context;
    observed_signal = signal;
    fault_address = (uintptr_t)info->si_addr;
#if defined(__APPLE__) && defined(__x86_64__)
    observed_ax = state->uc_mcontext->__ss.__rax;
    observed_flags = state->uc_mcontext->__ss.__rflags;
    fault_pc = state->uc_mcontext->__ss.__rip;
#elif defined(__linux__) && defined(__i386__)
    observed_ax = (uint32_t)state->uc_mcontext.gregs[REG_EAX];
    observed_flags = (uint32_t)state->uc_mcontext.gregs[REG_EFL];
    fault_pc = (uint32_t)state->uc_mcontext.gregs[REG_EIP];
#else
#error Unsupported oracle architecture
#endif
    siglongjmp(recovery, 1);
}

int main(void)
{
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0)
        return 2;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = fault_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL) || sigaction(SIGBUS, &action, NULL))
        return 3;
    const long page = sysconf(_SC_PAGESIZE);
    if (page < 8)
        return 4;
    unsigned char *memory =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED)
        return 5;
    memset(memory, 0xA7, (size_t)page);
    if (mprotect(memory + page, (size_t)page, PROT_NONE))
        return 6;
    for (unsigned seed = 0; seed < 8; ++seed)
    {
        word_t destination =
            (word_t)(UINT64_C(0xFEDCBA9876543210) ^ UINT64_C(0x9E3779B97F4A7C15) * seed);
        for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        {
            for (unsigned mode = 0; mode < 3; ++mode)
            {
                unsigned available = mode == 0 ? 0 : cases[i].width - (mode == 1);
                unsigned char *source = memory + page - available;
                uint64_t result = 0, flags = 0;
                observed_signal = 0;
                if (sigsetjmp(recovery, 1) == 0)
                    result =
                        vc_invoke(cases[i].function, destination, 0, (uint64_t *)source, &flags);
                else
                {
                    result = observed_ax;
                    flags = observed_flags;
                }
                printf("{\"name\":\"%s\",\"seed\":%u,\"available_bytes\":%u,\"width_bytes\":%u,"
                       "\"destination\":%" PRIu64 ",\"result\":%" PRIu64 ",\"flags\":%" PRIu64
                       ",\"signal\":%d,\"fault_byte_offset\":%" PRIuPTR
                       ",\"fault_instruction_offset\":%" PRIuPTR "}\n",
                       cases[i].name, seed, available, cases[i].width, (uint64_t)destination,
                       result, flags & UINT64_C(0x8C5), (int)observed_signal,
                       observed_signal ? fault_address - (uintptr_t)source : 0,
                       observed_signal ? fault_pc - (uintptr_t)cases[i].function : 0);
            }
        }
    }
    if (munmap(memory, (size_t)page * 2))
        return 7;
    return 0;
}
