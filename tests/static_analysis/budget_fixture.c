/* Large straight-line function for live static-analysis budget validation.
 * Compile with a native Clang/GCC toolchain, e.g. cc -O0 budget_fixture.c -o fixture.
 */
#if defined(__APPLE__)
#define SYMBOL(name) "_" #name
#else
#define SYMBOL(name) #name
#endif

#if !defined(__aarch64__) && !defined(__x86_64__)
#error This fixture requires AArch64 or x86-64.
#endif

__asm__(".text\n"
        ".globl " SYMBOL(budget_fixture) "\n"
        SYMBOL(budget_fixture) ":\n"
        ".rept 65536\n"
        "nop\n"
        ".endr\n"
        "ret\n");

extern void budget_fixture(void);
int main(void) { budget_fixture(); return 0; }
