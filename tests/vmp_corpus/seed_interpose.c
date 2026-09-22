// Test-only macOS fixture-generation instrument. Override only the C PRNG seed.
// No protector instructions, licensing state, or protected runtime are patched.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void corpus_srand(unsigned requested)
{
    const char *text = getenv("CHERNOBOG_CORPUS_PROTECTOR_SEED");
    char *end = 0;
    unsigned long parsed = text ? strtoul(text, &end, 0) : UINT64_MAX;
    if (!text || !end || end == text || *end || parsed > UINT32_MAX)
        _exit(121);
    // dyld excludes bindings in the interposer image from its own replacement.
    srand((unsigned)parsed);
    char line[128];
    int size = snprintf(line, sizeof(line), "CHERNOBOG_CORPUS_SRAND=%u requested=%u\n",
                        (unsigned)parsed, requested);
    if (size <= 0 || size >= (int)sizeof(line) || write(STDERR_FILENO, line, (size_t)size) != size)
        _exit(122);
}

__attribute__((used, section("__DATA,__interpose"))) static struct
{
    const void *replacement;
    const void *original;
} corpus_interpose = {(const void *)(uintptr_t)&corpus_srand, (const void *)(uintptr_t)&srand};
