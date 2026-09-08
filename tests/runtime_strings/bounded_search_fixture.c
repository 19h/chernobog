/* Native fixture for bounded libc summaries; compile with -O1 -fno-builtin. */
#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdio.h>
#include <string.h>

char bounded_text[3] = { 'a', 'b', 'c' }; /* Deliberately lacks a terminator. */
unsigned char bounded_bytes[3] = { 0x41, 0x80, 0x5a };
volatile size_t bounded_limit = 3;
volatile int bounded_needle = 0x180; /* memchr converts this to unsigned char. */
volatile unsigned char bounded_key = 0x5a;
static const unsigned char encoded[] = { 0x38, 0x35, 0x2f, 0x34, 0x3e, 0x3f, 0x3e, 0x7a, 0x29, 0x3f, 0x3b, 0x28, 0x39, 0x32, 0x7a, 0x15, 0x11, 0x5a };
unsigned char bounded_output[sizeof(encoded)];

__attribute__((noinline)) int bounded_search_fixture(void)
{
    size_t length = strnlen(bounded_text, bounded_limit);
    void *match = memchr(bounded_bytes, bounded_needle, bounded_limit);
    if (length != 3 || match != bounded_bytes + 1)
        return -1;
    for (size_t i = 0; i < sizeof(encoded); ++i)
        bounded_output[i] = encoded[i] ^ bounded_key;
    return puts((const char *)bounded_output);
}

int main(void) { return bounded_search_fixture(); }
