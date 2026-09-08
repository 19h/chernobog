/*
 * Native self-check for the ARM64 numeric-CFString display fixture.
 *
 * Build on macOS:
 *   xcrun clang -arch arm64 -O1 -g0 -fno-builtin \
 *     tests/runtime_strings/numeric_cfstring_fixture.c \
 *     tests/runtime_strings/numeric_cfstring_fixture.S \
 *     -framework CoreFoundation -o /tmp/numeric_cfstring_fixture
 *
 * The decoder and descriptor-address stores are one assembly function.  Raw
 * descriptor declarations deliberately avoid injecting C structure types.
 * No CoreFoundation API is called; its class-reference import supplies the
 * normal linker binding used by compiler-generated constant-string headers.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern int numeric_cfstring_fixture(void);
extern unsigned char cf_projection_output_one[15];
extern unsigned char cf_projection_output_two[15];
extern uint64_t cf_projection_stores[10];
extern uint64_t *volatile cf_projection_stores_ptr;
extern volatile uint64_t cf_projection_delta;
extern volatile uint32_t cf_projection_selector;

extern const unsigned char cf_projection_good_one[];
extern const unsigned char cf_projection_good_two[];
extern const unsigned char cf_projection_bad_flags[];
extern const unsigned char cf_projection_bad_length[];
extern const unsigned char cf_projection_bad_class[];
extern const unsigned char cf_projection_no_fact[];

_Static_assert(sizeof(uintptr_t) == 8, "Fixture requires 64-bit pointers");

static int check_stores(void)
{
    const uintptr_t expected[] = {
        (uintptr_t)cf_projection_good_one,
        (uintptr_t)cf_projection_good_two,
        (uintptr_t)cf_projection_bad_flags,
        (uintptr_t)cf_projection_bad_length,
        (uintptr_t)cf_projection_bad_class,
        (uintptr_t)cf_projection_no_fact,
        (uintptr_t)cf_projection_good_one,
        (uintptr_t)cf_projection_good_one + cf_projection_delta,
        (uintptr_t)cf_projection_good_one,
        (uint32_t)(uintptr_t)cf_projection_good_one,
    };
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i)
        if (cf_projection_stores[i] != expected[i])
            return (int)i + 10;
    return 0;
}

int main(void)
{
    if (cf_projection_stores_ptr != cf_projection_stores)
        return 5;
    int result = numeric_cfstring_fixture();
    if (result != 0)
        return 1;
    if (memcmp(cf_projection_output_one, "projection-one", 15) != 0)
        return 2;
    if (memcmp(cf_projection_output_two, "projection-two", 15) != 0)
        return 3;
    result = check_stores();
    if (result != 0)
        return result;

    /* Exercise the alternate store entry and a nonzero arithmetic offset. */
    cf_projection_selector = 1;
    cf_projection_delta = 7;
    if (numeric_cfstring_fixture() != 0)
        return 4;
    return check_stores();
}
