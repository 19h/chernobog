#include <stdint.h>
#include <stdio.h>

#if defined(__clang__) || defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE __declspec(noinline)
#endif

uint32_t observed;
uint32_t calls;
uint32_t seed = 0x125abcdd;
uint32_t *escaped_object;
uint32_t **escaped_cell;

NOINLINE uint32_t read_seed(void) { return seed; }

NOINLINE uint32_t mba_expression(uint32_t x, uint32_t y)
{
    uint32_t different = x ^ y;
    uint32_t shared = x & y;
    return different + 2 * shared;
}

NOINLINE uint32_t helper(uint32_t value)
{
    ++calls;
    observed = value;
    return value ^ 0x5a;
}

NOINLINE void redirect(uint32_t **pointer, uint32_t *destination) { *pointer = destination; }

NOINLINE uint32_t *remember(uint32_t *object)
{
    ++calls;
    return object;
}

NOINLINE void redirect_escaped(uint32_t *destination) { *escaped_cell = destination; }

NOINLINE uint32_t object_escape(uint32_t input)
{
    uint32_t state = 0x81234567;
    uint32_t *pointer = &state;
    uint32_t object = input;
    uint32_t result = 0;
    for (;;)
    {
        switch (state)
        {
        case 0x81234567:
            escaped_object = remember(&object);
            *pointer = (input & 1) ? 0x23456789 : 0x92345678;
            break;
        case 0x23456789:
            *escaped_object += 7;
            *pointer = 0xa3456789;
            break;
        case 0x92345678:
            *escaped_object += 19;
            *pointer = 0xa3456789;
            break;
        case 0xa3456789:
            result = helper(object);
            *pointer = 0x456789ab;
            break;
        case 0x456789ab:
            return result;
        default:
            return 0xbad;
        }
    }
}

NOINLINE uint32_t cell_escape(uint32_t input)
{
    uint32_t first = input;
    uint32_t second = 83;
    uint32_t *pointer = &first;
    escaped_cell = &pointer;
    redirect_escaped(&second);
    *pointer = 71;
    return first * 100 + second;
}

NOINLINE uint32_t shared_dispatch(uint32_t input)
{
    uint32_t state = 0x81234567;
    uint32_t *pointer = &state;
    uint32_t result = input;
    uint32_t left, right, condition;
    for (;;)
    {
        switch (state)
        {
        case 0x81234567:
            left = 0x23456789;
            right = 0x92345678;
            condition = input & 1;
            goto select;
        case 0x23456789:
            result += 7;
            left = 0xa3456789;
            right = 0x34567890;
            condition = input & 2;
            goto select;
        case 0x92345678:
            result += 19;
            left = 0x34567890;
            right = 0xa3456789;
            condition = input & 4;
            goto select;
        case 0xa3456789:
            result = helper(result);
            *pointer = 0x456789ab;
            break;
        case 0x34567890:
            result ^= 0x321;
            *pointer = 0x456789ab;
            break;
        case 0x456789ab:
            return result;
        default:
            return 0xbad;
        }
        continue;
    select:
        *pointer = condition ? left : right;
    }
}

NOINLINE uint32_t flattened(uint32_t input)
{
    uint32_t state = 0x81234567;
    uint32_t *pointer = &state;
    uint32_t value = input;
    for (;;)
    {
        switch (state)
        {
        case 0x81234567:
            *pointer = (input & 1) ? 0x23456789 : 0x92345678;
            break;
        case 0x23456789:
            value += 7;
            *pointer = 0xa3456789;
            break;
        case 0x92345678:
            value += 19;
            *pointer = 0xa3456789;
            break;
        case 0xa3456789:
            value = helper(value);
            *pointer = 0x456789ab;
            break;
        case 0x456789ab:
            return value;
        default:
            return 0xbad;
        }
    }
}

NOINLINE uint32_t alias_join(uint32_t input)
{
    uint32_t first = 11;
    uint32_t second = 29;
    uint32_t *pointer;
    if (input & 1)
        pointer = &first;
    else
        pointer = &second;
    *pointer = 71;
    return first * 100 + second;
}

NOINLINE uint32_t alias_escape(uint32_t input)
{
    uint32_t first = input;
    uint32_t second = 83;
    uint32_t *pointer = &first;
    redirect(&pointer, &second);
    *pointer = 71;
    return first * 100 + second;
}

NOINLINE uint32_t partial_write(uint32_t input)
{
    uint32_t first = input;
    unsigned char *pointer = (unsigned char *)&first;
    *pointer = 0xa5;
    return first;
}

NOINLINE uint32_t loop_alias(uint32_t input)
{
    uint32_t first = 11;
    uint32_t second = 29;
    uint32_t *pointer = &first;
    for (uint32_t index = 0; index < (input & 3); ++index)
    {
        *pointer += index + 1;
        pointer = pointer == &first ? &second : &first;
    }
    return first * 100 + second;
}

NOINLINE uint64_t wide_state(uint32_t input)
{
    int32_t state = (input & 1) ? (int32_t)0x92345678u : 0x23456789;
    for (;;)
    {
        uint64_t widened = (uint64_t)(int64_t)state;
        if (state == (int32_t)0x92345678u || state == 0x23456789)
            return widened ^ input;
        state = 0x23456789;
    }
}

int main(void)
{
    const uint32_t inputs[] = {0, 1, 2, 7, 19, 0x7fffffff, 0x80000000, 0xffffffff};
    for (unsigned int i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
    {
        uint32_t x = inputs[i];
        calls = 0;
        uint32_t value = flattened(x);
        uint32_t escaped = object_escape(x);
        uint32_t cell = cell_escape(x);
        uint32_t shared = shared_dispatch(x);
        printf("%u %u %u %u %u %u %u %u %llu %u %u %u\n", x, value, observed, calls, alias_join(x),
               alias_escape(x), partial_write(x), loop_alias(x), (unsigned long long)wide_state(x),
               escaped, cell, shared);
    }
    return 0;
}
