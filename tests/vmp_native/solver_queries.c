#include <stdint.h>

/* A nonlinear candidate for the optional affine pass. Coefficient samples do
 * not prove affinity; the actual exclusion query must reject a false fit. */
__attribute__((noinline)) uint32_t query_nonlinear(uint32_t x, uint32_t y)
{
    return ((x * y + 3u) ^ (x + 5u)) + ((x * 7u + y) ^ (y + 11u));
}

__attribute__((noinline)) uint32_t query_linear(uint32_t x, uint32_t y)
{
    return (x ^ y) + 2u * (x & y);
}

int main(void)
{
    return query_nonlinear(2, 5) != 13u || query_linear(0xffffffffu, 7u) != 6u;
}
