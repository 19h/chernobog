#include <stdint.h>

extern const uint32_t early_constant_table[4];
extern const uint32_t early_constant_index;

__attribute__((noinline))
uint32_t early_indexed_read(uint32_t index)
{
  return early_constant_table[index & 3];
}

__attribute__((noinline))
uint32_t early_fixed_read(void)
{
  return early_constant_table[2];
}

__attribute__((noinline))
uint32_t early_known_index_read(void)
{
  return early_constant_table[early_constant_index];
}

int main(int argc, char **argv)
{
  (void)argv;
  return (int)(early_indexed_read((uint32_t)argc) ^ early_fixed_read()
               ^ early_known_index_read());
}
