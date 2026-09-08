#include <stdint.h>

/* Separate translation unit keeps the fixed memory read present without LTO. */
const uint32_t early_constant_table[4] = {
  UINT32_C(0x12345678), UINT32_C(0x23456789),
  UINT32_C(0x3456789A), UINT32_C(0x456789AB),
};

const uint32_t early_constant_index = 2;
