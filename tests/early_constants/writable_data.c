#include <stdint.h>

uint32_t early_alias_global = 7;
uint32_t early_call_global = 9;
const uint32_t early_readonly_control = UINT32_C(0x23456789);

/* The pointee is unknown within this separately compiled function. */
__attribute__((noinline))
void early_write_pointer(uint32_t *pointer, uint32_t value)
{
  *pointer = value;
}
