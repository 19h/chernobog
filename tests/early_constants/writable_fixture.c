#include <stdint.h>

extern uint32_t early_alias_global;
extern uint32_t early_call_global;
extern const uint32_t early_readonly_control;
extern void early_write_pointer(uint32_t *pointer, uint32_t value);

__attribute__((noinline))
uint32_t early_alias_store_then_read(uint32_t *pointer, uint32_t value)
{
  *pointer = value;
  return early_alias_global;
}

__attribute__((noinline, optnone))
uint32_t early_call_then_read(uint32_t value)
{
  early_write_pointer(&early_call_global, value);
  return early_call_global;
}

__attribute__((noinline))
uint32_t early_readonly_read(void)
{
  return early_readonly_control;
}

/* Retain a frame-relative store/load as a native and final-result control. */
__attribute__((noinline, optnone))
uint32_t early_stack_constant(void)
{
  uint32_t local = UINT32_C(0x3456789A);
  return local;
}

int main(void)
{
  const uint32_t alias = early_alias_store_then_read(&early_alias_global, 11);
  const uint32_t call = early_call_then_read(13);
  return alias != 11 || call != 13
      || early_readonly_read() != UINT32_C(0x23456789)
      || early_stack_constant() != UINT32_C(0x3456789A);
}
