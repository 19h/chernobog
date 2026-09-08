// Independent assembler oracle for test_aarch64_address_origin().
// clang -target arm64-apple-macos13.3 -c tests/aarch64_address_origin.s -o /tmp/address-origin.o
// otool -tvV /tmp/address-origin.o
// otool -s __TEXT __text /tmp/address-origin.o
.text
.globl _origin_oracle
_origin_oracle:
  adrp x8, #4096
  add x8, x8, #291
  str x8, [x0]
  adrp x30, #-4096
  add x30, x30, #4095
  str x30, [sp, #32760]
  adrp x0, #4294963200
  add x0, x0, #0
  str x0, [x1, #8]
  adrp x16, #-4294967296
  add x16, x16, #1
  str x16, [x17, #16]
  adr x8, #4096
  add x8, x8, #1, lsl #12
  adds x8, x8, #1
  add w8, w8, #1
  str w8, [x0]
  ldr x8, [x0]
  stur x8, [x0]
  str x8, [x0, x1]
  str x8, [x0], #8
  adrp xzr, #0
  add sp, sp, #0
  str xzr, [x0]
