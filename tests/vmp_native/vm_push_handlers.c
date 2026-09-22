#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef VM_PUSH_BITS
#define VM_PUSH_BITS 32
#endif
#ifndef VM_PUSH_BACKWARD
#define VM_PUSH_BACKWARD 0
#endif
#ifndef VM_PUSH_RELATIVE
#define VM_PUSH_RELATIVE 1
#endif
#ifndef VM_PUSH_ORACLE_XOR
#define VM_PUSH_ORACLE_XOR 0
#endif

struct capture
{
    uint8_t code[16];
    uint64_t key, stored, key_after, vip_after, fast, left, right;
};
_Static_assert(sizeof(struct capture) == 72, "assembly object size");
_Static_assert(offsetof(struct capture, key) == 16, "assembly input offset");
_Static_assert(offsetof(struct capture, right) == 64, "assembly guard offset");
extern uintptr_t vm_push_run(struct capture *, uintptr_t);

static uint64_t mask(unsigned bits) { return bits == 64 ? UINT64_MAX : (UINT64_C(1) << bits) - 1; }
static uint64_t rotate(uint64_t value, unsigned bits, unsigned count)
{
    return ((value << count) | (value >> (bits - count))) & mask(bits);
}
static uint64_t decode(uint64_t encoded, uint64_t key, unsigned bits)
{
    const uint64_t added = (rotate((encoded ^ key) & mask(bits), bits, 3) + 7) & mask(bits);
    return ((added ^ UINT64_C(0x5a)) - 9) & mask(bits);
}
static void put(uint8_t *bytes, uint64_t value, unsigned size)
{
    for (unsigned index = 0; index < size; ++index)
        bytes[index] = (uint8_t)(value >> (index * 8));
}
static int run(unsigned index, uint64_t encoded, uint64_t key, unsigned equal)
{
    const unsigned mode = sizeof(uintptr_t) * 8;
    const unsigned width = VM_PUSH_BITS;
    const unsigned dispatch_width = VM_PUSH_RELATIVE ? 32 : 8;
    const unsigned payload_bytes = width / 8, dispatch_bytes = dispatch_width / 8;
    const unsigned slot = width == 8 ? 2 : payload_bytes;
    key &= mask(mode);
    encoded &= mask(width);
    const uint64_t decoded = decode(encoded, key, width);
    const uint64_t payload_key = key ^ decoded;
    const int32_t deltas[] = {-32, INT32_MAX, INT32_MIN};
    const uint32_t delta = VM_PUSH_RELATIVE ? (uint32_t)deltas[index] : 0;
    const uint64_t key_after = payload_key ^ delta;
    const uint64_t inverse =
        (((((uint64_t)delta + 9) & mask(dispatch_width)) ^ UINT64_C(0x5a)) - 7) &
        mask(dispatch_width);
    const uint64_t dispatch_encoded =
        rotate(inverse, dispatch_width, dispatch_width - 3) ^ (payload_key & mask(dispatch_width));
    struct capture out = {{0}, 0, 0, 0, 0, 0, 0, 0};
    out.key = key;
    put(out.code + (VM_PUSH_BACKWARD ? dispatch_bytes : 0), encoded, payload_bytes);
    put(out.code + (VM_PUSH_BACKWARD ? 0 : payload_bytes), dispatch_encoded, dispatch_bytes);
    put(out.code + 12, delta, 4);
    const uintptr_t result = vm_push_run(&out, equal);
    const unsigned consumed = payload_bytes + ((VM_PUSH_RELATIVE || !equal) ? dispatch_bytes : 0);
    const uint64_t vip_after =
        VM_PUSH_BACKWARD ? payload_bytes + dispatch_bytes - consumed : consumed;
    const uint64_t stored =
        ((UINT64_C(0xa5a5a5a5a5a5a5a5) & ~mask(slot * 8)) | decoded) ^ VM_PUSH_ORACLE_XOR;
    const int passed = result == !equal && out.fast == !equal && out.stored == stored &&
                       out.key_after == key_after && out.vip_after == vip_after &&
                       out.left == UINT64_C(0x3c3c3c3c3c3c3c3c) &&
                       out.right == UINT64_C(0x5a5a5a5a5a5a5a5a);
    printf("%u %u %016" PRIx64 " %016" PRIx64 " %" PRIxPTR " %016" PRIx64 " %016" PRIx64
           " %016" PRIx64 " %016" PRIx64 " %016" PRIx64 " %u\n",
           index, equal, encoded, key, result, out.stored, out.key_after, out.vip_after, out.left,
           out.right, passed);
    return passed;
}
int main(void)
{
    const uint64_t encoded[] = {0, UINT64_MAX, UINT64_C(0x80017fffab0080fe)};
    const uint64_t keys[] = {0, UINT64_MAX, UINT64_C(0x9a785634a581f03c)};
    unsigned failures = 0;
    for (unsigned index = 0; index < 3; ++index)
        for (unsigned equal = 0; equal < 2; ++equal)
            failures += !run(index, encoded[index], keys[index], equal);
    return failures != 0;
}
