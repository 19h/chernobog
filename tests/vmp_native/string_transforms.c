/* Independent native fixtures for the source's rotate/add/XOR unit contracts.
 * Ciphertext is built at compile time; the noinline loops remain executable.
 */
#include <stdint.h>
#include <stddef.h>

#define KEY UINT32_C(0xA17E395B)
#define ROT32(k, n)                                                                                \
    (((uint32_t)(k) << ((n) & 31u)) | ((uint32_t)(k) >> ((32u - ((n) & 31u)) & 31u)))
#define ENC8(c, n) ((uint8_t)((uint8_t)(c) ^ (uint8_t)(ROT32(KEY, n) + (n))))
#define ENC16(c, n) ((uint16_t)((uint16_t)(c) ^ (uint16_t)(ROT32(KEY, n) + (n))))
#define FIXTURE __attribute__((noinline, used))

const uint8_t transform_bytes_source[] = {ENC8('V', 0), ENC8('M', 1), ENC8('P', 2),
                                          ENC8(' ', 3), ENC8('b', 4), ENC8('y', 5),
                                          ENC8('t', 6), ENC8('e', 7), ENC8(0, 8)};
const uint16_t transform_words_source[] = {ENC16('V', 0), ENC16('M', 1), ENC16('P', 2),
                                           ENC16(0x03A9, 3), ENC16(0, 4)};
/* UTF-16LE content encrypted by the BYTE transform, not the wide overload. */
const uint8_t transform_byte_utf16_source[] = {ENC8('W', 0), ENC8(0, 1), ENC8('i', 2), ENC8(0, 3),
                                               ENC8('d', 4), ENC8(0, 5), ENC8('e', 6), ENC8(0, 7),
                                               ENC8(0, 8),   ENC8(0, 9)};
uint8_t transform_bytes_output[sizeof(transform_bytes_source)];
uint16_t transform_words_output[sizeof(transform_words_source) / sizeof(uint16_t)];
uint8_t transform_byte_utf16_output[sizeof(transform_byte_utf16_source)];
uint8_t transform_negative_output[sizeof(transform_bytes_source)];
uint8_t transform_mutable_source[] = {ENC8('V', 0), ENC8('M', 1), ENC8('P', 2),
                                      ENC8(' ', 3), ENC8('b', 4), ENC8('y', 5),
                                      ENC8('t', 6), ENC8('e', 7), ENC8(0, 8)};
uint16_t transform_negative_words[sizeof(transform_words_source) / sizeof(uint16_t)];
unsigned transform_side_effect;

FIXTURE void transform_bytes(void)
{
    for (size_t i = 0; i < sizeof(transform_bytes_source); ++i)
        transform_bytes_output[i] = transform_bytes_source[i] ^ (uint8_t)(ROT32(KEY, i) + i);
}

FIXTURE void transform_words(void)
{
    for (size_t i = 0; i < sizeof(transform_words_source) / sizeof(uint16_t); ++i)
        transform_words_output[i] = transform_words_source[i] ^ (uint16_t)(ROT32(KEY, i) + i);
}

FIXTURE void transform_byte_utf16(void)
{
    for (size_t i = 0; i < sizeof(transform_byte_utf16_source); ++i)
        transform_byte_utf16_output[i] =
            transform_byte_utf16_source[i] ^ (uint8_t)(ROT32(KEY, i) + i);
}

FIXTURE void transform_wrong_rotate(void)
{
    for (size_t i = 0; i < sizeof(transform_bytes_source); ++i)
        transform_negative_output[i] =
            transform_bytes_source[i] ^ (uint8_t)(ROT32(KEY, 32u - (i & 31u)) + i);
}

FIXTURE void transform_wrong_index(void)
{
    for (size_t i = 0; i < sizeof(transform_bytes_source); ++i)
        transform_negative_output[i] =
            transform_bytes_source[i] ^ (uint8_t)(ROT32(KEY, i) + i + 1u);
}

FIXTURE void transform_unknown_key(uint32_t key)
{
    for (size_t i = 0; i < sizeof(transform_bytes_source); ++i)
        transform_negative_output[i] = transform_bytes_source[i] ^ (uint8_t)(ROT32(key, i) + i);
}

FIXTURE void transform_missing_terminator(void)
{
    for (size_t i = 0; i + 1 < sizeof(transform_bytes_source); ++i)
        transform_negative_output[i] = transform_bytes_source[i] ^ (uint8_t)(ROT32(KEY, i) + i);
}

FIXTURE void transform_narrow_rotate(void)
{
    for (size_t i = 0; i < sizeof(transform_bytes_source); ++i)
    {
        const uint8_t key = (uint8_t)KEY;
        const uint8_t rotated = (uint8_t)((key << (i & 7u)) | (key >> ((8u - (i & 7u)) & 7u)));
        transform_negative_output[i] = transform_bytes_source[i] ^ (uint8_t)(rotated + i);
    }
}

FIXTURE void transform_word_byte_index(void)
{
    for (size_t i = 0; i < sizeof(transform_words_source) / sizeof(uint16_t); ++i)
        transform_negative_words[i] =
            transform_words_source[i] ^ (uint16_t)(ROT32(KEY, 2 * i) + 2 * i);
}

FIXTURE void transform_mutable(void)
{
    for (size_t i = 0; i < sizeof(transform_mutable_source); ++i)
        transform_negative_output[i] = transform_mutable_source[i] ^ (uint8_t)(ROT32(KEY, i) + i);
}

FIXTURE void transform_alias(void)
{
    for (size_t i = 0; i < sizeof(transform_mutable_source); ++i)
        transform_mutable_source[i] ^= (uint8_t)(ROT32(KEY, i) + i);
}

FIXTURE void transform_extra_write(void)
{
    for (size_t i = 0; i < sizeof(transform_bytes_source); ++i)
    {
        transform_negative_output[i] = transform_bytes_source[i] ^ (uint8_t)(ROT32(KEY, i) + i);
        transform_side_effect += transform_negative_output[i];
    }
}

int main(void)
{
    transform_bytes();
    transform_words();
    transform_byte_utf16();
    const uint8_t expected_bytes[] = "VMP byte";
    const uint16_t expected_words[] = {'V', 'M', 'P', 0x03A9, 0};
    const uint8_t expected_byte_utf16[] = {'W', 0, 'i', 0, 'd', 0, 'e', 0, 0, 0};
    for (size_t i = 0; i < sizeof(expected_bytes); ++i)
        if (transform_bytes_output[i] != expected_bytes[i])
            return 1;
    for (size_t i = 0; i < sizeof(expected_words) / 2; ++i)
        if (transform_words_output[i] != expected_words[i])
            return 2;
    for (size_t i = 0; i < sizeof(expected_byte_utf16); ++i)
        if (transform_byte_utf16_output[i] != expected_byte_utf16[i])
            return 3;
    return 0;
}
