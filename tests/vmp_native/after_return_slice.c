#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct after_return_output
{
    uint64_t rax, rbx, rbp, r12, rsi, rflags;
    uint64_t entry_rsp, exit_rsp;
};

extern void after_return_run(uint8_t *data, uint64_t r12, struct after_return_output *output);
extern const uint8_t after_return_slice[];

static int nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 4 || strlen(argv[1]) != 128 || strlen(argv[3]) != 150)
        return 2;
    uint8_t data[64];
    for (size_t index = 0; index < sizeof(data); ++index)
    {
        const int high = nibble(argv[1][2 * index]);
        const int low = nibble(argv[1][2 * index + 1]);
        if (high < 0 || low < 0)
            return 2;
        data[index] = (uint8_t)((high << 4) | low);
    }
    uint8_t expected_code[75];
    for (size_t index = 0; index < sizeof(expected_code); ++index)
    {
        const int high = nibble(argv[3][2 * index]);
        const int low = nibble(argv[3][2 * index + 1]);
        if (high < 0 || low < 0)
            return 2;
        expected_code[index] = (uint8_t)((high << 4) | low);
    }
    if (memcmp(after_return_slice, expected_code, sizeof(expected_code)) != 0)
        return 3;
    char *end = NULL;
    const uint64_t r12 = strtoull(argv[2], &end, 16);
    if (end == argv[2] || *end != '\0')
        return 2;
    struct after_return_output output = {0};
    after_return_run(data, r12, &output);
    printf("code_matched=1\nrax=%" PRIx64 "\nrbx=%" PRIx64 "\nrbp=%" PRIx64 "\nr12=%" PRIx64
           "\nrsi=%" PRIx64 "\nrflags=%" PRIx64 "\nrsp_restored=%d\ndata=",
           output.rax, output.rbx, output.rbp, output.r12, output.rsi, output.rflags,
           output.entry_rsp == output.exit_rsp);
    for (size_t index = 0; index < sizeof(data); ++index)
        printf("%02x", data[index]);
    putchar('\n');
    return 0;
}
