#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach-o/dyld.h>

enum
{
    GPR_COUNT = 16,
    STACK_BYTES = 128,
    WINDOW_BYTES = 40
};

struct capture_record
{
    uint64_t magic;
    uint64_t count;
    uint64_t return_pc;
    uint64_t gprs[GPR_COUNT];
    uint64_t rflags;
    uint8_t stack_above[STACK_BYTES];
    uint8_t window[WINDOW_BYTES];
} __attribute__((packed));

_Static_assert(sizeof(struct capture_record) ==
                   8 * (3 + GPR_COUNT + 1) + STACK_BYTES + WINDOW_BYTES,
               "capture record layout");

__attribute__((used)) void *real_printf_ptr;
__attribute__((used)) uint64_t expected_postcall_pc;
static struct capture_record capture;
static const char *output_path;

extern int capture_printf(const char *, ...);

__attribute__((used, section("__DATA,__interpose"))) static const struct
{
    const void *replacement;
    const void *replacee;
} interpose_printf = {(const void *)capture_printf, (const void *)printf};

static void write_capture(void)
{
    if (!output_path || capture.count != 1)
        return;
    const int fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return;
    const uint8_t *bytes = (const uint8_t *)&capture;
    size_t remaining = sizeof(capture);
    while (remaining)
    {
        const ssize_t written = write(fd, bytes, remaining);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            break;
        bytes += written;
        remaining -= (size_t)written;
    }
    close(fd);
}

__attribute__((constructor)) static void initialize_capture(void)
{
    output_path = getenv("CHERNOBOG_HELLO_POSTCALL_CAPTURE");
    expected_postcall_pc = UINT64_C(0x100001452) + (uint64_t)_dyld_get_image_vmaddr_slide(0);
    real_printf_ptr = (void *)interpose_printf.replacee;
    if (real_printf_ptr == (void *)capture_printf)
        _exit(125);
    Dl_info info;
    if (!dladdr(real_printf_ptr, &info) || !info.dli_sname || strcmp(info.dli_sname, "printf") != 0)
        _exit(125);
    capture.magic = UINT64_C(0x4348504f53544331);
    atexit(write_capture);
}

void record_postcall_state(const uint64_t *registers)
{
    const uint64_t before_return_sp = registers[4];
    if (!output_path || !real_printf_ptr ||
        *(const uint64_t *)(uintptr_t)before_return_sp != expected_postcall_pc)
        return;
    ++capture.count;
    if (capture.count != 1)
        return;
    capture.return_pc = expected_postcall_pc;
    memcpy(capture.gprs, registers, sizeof(capture.gprs));
    capture.gprs[4] = before_return_sp + 8;
    capture.rflags = registers[16];
    memcpy(capture.stack_above, (const void *)(uintptr_t)(before_return_sp + 8), STACK_BYTES);
    memcpy(capture.window, (const void *)(uintptr_t)(expected_postcall_pc - 18), WINDOW_BYTES);
}

// Keep one assembly instruction per source line for register-order inspection.
// clang-format off
__asm__(
    ".text\n"
    ".globl _capture_printf\n"
    "_capture_printf:\n"
    "movq _expected_postcall_pc(%rip), %r11\n"
    "cmpq %r11, (%rsp)\n"
    "jne 1f\n"
    "pushq %rbx\n"
    "pushq %rbp\n"
    "pushq %r12\n"
    "pushq %r13\n"
    "pushq %r14\n"
    "pushq %r15\n"
    "leaq -8(%rsp), %rsp\n"
    "callq *_real_printf_ptr(%rip)\n"
    "leaq 8(%rsp), %rsp\n"
    "popq %r15\n"
    "popq %r14\n"
    "popq %r13\n"
    "popq %r12\n"
    "popq %rbp\n"
    "popq %rbx\n"
    "pushfq\n"
    "subq $160, %rsp\n"
    "movq %rax, 0(%rsp)\n"
    "movq %rcx, 8(%rsp)\n"
    "movq %rdx, 16(%rsp)\n"
    "movq %rbx, 24(%rsp)\n"
    "movq %rbp, 40(%rsp)\n"
    "movq %rsi, 48(%rsp)\n"
    "movq %rdi, 56(%rsp)\n"
    "movq %r8, 64(%rsp)\n"
    "movq %r9, 72(%rsp)\n"
    "movq %r10, 80(%rsp)\n"
    "movq %r11, 88(%rsp)\n"
    "movq %r12, 96(%rsp)\n"
    "movq %r13, 104(%rsp)\n"
    "movq %r14, 112(%rsp)\n"
    "movq %r15, 120(%rsp)\n"
    "leaq 168(%rsp), %r11\n"
    "movq %r11, 32(%rsp)\n"
    "movq 160(%rsp), %r11\n"
    "movq %r11, 128(%rsp)\n"
    "movq %rsp, %rdi\n"
    "callq _record_postcall_state\n"
    "movq 0(%rsp), %rax\n"
    "movq 8(%rsp), %rcx\n"
    "movq 16(%rsp), %rdx\n"
    "movq 24(%rsp), %rbx\n"
    "movq 40(%rsp), %rbp\n"
    "movq 48(%rsp), %rsi\n"
    "movq 56(%rsp), %rdi\n"
    "movq 64(%rsp), %r8\n"
    "movq 72(%rsp), %r9\n"
    "movq 80(%rsp), %r10\n"
    "movq 88(%rsp), %r11\n"
    "movq 96(%rsp), %r12\n"
    "movq 104(%rsp), %r13\n"
    "movq 112(%rsp), %r14\n"
    "movq 120(%rsp), %r15\n"
    "leaq 160(%rsp), %rsp\n"
    "popfq\n"
    "retq\n"
    "1: jmpq *_real_printf_ptr(%rip)\n");
// clang-format on
