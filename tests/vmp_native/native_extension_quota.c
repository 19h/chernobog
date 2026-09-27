#ifndef OLD_NOPS
#define OLD_NOPS 4087
#endif
#define QUOTA_TEXT_INNER(value) #value
#define QUOTA_TEXT(value) QUOTA_TEXT_INNER(value)

__asm__(".text\n"
        ".globl _native_extension_quota\n"
        "_native_extension_quota:\n"
        "xorl %eax, %eax\n"
        "jne 1f\n"
        "leaq 2f(%rip), %rax\n"
        "jmp *%rax\n"
        "1:\n"
        ".rept " QUOTA_TEXT(OLD_NOPS) "\n"
                                      "nop\n"
                                      ".endr\n"
                                      "ret\n"
                                      "2:\n"
                                      "jne 1b\n"
                                      "movl $42, %eax\n"
                                      "nop\n"
                                      "ret\n");

extern int native_extension_quota(void);

int main(void) { return native_extension_quota() == 42 ? 0 : 1; }
