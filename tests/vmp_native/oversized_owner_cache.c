__asm__(".text\n"
        ".globl _cache_condition\n"
        "_cache_condition:\n"
        "testl %edi, %edi\n"
        "je 1f\n"
        "movl $1, %ecx\n"
        "jmp 2f\n"
        "1:\n"
        "movl $1, %ecx\n"
        "2:\n"
        "testl %ecx, %ecx\n"
        "sete %al\n"
        "movzbl %al, %eax\n"
        "ret\n"
        ".p2align 12, 0xcc\n"
        ".globl _cache_filler\n"
        "_cache_filler:\n"
        ".rept 4087\n"
        "nop\n"
        ".endr\n"
        "ret\n");

extern int cache_condition(int value);
extern void cache_filler(void);

int main(void)
{
    cache_filler();
    return cache_condition(0);
}
