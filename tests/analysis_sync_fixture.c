#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

volatile int analysis_counter;

NOINLINE int analysis_target(int value)
{
    analysis_counter ^= value;
    return analysis_counter;
}

NOINLINE void analysis_sink(const char *text) { analysis_counter += text[0]; }

NOINLINE void analysis_prefix(void)
{
    char text[] = "prefix-stack";
    analysis_sink(text);
}

#define CALL analysis_target(0);
#define TEN CALL CALL CALL CALL CALL CALL CALL CALL CALL CALL
#define EIGHTY TEN TEN TEN TEN TEN TEN TEN TEN

NOINLINE void analysis_callers(void) { EIGHTY EIGHTY EIGHTY EIGHTY }

int main(void)
{
    analysis_callers();
    analysis_prefix();
    return 0;
}
