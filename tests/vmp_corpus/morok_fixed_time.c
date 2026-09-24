#include <time.h>

#ifndef MOROK_FIXED_EPOCH
#define MOROK_FIXED_EPOCH 1700000000
#endif

time_t time(time_t *result)
{
    const time_t fixed = (time_t)MOROK_FIXED_EPOCH;
    if (result != 0)
    {
        *result = fixed;
    }
    return fixed;
}
