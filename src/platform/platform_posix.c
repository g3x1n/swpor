/* 平台抽象层：POSIX 实现（macOS、Linux）。见 SPEC 2.1。 */

#if !defined(_WIN32)

#define _POSIX_C_SOURCE 200809L

#include "platform.h"

#include <time.h>

#include "swpor/error.h"

int swpor_platform_init(void)
{
    return SWPOR_OK;
}

void swpor_platform_cleanup(void)
{
}

uint64_t swpor_time_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

const char *swpor_platform_name(void)
{
#if defined(__APPLE__)
    return "macos";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

#else
/* 避免 ISO C 的"空翻译单元"警告 */
typedef int swpor_platform_posix_unused;
#endif /* !_WIN32 */
