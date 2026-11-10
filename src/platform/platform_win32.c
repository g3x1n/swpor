/* 平台抽象层：Windows 实现（只需客户端功能）。见 SPEC 2.1。 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>

#include "platform.h"

#include "swpor/error.h"

int swpor_platform_init(void)
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return SWPOR_E_NET;
    }
    return SWPOR_OK;
}

void swpor_platform_cleanup(void)
{
    WSACleanup();
}

uint64_t swpor_time_ns(void)
{
    static LARGE_INTEGER freq; /* 进程内只需查询一次；并发首次写入的值相同，无害 */
    LARGE_INTEGER now;
    if (freq.QuadPart == 0) {
        QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&now);
    /* 拆成整秒与余数两部分计算，避免 now * 1e9 溢出 */
    uint64_t f = (uint64_t)freq.QuadPart;
    uint64_t c = (uint64_t)now.QuadPart;
    return (c / f) * 1000000000u + ((c % f) * 1000000000u) / f;
}

const char *swpor_platform_name(void)
{
    return "windows";
}

#else
typedef int swpor_platform_win32_unused;
#endif /* _WIN32 */
