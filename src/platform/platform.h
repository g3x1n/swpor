#ifndef SWPOR_PLATFORM_H
#define SWPOR_PLATFORM_H

/*
 * 平台抽象层（SPEC 2.1）。
 *
 * 规则：只有 src/platform/ 下的 .c 文件可以包含操作系统头文件，
 * 也只有这里可以出现 _WIN32 / __APPLE__ / __linux__ 条件编译。
 * 其余代码一律通过本头文件中的接口使用系统功能。
 *
 * 实现状态：
 *   [已实现] swpor_platform_init / cleanup、swpor_time_ns
 *   [M0]     文件：swpor_file_*、swpor_mkdir_p
 *   [M3]     套接字：swpor_sock_*；线程与锁：swpor_thread_* / swpor_mutex_* /
 *            swpor_rwlock_* / swpor_cond_*
 * 尚未实现的接口在实现时再在此声明，避免出现"声明了却不存在"的符号。
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 进程级初始化。必须在使用网络等功能前调用一次（Windows 上执行 WSAStartup）。
 * @return SWPOR_OK 或 SWPOR_E_NET
 */
int swpor_platform_init(void);

/** 进程级清理，与 swpor_platform_init 成对调用（Windows 上执行 WSACleanup）。 */
void swpor_platform_cleanup(void);

/** 单调递增的高精度时间，单位纳秒，只用于计算时间差（基准测试、超时）。 */
uint64_t swpor_time_ns(void);

/** 返回平台名称："macos"、"linux"、"windows" 或 "unknown"。 */
const char *swpor_platform_name(void);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_PLATFORM_H */
