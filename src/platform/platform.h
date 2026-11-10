#ifndef SWPOR_PLATFORM_H
#define SWPOR_PLATFORM_H

/*
 * 平台抽象层（SPEC 2.1）。
 *
 * 规则：只有 src/platform/ 下的 .c 文件可以包含操作系统头文件，
 * 也只有这里可以出现 _WIN32 / __APPLE__ / __linux__ 条件编译。
 * 其余代码一律通过本头文件中的接口使用系统功能。
 *
 * 所有路径参数均为 UTF-8 字符串（Windows 实现内部转为 UTF-16）。
 * 所有函数返回 SWPOR_OK 或负的错误码（swpor/error.h）。
 *
 * 实现分布：
 *   platform_posix.c / platform_win32.c   进程初始化、计时、文件、目录、线程与锁
 *   sock_posix.c / sock_win32.c           套接字（编译进 swpor_net 库，见 SPEC 9.1）
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== */
/* 进程、计时                                                             */
/* ===================================================================== */

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

/** 返回在线 CPU 核数（至少为 1）。用于线程池默认大小（SPEC 8.4）。 */
unsigned swpor_cpu_count(void);

/** 当前线程休眠 ms 毫秒（porta 定时审计用）。 */
void swpor_sleep_ms(uint32_t ms);

/* ===================================================================== */
/* 文件（SPEC 2.1 文件随机读写、私有密钥文件）                              */
/* ===================================================================== */

typedef struct swpor_file swpor_file_t;

typedef enum {
    SWPOR_FILE_READ = 1,   /* 打开已有文件，只读 */
    SWPOR_FILE_RDWR = 2,   /* 打开已有文件，读写 */
    SWPOR_FILE_CREATE = 3  /* 创建（已存在则截断），读写，权限 0644 */
} swpor_file_mode_t;

/**
 * 以二进制方式打开文件。
 * @return SWPOR_OK；文件不存在返回 SWPOR_E_NOT_FOUND；其他失败返回 SWPOR_E_IO
 */
int swpor_file_open(const char *path, swpor_file_mode_t mode, swpor_file_t **out);

/**
 * 创建只有当前用户可读写的文件（POSIX 0600；Windows 仅当前用户 ACL），用于保存秘密密钥（SPEC 7）。
 * @param force  0：文件已存在时返回 SWPOR_E_EXISTS；非 0：先删除已有文件再创建
 */
int swpor_file_create_private(const char *path, int force, swpor_file_t **out);

/** 从偏移 off 处读满 len 字节；读到文件末尾仍不足 len 字节时返回 SWPOR_E_IO。 */
int swpor_file_pread(swpor_file_t *f, void *buf, size_t len, uint64_t off);

/**
 * 从偏移 off 处最多读 len 字节，实际读到的字节数写入 *got（到达文件末尾时可能小于 len）。
 * 用于顺序读取任意长度的输入文件。
 */
int swpor_file_pread_some(swpor_file_t *f, void *buf, size_t len, uint64_t off, size_t *got);

/** 在偏移 off 处写入 len 字节（必要时扩展文件）。 */
int swpor_file_pwrite(swpor_file_t *f, const void *buf, size_t len, uint64_t off);

/** 获取文件当前长度。 */
int swpor_file_size(swpor_file_t *f, uint64_t *size);

/** 把文件数据刷到磁盘。 */
int swpor_file_sync(swpor_file_t *f);

/** 关闭文件。传入 NULL 安全。 */
void swpor_file_close(swpor_file_t *f);

/** 路径是否存在（文件或目录）。 */
int swpor_path_exists(const char *path);

/** 递归创建目录（类似 mkdir -p）。已存在时返回 SWPOR_OK。 */
int swpor_mkdir_p(const char *path);

/** 删除文件。不存在时返回 SWPOR_E_NOT_FOUND。 */
int swpor_remove_file(const char *path);

/** 删除空目录。 */
int swpor_remove_dir(const char *path);

/** 原子地把 from 重命名为 to（to 已存在时覆盖）。 */
int swpor_rename(const char *from, const char *to);

/**
 * 拼接路径 a 与 b（中间加平台分隔符），结果写入 out。
 * @return 空间不足返回 SWPOR_E_RANGE
 */
int swpor_path_join(char *out, size_t cap, const char *a, const char *b);

/* ===================================================================== */
/* 线程与同步（SPEC 8.4）                                                  */
/* ===================================================================== */

typedef struct swpor_thread swpor_thread_t;
typedef struct swpor_mutex swpor_mutex_t;
typedef struct swpor_cond swpor_cond_t;
typedef struct swpor_rwlock swpor_rwlock_t;

typedef void (*swpor_thread_fn)(void *arg);

/** 创建并启动线程。 */
int swpor_thread_create(swpor_thread_fn fn, void *arg, swpor_thread_t **out);
/** 等待线程结束并释放句柄。 */
void swpor_thread_join(swpor_thread_t *t);

int swpor_mutex_new(swpor_mutex_t **out);
void swpor_mutex_free(swpor_mutex_t *m);
void swpor_mutex_lock(swpor_mutex_t *m);
void swpor_mutex_unlock(swpor_mutex_t *m);

int swpor_cond_new(swpor_cond_t **out);
void swpor_cond_free(swpor_cond_t *c);
void swpor_cond_wait(swpor_cond_t *c, swpor_mutex_t *m);
void swpor_cond_signal(swpor_cond_t *c);
void swpor_cond_broadcast(swpor_cond_t *c);

int swpor_rwlock_new(swpor_rwlock_t **out);
void swpor_rwlock_free(swpor_rwlock_t *l);
void swpor_rwlock_rdlock(swpor_rwlock_t *l);
void swpor_rwlock_wrlock(swpor_rwlock_t *l);
void swpor_rwlock_rdunlock(swpor_rwlock_t *l);
void swpor_rwlock_wrunlock(swpor_rwlock_t *l);

/* ===================================================================== */
/* 套接字（SPEC 8.1，实现位于 sock_*.c，属于 swpor_net 库）                  */
/* ===================================================================== */

typedef struct swpor_sock swpor_sock_t;

/**
 * 在 host:port 上监听（host 为 NULL 或 "0.0.0.0" 表示所有 IPv4 地址；port 为 0 时由系统分配）。
 * Windows 上返回 SWPOR_E_UNSUPPORTED（SPEC 2.1：Windows 只做客户端）。
 */
int swpor_sock_listen(const char *host, uint16_t port, int backlog, swpor_sock_t **out);

/** 接受一个连接。 */
int swpor_sock_accept(swpor_sock_t *ls, swpor_sock_t **out);

/** 连接到 host:port（TCP）。 */
int swpor_sock_connect(const char *host, uint16_t port, swpor_sock_t **out);

/** 设置读写超时（毫秒，0 表示不超时）。平台差异（timeval / DWORD）在实现中屏蔽（SPEC 8.4）。 */
int swpor_sock_set_timeout(swpor_sock_t *s, uint32_t ms);

/** 发送全部 len 字节。 */
int swpor_sock_send_all(swpor_sock_t *s, const void *buf, size_t len);

/**
 * 接收恰好 len 字节。
 * @return 对端关闭返回 SWPOR_E_NET；超时返回 SWPOR_E_TIMEOUT
 */
int swpor_sock_recv_all(swpor_sock_t *s, void *buf, size_t len);

/** 关闭写方向（半关闭）。 */
void swpor_sock_shutdown_write(swpor_sock_t *s);

/** 获取本地端口（测试中用于 port=0 的监听套接字）。 */
int swpor_sock_local_port(swpor_sock_t *s, uint16_t *port);

/** 关闭并释放套接字。传入 NULL 安全。 */
void swpor_sock_close(swpor_sock_t *s);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_PLATFORM_H */
