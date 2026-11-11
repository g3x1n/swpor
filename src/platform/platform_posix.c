/* 平台抽象层：POSIX 实现（macOS、Linux）。见 SPEC 2.1。 */

#if !defined(_WIN32)

#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#else
#define _GNU_SOURCE 1
#endif

#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif

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

unsigned swpor_cpu_count(void)
{
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n < 1) {
        return 1;
    }
    if (n > 1024) {
        return 1024;
    }
    return (unsigned)n;
}

void swpor_cpu_model(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return;
    }
    (void)snprintf(out, cap, "unknown");
#if defined(__APPLE__)
    size_t len = cap;
    if (sysctlbyname("machdep.cpu.brand_string", out, &len, NULL, 0) != 0) {
        (void)snprintf(out, cap, "unknown");
    }
#elif defined(__linux__)
    FILE *f = fopen("/proc/cpuinfo", "rb");
    if (f == NULL) {
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "model name", 10) == 0) {
            const char *colon = strchr(line, ':');
            if (colon != NULL) {
                colon++;
                while (*colon == ' ' || *colon == '\t') {
                    colon++;
                }
                (void)snprintf(out, cap, "%s", colon);
                size_t l = strlen(out);
                while (l > 0 && (out[l - 1] == '\n' || out[l - 1] == '\r')) {
                    out[--l] = '\0';
                }
            }
            break;
        }
    }
    fclose(f);
#endif
}

uint64_t swpor_mem_total(void)
{
#if defined(__APPLE__)
    uint64_t mem = 0;
    size_t len = sizeof(mem);
    if (sysctlbyname("hw.memsize", &mem, &len, NULL, 0) != 0) {
        return 0;
    }
    return mem;
#else
    long pages = sysconf(_SC_PHYS_PAGES);
    long psize = sysconf(_SC_PAGESIZE);
    if (pages <= 0 || psize <= 0) {
        return 0;
    }
    return (uint64_t)pages * (uint64_t)psize;
#endif
}

void swpor_sleep_ms(uint32_t ms)
{
    struct timespec ts;
    ts.tv_sec = (time_t)(ms / 1000u);
    ts.tv_nsec = (long)(ms % 1000u) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

/* ===================================================================== */
/* 文件                                                                   */
/* ===================================================================== */

struct swpor_file {
    int fd;
};

static int wrap_fd(int fd, swpor_file_t **out)
{
    swpor_file_t *f = malloc(sizeof(*f));
    if (f == NULL) {
        close(fd);
        return SWPOR_E_NOMEM;
    }
    f->fd = fd;
    *out = f;
    return SWPOR_OK;
}

int swpor_file_open(const char *path, swpor_file_mode_t mode, swpor_file_t **out)
{
    if (path == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    int flags;
    switch (mode) {
    case SWPOR_FILE_READ:
        flags = O_RDONLY;
        break;
    case SWPOR_FILE_RDWR:
        flags = O_RDWR;
        break;
    case SWPOR_FILE_CREATE:
        flags = O_RDWR | O_CREAT | O_TRUNC;
        break;
    default:
        return SWPOR_E_INVALID_ARG;
    }
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags, 0644);
    if (fd < 0) {
        return errno == ENOENT ? SWPOR_E_NOT_FOUND : SWPOR_E_IO;
    }
    return wrap_fd(fd, out);
}

int swpor_file_create_private(const char *path, int force, swpor_file_t **out)
{
    if (path == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (force) {
        if (unlink(path) != 0 && errno != ENOENT) {
            return SWPOR_E_IO;
        }
    }
    int flags = O_RDWR | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
    int fd = open(path, flags, 0600);
    if (fd < 0) {
        return errno == EEXIST ? SWPOR_E_EXISTS : SWPOR_E_IO;
    }
    return wrap_fd(fd, out);
}

int swpor_file_pread_some(swpor_file_t *f, void *buf, size_t len, uint64_t off, size_t *got)
{
    if (f == NULL || (buf == NULL && len > 0) || got == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t done = 0;
    uint8_t *p = buf;
    while (done < len) {
        uint64_t pos = off + done;
        if (pos > (uint64_t)INT64_MAX) {
            return SWPOR_E_RANGE;
        }
        int64_t r = (int64_t)pread(f->fd, p + done, len - done, (off_t)pos);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SWPOR_E_IO;
        }
        if (r == 0) {
            break;
        }
        done += (size_t)r;
    }
    *got = done;
    return SWPOR_OK;
}

int swpor_file_pread(swpor_file_t *f, void *buf, size_t len, uint64_t off)
{
    size_t got = 0;
    int rc = swpor_file_pread_some(f, buf, len, off, &got);
    if (rc != SWPOR_OK) {
        return rc;
    }
    return got == len ? SWPOR_OK : SWPOR_E_IO;
}

int swpor_file_pwrite(swpor_file_t *f, const void *buf, size_t len, uint64_t off)
{
    if (f == NULL || (buf == NULL && len > 0)) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t done = 0;
    const uint8_t *p = buf;
    while (done < len) {
        uint64_t pos = off + done;
        if (pos > (uint64_t)INT64_MAX) {
            return SWPOR_E_RANGE;
        }
        int64_t r = (int64_t)pwrite(f->fd, p + done, len - done, (off_t)pos);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return SWPOR_E_IO;
        }
        done += (size_t)r;
    }
    return SWPOR_OK;
}

int swpor_file_size(swpor_file_t *f, uint64_t *size)
{
    if (f == NULL || size == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    struct stat st;
    if (fstat(f->fd, &st) != 0 || st.st_size < 0) {
        return SWPOR_E_IO;
    }
    *size = (uint64_t)st.st_size;
    return SWPOR_OK;
}

int swpor_file_sync(swpor_file_t *f)
{
    if (f == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    return fsync(f->fd) == 0 ? SWPOR_OK : SWPOR_E_IO;
}

void swpor_file_close(swpor_file_t *f)
{
    if (f == NULL) {
        return;
    }
    close(f->fd);
    free(f);
}

int swpor_path_exists(const char *path)
{
    struct stat st;
    return path != NULL && stat(path, &st) == 0;
}

int swpor_mkdir_p(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return SWPOR_E_INVALID_ARG;
    }
    size_t len = strlen(path);
    char *tmp = malloc(len + 1);
    if (tmp == NULL) {
        return SWPOR_E_NOMEM;
    }
    memcpy(tmp, path, len + 1);
    int rc = SWPOR_OK;
    for (size_t i = 1; i <= len; i++) {
        if (tmp[i] == '/' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                rc = SWPOR_E_IO;
                break;
            }
            tmp[i] = saved;
        }
    }
    free(tmp);
    return rc;
}

int swpor_remove_file(const char *path)
{
    if (path == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (unlink(path) != 0) {
        return errno == ENOENT ? SWPOR_E_NOT_FOUND : SWPOR_E_IO;
    }
    return SWPOR_OK;
}

int swpor_remove_dir(const char *path)
{
    if (path == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (rmdir(path) != 0) {
        return errno == ENOENT ? SWPOR_E_NOT_FOUND : SWPOR_E_IO;
    }
    return SWPOR_OK;
}

int swpor_rename(const char *from, const char *to)
{
    if (from == NULL || to == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    return rename(from, to) == 0 ? SWPOR_OK : SWPOR_E_IO;
}

int swpor_path_join(char *out, size_t cap, const char *a, const char *b)
{
    if (out == NULL || a == NULL || b == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int need_sep = la > 0 && a[la - 1] != '/';
    size_t total = la + (size_t)need_sep + lb + 1;
    if (total > cap) {
        return SWPOR_E_RANGE;
    }
    memmove(out, a, la);
    if (need_sep) {
        out[la] = '/';
    }
    memcpy(out + la + (size_t)need_sep, b, lb);
    out[total - 1] = '\0';
    return SWPOR_OK;
}

/* ===================================================================== */
/* 线程与同步                                                              */
/* ===================================================================== */

struct swpor_thread {
    pthread_t tid;
    swpor_thread_fn fn;
    void *arg;
};

struct swpor_mutex {
    pthread_mutex_t m;
};

struct swpor_cond {
    pthread_cond_t c;
};

struct swpor_rwlock {
    pthread_rwlock_t l;
};

static void *thread_trampoline(void *p)
{
    swpor_thread_t *t = p;
    t->fn(t->arg);
    return NULL;
}

int swpor_thread_create(swpor_thread_fn fn, void *arg, swpor_thread_t **out)
{
    if (fn == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_thread_t *t = malloc(sizeof(*t));
    if (t == NULL) {
        return SWPOR_E_NOMEM;
    }
    t->fn = fn;
    t->arg = arg;
    if (pthread_create(&t->tid, NULL, thread_trampoline, t) != 0) {
        free(t);
        return SWPOR_E_NOMEM;
    }
    *out = t;
    return SWPOR_OK;
}

void swpor_thread_join(swpor_thread_t *t)
{
    if (t == NULL) {
        return;
    }
    pthread_join(t->tid, NULL);
    free(t);
}

int swpor_mutex_new(swpor_mutex_t **out)
{
    swpor_mutex_t *m = malloc(sizeof(*m));
    if (m == NULL) {
        return SWPOR_E_NOMEM;
    }
    if (pthread_mutex_init(&m->m, NULL) != 0) {
        free(m);
        return SWPOR_E_NOMEM;
    }
    *out = m;
    return SWPOR_OK;
}

void swpor_mutex_free(swpor_mutex_t *m)
{
    if (m == NULL) {
        return;
    }
    pthread_mutex_destroy(&m->m);
    free(m);
}

void swpor_mutex_lock(swpor_mutex_t *m)
{
    pthread_mutex_lock(&m->m);
}

void swpor_mutex_unlock(swpor_mutex_t *m)
{
    pthread_mutex_unlock(&m->m);
}

int swpor_cond_new(swpor_cond_t **out)
{
    swpor_cond_t *c = malloc(sizeof(*c));
    if (c == NULL) {
        return SWPOR_E_NOMEM;
    }
    if (pthread_cond_init(&c->c, NULL) != 0) {
        free(c);
        return SWPOR_E_NOMEM;
    }
    *out = c;
    return SWPOR_OK;
}

void swpor_cond_free(swpor_cond_t *c)
{
    if (c == NULL) {
        return;
    }
    pthread_cond_destroy(&c->c);
    free(c);
}

void swpor_cond_wait(swpor_cond_t *c, swpor_mutex_t *m)
{
    pthread_cond_wait(&c->c, &m->m);
}

void swpor_cond_signal(swpor_cond_t *c)
{
    pthread_cond_signal(&c->c);
}

void swpor_cond_broadcast(swpor_cond_t *c)
{
    pthread_cond_broadcast(&c->c);
}

int swpor_rwlock_new(swpor_rwlock_t **out)
{
    swpor_rwlock_t *l = malloc(sizeof(*l));
    if (l == NULL) {
        return SWPOR_E_NOMEM;
    }
    if (pthread_rwlock_init(&l->l, NULL) != 0) {
        free(l);
        return SWPOR_E_NOMEM;
    }
    *out = l;
    return SWPOR_OK;
}

void swpor_rwlock_free(swpor_rwlock_t *l)
{
    if (l == NULL) {
        return;
    }
    pthread_rwlock_destroy(&l->l);
    free(l);
}

void swpor_rwlock_rdlock(swpor_rwlock_t *l)
{
    pthread_rwlock_rdlock(&l->l);
}

void swpor_rwlock_wrlock(swpor_rwlock_t *l)
{
    pthread_rwlock_wrlock(&l->l);
}

void swpor_rwlock_rdunlock(swpor_rwlock_t *l)
{
    pthread_rwlock_unlock(&l->l);
}

void swpor_rwlock_wrunlock(swpor_rwlock_t *l)
{
    pthread_rwlock_unlock(&l->l);
}

#else
/* 避免 ISO C 的"空翻译单元"警告 */
typedef int swpor_platform_posix_unused;
#endif /* !_WIN32 */
