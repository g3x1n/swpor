/* 平台抽象层：Windows 实现（只需客户端功能）。见 SPEC 2.1。 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

unsigned swpor_cpu_count(void)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors > 0 ? (unsigned)si.dwNumberOfProcessors : 1u;
}

void swpor_cpu_model(char *out, size_t cap)
{
    if (out == NULL || cap == 0) {
        return;
    }
    DWORD len = (DWORD)cap;
    if (RegGetValueA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                     "ProcessorNameString", RRF_RT_REG_SZ, NULL, out, &len) != ERROR_SUCCESS) {
        (void)snprintf(out, cap, "unknown");
    }
}

uint64_t swpor_mem_total(void)
{
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) {
        return 0;
    }
    return (uint64_t)ms.ullTotalPhys;
}

void swpor_sleep_ms(uint32_t ms)
{
    Sleep(ms);
}

/* ===================================================================== */
/* UTF-8 → UTF-16                                                         */
/* ===================================================================== */

static wchar_t *utf8_to_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    if (n <= 0) {
        return NULL;
    }
    wchar_t *w = malloc((size_t)n * sizeof(wchar_t));
    if (w == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
        free(w);
        return NULL;
    }
    return w;
}

/* ===================================================================== */
/* 文件                                                                   */
/* ===================================================================== */

struct swpor_file {
    HANDLE h;
};

static int wrap_handle(HANDLE h, swpor_file_t **out)
{
    swpor_file_t *f = malloc(sizeof(*f));
    if (f == NULL) {
        CloseHandle(h);
        return SWPOR_E_NOMEM;
    }
    f->h = h;
    *out = f;
    return SWPOR_OK;
}

static int map_open_error(DWORD e)
{
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) {
        return SWPOR_E_NOT_FOUND;
    }
    if (e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS) {
        return SWPOR_E_EXISTS;
    }
    return SWPOR_E_IO;
}

int swpor_file_open(const char *path, swpor_file_mode_t mode, swpor_file_t **out)
{
    if (path == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    DWORD access;
    DWORD disp;
    switch (mode) {
    case SWPOR_FILE_READ:
        access = GENERIC_READ;
        disp = OPEN_EXISTING;
        break;
    case SWPOR_FILE_RDWR:
        access = GENERIC_READ | GENERIC_WRITE;
        disp = OPEN_EXISTING;
        break;
    case SWPOR_FILE_CREATE:
        access = GENERIC_READ | GENERIC_WRITE;
        disp = CREATE_ALWAYS;
        break;
    default:
        return SWPOR_E_INVALID_ARG;
    }
    wchar_t *w = utf8_to_wide(path);
    if (w == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    HANDLE h = CreateFileW(w, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        return map_open_error(GetLastError());
    }
    return wrap_handle(h, out);
}

int swpor_file_create_private(const char *path, int force, swpor_file_t **out)
{
    if (path == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    wchar_t *w = utf8_to_wide(path);
    if (w == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (force) {
        if (!DeleteFileW(w)) {
            DWORD e = GetLastError();
            if (e != ERROR_FILE_NOT_FOUND) {
                free(w);
                return SWPOR_E_IO;
            }
        }
    }
    /* 受保护的 DACL：只允许当前用户（OWNER RIGHTS）完全访问，不继承父目录的 ACE */
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR sd = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;OW)", SDDL_REVISION_1,
                                                              &sd, NULL)) {
        free(w);
        return SWPOR_E_IO;
    }
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    HANDLE h = CreateFileW(w, GENERIC_READ | GENERIC_WRITE, 0, &sa, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD err = GetLastError();
    LocalFree(sd);
    free(w);
    if (h == INVALID_HANDLE_VALUE) {
        return map_open_error(err);
    }
    return wrap_handle(h, out);
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
        size_t want = len - done;
        DWORD chunk = want > 0x40000000u ? 0x40000000u : (DWORD)want;
        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(pos & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)(pos >> 32);
        DWORD r = 0;
        if (!ReadFile(f->h, p + done, chunk, &r, &ov)) {
            if (GetLastError() == ERROR_HANDLE_EOF) {
                break;
            }
            return SWPOR_E_IO;
        }
        if (r == 0) {
            break;
        }
        done += r;
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
        size_t want = len - done;
        DWORD chunk = want > 0x40000000u ? 0x40000000u : (DWORD)want;
        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(pos & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)(pos >> 32);
        DWORD w = 0;
        if (!WriteFile(f->h, p + done, chunk, &w, &ov) || w == 0) {
            return SWPOR_E_IO;
        }
        done += w;
    }
    return SWPOR_OK;
}

int swpor_file_size(swpor_file_t *f, uint64_t *size)
{
    if (f == NULL || size == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    LARGE_INTEGER li;
    if (!GetFileSizeEx(f->h, &li) || li.QuadPart < 0) {
        return SWPOR_E_IO;
    }
    *size = (uint64_t)li.QuadPart;
    return SWPOR_OK;
}

int swpor_file_sync(swpor_file_t *f)
{
    if (f == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    return FlushFileBuffers(f->h) ? SWPOR_OK : SWPOR_E_IO;
}

void swpor_file_close(swpor_file_t *f)
{
    if (f == NULL) {
        return;
    }
    CloseHandle(f->h);
    free(f);
}

int swpor_path_exists(const char *path)
{
    if (path == NULL) {
        return 0;
    }
    wchar_t *w = utf8_to_wide(path);
    if (w == NULL) {
        return 0;
    }
    DWORD attr = GetFileAttributesW(w);
    free(w);
    return attr != INVALID_FILE_ATTRIBUTES;
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
        if (tmp[i] == '/' || tmp[i] == '\\' || tmp[i] == '\0') {
            char saved = tmp[i];
            tmp[i] = '\0';
            /* 跳过盘符 "C:" */
            if (!(i == 2 && tmp[1] == ':')) {
                wchar_t *w = utf8_to_wide(tmp);
                if (w == NULL) {
                    rc = SWPOR_E_INVALID_ARG;
                    break;
                }
                if (!CreateDirectoryW(w, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    free(w);
                    rc = SWPOR_E_IO;
                    break;
                }
                free(w);
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
    wchar_t *w = utf8_to_wide(path);
    if (w == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    BOOL ok = DeleteFileW(w);
    DWORD e = GetLastError();
    free(w);
    if (!ok) {
        return (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? SWPOR_E_NOT_FOUND
                                                                       : SWPOR_E_IO;
    }
    return SWPOR_OK;
}

int swpor_remove_dir(const char *path)
{
    if (path == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    wchar_t *w = utf8_to_wide(path);
    if (w == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    BOOL ok = RemoveDirectoryW(w);
    DWORD e = GetLastError();
    free(w);
    if (!ok) {
        return (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? SWPOR_E_NOT_FOUND
                                                                       : SWPOR_E_IO;
    }
    return SWPOR_OK;
}

int swpor_rename(const char *from, const char *to)
{
    if (from == NULL || to == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    wchar_t *wf = utf8_to_wide(from);
    wchar_t *wt = utf8_to_wide(to);
    int rc = SWPOR_E_INVALID_ARG;
    if (wf != NULL && wt != NULL) {
        rc = MoveFileExW(wf, wt, MOVEFILE_REPLACE_EXISTING) ? SWPOR_OK : SWPOR_E_IO;
    }
    free(wf);
    free(wt);
    return rc;
}

int swpor_path_join(char *out, size_t cap, const char *a, const char *b)
{
    if (out == NULL || a == NULL || b == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t la = strlen(a);
    size_t lb = strlen(b);
    int need_sep = la > 0 && a[la - 1] != '/' && a[la - 1] != '\\';
    size_t total = la + (size_t)need_sep + lb + 1;
    if (total > cap) {
        return SWPOR_E_RANGE;
    }
    memmove(out, a, la);
    if (need_sep) {
        out[la] = '\\';
    }
    memcpy(out + la + (size_t)need_sep, b, lb);
    out[total - 1] = '\0';
    return SWPOR_OK;
}

/* ===================================================================== */
/* 线程与同步                                                              */
/* ===================================================================== */

struct swpor_thread {
    HANDLE h;
    swpor_thread_fn fn;
    void *arg;
};

struct swpor_mutex {
    CRITICAL_SECTION cs;
};

struct swpor_cond {
    CONDITION_VARIABLE cv;
};

struct swpor_rwlock {
    SRWLOCK l;
};

static DWORD WINAPI thread_trampoline(LPVOID p)
{
    swpor_thread_t *t = p;
    t->fn(t->arg);
    return 0;
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
    t->h = CreateThread(NULL, 0, thread_trampoline, t, 0, NULL);
    if (t->h == NULL) {
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
    WaitForSingleObject(t->h, INFINITE);
    CloseHandle(t->h);
    free(t);
}

int swpor_mutex_new(swpor_mutex_t **out)
{
    swpor_mutex_t *m = malloc(sizeof(*m));
    if (m == NULL) {
        return SWPOR_E_NOMEM;
    }
    InitializeCriticalSection(&m->cs);
    *out = m;
    return SWPOR_OK;
}

void swpor_mutex_free(swpor_mutex_t *m)
{
    if (m == NULL) {
        return;
    }
    DeleteCriticalSection(&m->cs);
    free(m);
}

void swpor_mutex_lock(swpor_mutex_t *m)
{
    EnterCriticalSection(&m->cs);
}

void swpor_mutex_unlock(swpor_mutex_t *m)
{
    LeaveCriticalSection(&m->cs);
}

int swpor_cond_new(swpor_cond_t **out)
{
    swpor_cond_t *c = malloc(sizeof(*c));
    if (c == NULL) {
        return SWPOR_E_NOMEM;
    }
    InitializeConditionVariable(&c->cv);
    *out = c;
    return SWPOR_OK;
}

void swpor_cond_free(swpor_cond_t *c)
{
    free(c);
}

void swpor_cond_wait(swpor_cond_t *c, swpor_mutex_t *m)
{
    SleepConditionVariableCS(&c->cv, &m->cs, INFINITE);
}

void swpor_cond_signal(swpor_cond_t *c)
{
    WakeConditionVariable(&c->cv);
}

void swpor_cond_broadcast(swpor_cond_t *c)
{
    WakeAllConditionVariable(&c->cv);
}

int swpor_rwlock_new(swpor_rwlock_t **out)
{
    swpor_rwlock_t *l = malloc(sizeof(*l));
    if (l == NULL) {
        return SWPOR_E_NOMEM;
    }
    InitializeSRWLock(&l->l);
    *out = l;
    return SWPOR_OK;
}

void swpor_rwlock_free(swpor_rwlock_t *l)
{
    free(l);
}

void swpor_rwlock_rdlock(swpor_rwlock_t *l)
{
    AcquireSRWLockShared(&l->l);
}

void swpor_rwlock_wrlock(swpor_rwlock_t *l)
{
    AcquireSRWLockExclusive(&l->l);
}

void swpor_rwlock_rdunlock(swpor_rwlock_t *l)
{
    ReleaseSRWLockShared(&l->l);
}

void swpor_rwlock_wrunlock(swpor_rwlock_t *l)
{
    ReleaseSRWLockExclusive(&l->l);
}

#else
typedef int swpor_platform_win32_unused;
#endif /* _WIN32 */
