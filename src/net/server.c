/*
 * 存储服务端（SPEC 8.4）：固定大小线程池 + 有界任务队列。
 *   主线程 accept → 放入队列（满则回 ERROR(BUSY) 并关闭）→ 工作线程用阻塞 I/O 处理整个连接。
 *   每文件一个读写锁：STORE 与 DELETE 持写锁，CHALLENGE / GET_* 持读锁。
 * 所有输入都视为不可信（SPEC 11）：长度、范围、l 上限、帧大小均做检查。
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "endian.h"
#include "internal.h"
#include "platform.h"
#include "swpor/error.h"
#include "swpor/net.h"
#include "swpor/params.h"
#include "swpor/store.h"

/* ===================================================================== */
/* 每文件读写锁表                                                          */
/* ===================================================================== */

typedef struct file_lock {
    uint8_t file_id[32];
    swpor_rwlock_t *lock;
    unsigned refs;
    struct file_lock *next;
} file_lock_t;

typedef struct {
    swpor_mutex_t *mu;
    file_lock_t *head;
} lock_table_t;

static file_lock_t *lock_acquire(lock_table_t *t, const uint8_t file_id[32])
{
    swpor_mutex_lock(t->mu);
    file_lock_t *e = t->head;
    while (e != NULL && memcmp(e->file_id, file_id, 32) != 0) {
        e = e->next;
    }
    if (e == NULL) {
        e = calloc(1, sizeof(*e));
        if (e != NULL && swpor_rwlock_new(&e->lock) != SWPOR_OK) {
            free(e);
            e = NULL;
        }
        if (e != NULL) {
            memcpy(e->file_id, file_id, 32);
            e->next = t->head;
            t->head = e;
        }
    }
    if (e != NULL) {
        e->refs++;
    }
    swpor_mutex_unlock(t->mu);
    return e;
}

static void lock_release(lock_table_t *t, file_lock_t *e)
{
    swpor_mutex_lock(t->mu);
    if (--e->refs == 0) {
        file_lock_t **pp = &t->head;
        while (*pp != e) {
            pp = &(*pp)->next;
        }
        *pp = e->next;
        swpor_rwlock_free(e->lock);
        free(e);
    }
    swpor_mutex_unlock(t->mu);
}

/* ===================================================================== */
/* 服务端对象                                                              */
/* ===================================================================== */

struct swpor_server {
    swpor_server_config_t cfg;
    char *data_dir;
    swpor_sock_t *listener;
    uint16_t port;
    volatile int stopping;

    /* 有界队列（环形缓冲） */
    swpor_mutex_t *qmu;
    swpor_cond_t *qcv;
    swpor_sock_t **queue;
    unsigned qcap, qhead, qlen;

    swpor_thread_t **workers;
    unsigned nworkers;
    lock_table_t locks;
};

static void slog(swpor_server_t *s, int level, const char *fmt, const char *a, int b)
{
    if (s->cfg.log == NULL) {
        return;
    }
    char msg[256];
    (void)snprintf(msg, sizeof(msg), fmt, a, b);
    s->cfg.log(s->cfg.log_user, level, msg);
}

/* 回 ERROR：code = |err|（SPEC 8.3） */
static void send_error(swpor_sock_t *sock, int err, const char *msg)
{
    size_t ml = strlen(msg);
    if (ml > 200) {
        ml = 200;
    }
    uint8_t buf[204];
    swpor_store_be16(buf, (uint16_t)(err < 0 ? -err : err));
    swpor_store_be16(buf + 2, (uint16_t)ml);
    memcpy(buf + 4, msg, ml);
    (void)swpor_frame_send(sock, SWPOR_MSG_ERROR, buf, 4 + ml);
}

/* ===================================================================== */
/* 连接处理                                                               */
/* ===================================================================== */

typedef struct {
    swpor_server_t *srv;
    swpor_sock_t *sock;
    swpor_ctx_t *ctx;
    /* 进行中的 STORE */
    swpor_store_t *st;
    file_lock_t *st_lock;
    uint8_t st_tag[SWPOR_TAG_MAX_BYTES];
    size_t st_tag_len;
    uint8_t *got_block; /* 位图：每个位置是否已收到 */
    uint8_t *got_sigma;
    uint64_t nblocks_got;
    uint64_t nsigmas_got;
} conn_t;

static void store_abort(conn_t *c)
{
    if (c->st == NULL) {
        return;
    }
    swpor_store_close(c->st);
    c->st = NULL;
    /* 未完成的上传：删除残留文件 */
    (void)swpor_store_delete(c->srv->data_dir, c->st_tag + 8);
    swpor_rwlock_wrunlock(c->st_lock->lock);
    lock_release(&c->srv->locks, c->st_lock);
    c->st_lock = NULL;
    free(c->got_block);
    free(c->got_sigma);
    c->got_block = c->got_sigma = NULL;
}

static int bit_test_set(uint8_t *bm, uint64_t i)
{
    uint8_t mask = (uint8_t)(1u << (i & 7u));
    int was = (bm[i >> 3] & mask) != 0;
    bm[i >> 3] |= mask;
    return was;
}

/* STORE_BEGIN：tag_len u32 ‖ tag ‖ n u64 ‖ block_bytes u32 ‖ sigma_bytes u8 */
static int on_store_begin(conn_t *c, const uint8_t *p, size_t len)
{
    if (c->st != NULL) {
        return SWPOR_E_PARSE; /* 不允许嵌套 */
    }
    if (len < 4) {
        return SWPOR_E_PARSE;
    }
    uint32_t tl = swpor_load_be32(p);
    if (tl > SWPOR_TAG_MAX_BYTES || len != 4u + tl + 13u) {
        return SWPOR_E_PARSE;
    }
    swpor_tag_header_t h;
    int rc = swpor_tag_header_decode(p + 4, tl, &h);
    if (rc != SWPOR_OK) {
        return rc;
    }
    uint64_t n = swpor_load_be64(p + 4 + tl);
    uint32_t bb = swpor_load_be32(p + 12 + tl);
    uint8_t sb = p[16 + tl];
    /* 标签长度、n、块大小、σ 大小必须与明文头一致 */
    size_t expect_tl = h.scheme == SWPOR_SCHEME_PUB ? SWPOR_PUB_TAG_BYTES
                       : (h.flags & (SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT)) ? SWPOR_PRIV_TAG_BYTES_LONG
                                                                           : SWPOR_PRIV_TAG_BYTES_SHORT;
    if (tl != expect_tl || n != h.n || bb != swpor_block_bytes(h.s) ||
        sb != swpor_sigma_bytes(h.scheme)) {
        return SWPOR_E_PARSE;
    }
    c->st_lock = lock_acquire(&c->srv->locks, h.file_id);
    if (c->st_lock == NULL) {
        return SWPOR_E_NOMEM;
    }
    swpor_rwlock_wrlock(c->st_lock->lock);
    swpor_store_t *existing = NULL;
    rc = swpor_store_open(c->srv->data_dir, h.file_id, 0, &existing);
    if (rc == SWPOR_OK) {
        swpor_store_close(existing);
        rc = SWPOR_E_EXISTS; /* 不覆盖已有文件 */
    } else if (rc == SWPOR_E_NOT_FOUND || rc == SWPOR_E_PARSE) {
        rc = SWPOR_OK;
    }
    if (rc == SWPOR_OK) {
        c->got_block = calloc((size_t)(n / 8u + 1u), 1);
        c->got_sigma = calloc((size_t)(n / 8u + 1u), 1);
        rc = (c->got_block == NULL || c->got_sigma == NULL) ? SWPOR_E_NOMEM : SWPOR_OK;
    }
    if (rc == SWPOR_OK) {
        rc = swpor_store_create(c->srv->data_dir, h.file_id, h.scheme, n, h.s, &c->st);
    }
    if (rc != SWPOR_OK) {
        free(c->got_block);
        free(c->got_sigma);
        c->got_block = c->got_sigma = NULL;
        swpor_rwlock_wrunlock(c->st_lock->lock);
        lock_release(&c->srv->locks, c->st_lock);
        c->st_lock = NULL;
        return rc;
    }
    memcpy(c->st_tag, p + 4, tl);
    c->st_tag_len = tl;
    c->nblocks_got = c->nsigmas_got = 0;
    return SWPOR_OK;
}

/* STORE_BLOCKS / STORE_SIGMAS：start u64 ‖ count u32 ‖ 数据 */
static int on_store_range(conn_t *c, int sigmas, const uint8_t *p, size_t len)
{
    if (c->st == NULL || len < 12) {
        return SWPOR_E_PARSE;
    }
    uint64_t start = swpor_load_be64(p);
    uint32_t count = swpor_load_be32(p + 8);
    uint64_t n = swpor_store_n(c->st);
    size_t unit = sigmas ? swpor_store_sigma_bytes(c->st) : swpor_store_block_bytes(c->st);
    if (count == 0 || start >= n || count > n - start || (uint64_t)(len - 12) != (uint64_t)count * unit) {
        return SWPOR_E_RANGE;
    }
    for (uint32_t k = 0; k < count; k++) {
        uint64_t i = start + k;
        const uint8_t *d = p + 12 + (size_t)k * unit;
        int rc = sigmas ? swpor_store_write_sigma(c->st, i, d) : swpor_store_write_block(c->st, i, d);
        if (rc != SWPOR_OK) {
            return rc;
        }
        if (!bit_test_set(sigmas ? c->got_sigma : c->got_block, i)) {
            if (sigmas) {
                c->nsigmas_got++;
            } else {
                c->nblocks_got++;
            }
        }
    }
    return SWPOR_OK;
}

static int on_store_end(conn_t *c, size_t len)
{
    if (c->st == NULL || len != 0) {
        return SWPOR_E_PARSE;
    }
    uint64_t n = swpor_store_n(c->st);
    if (c->nblocks_got != n || c->nsigmas_got != n) {
        return SWPOR_E_RANGE; /* 数据不完整 */
    }
    int rc = swpor_store_write_tag(c->st, c->st_tag, c->st_tag_len);
    if (rc != SWPOR_OK) {
        return rc;
    }
    swpor_store_close(c->st);
    c->st = NULL;
    swpor_rwlock_wrunlock(c->st_lock->lock);
    lock_release(&c->srv->locks, c->st_lock);
    c->st_lock = NULL;
    free(c->got_block);
    free(c->got_sigma);
    c->got_block = c->got_sigma = NULL;
    char hex[65];
    swpor_hex_encode(c->st_tag + 8, 32, hex);
    slog(c->srv, 0, "stored %s (%d blocks)", hex, (int)(n > 0x7FFFFFFF ? 0x7FFFFFFF : n));
    return swpor_frame_send(c->sock, SWPOR_MSG_STORE_OK, c->st_tag + 8, 32);
}

/* 以读锁打开文件，执行 fn */
typedef int (*read_op_fn)(conn_t *c, swpor_store_t *st, const uint8_t *p, size_t len);

static int with_file(conn_t *c, const uint8_t *p, size_t len, read_op_fn fn)
{
    if (len < 32) {
        return SWPOR_E_PARSE;
    }
    file_lock_t *fl = lock_acquire(&c->srv->locks, p);
    if (fl == NULL) {
        return SWPOR_E_NOMEM;
    }
    swpor_rwlock_rdlock(fl->lock);
    swpor_store_t *st = NULL;
    int rc = swpor_store_open(c->srv->data_dir, p, 0, &st);
    if (rc == SWPOR_OK) {
        rc = fn(c, st, p, len);
        swpor_store_close(st);
    } else if (rc == SWPOR_E_PARSE) {
        rc = SWPOR_E_NOT_FOUND; /* 文件不完整或损坏：对外视为不存在 */
    }
    swpor_rwlock_rdunlock(fl->lock);
    lock_release(&c->srv->locks, fl);
    return rc;
}

/* CHALLENGE：解析与校验见 swpor_chal_decode_wire（frame.c） */
static int op_challenge(conn_t *c, swpor_store_t *st, const uint8_t *p, size_t len)
{
    const swpor_tag_header_t *h = swpor_store_header(st);
    swpor_chal_t *chal = NULL;
    int rc = swpor_chal_decode_wire(p, len, h->n, c->srv->cfg.max_l, &chal);
    if (rc != SWPOR_OK) {
        return rc;
    }
    size_t cap = swpor_proof_bytes(h->scheme, h->s);
    uint8_t *proof = malloc(cap);
    size_t plen = 0;
    rc = proof == NULL ? SWPOR_E_NOMEM
                       : swpor_prove(c->ctx, h, chal, swpor_store_reader, st, proof, cap, &plen);
    if (rc == SWPOR_OK) {
        rc = swpor_frame_send(c->sock, SWPOR_MSG_PROOF, proof, plen);
    }
    free(proof);
    swpor_chal_free(chal);
    return rc;
}

static int op_get_tag(conn_t *c, swpor_store_t *st, const uint8_t *p, size_t len)
{
    (void)p;
    if (len != 32) {
        return SWPOR_E_PARSE;
    }
    size_t tl = 0;
    const uint8_t *tag = swpor_store_tag(st, &tl);
    uint8_t buf[4 + SWPOR_TAG_MAX_BYTES];
    swpor_store_be32(buf, (uint32_t)tl);
    memcpy(buf + 4, tag, tl);
    return swpor_frame_send(c->sock, SWPOR_MSG_TAG, buf, 4 + tl);
}

/* GET_BLOCKS / GET_SIGMAS：file_id ‖ start u64 ‖ count u32 */
static int get_range(conn_t *c, swpor_store_t *st, const uint8_t *p, size_t len, int sigmas)
{
    if (len != 44) {
        return SWPOR_E_PARSE;
    }
    uint64_t start = swpor_load_be64(p + 32);
    uint32_t count = swpor_load_be32(p + 40);
    uint64_t n = swpor_store_n(st);
    size_t unit = sigmas ? swpor_store_sigma_bytes(st) : swpor_store_block_bytes(st);
    if (count == 0 || start >= n || count > n - start ||
        (uint64_t)count * unit + 13u > SWPOR_MAX_FRAME_BYTES) {
        return SWPOR_E_RANGE;
    }
    size_t dl = (size_t)count * unit;
    uint8_t *buf = malloc(12u + dl);
    if (buf == NULL) {
        return SWPOR_E_NOMEM;
    }
    swpor_store_be64(buf, start);
    swpor_store_be32(buf + 8, count);
    int rc = SWPOR_OK;
    for (uint32_t k = 0; k < count && rc == SWPOR_OK; k++) {
        uint8_t *d = buf + 12 + (size_t)k * unit;
        rc = sigmas ? swpor_store_read_sigma(st, start + k, d)
                    : swpor_store_read_block(st, start + k, d);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_frame_send(c->sock, sigmas ? SWPOR_MSG_SIGMAS : SWPOR_MSG_BLOCKS, buf, 12u + dl);
    }
    free(buf);
    return rc;
}

static int op_get_blocks(conn_t *c, swpor_store_t *st, const uint8_t *p, size_t len)
{
    return get_range(c, st, p, len, 0);
}

static int op_get_sigmas(conn_t *c, swpor_store_t *st, const uint8_t *p, size_t len)
{
    return get_range(c, st, p, len, 1);
}

/* DELETE：持写锁，确认文件存在后删除（SPEC 8.4：与 STORE 互斥） */
static int on_delete(conn_t *c, const uint8_t *p, size_t len)
{
    if (len != 32) {
        return SWPOR_E_PARSE;
    }
    file_lock_t *fl = lock_acquire(&c->srv->locks, p);
    if (fl == NULL) {
        return SWPOR_E_NOMEM;
    }
    swpor_rwlock_wrlock(fl->lock);
    swpor_store_t *st = NULL;
    int rc = swpor_store_open(c->srv->data_dir, p, 0, &st);
    if (rc == SWPOR_OK) {
        swpor_store_close(st);
        rc = swpor_store_delete(c->srv->data_dir, p);
    } else if (rc == SWPOR_E_PARSE) {
        rc = SWPOR_E_NOT_FOUND;
    }
    swpor_rwlock_wrunlock(fl->lock);
    lock_release(&c->srv->locks, fl);
    if (rc == SWPOR_OK) {
        rc = swpor_frame_send(c->sock, SWPOR_MSG_OK, NULL, 0);
    }
    return rc;
}

static int dispatch(conn_t *c, uint8_t type, const uint8_t *p, size_t len)
{
    /* 上传过程中本连接持有该文件的写锁，只允许继续 STORE_*（否则同一线程再加锁会死锁） */
    if (c->st != NULL && type != SWPOR_MSG_STORE_BLOCKS && type != SWPOR_MSG_STORE_SIGMAS &&
        type != SWPOR_MSG_STORE_END) {
        return SWPOR_E_PARSE;
    }
    switch (type) {
    case SWPOR_MSG_STORE_BEGIN:
        return on_store_begin(c, p, len);
    case SWPOR_MSG_STORE_BLOCKS:
        return on_store_range(c, 0, p, len);
    case SWPOR_MSG_STORE_SIGMAS:
        return on_store_range(c, 1, p, len);
    case SWPOR_MSG_STORE_END:
        return on_store_end(c, len);
    case SWPOR_MSG_CHALLENGE:
        return with_file(c, p, len, op_challenge);
    case SWPOR_MSG_GET_TAG:
        return with_file(c, p, len, op_get_tag);
    case SWPOR_MSG_GET_BLOCKS:
        return with_file(c, p, len, op_get_blocks);
    case SWPOR_MSG_GET_SIGMAS:
        return with_file(c, p, len, op_get_sigmas);
    case SWPOR_MSG_DELETE:
        return on_delete(c, p, len);
    default:
        return SWPOR_E_UNSUPPORTED; /* 未知 type（SPEC 8.2） */
    }
}

static void handle_conn(swpor_server_t *srv, swpor_sock_t *sock)
{
    conn_t c;
    memset(&c, 0, sizeof(c));
    c.srv = srv;
    c.sock = sock;
    if (swpor_ctx_new(&c.ctx) == SWPOR_OK && srv->cfg.trace != NULL) {
        swpor_set_trace(c.ctx, srv->cfg.trace, srv->cfg.trace_user);
    }
    (void)swpor_sock_set_timeout(sock, srv->cfg.timeout_ms);

    int hello = 0;
    for (;;) {
        uint8_t type = 0;
        uint8_t *p = NULL;
        size_t len = 0;
        int rc = swpor_frame_recv(sock, SWPOR_MAX_FRAME_BYTES, &type, &p, &len);
        if (rc == SWPOR_E_NET || rc == SWPOR_E_TIMEOUT) {
            free(p);
            break; /* 连接关闭或超时 */
        }
        if (rc != SWPOR_OK) {
            send_error(sock, rc, rc == SWPOR_E_RANGE ? "frame too large" : "bad frame");
            free(p);
            break;
        }
        if (!hello) {
            if (type != SWPOR_MSG_HELLO || len != 2) {
                send_error(sock, SWPOR_E_PARSE, "expected HELLO");
                free(p);
                break;
            }
            if (swpor_load_be16(p) != SWPOR_PROTO_VERSION) {
                send_error(sock, SWPOR_E_UNSUPPORTED, "unsupported protocol version");
                free(p);
                break;
            }
            uint8_t ok[6];
            swpor_store_be16(ok, SWPOR_PROTO_VERSION);
            swpor_store_be32(ok + 2, 0); /* server_caps：v1 无扩展能力 */
            free(p);
            if (swpor_frame_send(sock, SWPOR_MSG_HELLO_OK, ok, sizeof(ok)) != SWPOR_OK) {
                break;
            }
            hello = 1;
            continue;
        }
        rc = dispatch(&c, type, p, len);
        free(p);
        if (rc != SWPOR_OK) {
            /* SPEC 8.2：解析失败等一律返回 ERROR 并关闭连接 */
            send_error(sock, rc, swpor_strerror(rc));
            slog(srv, 1, "request failed: %s (%d)", swpor_strerror(rc), rc);
            break;
        }
    }
    store_abort(&c);
    swpor_ctx_free(c.ctx);
    swpor_sock_close(sock);
}

/* ===================================================================== */
/* 线程池                                                                 */
/* ===================================================================== */

static void worker_main(void *arg)
{
    swpor_server_t *s = arg;
    for (;;) {
        swpor_mutex_lock(s->qmu);
        while (s->qlen == 0 && !s->stopping) {
            swpor_cond_wait(s->qcv, s->qmu);
        }
        if (s->qlen == 0 && s->stopping) {
            swpor_mutex_unlock(s->qmu);
            return;
        }
        swpor_sock_t *sock = s->queue[s->qhead];
        s->qhead = (s->qhead + 1u) % s->qcap;
        s->qlen--;
        swpor_mutex_unlock(s->qmu);
        handle_conn(s, sock);
    }
}

void swpor_server_free(swpor_server_t *s)
{
    if (s == NULL) {
        return;
    }
    if (s->workers != NULL) {
        swpor_mutex_lock(s->qmu);
        s->stopping = 1;
        swpor_cond_broadcast(s->qcv);
        swpor_mutex_unlock(s->qmu);
        for (unsigned k = 0; k < s->nworkers; k++) {
            swpor_thread_join(s->workers[k]);
        }
        free(s->workers);
    }
    if (s->queue != NULL) {
        for (unsigned k = 0; k < s->qlen; k++) {
            swpor_sock_close(s->queue[(s->qhead + k) % s->qcap]);
        }
        free(s->queue);
    }
    swpor_sock_close(s->listener);
    swpor_cond_free(s->qcv);
    swpor_mutex_free(s->qmu);
    swpor_mutex_free(s->locks.mu);
    free(s->data_dir);
    free(s);
}

int swpor_server_new(const swpor_server_config_t *cfg, swpor_server_t **out)
{
    if (cfg == NULL || cfg->data_dir == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_server_t *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return SWPOR_E_NOMEM;
    }
    s->cfg = *cfg;
    if (s->cfg.max_l == 0) {
        s->cfg.max_l = SWPOR_DEFAULT_MAX_L;
    }
    if (s->cfg.threads == 0) {
        s->cfg.threads = swpor_cpu_count();
    }
    if (s->cfg.queue_cap == 0) {
        s->cfg.queue_cap = 4u * s->cfg.threads;
    }
    if (s->cfg.timeout_ms == 0) {
        s->cfg.timeout_ms = SWPOR_DEFAULT_IO_TIMEOUT_MS;
    }
    size_t dl = strlen(cfg->data_dir);
    s->data_dir = malloc(dl + 1);
    int rc = s->data_dir == NULL ? SWPOR_E_NOMEM : SWPOR_OK;
    if (rc == SWPOR_OK) {
        memcpy(s->data_dir, cfg->data_dir, dl + 1);
        rc = swpor_mkdir_p(s->data_dir);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_mutex_new(&s->qmu);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_cond_new(&s->qcv);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_mutex_new(&s->locks.mu);
    }
    if (rc == SWPOR_OK) {
        s->qcap = s->cfg.queue_cap;
        s->queue = calloc(s->qcap, sizeof(*s->queue));
        rc = s->queue == NULL ? SWPOR_E_NOMEM : SWPOR_OK;
    }
    if (rc == SWPOR_OK) {
        rc = swpor_sock_listen(cfg->host, cfg->port, 128, &s->listener);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_sock_local_port(s->listener, &s->port);
    }
    if (rc == SWPOR_OK) {
        s->workers = calloc(s->cfg.threads, sizeof(*s->workers));
        rc = s->workers == NULL ? SWPOR_E_NOMEM : SWPOR_OK;
    }
    for (unsigned k = 0; rc == SWPOR_OK && k < s->cfg.threads; k++) {
        rc = swpor_thread_create(worker_main, s, &s->workers[k]);
        if (rc == SWPOR_OK) {
            s->nworkers++;
        }
    }
    if (rc != SWPOR_OK) {
        swpor_server_free(s);
        return rc;
    }
    *out = s;
    return SWPOR_OK;
}

uint16_t swpor_server_port(const swpor_server_t *s)
{
    return s->port;
}

int swpor_server_run(swpor_server_t *s)
{
    if (s == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    slog(s, 0, "listening on port %s%d", "", (int)s->port);
    while (!s->stopping) {
        swpor_sock_t *conn = NULL;
        int rc = swpor_sock_accept(s->listener, &conn);
        if (rc != SWPOR_OK) {
            if (s->stopping) {
                break;
            }
            continue;
        }
        if (s->stopping) {
            swpor_sock_close(conn);
            break;
        }
        swpor_mutex_lock(s->qmu);
        int full = s->qlen >= s->qcap;
        if (!full) {
            s->queue[(s->qhead + s->qlen) % s->qcap] = conn;
            s->qlen++;
            swpor_cond_signal(s->qcv);
        }
        swpor_mutex_unlock(s->qmu);
        if (full) {
            /* 有界队列已满：直接回 BUSY 并关闭，不无限排队（SPEC 8.4） */
            (void)swpor_sock_set_timeout(conn, 1000);
            send_error(conn, SWPOR_E_BUSY, "server busy");
            swpor_sock_close(conn);
            slog(s, 1, "queue full, rejected connection%s%d", "", 0);
        }
    }
    return SWPOR_OK;
}

void swpor_server_stop(swpor_server_t *s)
{
    if (s == NULL) {
        return;
    }
    s->stopping = 1;
    /* 连接自己一次，唤醒阻塞在 accept 上的主线程 */
    swpor_sock_t *wake = NULL;
    if (swpor_sock_connect("127.0.0.1", s->port, &wake) == SWPOR_OK) {
        swpor_sock_close(wake);
    }
}
