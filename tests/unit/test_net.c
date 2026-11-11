/*
 * M3 测试：网络协议与服务端（SPEC 8），T-15～T-18。
 * 在进程内启动服务端（端口由系统分配），客户端通过 127.0.0.1 访问。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "endian.h"
#include "mem_backend.h"
#include "platform.h"
#include "swpor/net.h"
#include "swpor/swpor.h"

static char g_dir[256];
static swpor_priv_key_t *g_key;
static swpor_pub_sk_t *g_psk;
static swpor_pub_pk_t *g_ppk;

typedef struct {
    swpor_server_t *srv;
    swpor_thread_t *th;
} server_handle_t;

static void server_thread(void *arg)
{
    (void)swpor_server_run((swpor_server_t *)arg);
}

static server_handle_t start_server(unsigned threads, unsigned queue_cap, uint32_t timeout_ms)
{
    server_handle_t h;
    swpor_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.data_dir = g_dir;
    cfg.host = "127.0.0.1";
    cfg.threads = threads;
    cfg.queue_cap = queue_cap;
    cfg.timeout_ms = timeout_ms;
    cfg.max_l = 512;
    assert_int_equal(swpor_server_new(&cfg, &h.srv), SWPOR_OK);
    assert_int_equal(swpor_thread_create(server_thread, h.srv, &h.th), SWPOR_OK);
    return h;
}

static void stop_server(server_handle_t *h)
{
    swpor_server_stop(h->srv);
    swpor_thread_join(h->th);
    swpor_server_free(h->srv);
}

static int setup(void **state)
{
    (void)state;
    (void)snprintf(g_dir, sizeof(g_dir), "swpor_test_net_%u", (unsigned)(swpor_time_ns() % 1000000));
    if (swpor_platform_init() != SWPOR_OK || swpor_priv_keygen(&g_key) != SWPOR_OK ||
        swpor_pub_keygen(&g_psk, &g_ppk) != SWPOR_OK) {
        return -1;
    }
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    swpor_priv_key_free(g_key);
    swpor_pub_sk_free(g_psk);
    swpor_pub_pk_free(g_ppk);
    swpor_platform_cleanup();
    return 0;
}

static swpor_keys_t keys_for(uint8_t scheme)
{
    swpor_keys_t k;
    memset(&k, 0, sizeof(k));
    k.scheme = scheme;
    k.priv_key = g_key;
    k.pub_sk = g_psk;
    k.pub_pk = g_ppk;
    return k;
}

/* 通过网络上传随机文件，返回 file_id 与标签 */
static void remote_store(uint16_t port, uint8_t scheme, uint16_t flags, size_t len, uint8_t *data,
                         uint8_t file_id[32], uint8_t *tag, size_t *tag_len)
{
    swpor_client_t *c = NULL;
    assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
    swpor_remote_t *r = NULL;
    assert_int_equal(swpor_remote_new(c, &r), SWPOR_OK);
    assert_int_equal(swpor_random_bytes(data, len), SWPOR_OK);
    mem_input_t in = {data, len, 0};
    swpor_keys_t keys = keys_for(scheme);
    swpor_st_params_t p = {16, flags, 4, 4};
    swpor_tag_header_t h;
    assert_int_equal(swpor_st_run(NULL, &keys, &p, len, mem_input, &in, swpor_remote_sink(), r, tag,
                                  SWPOR_TAG_MAX_BYTES, tag_len, &h),
                     SWPOR_OK);
    memcpy(file_id, swpor_remote_file_id(r), 32);
    assert_memory_equal(file_id, h.file_id, 32);
    swpor_remote_free(r);
    swpor_client_close(c);
}

static int remote_audit(uint16_t port, uint8_t scheme, const uint8_t file_id[32], const uint8_t *tag,
                        size_t tag_len, uint32_t l, int seed)
{
    swpor_client_t *c = NULL;
    assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
    swpor_remote_t *r = NULL;
    assert_int_equal(swpor_remote_new(c, &r), SWPOR_OK);
    swpor_remote_set_file_id(r, file_id);
    swpor_keys_t keys = keys_for(scheme);
    swpor_audit_result_t res;
    assert_int_equal(swpor_audit_run(NULL, &keys, tag, tag_len, l, seed, swpor_remote_prove, r, &res),
                     SWPOR_OK);
    swpor_remote_free(r);
    swpor_client_close(c);
    return res.pass;
}

static int local_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap, size_t *len)
{
    swpor_store_t *st = user;
    return swpor_prove(NULL, swpor_store_header(st), chal, swpor_store_reader, st, proof, cap, len);
}

/* ---------------- T-15：本地模式与远程模式结果一致 ---------------- */

static void test_T15_local_and_remote_agree(void **state)
{
    (void)state;
    server_handle_t sh = start_server(2, 8, 5000);
    uint16_t port = swpor_server_port(sh.srv);
    static const struct {
        uint8_t scheme;
        uint16_t flags;
    } cases[] = {{SWPOR_SCHEME_PRIV, SWPOR_FLAG_RS},
                 {SWPOR_SCHEME_PRIV, SWPOR_FLAG_RS | SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT},
                 {SWPOR_SCHEME_PUB, SWPOR_FLAG_RS},
                 {SWPOR_SCHEME_PUB, 0}};
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        const size_t len = 30000;
        uint8_t *data = malloc(len);
        assert_non_null(data);
        uint8_t fid[32];
        uint8_t tag[SWPOR_TAG_MAX_BYTES];
        size_t tl;
        remote_store(port, cases[k].scheme, cases[k].flags, len, data, fid, tag, &tl);

        /* 远程审计（显式与种子） */
        assert_int_equal(remote_audit(port, cases[k].scheme, fid, tag, tl, 20, 0), 1);
        assert_int_equal(remote_audit(port, cases[k].scheme, fid, tag, tl, 20, 1), 1);

        /* 直接读服务端的数据目录做本地审计：结果一致 */
        swpor_store_t *st = NULL;
        assert_int_equal(swpor_store_open(g_dir, fid, 0, &st), SWPOR_OK);
        swpor_keys_t keys = keys_for(cases[k].scheme);
        swpor_audit_result_t res;
        assert_int_equal(swpor_audit_run(NULL, &keys, tag, tl, 20, 0, local_prove, st, &res),
                         SWPOR_OK);
        assert_int_equal(res.pass, 1);
        swpor_store_close(st);

        /* 远程检索：下载到本地目录再解码 */
        char dl[300];
        (void)snprintf(dl, sizeof(dl), "%s_dl", g_dir);
        swpor_client_t *c = NULL;
        assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
        assert_int_equal(swpor_remote_download(c, fid, dl), SWPOR_OK);
        uint8_t tag2[SWPOR_TAG_MAX_BYTES];
        size_t tl2;
        assert_int_equal(swpor_client_get_tag(c, fid, tag2, sizeof(tag2), &tl2), SWPOR_OK);
        assert_int_equal(tl2, tl);
        assert_memory_equal(tag2, tag, tl);
        assert_int_equal(swpor_store_open(dl, fid, 0, &st), SWPOR_OK);
        mem_output_t out;
        memset(&out, 0, sizeof(out));
        assert_int_equal(swpor_retrieve_run(NULL, &keys, tag, tl, swpor_store_reader, st,
                                            mem_output, &out, NULL),
                         SWPOR_OK);
        assert_int_equal(out.len, len);
        assert_memory_equal(out.data, data, len);
        swpor_store_close(st);
        assert_int_equal(swpor_store_delete(dl, fid), SWPOR_OK);
        (void)swpor_remove_dir(dl);

        /* 删除后再审计：NOT_FOUND */
        assert_int_equal(swpor_client_delete(c, fid), SWPOR_OK);
        swpor_client_close(c);
        assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
        assert_int_equal(swpor_client_delete(c, fid), SWPOR_E_NOT_FOUND);
        swpor_client_close(c);
        free(out.data);
        free(data);
    }
    stop_server(&sh);
}

/* 原始 TCP 连接，用于发送畸形数据 */
static swpor_sock_t *raw_connect(uint16_t port, int do_hello)
{
    swpor_sock_t *s = NULL;
    assert_int_equal(swpor_sock_connect("127.0.0.1", port, &s), SWPOR_OK);
    assert_int_equal(swpor_sock_set_timeout(s, 5000), SWPOR_OK);
    if (do_hello) {
        uint8_t hello[2];
        swpor_store_be16(hello, SWPOR_PROTO_VERSION);
        assert_int_equal(swpor_frame_send(s, SWPOR_MSG_HELLO, hello, 2), SWPOR_OK);
        uint8_t type;
        uint8_t *p;
        size_t len;
        assert_int_equal(swpor_frame_recv(s, 1024, &type, &p, &len), SWPOR_OK);
        assert_int_equal(type, SWPOR_MSG_HELLO_OK);
        free(p);
    }
    return s;
}

/* 期望收到 ERROR 帧，随后连接被关闭 */
static void expect_error_and_close(swpor_sock_t *s)
{
    uint8_t type = 0;
    uint8_t *p = NULL;
    size_t len = 0;
    assert_int_equal(swpor_frame_recv(s, 1 << 20, &type, &p, &len), SWPOR_OK);
    assert_int_equal(type, SWPOR_MSG_ERROR);
    free(p);
    uint8_t b;
    assert_int_not_equal(swpor_sock_recv_all(s, &b, 1), SWPOR_OK);
    swpor_sock_close(s);
}

/* ---------------- T-16：协议健壮性 ---------------- */

static void test_T16_protocol_robustness(void **state)
{
    (void)state;
    server_handle_t sh = start_server(2, 8, 2000);
    uint16_t port = swpor_server_port(sh.srv);
    swpor_sock_t *s;

    /* 1. 第一帧不是 HELLO */
    s = raw_connect(port, 0);
    assert_int_equal(swpor_frame_send(s, SWPOR_MSG_GET_TAG, (const uint8_t *)"x", 1), SWPOR_OK);
    expect_error_and_close(s);

    /* 2. 未知 type */
    s = raw_connect(port, 1);
    assert_int_equal(swpor_frame_send(s, 0x55, NULL, 0), SWPOR_OK);
    expect_error_and_close(s);

    /* 3. 超长帧：声明长度 32 MiB */
    s = raw_connect(port, 1);
    uint8_t head[5];
    swpor_store_be32(head, 32u << 20);
    head[4] = SWPOR_MSG_STORE_BLOCKS;
    assert_int_equal(swpor_sock_send_all(s, head, 5), SWPOR_OK);
    expect_error_and_close(s);

    /* 4. 长度为 0 的帧 */
    s = raw_connect(port, 1);
    swpor_store_be32(head, 0);
    assert_int_equal(swpor_sock_send_all(s, head, 4), SWPOR_OK);
    expect_error_and_close(s);

    /* 5. 解析失败：长度错误的 CHALLENGE、l 超上限、未知 file_id、非法下标 */
    uint8_t ch[37 + 24];
    memset(ch, 0, sizeof(ch));
    s = raw_connect(port, 1);
    assert_int_equal(swpor_frame_send(s, SWPOR_MSG_CHALLENGE, ch, 10), SWPOR_OK);
    expect_error_and_close(s);
    s = raw_connect(port, 1);
    swpor_store_be32(ch + 33, 1);
    assert_int_equal(swpor_frame_send(s, SWPOR_MSG_CHALLENGE, ch, sizeof(ch)), SWPOR_OK);
    expect_error_and_close(s); /* 未知 file_id */

    /* 准备一个真实文件，用于下标越界、重复下标、l 过大 */
    const size_t len = 4000;
    uint8_t *data = malloc(len);
    assert_non_null(data);
    uint8_t fid[32];
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tl;
    remote_store(port, SWPOR_SCHEME_PRIV, 0, len, data, fid, tag, &tl);
    {
        uint8_t req[37 + 2 * 24];
        memset(req, 0, sizeof(req));
        memcpy(req, fid, 32);
        req[32] = SWPOR_CHAL_EXPLICIT;
        swpor_store_be32(req + 33, 2);
        req[37 + 23] = 1;
        req[37 + 24 + 23] = 1; /* 两个下标都为 0：重复 */
        s = raw_connect(port, 1);
        assert_int_equal(swpor_frame_send(s, SWPOR_MSG_CHALLENGE, req, sizeof(req)), SWPOR_OK);
        expect_error_and_close(s);
        swpor_store_be64(req + 37 + 24, 1000000); /* 越界 */
        s = raw_connect(port, 1);
        assert_int_equal(swpor_frame_send(s, SWPOR_MSG_CHALLENGE, req, sizeof(req)), SWPOR_OK);
        expect_error_and_close(s);
        swpor_store_be64(req + 37 + 24, 1);
        req[37 + 23] = 0; /* ν = 0 */
        s = raw_connect(port, 1);
        assert_int_equal(swpor_frame_send(s, SWPOR_MSG_CHALLENGE, req, sizeof(req)), SWPOR_OK);
        expect_error_and_close(s);

        uint8_t sreq[37 + 32];
        memset(sreq, 0, sizeof(sreq));
        memcpy(sreq, fid, 32);
        sreq[32] = SWPOR_CHAL_SEED;
        swpor_store_be32(sreq + 33, 100000); /* 超过 max_l = 512 */
        s = raw_connect(port, 1);
        assert_int_equal(swpor_frame_send(s, SWPOR_MSG_CHALLENGE, sreq, sizeof(sreq)), SWPOR_OK);
        expect_error_and_close(s);
        /* GET_BLOCKS 越界 */
        uint8_t g[44];
        memcpy(g, fid, 32);
        swpor_store_be64(g + 32, 0);
        swpor_store_be32(g + 40, 1000);
        s = raw_connect(port, 1);
        assert_int_equal(swpor_frame_send(s, SWPOR_MSG_GET_BLOCKS, g, sizeof(g)), SWPOR_OK);
        expect_error_and_close(s);
    }

    /* 6. 半关闭：发出半个帧头后关闭写方向；以及上传中途断开 */
    s = raw_connect(port, 1);
    assert_int_equal(swpor_sock_send_all(s, head, 2), SWPOR_OK);
    swpor_sock_shutdown_write(s);
    swpor_sock_close(s);
    {
        swpor_client_t *c = NULL;
        assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
        uint8_t ptag[SWPOR_TAG_MAX_BYTES];
        size_t ptl = 0;
        swpor_tag_header_t h;
        memset(&h, 0, sizeof(h));
        h.version = 1;
        h.scheme = SWPOR_SCHEME_PRIV;
        h.n = 4;
        h.s = 2;
        h.length = 10;
        assert_int_equal(swpor_random_bytes(h.file_id, 32), SWPOR_OK);
        swpor_priv_file_keys_t fk;
        assert_int_equal(swpor_priv_file_keys_gen(&fk), SWPOR_OK);
        assert_int_equal(swpor_priv_tag_seal(g_key, &h, &fk, ptag, sizeof(ptag), &ptl), SWPOR_OK);
        assert_int_equal(swpor_client_store_begin(c, ptag, ptl, 4, 62, 32), SWPOR_OK);
        uint8_t blk[62] = {0};
        assert_int_equal(swpor_client_store_blocks(c, 0, 1, blk, 62), SWPOR_OK);
        swpor_client_close(c); /* 中途断开：服务端应清理残留 */
        /* STORE_END 时数据不完整必须报错 */
        assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
        assert_int_equal(swpor_client_store_begin(c, ptag, ptl, 4, 62, 32), SWPOR_OK);
        uint8_t fid2[32];
        assert_int_not_equal(swpor_client_store_end(c, fid2), SWPOR_OK);
        swpor_client_close(c);
        /* 与标签不一致的 n */
        assert_int_equal(swpor_client_connect("127.0.0.1", port, 5000, &c), SWPOR_OK);
        assert_int_equal(swpor_client_store_begin(c, ptag, ptl, 5, 62, 32), SWPOR_OK);
        assert_int_not_equal(swpor_client_store_end(c, fid2), SWPOR_OK);
        swpor_client_close(c);
    }

    /* 7. 随机字节流 */
    for (int rep = 0; rep < 20; rep++) {
        s = raw_connect(port, rep % 2);
        uint8_t junk[300];
        assert_int_equal(swpor_random_bytes(junk, sizeof(junk)), SWPOR_OK);
        swpor_store_be32(junk, 200);
        (void)swpor_sock_send_all(s, junk, sizeof(junk));
        swpor_sock_close(s);
    }

    /* 服务端仍然存活、数据仍可审计 */
    assert_int_equal(remote_audit(port, SWPOR_SCHEME_PRIV, fid, tag, tl, 8, 1), 1);
    free(data);
    stop_server(&sh);
}

/* ---------------- T-17：并发审计 ---------------- */

typedef struct {
    uint16_t port;
    const uint8_t *fid;
    const uint8_t *tag;
    size_t tl;
    uint8_t scheme;
    int passes;
    int rounds;
} conc_arg_t;

static void conc_worker(void *p)
{
    conc_arg_t *a = p;
    for (int r = 0; r < a->rounds; r++) {
        swpor_client_t *c = NULL;
        if (swpor_client_connect("127.0.0.1", a->port, 10000, &c) != SWPOR_OK) {
            continue;
        }
        swpor_remote_t *rm = NULL;
        if (swpor_remote_new(c, &rm) == SWPOR_OK) {
            swpor_remote_set_file_id(rm, a->fid);
            swpor_keys_t keys = keys_for(a->scheme);
            swpor_audit_result_t res;
            if (swpor_audit_run(NULL, &keys, a->tag, a->tl, 16, r % 2, swpor_remote_prove, rm,
                                &res) == SWPOR_OK &&
                res.pass) {
                a->passes++;
            }
        }
        swpor_remote_free(rm);
        swpor_client_close(c);
    }
}

static void test_T17_concurrent_audits(void **state)
{
    (void)state;
    server_handle_t sh = start_server(4, 64, 10000);
    uint16_t port = swpor_server_port(sh.srv);
    const size_t len = 20000;
    uint8_t *d1 = malloc(len);
    uint8_t *d2 = malloc(len);
    assert_non_null(d1);
    assert_non_null(d2);
    uint8_t f1[32], f2[32], t1[SWPOR_TAG_MAX_BYTES], t2[SWPOR_TAG_MAX_BYTES];
    size_t l1, l2;
    remote_store(port, SWPOR_SCHEME_PRIV, SWPOR_FLAG_RS, len, d1, f1, t1, &l1);
    remote_store(port, SWPOR_SCHEME_PUB, SWPOR_FLAG_RS, len, d2, f2, t2, &l2);

    enum { N = 8 };
    conc_arg_t args[N];
    swpor_thread_t *th[N];
    for (int k = 0; k < N; k++) {
        args[k].port = port;
        args[k].fid = (k % 2) ? f2 : f1;
        args[k].tag = (k % 2) ? t2 : t1;
        args[k].tl = (k % 2) ? l2 : l1;
        args[k].scheme = (k % 2) ? SWPOR_SCHEME_PUB : SWPOR_SCHEME_PRIV;
        args[k].passes = 0;
        args[k].rounds = 5;
        assert_int_equal(swpor_thread_create(conc_worker, &args[k], &th[k]), SWPOR_OK);
    }
    for (int k = 0; k < N; k++) {
        swpor_thread_join(th[k]);
        assert_int_equal(args[k].passes, args[k].rounds);
    }
    free(d1);
    free(d2);
    stop_server(&sh);
}

/* 有界队列满时返回 BUSY（SPEC 8.4） */
static void test_server_busy(void **state)
{
    (void)state;
    server_handle_t sh = start_server(1, 1, 3000);
    uint16_t port = swpor_server_port(sh.srv);
    /* 第一个连接占住唯一的工作线程，第二个占住队列 */
    swpor_sock_t *a = raw_connect(port, 1);
    swpor_sock_t *b = NULL;
    assert_int_equal(swpor_sock_connect("127.0.0.1", port, &b), SWPOR_OK);
    swpor_sleep_ms(200);
    swpor_client_t *c = NULL;
    assert_int_equal(swpor_client_connect("127.0.0.1", port, 3000, &c), SWPOR_E_BUSY);
    swpor_sock_close(a);
    swpor_sock_close(b);
    stop_server(&sh);
}

/* ---------------- T-18：服务端重启后数据仍可审计 ---------------- */

static void test_T18_restart_persistence(void **state)
{
    (void)state;
    server_handle_t sh = start_server(2, 8, 5000);
    uint16_t port = swpor_server_port(sh.srv);
    const size_t len = 15000;
    uint8_t *data = malloc(len);
    assert_non_null(data);
    uint8_t fid[32];
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tl;
    remote_store(port, SWPOR_SCHEME_PRIV, SWPOR_FLAG_RS | SWPOR_FLAG_PERM, len, data, fid, tag, &tl);
    stop_server(&sh);

    sh = start_server(2, 8, 5000);
    port = swpor_server_port(sh.srv);
    assert_int_equal(remote_audit(port, SWPOR_SCHEME_PRIV, fid, tag, tl, 32, 0), 1);
    assert_int_equal(remote_audit(port, SWPOR_SCHEME_PRIV, fid, tag, tl, 32, 1), 1);
    stop_server(&sh);
    assert_int_equal(swpor_store_delete(g_dir, fid), SWPOR_OK);
    free(data);
}

static void test_parse_hostport(void **state)
{
    (void)state;
    char host[64];
    uint16_t port;
    assert_int_equal(swpor_parse_hostport("example.org:9000", host, sizeof(host), &port), SWPOR_OK);
    assert_string_equal(host, "example.org");
    assert_int_equal(port, 9000);
    assert_int_equal(swpor_parse_hostport("10.0.0.1", host, sizeof(host), &port), SWPOR_OK);
    assert_int_equal(port, SWPOR_DEFAULT_PORT);
    assert_int_equal(swpor_parse_hostport("h:99999", host, sizeof(host), &port), SWPOR_E_INVALID_ARG);
    assert_int_equal(swpor_parse_hostport(":80", host, sizeof(host), &port), SWPOR_E_INVALID_ARG);
    assert_int_equal(swpor_parse_hostport("h:", host, sizeof(host), &port), SWPOR_E_INVALID_ARG);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_hostport),
        cmocka_unit_test(test_T15_local_and_remote_agree),
        cmocka_unit_test(test_T16_protocol_robustness),
        cmocka_unit_test(test_T17_concurrent_audits),
        cmocka_unit_test(test_server_busy),
        cmocka_unit_test(test_T18_restart_persistence),
    };
    int rc = cmocka_run_group_tests(tests, setup, teardown);
    return rc;
}
