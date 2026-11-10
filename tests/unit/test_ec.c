/*
 * M2 单元测试：纠删码层与检索（SPEC 5、6），T-09～T-13、T-26（库层面）。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "mem_backend.h"
#include "platform.h"
#include "swpor/swpor.h"

static swpor_priv_key_t *g_key;

static int setup(void **state)
{
    (void)state;
    return swpor_priv_keygen(&g_key) == SWPOR_OK ? 0 : -1;
}

static int teardown(void **state)
{
    (void)state;
    swpor_priv_key_free(g_key);
    return 0;
}

static swpor_keys_t priv_keys(void)
{
    swpor_keys_t k;
    memset(&k, 0, sizeof(k));
    k.scheme = SWPOR_SCHEME_PRIV;
    k.priv_key = g_key;
    return k;
}

/* store → 检索，返回检索的错误码；输出写入 *out */
static int roundtrip(const uint8_t *data, size_t len, const swpor_st_params_t *p, mem_backend_t *mb,
                     mem_output_t *out, int (*damage)(mem_backend_t *, void *), void *dmg_arg,
                     uint64_t *erased)
{
    swpor_keys_t keys = priv_keys();
    mem_input_t in = {data, len, 0};
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    memset(mb, 0, sizeof(*mb));
    assert_int_equal(swpor_st_run(NULL, &keys, p, len, mem_input, &in, &k_mem_sink, mb, tag,
                                  sizeof(tag), &tag_len, NULL),
                     SWPOR_OK);
    assert_true(mb->finished);
    /* 诚实存储：审计通过 */
    swpor_audit_result_t res;
    assert_int_equal(swpor_audit_run(NULL, &keys, tag, tag_len, 16, 0, mem_prove, mb, &res),
                     SWPOR_OK);
    assert_int_equal(res.pass, 1);
    if (damage != NULL) {
        assert_int_equal(damage(mb, dmg_arg), 0);
    }
    memset(out, 0, sizeof(*out));
    return swpor_retrieve_run(NULL, &keys, tag, tag_len, mem_get, mb, mem_output, out, erased);
}

static uint8_t *random_data(size_t len)
{
    uint8_t *d = malloc(len > 0 ? len : 1);
    assert_non_null(d);
    assert_int_equal(swpor_random_bytes(d, len), SWPOR_OK);
    return d;
}

/* ---------------- T-09：边界情况 ---------------- */

static void test_T09_boundary_cases(void **state)
{
    (void)state;
    const uint16_t s = 4;
    const size_t bb = 31u * s;
    const size_t lens[] = {0, 1, bb - 1, bb, bb + 1, 3 * bb, 7 * bb + 5};
    const swpor_st_params_t params[] = {
        {s, 0, 0, 0},
        {s, SWPOR_FLAG_RS, 2, 2},
        {s, SWPOR_FLAG_RS, 3, 1},
        {s, SWPOR_FLAG_RS | SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT, 4, 2},
    };
    for (size_t a = 0; a < sizeof(lens) / sizeof(lens[0]); a++) {
        for (size_t b = 0; b < sizeof(params) / sizeof(params[0]); b++) {
            uint8_t *d = random_data(lens[a]);
            mem_backend_t mb;
            mem_output_t out;
            assert_int_equal(roundtrip(d, lens[a], &params[b], &mb, &out, NULL, NULL, NULL),
                             SWPOR_OK);
            assert_int_equal(out.len, lens[a]);
            if (lens[a] > 0) {
                assert_memory_equal(out.data, d, lens[a]);
            }
            /* n = 1 的情况：L <= bb 且不启用 RS */
            if (params[b].flags == 0 && lens[a] <= bb) {
                assert_true(mb.n == 1);
            }
            /* l > n：挑战全部块，仍能通过（roundtrip 中 l = 16） */
            free(out.data);
            mem_backend_free(&mb);
            free(d);
        }
    }
}

static void test_T09_layout(void **state)
{
    (void)state;
    swpor_layout_t lay;
    assert_int_equal(swpor_layout_compute(0, 128, 0, 0, 0, &lay), SWPOR_OK);
    assert_true(lay.n == 1 && lay.data_blocks == 1);
    assert_int_equal(swpor_layout_compute(3968u * 64u, 128, SWPOR_FLAG_RS, 64, 64, &lay), SWPOR_OK);
    assert_true(lay.stripes == 1 && lay.n == 128);
    assert_int_equal(swpor_layout_compute(3968u * 64u + 1u, 128, SWPOR_FLAG_RS, 64, 64, &lay),
                     SWPOR_OK);
    assert_true(lay.stripes == 2 && lay.n == 256);
    assert_int_equal(swpor_layout_compute(10, 128, SWPOR_FLAG_RS, 200, 57, &lay),
                     SWPOR_E_INVALID_ARG);
    assert_int_equal(swpor_layout_compute(10, 0, 0, 0, 0, &lay), SWPOR_E_INVALID_ARG);
}

/* ---------------- T-10：无损坏时逐字节恢复 ---------------- */

static void test_T10_retrieve_intact(void **state)
{
    (void)state;
    const size_t len = 100000;
    uint8_t *d = random_data(len);
    swpor_st_params_t p = {16, SWPOR_FLAG_RS, 8, 8};
    mem_backend_t mb;
    mem_output_t out;
    uint64_t erased = 99;
    assert_int_equal(roundtrip(d, len, &p, &mb, &out, NULL, NULL, &erased), SWPOR_OK);
    assert_int_equal(out.len, len);
    assert_memory_equal(out.data, d, len);
    assert_true(erased == 0);
    free(out.data);
    mem_backend_free(&mb);
    free(d);
}

/* 损坏方式：对每个条带删除（或篡改）指定个数的块 */
typedef struct {
    uint32_t per_stripe;
    int mode; /* 0 = 删除（读失败），1 = 置零，2 = 翻转一位 */
    int only_stripe; /* -1 表示所有条带 */
} damage_t;

static int damage_stripes(mem_backend_t *mb, void *arg)
{
    damage_t *dm = arg;
    const uint32_t w = (uint32_t)mb->hdr.rs_k + mb->hdr.rs_m;
    /* 未启用置乱：原始位置即存储位置，条带 t 占 [t·w, (t+1)·w) */
    for (uint64_t t = 0; t < mb->n / w; t++) {
        if (dm->only_stripe >= 0 && (uint64_t)dm->only_stripe != t) {
            continue;
        }
        for (uint32_t j = 0; j < dm->per_stripe; j++) {
            /* 交替选择数据块与校验块 */
            uint64_t pos = t * w + (j * 7u) % w;
            while (mb->deleted[pos] || (dm->mode && mb->blocks[pos * mb->bb] == 0xEE)) {
                pos = t * w + (pos - t * w + 1) % w;
            }
            if (dm->mode == 0) {
                mb->deleted[pos] = 1;
            } else if (dm->mode == 1) {
                memset(mb->blocks + pos * mb->bb, 0, mb->bb);
                mb->blocks[pos * mb->bb] = 0xEE; /* 标记已处理（σ 校验仍会失败） */
            } else {
                mb->blocks[pos * mb->bb + 3] ^= 0x10;
                mb->blocks[pos * mb->bb] = 0xEE;
            }
        }
    }
    return 0;
}

/* ---------------- T-11：每条带损坏 <= m 块仍能恢复 ---------------- */

static void test_T11_recover_up_to_m(void **state)
{
    (void)state;
    const size_t len = 50000;
    uint8_t *d = random_data(len);
    swpor_st_params_t p = {8, SWPOR_FLAG_RS, 6, 4};
    for (int mode = 0; mode < 3; mode++) {
        for (uint32_t cnt = 1; cnt <= 4; cnt++) {
            damage_t dm = {cnt, mode, -1};
            mem_backend_t mb;
            mem_output_t out;
            uint64_t erased = 0;
            assert_int_equal(roundtrip(d, len, &p, &mb, &out, damage_stripes, &dm, &erased),
                             SWPOR_OK);
            assert_int_equal(out.len, len);
            assert_memory_equal(out.data, d, len);
            assert_true(erased > 0);
            free(out.data);
            mem_backend_free(&mb);
        }
    }
    free(d);
}

/* ---------------- T-12：某条带损坏 > m 块时报告失败 ---------------- */

static void test_T12_too_many_erasures_fail(void **state)
{
    (void)state;
    const size_t len = 50000;
    uint8_t *d = random_data(len);
    swpor_st_params_t p = {8, SWPOR_FLAG_RS, 6, 4};
    for (int mode = 0; mode < 3; mode++) {
        damage_t dm = {5, mode, 1}; /* 只破坏第 1 个条带 */
        mem_backend_t mb;
        mem_output_t out;
        assert_int_equal(roundtrip(d, len, &p, &mb, &out, damage_stripes, &dm, NULL),
                         SWPOR_E_DECODE);
        free(out.data);
        mem_backend_free(&mb);
    }
    /* 未启用 RS：任一块损坏即失败 */
    swpor_st_params_t p0 = {8, 0, 0, 0};
    mem_backend_t mb;
    mem_output_t out;
    swpor_keys_t keys = priv_keys();
    mem_input_t in = {d, len, 0};
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    memset(&mb, 0, sizeof(mb));
    assert_int_equal(swpor_st_run(NULL, &keys, &p0, len, mem_input, &in, &k_mem_sink, &mb, tag,
                                  sizeof(tag), &tag_len, NULL),
                     SWPOR_OK);
    mb.blocks[5 * mb.bb] ^= 1;
    memset(&out, 0, sizeof(out));
    assert_int_equal(swpor_retrieve_run(NULL, &keys, tag, tag_len, mem_get, &mb, mem_output, &out,
                                        NULL),
                     SWPOR_E_DECODE);
    free(out.data);
    mem_backend_free(&mb);
    free(d);
}

/* ---------------- T-13：--perm --encrypt 往返 ---------------- */

static int damage_random_positions(mem_backend_t *mb, void *arg)
{
    /* 置乱后无法按条带定位；删除 n/(k+m) 个随机位置，每条带期望删除 1 个，最多 m 个 */
    (void)arg;
    uint64_t cnt = mb->n / ((uint64_t)mb->hdr.rs_k + mb->hdr.rs_m);
    swpor_chal_t *c = NULL;
    if (swpor_chal_explicit(mb->n, (uint32_t)cnt, &c) != SWPOR_OK) {
        return -1;
    }
    for (uint32_t k = 0; k < c->count; k++) {
        mb->deleted[c->items[k].index] = 1;
    }
    swpor_chal_free(c);
    return 0;
}

static void test_T13_perm_encrypt_roundtrip(void **state)
{
    (void)state;
    const size_t len = 77777;
    uint8_t *d = random_data(len);
    swpor_st_params_t p = {16, SWPOR_FLAG_RS | SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT, 8, 8};
    mem_backend_t mb;
    mem_output_t out;
    assert_int_equal(roundtrip(d, len, &p, &mb, &out, NULL, NULL, NULL), SWPOR_OK);
    assert_int_equal(out.len, len);
    assert_memory_equal(out.data, d, len);
    /* 加密后存储的数据块不等于明文 */
    assert_memory_not_equal(mb.blocks, d, 31u * 16u);
    free(out.data);
    mem_backend_free(&mb);

    assert_int_equal(roundtrip(d, len, &p, &mb, &out, damage_random_positions, NULL, NULL),
                     SWPOR_OK);
    assert_int_equal(out.len, len);
    assert_memory_equal(out.data, d, len);
    free(out.data);
    mem_backend_free(&mb);
    free(d);
}

static void test_perm_is_permutation(void **state)
{
    (void)state;
    uint8_t k[32] = {7};
    const uint64_t n = 1000;
    uint64_t *p = malloc(n * sizeof(*p));
    uint8_t *seen = calloc(n, 1);
    assert_non_null(p);
    assert_non_null(seen);
    assert_int_equal(swpor_perm_compute(k, n, p), SWPOR_OK);
    uint64_t fixed = 0;
    for (uint64_t i = 0; i < n; i++) {
        assert_true(p[i] < n);
        assert_false(seen[p[i]]);
        seen[p[i]] = 1;
        fixed += p[i] == i;
    }
    assert_true(fixed < 20); /* 随机置换的不动点期望为 1 */
    uint64_t one;
    assert_int_equal(swpor_perm_compute(k, 1, &one), SWPOR_OK);
    assert_true(one == 0);
    free(p);
    free(seen);
}

/* 输入长度与声明的 L 不一致时报错 */
static void test_encode_length_mismatch(void **state)
{
    (void)state;
    uint8_t d[100] = {0};
    swpor_keys_t keys = priv_keys();
    swpor_st_params_t p = {4, 0, 0, 0};
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    mem_backend_t mb;
    mem_input_t in = {d, 100, 0};
    memset(&mb, 0, sizeof(mb));
    assert_int_equal(swpor_st_run(NULL, &keys, &p, 101, mem_input, &in, &k_mem_sink, &mb, tag,
                                  sizeof(tag), &tag_len, NULL),
                     SWPOR_E_IO);
    mem_backend_free(&mb);
    in.pos = 0;
    memset(&mb, 0, sizeof(mb));
    assert_int_equal(swpor_st_run(NULL, &keys, &p, 99, mem_input, &in, &k_mem_sink, &mb, tag,
                                  sizeof(tag), &tag_len, NULL),
                     SWPOR_E_IO);
    mem_backend_free(&mb);
}

/* ---------------- 磁盘存储（SPEC 6）+ 非 ASCII 路径（T-26 库层面） ---------------- */

typedef struct {
    swpor_store_t *st;
    const char *root;
} disk_sink_t;

static int disk_begin(void *user, const uint8_t *tag, size_t tag_len, const swpor_tag_header_t *h)
{
    (void)tag;
    (void)tag_len;
    disk_sink_t *ds = user;
    return swpor_store_create(ds->root, h->file_id, h->scheme, h->n, h->s, &ds->st);
}

static int disk_put(void *user, uint64_t pos, const uint8_t *block, size_t bl, const uint8_t *sigma,
                    size_t sl)
{
    (void)bl;
    (void)sl;
    disk_sink_t *ds = user;
    int rc = swpor_store_write_block(ds->st, pos, block);
    return rc == SWPOR_OK ? swpor_store_write_sigma(ds->st, pos, sigma) : rc;
}

static int disk_finish(void *user)
{
    (void)user;
    return SWPOR_OK;
}

static int disk_get(void *user, uint64_t pos, uint8_t *block, size_t bl, uint8_t *sigma, size_t sl)
{
    return swpor_store_reader(user, pos, block, bl, sigma, sl);
}

static int disk_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap, size_t *len)
{
    swpor_store_t *st = user;
    return swpor_prove(NULL, swpor_store_header(st), chal, swpor_store_reader, st, proof, cap, len);
}

static void test_T26_disk_store_unicode_path(void **state)
{
    (void)state;
    char root[256];
    (void)snprintf(root, sizeof(root), "swpor_test_存储 目录_%u",
                   (unsigned)(swpor_time_ns() % 100000));
    const size_t len = 20000;
    uint8_t *d = random_data(len);
    swpor_keys_t keys = priv_keys();
    swpor_st_params_t p = {8, SWPOR_FLAG_RS | SWPOR_FLAG_PERM, 4, 4};
    disk_sink_t ds = {NULL, root};
    const swpor_st_sink_t sink = {disk_begin, disk_put, disk_finish};
    mem_input_t in = {d, len, 0};
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    swpor_tag_header_t h;
    assert_int_equal(swpor_st_run(NULL, &keys, &p, len, mem_input, &in, &sink, &ds, tag,
                                  sizeof(tag), &tag_len, &h),
                     SWPOR_OK);
    /* 写完 tag.bin 之前文件不可打开 */
    swpor_store_t *st = NULL;
    assert_int_equal(swpor_store_open(root, h.file_id, 0, &st), SWPOR_E_NOT_FOUND);
    assert_int_equal(swpor_store_write_tag(ds.st, tag, tag_len), SWPOR_OK);
    swpor_store_close(ds.st);

    /* 重新打开（模拟服务端重启后，T-18 的库层面） */
    assert_int_equal(swpor_store_open(root, h.file_id, 0, &st), SWPOR_OK);
    size_t tl = 0;
    assert_memory_equal(swpor_store_tag(st, &tl), tag, tag_len);
    swpor_audit_result_t res;
    assert_int_equal(swpor_audit_run(NULL, &keys, tag, tag_len, 32, 1, disk_prove, st, &res),
                     SWPOR_OK);
    assert_int_equal(res.pass, 1);
    mem_output_t out;
    memset(&out, 0, sizeof(out));
    assert_int_equal(swpor_retrieve_run(NULL, &keys, tag, tag_len, disk_get, st, mem_output, &out,
                                        NULL),
                     SWPOR_OK);
    assert_int_equal(out.len, len);
    assert_memory_equal(out.data, d, len);
    swpor_store_close(st);

    assert_int_equal(swpor_store_delete(root, h.file_id), SWPOR_OK);
    assert_int_equal(swpor_store_delete(root, h.file_id), SWPOR_E_NOT_FOUND);
    assert_int_equal(swpor_remove_dir(root), SWPOR_OK);
    free(out.data);
    free(d);
}

/* ---------------- 密钥文件（SPEC 7） ---------------- */

static void test_keyfiles(void **state)
{
    (void)state;
    char path[256];
    (void)snprintf(path, sizeof(path), "swpor_test_key_%u.key", (unsigned)(swpor_time_ns() % 100000));
    assert_int_equal(swpor_keyfile_save_priv(path, g_key, 0), SWPOR_OK);
    assert_int_equal(swpor_keyfile_save_priv(path, g_key, 0), SWPOR_E_EXISTS);
    int kind;
    uint8_t scheme;
    assert_int_equal(swpor_keyfile_probe(path, &kind, &scheme), SWPOR_OK);
    assert_int_equal(kind, SWPOR_KEYFILE_SECRET);
    assert_int_equal(scheme, SWPOR_SCHEME_PRIV);
    swpor_priv_key_t *k2 = NULL;
    assert_int_equal(swpor_keyfile_load_priv(path, &k2), SWPOR_OK);
    uint8_t a[32], b[32];
    swpor_priv_key_export(g_key, a);
    swpor_priv_key_export(k2, b);
    assert_memory_equal(a, b, 32);
    swpor_priv_key_free(k2);
    swpor_pub_sk_t *psk = NULL;
    assert_int_equal(swpor_keyfile_load_pub_sk(path, &psk), SWPOR_E_PARSE); /* 方案不符 */
    assert_int_equal(swpor_remove_file(path), SWPOR_OK);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_T09_boundary_cases),
        cmocka_unit_test(test_T09_layout),
        cmocka_unit_test(test_T10_retrieve_intact),
        cmocka_unit_test(test_T11_recover_up_to_m),
        cmocka_unit_test(test_T12_too_many_erasures_fail),
        cmocka_unit_test(test_T13_perm_encrypt_roundtrip),
        cmocka_unit_test(test_perm_is_permutation),
        cmocka_unit_test(test_encode_length_mismatch),
        cmocka_unit_test(test_T26_disk_store_unicode_path),
        cmocka_unit_test(test_keyfiles),
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
