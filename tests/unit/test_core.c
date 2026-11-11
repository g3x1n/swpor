/*
 * M0 单元测试：域运算与扇区编码（T-01）、PRF（T-02）、挑战生成（SPEC 3.5）、
 * 文件标签头（SPEC 4.3）、平台层文件接口。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "fr.h"
#include "platform.h"
#include "prf.h"
#include "swpor/swpor.h"
#include "swpor/por.h"

/* r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001 */
static const uint8_t k_r[32] = {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8,
                                0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe,
                                0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01};

/* ---------------- T-01：域运算与扇区编码 ---------------- */

static void test_T01_sector_roundtrip(void **state)
{
    (void)state;
    for (int iter = 0; iter < 200; iter++) {
        uint8_t in[31];
        uint8_t out[31];
        assert_int_equal(swpor_random_bytes(in, sizeof(in)), SWPOR_OK);
        if (iter == 0) {
            memset(in, 0xFF, sizeof(in)); /* 最大值 2^248 - 1 */
        } else if (iter == 1) {
            memset(in, 0, sizeof(in));
        }
        swpor_fr_t m;
        swpor_fr_from_sector(&m, in);
        assert_int_equal(swpor_fr_to_sector(out, &m), SWPOR_OK);
        assert_memory_equal(in, out, sizeof(in));
    }
}

static void test_T01_sector_rejects_large(void **state)
{
    (void)state;
    /* m = 2^248 不能解码为扇区 */
    uint8_t b[32] = {0};
    b[0] = 0x01;
    swpor_fr_t m;
    assert_int_equal(swpor_fr_from_canonical(&m, b), SWPOR_OK);
    uint8_t out[31];
    assert_int_equal(swpor_fr_to_sector(out, &m), SWPOR_E_PARSE);
}

static void test_T01_canonical_check(void **state)
{
    (void)state;
    swpor_fr_t a;
    uint8_t b[32];
    /* r 本身不是规范编码 */
    assert_int_equal(swpor_fr_from_canonical(&a, k_r), SWPOR_E_PARSE);
    /* r - 1 是 */
    memcpy(b, k_r, 32);
    b[31] = 0x00;
    assert_int_equal(swpor_fr_from_canonical(&a, b), SWPOR_OK);
    uint8_t back[32];
    swpor_fr_to_bytes(back, &a);
    assert_memory_equal(b, back, 32);
    /* 全 0xFF 不是 */
    memset(b, 0xFF, 32);
    assert_int_equal(swpor_fr_from_canonical(&a, b), SWPOR_E_PARSE);
}

static void test_T01_field_arith(void **state)
{
    (void)state;
    /* (r-1) + 1 == 0；(r-1)·(r-1) == 1 */
    uint8_t b[32];
    memcpy(b, k_r, 32);
    b[31] = 0x00;
    swpor_fr_t minus1, one, zero, t;
    assert_int_equal(swpor_fr_from_canonical(&minus1, b), SWPOR_OK);
    memset(b, 0, 32);
    b[31] = 1;
    assert_int_equal(swpor_fr_from_canonical(&one, b), SWPOR_OK);
    swpor_fr_zero(&zero);
    swpor_fr_add(&t, &minus1, &one);
    assert_true(swpor_fr_equal_ct(&t, &zero));
    swpor_fr_mul(&t, &minus1, &minus1);
    assert_true(swpor_fr_equal_ct(&t, &one));
    /* 模规约：r 规约为 0；r+1 规约为 1 */
    swpor_fr_from_be_reduce(&t, k_r, 32);
    assert_true(swpor_fr_equal_ct(&t, &zero));
    uint8_t big[64] = {0};
    memcpy(big + 32, k_r, 32);
    big[63] = 0x02;
    swpor_fr_from_be_reduce(&t, big, 64);
    assert_true(swpor_fr_equal_ct(&t, &one));
}

static void test_T01_block_to_fr(void **state)
{
    (void)state;
    uint8_t block[31 * 4];
    for (size_t k = 0; k < sizeof(block); k++) {
        block[k] = (uint8_t)k;
    }
    swpor_fr_t m[4];
    swpor_block_to_fr(block, 4, m);
    for (int j = 0; j < 4; j++) {
        uint8_t out[31];
        assert_int_equal(swpor_fr_to_sector(out, &m[j]), SWPOR_OK);
        assert_memory_equal(out, block + 31 * j, 31);
    }
}

/* ---------------- T-02：PRF ---------------- */

static void test_T02_prf_deterministic_and_distinct(void **state)
{
    (void)state;
    uint8_t k1[32];
    uint8_t k2[32];
    memset(k1, 0x11, sizeof(k1));
    memset(k2, 0x22, sizeof(k2));
    swpor_prf_t *p1 = NULL;
    swpor_prf_t *p1b = NULL;
    swpor_prf_t *p2 = NULL;
    swpor_prf_t *pa = NULL;
    assert_int_equal(swpor_prf_new(k1, SWPOR_DST_PRF, &p1), SWPOR_OK);
    assert_int_equal(swpor_prf_new(k1, SWPOR_DST_PRF, &p1b), SWPOR_OK);
    assert_int_equal(swpor_prf_new(k2, SWPOR_DST_PRF, &p2), SWPOR_OK);
    assert_int_equal(swpor_prf_new(k1, SWPOR_DST_ALPHA, &pa), SWPOR_OK);

    swpor_fr_t a, b, c, d, e;
    for (uint64_t i = 0; i < 50; i++) {
        assert_int_equal(swpor_prf_eval(p1, i, &a), SWPOR_OK);
        assert_int_equal(swpor_prf_eval(p1b, i, &b), SWPOR_OK);
        assert_int_equal(swpor_prf_eval(p2, i, &c), SWPOR_OK);
        assert_int_equal(swpor_prf_eval(p1, i + 1, &d), SWPOR_OK);
        assert_int_equal(swpor_prf_eval(pa, i, &e), SWPOR_OK);
        assert_true(swpor_fr_equal_ct(&a, &b));  /* 确定性 */
        assert_false(swpor_fr_equal_ct(&a, &c)); /* 不同 k */
        assert_false(swpor_fr_equal_ct(&a, &d)); /* 不同 i */
        assert_false(swpor_fr_equal_ct(&a, &e)); /* 不同域分隔串 */
    }
    swpor_prf_free(p1);
    swpor_prf_free(p1b);
    swpor_prf_free(p2);
    swpor_prf_free(pa);
    swpor_prf_free(NULL);
}

static void test_T02_prf_known_answer(void **state)
{
    (void)state;
    /*
     * 已知答案：k = 00..1f，i = 1。期望值由 Python 标准库独立计算：
     *   int.from_bytes(hmac.new(k, b"SWPOR-PRF-V1" + (1).to_bytes(8,"big"), sha512).digest(),"big") % r
     * 差分测试 T-03（tests/ref/）覆盖更多输入。
     */
    uint8_t k[32];
    for (int i = 0; i < 32; i++) {
        k[i] = (uint8_t)i;
    }
    swpor_prf_t *p = NULL;
    assert_int_equal(swpor_prf_new(k, SWPOR_DST_PRF, &p), SWPOR_OK);
    swpor_fr_t v;
    assert_int_equal(swpor_prf_eval(p, 1, &v), SWPOR_OK);
    uint8_t out[32];
    swpor_fr_to_bytes(out, &v);
    char hex[65];
    swpor_hex_encode(out, 32, hex);
    assert_string_equal(hex, "2def4183c731fc4d1b8099fb8518a95e0fb1bba25dede4e671b57e204313a3fe");
    swpor_prf_free(p);
}

static void test_hkdf_and_hstream(void **state)
{
    (void)state;
    /* RFC 5869 测试向量 3（salt 与 info 都为空）：IKM = 0x0b × 22，L = 42 */
    uint8_t ikm[22];
    memset(ikm, 0x0b, sizeof(ikm));
    uint8_t okm[42];
    assert_int_equal(swpor_hkdf_sha256(okm, sizeof(okm), ikm, sizeof(ikm), ""), SWPOR_OK);
    static const uint8_t expect[42] = {
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c,
        0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f,
        0x3c, 0x73, 0x8d, 0x2d, 0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8};
    assert_memory_equal(okm, expect, sizeof(expect));

    /* 字节流：分段读取与一次读取结果一致 */
    uint8_t key[32] = {1};
    swpor_hstream_t a, b;
    assert_int_equal(swpor_hstream_init(&a, key, 32, SWPOR_DST_CHAL), SWPOR_OK);
    assert_int_equal(swpor_hstream_init(&b, key, 32, SWPOR_DST_CHAL), SWPOR_OK);
    uint8_t x[100];
    uint8_t y[100];
    assert_int_equal(swpor_hstream_read(&a, x, 100), SWPOR_OK);
    assert_int_equal(swpor_hstream_read(&b, y, 7), SWPOR_OK);
    assert_int_equal(swpor_hstream_read(&b, y + 7, 60), SWPOR_OK);
    assert_int_equal(swpor_hstream_read(&b, y + 67, 33), SWPOR_OK);
    assert_memory_equal(x, y, 100);
    swpor_hstream_clear(&a);
    swpor_hstream_clear(&b);
}

/* ---------------- 挑战（SPEC 3.5） ---------------- */

static void check_chal_wellformed(const swpor_chal_t *c, uint64_t n, uint32_t l)
{
    uint32_t expect = (uint64_t)l >= n ? (uint32_t)n : l;
    assert_int_equal(c->count, expect);
    for (uint32_t k = 0; k < c->count; k++) {
        assert_true(c->items[k].index < n);
        if (k > 0) {
            assert_true(c->items[k].index > c->items[k - 1].index);
        }
        uint8_t z[16] = {0};
        assert_memory_not_equal(c->items[k].nu, z, 16);
    }
}

static void test_challenge_explicit(void **state)
{
    (void)state;
    static const uint64_t ns[] = {1, 2, 7, 100, 1000, 1u << 20};
    static const uint32_t ls[] = {1, 5, 128, 460};
    for (size_t a = 0; a < sizeof(ns) / sizeof(ns[0]); a++) {
        for (size_t b = 0; b < sizeof(ls) / sizeof(ls[0]); b++) {
            swpor_chal_t *c = NULL;
            assert_int_equal(swpor_chal_explicit(ns[a], ls[b], &c), SWPOR_OK);
            check_chal_wellformed(c, ns[a], ls[b]);
            swpor_chal_free(c);
        }
    }
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_explicit(10, 0, &c), SWPOR_E_INVALID_ARG);
    assert_int_equal(swpor_chal_explicit(0, 1, &c), SWPOR_E_INVALID_ARG);
}

static void test_challenge_seed_deterministic(void **state)
{
    (void)state;
    uint8_t seed[32];
    memset(seed, 0x5A, sizeof(seed));
    swpor_chal_t *a = NULL;
    swpor_chal_t *b = NULL;
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_from_seed(seed, 1000, 128, &a), SWPOR_OK);
    assert_int_equal(swpor_chal_from_seed(seed, 1000, 128, &b), SWPOR_OK);
    check_chal_wellformed(a, 1000, 128);
    assert_int_equal(a->count, b->count);
    assert_memory_equal(a->items, b->items, a->count * sizeof(*a->items));
    seed[0] ^= 1;
    assert_int_equal(swpor_chal_from_seed(seed, 1000, 128, &c), SWPOR_OK);
    assert_memory_not_equal(a->items, c->items, a->count * sizeof(*a->items));
    swpor_chal_free(a);
    swpor_chal_free(b);
    swpor_chal_free(c);

    /* l >= n：挑战全部块 */
    assert_int_equal(swpor_chal_from_seed(seed, 5, 128, &a), SWPOR_OK);
    check_chal_wellformed(a, 5, 128);
    swpor_chal_free(a);
}

static void test_challenge_from_items_validation(void **state)
{
    (void)state;
    swpor_chal_item_t it[3];
    memset(it, 0, sizeof(it));
    it[0].index = 5;
    it[1].index = 1;
    it[2].index = 3;
    for (int k = 0; k < 3; k++) {
        it[k].nu[15] = 1;
    }
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_from_items(it, 3, 10, 4096, &c), SWPOR_OK);
    assert_true(c->items[0].index == 1 && c->items[1].index == 3 && c->items[2].index == 5);
    swpor_chal_free(c);

    it[2].index = 5; /* 重复 */
    assert_int_equal(swpor_chal_from_items(it, 3, 10, 4096, &c), SWPOR_E_RANGE);
    it[2].index = 10; /* 越界 */
    assert_int_equal(swpor_chal_from_items(it, 3, 10, 4096, &c), SWPOR_E_RANGE);
    it[2].index = 3;
    it[2].nu[15] = 0; /* ν = 0 不在 B 中（SPEC 11 第 7 条） */
    assert_int_equal(swpor_chal_from_items(it, 3, 10, 4096, &c), SWPOR_E_RANGE);
    it[2].nu[15] = 1;
    assert_int_equal(swpor_chal_from_items(it, 3, 10, 2, &c), SWPOR_E_RANGE); /* 超过 max_l */
    assert_int_equal(swpor_chal_from_items(it, 0, 10, 4096, &c), SWPOR_E_RANGE);
}

static void test_uniform_u64_bounds(void **state)
{
    (void)state;
    uint64_t v;
    for (int k = 0; k < 1000; k++) {
        assert_int_equal(swpor_uniform_u64(swpor_bytes_from_rng, NULL, 3, &v), SWPOR_OK);
        assert_true(v < 3);
    }
    assert_int_equal(swpor_uniform_u64(swpor_bytes_from_rng, NULL, 1, &v), SWPOR_OK);
    assert_true(v == 0);
    /* 2^63 整除 2^64：不拒绝 */
    assert_int_equal(swpor_uniform_u64(swpor_bytes_from_rng, NULL, (uint64_t)1 << 63, &v),
                     SWPOR_OK);
}

/* ---------------- 文件标签头（SPEC 4.3） ---------------- */

static swpor_tag_header_t sample_header(void)
{
    swpor_tag_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = SWPOR_FORMAT_VERSION;
    h.scheme = SWPOR_SCHEME_PRIV;
    h.flags = SWPOR_FLAG_RS;
    memset(h.file_id, 0xAB, sizeof(h.file_id));
    h.rs_k = 4;
    h.rs_m = 2;
    h.n = 12;
    h.s = 8;
    h.length = 1000;
    h.ctime = 1700000000;
    return h;
}

static void test_tag_header_roundtrip(void **state)
{
    (void)state;
    swpor_tag_header_t h = sample_header();
    uint8_t buf[72];
    swpor_tag_header_encode(&h, buf);
    assert_memory_equal(buf, "SWPT", 4);
    assert_int_equal(buf[5], SWPOR_SCHEME_PRIV);
    swpor_tag_header_t g;
    assert_int_equal(swpor_tag_header_decode(buf, sizeof(buf), &g), SWPOR_OK);
    assert_memory_equal(&h, &g, sizeof(h));
}

static void test_tag_header_rejects(void **state)
{
    (void)state;
    swpor_tag_header_t h = sample_header();
    swpor_tag_header_t g;
    uint8_t buf[72];

    swpor_tag_header_encode(&h, buf);
    assert_int_equal(swpor_tag_header_decode(buf, 71, &g), SWPOR_E_PARSE);
    buf[0] = 'X';
    assert_int_equal(swpor_tag_header_decode(buf, 72, &g), SWPOR_E_PARSE);

    h = sample_header();
    h.version = 2;
    swpor_tag_header_encode(&h, buf);
    assert_int_equal(swpor_tag_header_decode(buf, 72, &g), SWPOR_E_UNSUPPORTED);

    h = sample_header();
    h.n = 13; /* 不是 k+m 的整数倍 */
    swpor_tag_header_encode(&h, buf);
    assert_int_equal(swpor_tag_header_decode(buf, 72, &g), SWPOR_E_PARSE);

    h = sample_header();
    h.length = 8u * 4u * 31u * 8u + 1u; /* 超过数据块容量 */
    swpor_tag_header_encode(&h, buf);
    assert_int_equal(swpor_tag_header_decode(buf, 72, &g), SWPOR_E_PARSE);

    h = sample_header();
    h.flags = 0x8000;
    swpor_tag_header_encode(&h, buf);
    assert_int_equal(swpor_tag_header_decode(buf, 72, &g), SWPOR_E_PARSE);

    h = sample_header();
    swpor_tag_header_encode(&h, buf);
    buf[55] = 1; /* 保留字段非 0 */
    assert_int_equal(swpor_tag_header_decode(buf, 72, &g), SWPOR_E_PARSE);
}

static void test_hex(void **state)
{
    (void)state;
    uint8_t in[3] = {0x00, 0xAB, 0xFF};
    char hex[7];
    swpor_hex_encode(in, 3, hex);
    assert_string_equal(hex, "00abff");
    uint8_t out[3];
    assert_int_equal(swpor_hex_decode("00ABff", out, 3), SWPOR_OK);
    assert_memory_equal(in, out, 3);
    assert_int_equal(swpor_hex_decode("00ab", out, 3), SWPOR_E_PARSE);
    assert_int_equal(swpor_hex_decode("00abzz", out, 3), SWPOR_E_PARSE);
}

/* ---------------- 平台层文件接口 ---------------- */

static void test_platform_files(void **state)
{
    (void)state;
    char dir[256];
    char path[512];
    (void)snprintf(dir, sizeof(dir), "swpor_test_tmp_%u/a/b", (unsigned)(swpor_time_ns() % 100000));
    assert_int_equal(swpor_mkdir_p(dir), SWPOR_OK);
    assert_int_equal(swpor_mkdir_p(dir), SWPOR_OK);
    assert_int_equal(swpor_path_join(path, sizeof(path), dir, "f.bin"), SWPOR_OK);

    swpor_file_t *f = NULL;
    assert_int_equal(swpor_file_open(path, SWPOR_FILE_CREATE, &f), SWPOR_OK);
    uint8_t data[100];
    for (int i = 0; i < 100; i++) {
        data[i] = (uint8_t)i;
    }
    assert_int_equal(swpor_file_pwrite(f, data, 100, 50), SWPOR_OK);
    uint64_t size = 0;
    assert_int_equal(swpor_file_size(f, &size), SWPOR_OK);
    assert_true(size == 150);
    uint8_t back[100];
    assert_int_equal(swpor_file_pread(f, back, 100, 50), SWPOR_OK);
    assert_memory_equal(data, back, 100);
    assert_int_equal(swpor_file_pread(f, back, 100, 51), SWPOR_E_IO); /* 越过文件尾 */
    size_t got = 0;
    assert_int_equal(swpor_file_pread_some(f, back, 100, 100, &got), SWPOR_OK);
    assert_true(got == 50);
    swpor_file_close(f);

    /* 私有文件：不覆盖已有文件 */
    char kpath[512];
    assert_int_equal(swpor_path_join(kpath, sizeof(kpath), dir, "k.key"), SWPOR_OK);
    assert_int_equal(swpor_file_create_private(kpath, 0, &f), SWPOR_OK);
    swpor_file_close(f);
    assert_int_equal(swpor_file_create_private(kpath, 0, &f), SWPOR_E_EXISTS);
    assert_int_equal(swpor_file_create_private(kpath, 1, &f), SWPOR_OK);
    swpor_file_close(f);

    assert_int_equal(swpor_file_open("no/such/file", SWPOR_FILE_READ, &f), SWPOR_E_NOT_FOUND);
    assert_int_equal(swpor_remove_file(path), SWPOR_OK);
    assert_int_equal(swpor_remove_file(kpath), SWPOR_OK);
    assert_int_equal(swpor_remove_file(path), SWPOR_E_NOT_FOUND);
    assert_int_equal(swpor_remove_dir(dir), SWPOR_OK);
    swpor_file_close(NULL);
}

static void test_platform_threads(void **state)
{
    (void)state;
    assert_true(swpor_cpu_count() >= 1);
    swpor_mutex_t *m = NULL;
    assert_int_equal(swpor_mutex_new(&m), SWPOR_OK);
    swpor_mutex_lock(m);
    swpor_mutex_unlock(m);
    swpor_mutex_free(m);
    swpor_rwlock_t *l = NULL;
    assert_int_equal(swpor_rwlock_new(&l), SWPOR_OK);
    swpor_rwlock_rdlock(l);
    swpor_rwlock_rdlock(l);
    swpor_rwlock_rdunlock(l);
    swpor_rwlock_rdunlock(l);
    swpor_rwlock_wrlock(l);
    swpor_rwlock_wrunlock(l);
    swpor_rwlock_free(l);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_T01_sector_roundtrip),
        cmocka_unit_test(test_T01_sector_rejects_large),
        cmocka_unit_test(test_T01_canonical_check),
        cmocka_unit_test(test_T01_field_arith),
        cmocka_unit_test(test_T01_block_to_fr),
        cmocka_unit_test(test_T02_prf_deterministic_and_distinct),
        cmocka_unit_test(test_T02_prf_known_answer),
        cmocka_unit_test(test_hkdf_and_hstream),
        cmocka_unit_test(test_challenge_explicit),
        cmocka_unit_test(test_challenge_seed_deterministic),
        cmocka_unit_test(test_challenge_from_items_validation),
        cmocka_unit_test(test_uniform_u64_bounds),
        cmocka_unit_test(test_tag_header_roundtrip),
        cmocka_unit_test(test_tag_header_rejects),
        cmocka_unit_test(test_hex),
        cmocka_unit_test(test_platform_files),
        cmocka_unit_test(test_platform_threads),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
