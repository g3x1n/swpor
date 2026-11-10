/*
 * M1 单元测试：Priv 方案（SPEC 4.1），T-04～T-08。
 * 使用内存中的"服务端"（块数组 + σ 数组），不涉及纠删码与磁盘。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "prf.h"
#include "swpor/priv.h"
#include "swpor/swpor.h"

typedef struct {
    swpor_tag_header_t hdr;
    swpor_priv_file_keys_t fk;
    size_t bb;
    uint8_t *blocks; /* n × bb */
    uint8_t *sigmas; /* n × 32 */
} mem_file_t;

static int mem_reader(void *user, uint64_t i, uint8_t *block, size_t block_len, uint8_t *sigma,
                      size_t sigma_len)
{
    mem_file_t *f = user;
    if (i >= f->hdr.n || block_len != f->bb || sigma_len != 32) {
        return SWPOR_E_RANGE;
    }
    memcpy(block, f->blocks + i * f->bb, f->bb);
    memcpy(sigma, f->sigmas + i * 32, 32);
    return SWPOR_OK;
}

/* 随机数据 → n 块 → 打标签（Priv.St） */
static mem_file_t *mem_file_new(uint64_t n, uint16_t s)
{
    mem_file_t *f = calloc(1, sizeof(*f));
    assert_non_null(f);
    f->hdr.version = SWPOR_FORMAT_VERSION;
    f->hdr.scheme = SWPOR_SCHEME_PRIV;
    f->hdr.n = n;
    f->hdr.s = s;
    f->hdr.length = n * swpor_block_bytes(s);
    f->bb = swpor_block_bytes(s);
    assert_int_equal(swpor_random_bytes(f->hdr.file_id, 32), SWPOR_OK);
    assert_int_equal(swpor_priv_file_keys_gen(&f->fk), SWPOR_OK);
    f->blocks = malloc(n * f->bb);
    f->sigmas = malloc(n * 32);
    assert_non_null(f->blocks);
    assert_non_null(f->sigmas);
    assert_int_equal(swpor_random_bytes(f->blocks, n * f->bb), SWPOR_OK);
    swpor_priv_tagger_t *t = NULL;
    assert_int_equal(swpor_priv_tagger_new(&f->fk, s, &t), SWPOR_OK);
    for (uint64_t i = 0; i < n; i++) {
        assert_int_equal(swpor_priv_tag_block(t, i, f->blocks + i * f->bb, f->sigmas + i * 32),
                         SWPOR_OK);
    }
    swpor_priv_tagger_free(t);
    return f;
}

static void mem_file_free(mem_file_t *f)
{
    swpor_priv_file_keys_cleanse(&f->fk);
    free(f->blocks);
    free(f->sigmas);
    free(f);
}

/* 一次完整审计：挑战 → 证明 → 验证。返回 pass；rc 写入 *verify_rc */
static int audit_once(mem_file_t *f, swpor_chal_t *c, int *verify_rc)
{
    size_t cap = swpor_proof_bytes(SWPOR_SCHEME_PRIV, f->hdr.s);
    uint8_t *proof = malloc(cap);
    assert_non_null(proof);
    size_t plen = 0;
    assert_int_equal(swpor_prove(NULL, &f->hdr, c, mem_reader, f, proof, cap, &plen), SWPOR_OK);
    int pass = -1;
    *verify_rc = swpor_priv_verify(NULL, &f->hdr, &f->fk, c, proof, plen, &pass);
    free(proof);
    return pass;
}

/* ---------------- T-04：诚实服务端 100% 通过 ---------------- */

static void test_T04_honest_prover_passes(void **state)
{
    (void)state;
    static const struct {
        uint64_t n;
        uint16_t s;
        uint32_t l;
    } cases[] = {{1, 1, 1},   {1, 4, 10},   {7, 1, 3},     {16, 4, 16},
                 {33, 8, 5},  {100, 16, 128}, {256, 128, 128}, {50, 3, 49}};
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        mem_file_t *f = mem_file_new(cases[k].n, cases[k].s);
        for (int rep = 0; rep < 5; rep++) {
            swpor_chal_t *c = NULL;
            if (rep % 2 == 0) {
                assert_int_equal(swpor_chal_explicit(f->hdr.n, cases[k].l, &c), SWPOR_OK);
            } else {
                assert_int_equal(swpor_chal_random_seed(f->hdr.n, cases[k].l, &c), SWPOR_OK);
            }
            int rc;
            assert_int_equal(audit_once(f, c, &rc), 1);
            assert_int_equal(rc, SWPOR_OK);
            swpor_chal_free(c);
        }
        mem_file_free(f);
    }
}

/* 构造必然命中块 target 的挑战 */
static swpor_chal_t *chal_hitting(uint64_t n, uint64_t target)
{
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_explicit(n, 8, &c), SWPOR_OK);
    int hit = 0;
    for (uint32_t k = 0; k < c->count; k++) {
        hit |= c->items[k].index == target;
    }
    if (!hit) {
        /* 用 from_items 重建：替换第一个下标为 target（保持互不相同） */
        swpor_chal_item_t *it = malloc(c->count * sizeof(*it));
        assert_non_null(it);
        memcpy(it, c->items, c->count * sizeof(*it));
        it[0].index = target;
        uint32_t cnt = c->count;
        swpor_chal_free(c);
        c = NULL;
        assert_int_equal(swpor_chal_from_items(it, cnt, n, 4096, &c), SWPOR_OK);
        free(it);
    }
    return c;
}

/* ---------------- T-05：篡改扇区后命中即失败 ---------------- */

static void test_T05_tampered_sector_detected(void **state)
{
    (void)state;
    mem_file_t *f = mem_file_new(64, 8);
    for (int rep = 0; rep < 20; rep++) {
        uint64_t target = (uint64_t)rep * 3 % 64;
        size_t byte = (size_t)rep * 37 % f->bb;
        f->blocks[target * f->bb + byte] ^= (uint8_t)(1u << (rep % 8));
        swpor_chal_t *c = chal_hitting(64, target);
        int rc;
        assert_int_equal(audit_once(f, c, &rc), 0);
        assert_int_equal(rc, SWPOR_OK);
        swpor_chal_free(c);
        f->blocks[target * f->bb + byte] ^= (uint8_t)(1u << (rep % 8)); /* 还原 */
    }
    mem_file_free(f);
}

/* ---------------- T-06：篡改 σ_i 后命中即失败 ---------------- */

static void test_T06_tampered_sigma_detected(void **state)
{
    (void)state;
    mem_file_t *f = mem_file_new(64, 8);
    for (int rep = 0; rep < 20; rep++) {
        uint64_t target = (uint64_t)rep * 5 % 64;
        /* 只改最低字节，保证仍是规范编码（< r），测试的是等式而不是解析 */
        f->sigmas[target * 32 + 31] ^= 0x01;
        swpor_chal_t *c = chal_hitting(64, target);
        int rc;
        assert_int_equal(audit_once(f, c, &rc), 0);
        assert_int_equal(rc, SWPOR_OK);
        swpor_chal_free(c);
        f->sigmas[target * 32 + 31] ^= 0x01;
    }
    mem_file_free(f);
}

/* ---------------- T-07：伪造响应被拒绝 ---------------- */

static void test_T07_forged_responses_rejected(void **state)
{
    (void)state;
    mem_file_t *f = mem_file_new(32, 4);
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_explicit(32, 10, &c), SWPOR_OK);
    size_t plen_ok = swpor_proof_bytes(SWPOR_SCHEME_PRIV, 4);
    uint8_t *proof = malloc(plen_ok + 1);
    assert_non_null(proof);
    size_t plen = 0;
    assert_int_equal(swpor_prove(NULL, &f->hdr, c, mem_reader, f, proof, plen_ok, &plen),
                     SWPOR_OK);
    int pass;

    /* 1. 随机 μ/σ（规范编码）：等式不成立 */
    for (int rep = 0; rep < 20; rep++) {
        uint8_t *bad = malloc(plen);
        assert_non_null(bad);
        memcpy(bad, proof, plen);
        for (size_t off = 2; off < plen; off += 32) {
            assert_int_equal(swpor_random_bytes(bad + off, 32), SWPOR_OK);
            bad[off] &= 0x3F; /* < r */
        }
        assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, bad, plen, &pass), SWPOR_OK);
        assert_int_equal(pass, 0);
        free(bad);
    }

    /* 2. 非规范编码（>= r）：μ_0 或 σ 置为全 0xFF */
    uint8_t *bad = malloc(plen);
    assert_non_null(bad);
    memcpy(bad, proof, plen);
    memset(bad + 2, 0xFF, 32);
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, bad, plen, &pass),
                     SWPOR_E_PARSE);
    assert_int_equal(pass, 0);
    memcpy(bad, proof, plen);
    memset(bad + plen - 32, 0xFF, 32);
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, bad, plen, &pass),
                     SWPOR_E_PARSE);
    assert_int_equal(pass, 0);

    /* 3. 长度错误：截短、加长、s 字段不一致 */
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, proof, plen - 1, &pass),
                     SWPOR_E_PARSE);
    assert_int_equal(pass, 0);
    memcpy(bad, proof, plen);
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, proof, plen + 1, &pass),
                     SWPOR_E_PARSE);
    bad[1] ^= 0x01;
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, bad, plen, &pass),
                     SWPOR_E_PARSE);
    assert_int_equal(pass, 0);

    /* 4. 对另一个挑战的有效证明不能通过本挑战 */
    swpor_chal_t *c2 = NULL;
    assert_int_equal(swpor_chal_explicit(32, 10, &c2), SWPOR_OK);
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c2, proof, plen, &pass), SWPOR_OK);
    assert_int_equal(pass, 0);

    /* 原证明仍通过 */
    assert_int_equal(swpor_priv_verify(NULL, &f->hdr, &f->fk, c, proof, plen, &pass), SWPOR_OK);
    assert_int_equal(pass, 1);

    free(bad);
    free(proof);
    swpor_chal_free(c);
    swpor_chal_free(c2);
    mem_file_free(f);
}

/* ---------------- T-08：篡改文件标签任一字节，解密失败 ---------------- */

static void check_tag_tamper(uint16_t flags)
{
    swpor_priv_key_t *key = NULL;
    assert_int_equal(swpor_priv_keygen(&key), SWPOR_OK);
    swpor_tag_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = SWPOR_FORMAT_VERSION;
    h.scheme = SWPOR_SCHEME_PRIV;
    h.flags = flags;
    h.n = 10;
    h.s = 4;
    h.length = 100;
    h.ctime = 1;
    swpor_priv_file_keys_t fk;
    assert_int_equal(swpor_priv_file_keys_gen(&fk), SWPOR_OK);

    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t len = 0;
    assert_int_equal(swpor_priv_tag_seal(key, &h, &fk, tag, sizeof(tag), &len), SWPOR_OK);
    assert_int_equal(len, (flags & (SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT)) ? SWPOR_PRIV_TAG_BYTES_LONG
                                                                       : SWPOR_PRIV_TAG_BYTES_SHORT);

    swpor_tag_header_t h2;
    swpor_priv_file_keys_t fk2;
    assert_int_equal(swpor_priv_tag_open(key, tag, len, &h2, &fk2), SWPOR_OK);
    assert_memory_equal(&h, &h2, sizeof(h));
    assert_memory_equal(fk.k_prf, fk2.k_prf, 32);
    assert_memory_equal(fk.k_alpha, fk2.k_alpha, 32);

    for (size_t pos = 0; pos < len; pos++) {
        tag[pos] ^= 0x01;
        assert_int_equal(swpor_priv_tag_open(key, tag, len, &h2, &fk2), SWPOR_E_TAG_AUTH);
        tag[pos] ^= 0x01;
    }
    /* 长度错误 */
    assert_int_equal(swpor_priv_tag_open(key, tag, len - 1, &h2, &fk2), SWPOR_E_PARSE);

    /* 另一把用户密钥不能打开 */
    swpor_priv_key_t *other = NULL;
    assert_int_equal(swpor_priv_keygen(&other), SWPOR_OK);
    assert_int_equal(swpor_priv_tag_open(other, tag, len, &h2, &fk2), SWPOR_E_TAG_AUTH);

    /* msk 导出后重建的密钥可以打开 */
    uint8_t msk[32];
    swpor_priv_key_export(key, msk);
    swpor_priv_key_t *again = NULL;
    assert_int_equal(swpor_priv_key_from_msk(msk, &again), SWPOR_OK);
    assert_int_equal(swpor_priv_tag_open(again, tag, len, &h2, &fk2), SWPOR_OK);

    swpor_priv_key_free(key);
    swpor_priv_key_free(other);
    swpor_priv_key_free(again);
    swpor_priv_key_free(NULL);
}

static void test_T08_tag_tamper_fails_auth(void **state)
{
    (void)state;
    check_tag_tamper(0);
    check_tag_tamper(SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT);
}

/* 服务端拒绝越界挑战下标 */
static void test_prove_rejects_out_of_range(void **state)
{
    (void)state;
    mem_file_t *f = mem_file_new(8, 2);
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_explicit(16, 16, &c), SWPOR_OK); /* 按 n = 16 生成 */
    size_t cap = swpor_proof_bytes(SWPOR_SCHEME_PRIV, 2);
    uint8_t *proof = malloc(cap);
    assert_non_null(proof);
    size_t plen;
    assert_int_equal(swpor_prove(NULL, &f->hdr, c, mem_reader, f, proof, cap, &plen),
                     SWPOR_E_RANGE);
    free(proof);
    swpor_chal_free(c);
    mem_file_free(f);
}

/* 检索用的单块完好性检查 */
static void test_priv_check_block(void **state)
{
    (void)state;
    mem_file_t *f = mem_file_new(4, 3);
    swpor_priv_tagger_t *t = NULL;
    assert_int_equal(swpor_priv_tagger_new(&f->fk, 3, &t), SWPOR_OK);
    int ok = 0;
    assert_int_equal(swpor_priv_check_block(t, 2, f->blocks + 2 * f->bb, f->sigmas + 64, &ok),
                     SWPOR_OK);
    assert_int_equal(ok, 1);
    /* 块位置错误也必须失败（σ_i 绑定下标 i） */
    assert_int_equal(swpor_priv_check_block(t, 1, f->blocks + 2 * f->bb, f->sigmas + 64, &ok),
                     SWPOR_OK);
    assert_int_equal(ok, 0);
    swpor_priv_tagger_free(t);
    mem_file_free(f);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_T04_honest_prover_passes),
        cmocka_unit_test(test_T05_tampered_sector_detected),
        cmocka_unit_test(test_T06_tampered_sigma_detected),
        cmocka_unit_test(test_T07_forged_responses_rejected),
        cmocka_unit_test(test_T08_tag_tamper_fails_auth),
        cmocka_unit_test(test_prove_rejects_out_of_range),
        cmocka_unit_test(test_priv_check_block),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
