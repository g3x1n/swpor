/*
 * M4 单元测试：Pub 方案（SPEC 4.2）。
 *   T-19：重复 T-04～T-08；T-20：σ 为非子群点、无穷远点、非法压缩编码时必须拒绝。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>

#include "blst.h"
#include "mem_backend.h"
#include "swpor/swpor.h"

static swpor_pub_sk_t *g_sk;
static swpor_pub_pk_t *g_pk;

static int setup(void **state)
{
    (void)state;
    return swpor_pub_keygen(&g_sk, &g_pk) == SWPOR_OK ? 0 : -1;
}

static int teardown(void **state)
{
    (void)state;
    swpor_pub_sk_free(g_sk);
    swpor_pub_pk_free(g_pk);
    return 0;
}

static swpor_keys_t pub_keys(void)
{
    swpor_keys_t k;
    memset(&k, 0, sizeof(k));
    k.scheme = SWPOR_SCHEME_PUB;
    k.pub_sk = g_sk;
    k.pub_pk = g_pk;
    return k;
}

/* 存入随机数据（不启用 RS，块与原文一一对应） */
static void store_random(mem_backend_t *mb, size_t len, uint16_t s, uint8_t *tag, size_t *tag_len)
{
    uint8_t *d = malloc(len);
    assert_non_null(d);
    assert_int_equal(swpor_random_bytes(d, len), SWPOR_OK);
    swpor_keys_t keys = pub_keys();
    swpor_st_params_t p = {s, 0, 0, 0};
    mem_input_t in = {d, len, 0};
    memset(mb, 0, sizeof(*mb));
    assert_int_equal(swpor_st_run(NULL, &keys, &p, len, mem_input, &in, &k_mem_sink, mb, tag,
                                  SWPOR_TAG_MAX_BYTES, tag_len, NULL),
                     SWPOR_OK);
    free(d);
}

/* 构造必然命中 target 的显式挑战 */
static swpor_chal_t *chal_hitting(uint64_t n, uint64_t target, uint32_t l)
{
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_explicit(n, l, &c), SWPOR_OK);
    for (uint32_t k = 0; k < c->count; k++) {
        if (c->items[k].index == target) {
            return c;
        }
    }
    swpor_chal_item_t *it = malloc(c->count * sizeof(*it));
    assert_non_null(it);
    memcpy(it, c->items, c->count * sizeof(*it));
    it[0].index = target;
    uint32_t cnt = c->count;
    swpor_chal_free(c);
    c = NULL;
    assert_int_equal(swpor_chal_from_items(it, cnt, n, 4096, &c), SWPOR_OK);
    free(it);
    return c;
}

/* 用给定挑战对内存存储做一次审计，返回 pass，验证返回码写入 *vrc */
static int audit_with(mem_backend_t *mb, const uint8_t *tag, size_t tag_len, swpor_chal_t *c,
                      int *vrc)
{
    swpor_tag_header_t h;
    uint8_t u_seed[32];
    assert_int_equal(swpor_pub_tag_open(g_pk, tag, tag_len, &h, u_seed), SWPOR_OK);
    size_t cap = swpor_proof_bytes(SWPOR_SCHEME_PUB, h.s);
    uint8_t *proof = malloc(cap);
    assert_non_null(proof);
    size_t plen = 0;
    assert_int_equal(mem_prove(mb, c, proof, cap, &plen), SWPOR_OK);
    int pass = -1;
    *vrc = swpor_pub_verify(NULL, g_pk, &h, u_seed, c, proof, plen, &pass);
    free(proof);
    return pass;
}

/* ---------------- T-19 / T-04：诚实服务端 ---------------- */

static void test_T19_T04_honest_prover_passes(void **state)
{
    (void)state;
    static const struct {
        size_t len;
        uint16_t s;
        uint32_t l;
    } cases[] = {{1, 1, 1}, {31 * 7, 1, 3}, {31 * 4 * 16, 4, 16}, {5000, 16, 8}, {40000, 128, 20}};
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        mem_backend_t mb;
        uint8_t tag[SWPOR_TAG_MAX_BYTES];
        size_t tag_len;
        store_random(&mb, cases[k].len, cases[k].s, tag, &tag_len);
        swpor_keys_t keys = pub_keys();
        for (int seed = 0; seed < 2; seed++) {
            swpor_audit_result_t res;
            assert_int_equal(
                swpor_audit_run(NULL, &keys, tag, tag_len, cases[k].l, seed, mem_prove, &mb, &res),
                SWPOR_OK);
            assert_int_equal(res.pass, 1);
            assert_int_equal(res.proof_bytes, 2 + 32u * cases[k].s + 48u);
        }
        mem_backend_free(&mb);
    }
}

/* ---------------- T-19 / T-05、T-06：篡改块或 σ_i ---------------- */

static void test_T19_T05_T06_tamper_detected(void **state)
{
    (void)state;
    mem_backend_t mb;
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    store_random(&mb, 31 * 8 * 32, 8, tag, &tag_len);
    for (int rep = 0; rep < 4; rep++) {
        uint64_t target = (uint64_t)rep * 7 % mb.n;
        int vrc;
        /* 篡改扇区 */
        mb.blocks[target * mb.bb + 10] ^= 0x04;
        swpor_chal_t *c = chal_hitting(mb.n, target, 6);
        assert_int_equal(audit_with(&mb, tag, tag_len, c, &vrc), 0);
        assert_int_equal(vrc, SWPOR_OK);
        mb.blocks[target * mb.bb + 10] ^= 0x04;
        assert_int_equal(audit_with(&mb, tag, tag_len, c, &vrc), 1);
        swpor_chal_free(c);

        /* 篡改 σ_i：换成另一块的 σ（合法群元素，但等式不成立） */
        uint64_t other = (target + 1) % mb.n;
        uint8_t saved[48];
        memcpy(saved, mb.sigmas + target * 48, 48);
        memcpy(mb.sigmas + target * 48, mb.sigmas + other * 48, 48);
        c = chal_hitting(mb.n, target, 1);
        assert_int_equal(audit_with(&mb, tag, tag_len, c, &vrc), 0);
        swpor_chal_free(c);
        memcpy(mb.sigmas + target * 48, saved, 48);
    }
    mem_backend_free(&mb);
}

/* 合法但不在 G1 子群中的点（x = 4，y 取较小的平方根），由 Python 计算得到 */
static const char k_nonsub_hex[] =
    "8000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000004";
/* 不在曲线上的点（x = 1：x^3 + 4 不是平方剩余） */
static const char k_offcurve_hex[] =
    "8000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000001";

/* ---------------- T-19 / T-07 与 T-20：伪造响应 ---------------- */

static void test_T19_T07_T20_forged_responses_rejected(void **state)
{
    (void)state;
    mem_backend_t mb;
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    store_random(&mb, 31 * 4 * 20, 4, tag, &tag_len);
    swpor_tag_header_t h;
    uint8_t u_seed[32];
    assert_int_equal(swpor_pub_tag_open(g_pk, tag, tag_len, &h, u_seed), SWPOR_OK);
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_random_seed(h.n, 8, &c), SWPOR_OK);
    size_t plen = swpor_proof_bytes(SWPOR_SCHEME_PUB, 4);
    uint8_t *proof = malloc(plen);
    uint8_t *bad = malloc(plen);
    assert_non_null(proof);
    assert_non_null(bad);
    size_t got;
    assert_int_equal(mem_prove(&mb, c, proof, plen, &got), SWPOR_OK);
    int pass;
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, proof, plen, &pass), SWPOR_OK);
    assert_int_equal(pass, 1);
    uint8_t *sig = bad + plen - 48;

    /* 随机 μ（规范编码） */
    memcpy(bad, proof, plen);
    assert_int_equal(swpor_random_bytes(bad + 2, 32), SWPOR_OK);
    bad[2] &= 0x3F;
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_OK);
    assert_int_equal(pass, 0);

    /* 非规范 μ（>= r） */
    memcpy(bad, proof, plen);
    memset(bad + 2, 0xFF, 32);
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_E_PARSE);
    assert_int_equal(pass, 0);

    /* 随机但合法的 σ（另一个 G1 点：哈希得到） */
    memcpy(bad, proof, plen);
    {
        blst_p1 p;
        blst_hash_to_g1(&p, (const byte *)"x", 1, (const byte *)"T", 1, NULL, 0);
        blst_p1_compress(sig, &p);
    }
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_OK);
    assert_int_equal(pass, 0);

    /* T-20：非子群点 */
    memcpy(bad, proof, plen);
    assert_int_equal(swpor_hex_decode(k_nonsub_hex, sig, 48), SWPOR_OK);
    {
        /* 确认测试数据本身：在曲线上但不在子群中 */
        blst_p1_affine a;
        assert_int_equal(blst_p1_uncompress(&a, sig), BLST_SUCCESS);
        assert_false(blst_p1_affine_in_g1(&a));
    }
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_E_PARSE);
    assert_int_equal(pass, 0);

    /* T-20：无穷远点（压缩编码 0xC0 ‖ 0…） */
    memset(sig, 0, 48);
    sig[0] = 0xC0;
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_E_PARSE);
    assert_int_equal(pass, 0);

    /* T-20：非法压缩编码（不在曲线上、缺少压缩标志位、x >= p） */
    assert_int_equal(swpor_hex_decode(k_offcurve_hex, sig, 48), SWPOR_OK);
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_E_PARSE);
    memcpy(bad, proof, plen);
    sig[0] &= 0x7F;
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_E_PARSE);
    memset(sig, 0xFF, 48);
    sig[0] = 0x9F;
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, bad, plen, &pass), SWPOR_E_PARSE);
    assert_int_equal(pass, 0);

    /* 长度错误 */
    assert_int_equal(swpor_pub_verify(NULL, g_pk, &h, u_seed, c, proof, plen - 1, &pass),
                     SWPOR_E_PARSE);

    /* 服务端：磁盘上的 σ_i 为非子群点时拒绝生成证明（SPEC 11 第 1 条） */
    assert_int_equal(swpor_hex_decode(k_nonsub_hex, mb.sigmas + c->items[0].index * 48, 48),
                     SWPOR_OK);
    assert_int_equal(mem_prove(&mb, c, proof, plen, &got), SWPOR_E_PARSE);

    free(proof);
    free(bad);
    swpor_chal_free(c);
    mem_backend_free(&mb);
}

/* ---------------- T-19 / T-08：篡改文件标签 ---------------- */

static void test_T19_T08_tag_tamper_fails_verify(void **state)
{
    (void)state;
    mem_backend_t mb;
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    store_random(&mb, 100, 2, tag, &tag_len);
    assert_int_equal(tag_len, SWPOR_PUB_TAG_BYTES);
    swpor_tag_header_t h;
    uint8_t u_seed[32];
    for (size_t pos = 0; pos < tag_len; pos++) {
        tag[pos] ^= 0x80;
        assert_int_equal(swpor_pub_tag_open(g_pk, tag, tag_len, &h, u_seed), SWPOR_E_TAG_AUTH);
        tag[pos] ^= 0x80;
    }
    assert_int_equal(swpor_pub_tag_open(g_pk, tag, tag_len - 1, &h, u_seed), SWPOR_E_PARSE);
    /* 另一对密钥不能验证 */
    swpor_pub_sk_t *sk2 = NULL;
    swpor_pub_pk_t *pk2 = NULL;
    assert_int_equal(swpor_pub_keygen(&sk2, &pk2), SWPOR_OK);
    assert_int_equal(swpor_pub_tag_open(pk2, tag, tag_len, &h, u_seed), SWPOR_E_TAG_AUTH);
    swpor_pub_sk_free(sk2);
    swpor_pub_pk_free(pk2);
    mem_backend_free(&mb);
}

/* Pub 方案不支持置乱 / 加密（标签中无处保存 k_perm / k_fenc） */
static void test_pub_rejects_perm(void **state)
{
    (void)state;
    uint8_t d[10] = {0};
    swpor_keys_t keys = pub_keys();
    swpor_st_params_t p = {4, SWPOR_FLAG_PERM, 0, 0};
    mem_input_t in = {d, sizeof(d), 0};
    mem_backend_t mb;
    memset(&mb, 0, sizeof(mb));
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    assert_int_equal(swpor_st_run(NULL, &keys, &p, sizeof(d), mem_input, &in, &k_mem_sink, &mb, tag,
                                  sizeof(tag), &tag_len, NULL),
                     SWPOR_E_UNSUPPORTED);
}

/* 密钥导出 / 导入、公钥检查 */
static void test_pub_key_io(void **state)
{
    (void)state;
    uint8_t x[32], ed[32], v[96], edp[32];
    assert_int_equal(swpor_pub_sk_export(g_sk, x, ed), SWPOR_OK);
    assert_int_equal(swpor_pub_pk_export(g_pk, v, edp), SWPOR_OK);
    swpor_pub_sk_t *sk = NULL;
    swpor_pub_pk_t *pk = NULL;
    assert_int_equal(swpor_pub_sk_import(x, ed, &sk), SWPOR_OK);
    assert_int_equal(swpor_pub_pk_from_sk(sk, &pk), SWPOR_OK);
    uint8_t v2[96], edp2[32];
    assert_int_equal(swpor_pub_pk_export(pk, v2, edp2), SWPOR_OK);
    assert_memory_equal(v, v2, 96);
    assert_memory_equal(edp, edp2, 32);
    swpor_pub_pk_free(pk);
    pk = NULL;
    /* x = 0 非法 */
    uint8_t zero[32] = {0};
    swpor_pub_sk_t *bad = NULL;
    assert_int_equal(swpor_pub_sk_import(zero, ed, &bad), SWPOR_E_PARSE);
    /* v 为无穷远点非法 */
    uint8_t inf[96] = {0xC0};
    assert_int_equal(swpor_pub_pk_import(inf, edp, &pk), SWPOR_E_PARSE);
    /* v 被篡改（多半不在曲线上） */
    v[50] ^= 1;
    assert_int_equal(swpor_pub_pk_import(v, edp, &pk), SWPOR_E_PARSE);
    swpor_pub_sk_free(sk);
}

/* 检索：单块校验 */
static void test_pub_retrieve(void **state)
{
    (void)state;
    const size_t len = 9000;
    uint8_t *d = malloc(len);
    assert_non_null(d);
    assert_int_equal(swpor_random_bytes(d, len), SWPOR_OK);
    swpor_keys_t keys = pub_keys();
    swpor_st_params_t p = {8, SWPOR_FLAG_RS, 4, 2};
    mem_input_t in = {d, len, 0};
    mem_backend_t mb;
    memset(&mb, 0, sizeof(mb));
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    assert_int_equal(swpor_st_run(NULL, &keys, &p, len, mem_input, &in, &k_mem_sink, &mb, tag,
                                  sizeof(tag), &tag_len, NULL),
                     SWPOR_OK);
    mb.blocks[0] ^= 1;  /* 条带 0 的一个数据块损坏 */
    mb.deleted[7] = 1;  /* 条带 1 的一个数据块被删除 */
    swpor_keys_t vk = keys;
    vk.pub_sk = NULL;   /* 检索与审计只需要公钥 */
    mem_output_t out;
    memset(&out, 0, sizeof(out));
    uint64_t erased = 0;
    assert_int_equal(swpor_retrieve_run(NULL, &vk, tag, tag_len, mem_get, &mb, mem_output, &out,
                                        &erased),
                     SWPOR_OK);
    assert_int_equal(out.len, len);
    assert_memory_equal(out.data, d, len);
    assert_true(erased == 2);
    free(out.data);
    free(d);
    mem_backend_free(&mb);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_T19_T04_honest_prover_passes),
        cmocka_unit_test(test_T19_T05_T06_tamper_detected),
        cmocka_unit_test(test_T19_T07_T20_forged_responses_rejected),
        cmocka_unit_test(test_T19_T08_tag_tamper_fails_verify),
        cmocka_unit_test(test_pub_rejects_perm),
        cmocka_unit_test(test_pub_key_io),
        cmocka_unit_test(test_pub_retrieve),
    };
    return cmocka_run_group_tests(tests, setup, teardown);
}
