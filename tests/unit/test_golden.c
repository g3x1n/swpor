/*
 * T-25（库层面）：跨平台逐字节一致。
 * 用固定的密钥与输入运行所有确定性的计算——加密 + RS 编码 + 置换（SPEC 5）、Priv σ_i（4.1）、
 * Pub σ_i（4.2）、种子挑战展开（3.5.2）、Pub 文件标签签名（Ed25519 是确定性签名）、证明生成——
 * 把全部输出做 SHA-256，与固定的期望值比较。
 *
 * 期望值是本测试第一次在 macOS arm64 上运行得到的回归值（Priv 部分另由 T-03 与 Python
 * 参考实现独立核对）。CI 在 Linux 与 Windows 上运行本测试，即检验三个平台的输出逐字节相同。
 * 若有意修改了格式或算法，需要更新期望值并在 SPEC 第 14 节登记。
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmocka.h>
#include <openssl/evp.h>

#include "mem_backend.h"
#include "swpor/swpor.h"

/* macOS arm64 上首次运行得到的回归值 */
#define SWPOR_T25_GOLDEN "d5fdc4f61ecf01f175f340f5557d33f0db4c986828ac1d2d7b8c0c88c008b93d"

static int collect_block(void *user, uint64_t pos, const uint8_t *block)
{
    mem_backend_t *m = user;
    if (pos >= m->n) {
        return SWPOR_E_RANGE;
    }
    memcpy(m->blocks + pos * m->bb, block, m->bb);
    return SWPOR_OK;
}

static void hash_update(EVP_MD_CTX *md, const char *label, const uint8_t *p, size_t len)
{
    assert_int_equal(EVP_DigestUpdate(md, label, strlen(label)), 1);
    assert_int_equal(EVP_DigestUpdate(md, p, len), 1);
}

static void test_T25_golden_outputs(void **state)
{
    (void)state;
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    assert_non_null(md);
    assert_int_equal(EVP_DigestInit_ex(md, EVP_sha256(), NULL), 1);

    /* 固定输入：L = 5000 字节，m[i] = (i·7 + 3) mod 256 */
    const size_t len = 5000;
    uint8_t *data = malloc(len);
    assert_non_null(data);
    for (size_t i = 0; i < len; i++) {
        data[i] = (uint8_t)((i * 7u + 3u) & 0xFFu);
    }
    swpor_priv_file_keys_t fk;
    for (int i = 0; i < 32; i++) {
        fk.k_prf[i] = (uint8_t)i;
        fk.k_alpha[i] = (uint8_t)(0x40 + i);
        fk.k_perm[i] = (uint8_t)(0x80 + i);
        fk.k_fenc[i] = (uint8_t)(0xC0 + i);
    }
    const uint16_t s = 8;
    const uint16_t flags = SWPOR_FLAG_RS | SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT;
    swpor_layout_t lay;
    assert_int_equal(swpor_layout_compute(len, s, flags, 6, 3, &lay), SWPOR_OK);

    /* 1. 预处理输出 M′ */
    mem_backend_t mb;
    memset(&mb, 0, sizeof(mb));
    mb.n = lay.n;
    mb.bb = swpor_block_bytes(s);
    mb.blocks = calloc((size_t)lay.n, mb.bb);
    assert_non_null(mb.blocks);
    mem_input_t in = {data, len, 0};
    assert_int_equal(swpor_encode(NULL, &lay, fk.k_perm, fk.k_fenc, mem_input, &in, collect_block, &mb),
                     SWPOR_OK);
    hash_update(md, "blocks", mb.blocks, (size_t)lay.n * mb.bb);

    /* 2. Priv σ_i */
    swpor_priv_tagger_t *pt = NULL;
    assert_int_equal(swpor_priv_tagger_new(&fk, s, &pt), SWPOR_OK);
    for (uint64_t i = 0; i < lay.n; i++) {
        uint8_t sg[32];
        assert_int_equal(swpor_priv_tag_block(pt, i, mb.blocks + i * mb.bb, sg), SWPOR_OK);
        hash_update(md, "priv", sg, 32);
    }
    swpor_priv_tagger_free(pt);

    /* 3. Pub σ_i 与签名（x、Ed25519 种子固定） */
    uint8_t x[32] = {0};
    x[31] = 0x2A;
    x[0] = 0x11;
    uint8_t ed[32];
    memset(ed, 0x5C, sizeof(ed));
    swpor_pub_sk_t *sk = NULL;
    assert_int_equal(swpor_pub_sk_import(x, ed, &sk), SWPOR_OK);
    uint8_t file_id[32];
    uint8_t u_seed[32];
    memset(file_id, 0xF1, sizeof(file_id));
    memset(u_seed, 0x0E, sizeof(u_seed));
    swpor_pub_tagger_t *ut = NULL;
    assert_int_equal(swpor_pub_tagger_new(sk, file_id, u_seed, s, &ut), SWPOR_OK);
    for (uint64_t i = 0; i < lay.n; i += 7) {
        uint8_t sg[48];
        assert_int_equal(swpor_pub_tag_block(ut, i, mb.blocks + i * mb.bb, sg), SWPOR_OK);
        hash_update(md, "pub", sg, 48);
    }
    swpor_pub_tagger_free(ut);
    swpor_tag_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = SWPOR_FORMAT_VERSION;
    h.scheme = SWPOR_SCHEME_PUB;
    h.flags = SWPOR_FLAG_RS;
    memcpy(h.file_id, file_id, 32);
    h.n = lay.n;
    h.s = s;
    h.rs_k = 6;
    h.rs_m = 3;
    h.length = len;
    h.ctime = 1767225600; /* 固定的创建时间 */
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    assert_int_equal(swpor_pub_tag_sign(sk, &h, u_seed, tag, sizeof(tag), &tag_len), SWPOR_OK);
    hash_update(md, "pubtag", tag, tag_len);
    uint8_t v[96], edp[32];
    swpor_pub_pk_t *pk = NULL;
    assert_int_equal(swpor_pub_pk_from_sk(sk, &pk), SWPOR_OK);
    assert_int_equal(swpor_pub_pk_export(pk, v, edp), SWPOR_OK);
    hash_update(md, "pk", v, 96);
    hash_update(md, "edpk", edp, 32);
    swpor_pub_pk_free(pk);
    swpor_pub_sk_free(sk);

    /* 4. 种子挑战与证明 */
    uint8_t seed[32];
    memset(seed, 0xA5, sizeof(seed));
    swpor_chal_t *c = NULL;
    assert_int_equal(swpor_chal_from_seed(seed, lay.n, 10, &c), SWPOR_OK);
    for (uint32_t k = 0; k < c->count; k++) {
        uint8_t idx[8];
        for (int b = 0; b < 8; b++) {
            idx[b] = (uint8_t)(c->items[k].index >> (56 - 8 * b));
        }
        hash_update(md, "i", idx, 8);
        hash_update(md, "nu", c->items[k].nu, 16);
    }
    swpor_chal_free(c);

    /* 5. 置换 P（SPEC 5） */
    uint64_t *perm = malloc((size_t)lay.n * sizeof(*perm));
    assert_non_null(perm);
    assert_int_equal(swpor_perm_compute(fk.k_perm, lay.n, perm), SWPOR_OK);
    for (uint64_t i = 0; i < lay.n; i++) {
        uint8_t b[8];
        for (int k = 0; k < 8; k++) {
            b[k] = (uint8_t)(perm[i] >> (56 - 8 * k));
        }
        hash_update(md, "perm", b, 8);
    }
    free(perm);

    uint8_t out[32];
    unsigned int outl = 0;
    assert_int_equal(EVP_DigestFinal_ex(md, out, &outl), 1);
    EVP_MD_CTX_free(md);
    char hex[65];
    swpor_hex_encode(out, 32, hex);
    printf("T-25 golden digest: %s\n", hex);
    assert_string_equal(hex, SWPOR_T25_GOLDEN);
    free(mb.blocks);
    free(data);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_T25_golden_outputs),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
