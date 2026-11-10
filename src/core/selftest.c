/*
 * 依赖自检（见 swpor.h 中 swpor_selftest 的说明）。
 * 只确认 OpenSSL 与 blst 已正确链接并能工作，不是算法测试。
 */

#include <stdint.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "blst.h"
#include "swpor/swpor.h"

const char *swpor_version(void)
{
    return SWPOR_VERSION_STRING;
}

const char *swpor_openssl_version(void)
{
    return OpenSSL_version(OPENSSL_VERSION);
}

/* HMAC-SHA-512 能否正常计算（EVP_MAC 高层接口，CLAUDE.md 要求） */
static int check_hmac_sha512(void)
{
    static const uint8_t key[32] = {0};
    static const char msg[] = "swpor-selftest";
    uint8_t out[64];
    size_t out_len = 0;
    int ok = 0;

    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *mctx = mac != NULL ? EVP_MAC_CTX_new(mac) : NULL;
    if (mctx == NULL) {
        goto cleanup;
    }
    char digest[] = "SHA512";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", digest, 0),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(mctx, key, sizeof(key), params) != 1 ||
        EVP_MAC_update(mctx, (const unsigned char *)msg, sizeof(msg) - 1) != 1 ||
        EVP_MAC_final(mctx, out, &out_len, sizeof(out)) != 1 || out_len != sizeof(out)) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return ok;
}

/* blst：哈希到 G1 + 子群检查 + 配对双线性性 e(aP, Q) == e(P, aQ) */
static int check_blst(void)
{
    static const uint8_t dst[] = "SWPOR-V1-SELFTEST-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    static const uint8_t msg[] = "swpor-selftest";

    blst_p1 h;
    blst_p1_affine h_aff;
    blst_hash_to_g1(&h, msg, sizeof(msg) - 1, dst, sizeof(dst) - 1, NULL, 0);
    blst_p1_to_affine(&h_aff, &h);
    if (!blst_p1_affine_in_g1(&h_aff)) {
        return 0;
    }

    /* 随机标量 a（blst 标量为小端字节序） */
    uint8_t a[32];
    if (RAND_bytes(a, (int)sizeof(a)) != 1) {
        return 0;
    }
    a[31] &= 0x3f; /* 保证 a < 2^254 < r，这里只做自检，不需要均匀分布 */

    blst_p1 aP;
    blst_p1_affine aP_aff;
    blst_p1_mult(&aP, &h, a, 254);
    blst_p1_to_affine(&aP_aff, &aP);

    blst_p2 aQ;
    blst_p2_affine aQ_aff;
    blst_p2_mult(&aQ, blst_p2_generator(), a, 254);
    blst_p2_to_affine(&aQ_aff, &aQ);

    blst_p2_affine q_aff;
    blst_p2_to_affine(&q_aff, blst_p2_generator());

    blst_fp12 lhs, rhs, tmp;
    blst_miller_loop(&tmp, &q_aff, &aP_aff);
    blst_final_exp(&lhs, &tmp);
    blst_miller_loop(&tmp, &aQ_aff, &h_aff);
    blst_final_exp(&rhs, &tmp);

    return blst_fp12_is_equal(&lhs, &rhs) ? 1 : 0;
}

int swpor_selftest(void)
{
    uint8_t buf[32];
    if (RAND_bytes(buf, (int)sizeof(buf)) != 1) {
        return SWPOR_E_CRYPTO;
    }
    if (!check_hmac_sha512()) {
        return SWPOR_E_CRYPTO;
    }
    if (!check_blst()) {
        return SWPOR_E_CRYPTO;
    }
    return SWPOR_OK;
}
