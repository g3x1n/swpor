/* PRF、HMAC 字节流、HKDF、随机数（SPEC 3.3、3.5.2、4.1、11）。 */

#include "prf.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include "endian.h"
#include "swpor/error.h"

/* 创建一个已设置好密钥的 HMAC 上下文。digest 为 "SHA512" 或 "SHA256"。 */
static EVP_MAC_CTX *hmac_ctx_new(const uint8_t *key, size_t key_len, const char *digest)
{
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (mac == NULL) {
        return NULL;
    }
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac); /* ctx 持有自己的引用 */
    if (ctx == NULL) {
        return NULL;
    }
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)digest, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_MAC_init(ctx, key, key_len, params) != 1) {
        EVP_MAC_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/* 用已设置的密钥计算 HMAC(dst ‖ I2OSP(i, 8))。EVP_MAC_init 传 NULL 密钥表示沿用原密钥。 */
static int hmac_counter(EVP_MAC_CTX *ctx, const char *dst, size_t dst_len, uint64_t i,
                        uint8_t *out, size_t out_cap)
{
    uint8_t ctr[8];
    swpor_store_be64(ctr, i);
    size_t outl = 0;
    if (EVP_MAC_init(ctx, NULL, 0, NULL) != 1 ||
        EVP_MAC_update(ctx, (const unsigned char *)dst, dst_len) != 1 ||
        EVP_MAC_update(ctx, ctr, sizeof(ctr)) != 1 ||
        EVP_MAC_final(ctx, out, &outl, out_cap) != 1 || outl != out_cap) {
        return SWPOR_E_CRYPTO;
    }
    return SWPOR_OK;
}

/* ===================================================================== */
/* PRF（SPEC 3.3）                                                        */
/* ===================================================================== */

struct swpor_prf {
    EVP_MAC_CTX *mac;
    char dst[32];
    size_t dst_len;
};

int swpor_prf_new(const uint8_t key[32], const char *dst, swpor_prf_t **out)
{
    if (key == NULL || dst == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t dl = strlen(dst);
    if (dl >= sizeof(((swpor_prf_t *)0)->dst)) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_prf_t *p = calloc(1, sizeof(*p));
    if (p == NULL) {
        return SWPOR_E_NOMEM;
    }
    p->mac = hmac_ctx_new(key, 32, "SHA512");
    if (p->mac == NULL) {
        free(p);
        return SWPOR_E_CRYPTO;
    }
    memcpy(p->dst, dst, dl + 1);
    p->dst_len = dl;
    *out = p;
    return SWPOR_OK;
}

int swpor_prf_eval(swpor_prf_t *prf, uint64_t i, swpor_fr_t *out)
{
    if (prf == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t h[64];
    int rc = hmac_counter(prf->mac, prf->dst, prf->dst_len, i, h, sizeof(h));
    if (rc == SWPOR_OK) {
        /* 512 bit 输出模 r，偏差 < 2^-256（SPEC 3.3） */
        swpor_fr_from_be_reduce(out, h, sizeof(h));
    }
    OPENSSL_cleanse(h, sizeof(h));
    return rc;
}

void swpor_prf_free(swpor_prf_t *prf)
{
    if (prf == NULL) {
        return;
    }
    EVP_MAC_CTX_free(prf->mac); /* OpenSSL 释放时会清零密钥 */
    OPENSSL_cleanse(prf, sizeof(*prf));
    free(prf);
}

/* ===================================================================== */
/* HMAC-SHA-256 计数器字节流（SPEC 3.5.2）                                  */
/* ===================================================================== */

int swpor_hstream_init(swpor_hstream_t *hs, const uint8_t *key, size_t key_len, const char *dst)
{
    if (hs == NULL || key == NULL || key_len == 0 || dst == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    memset(hs, 0, sizeof(*hs));
    size_t dl = strlen(dst);
    if (dl >= sizeof(hs->dst)) {
        return SWPOR_E_INVALID_ARG;
    }
    hs->mac = hmac_ctx_new(key, key_len, "SHA256");
    if (hs->mac == NULL) {
        return SWPOR_E_CRYPTO;
    }
    memcpy(hs->dst, dst, dl + 1);
    hs->dst_len = dl;
    hs->ctr = 0;
    hs->pos = sizeof(hs->buf);
    return SWPOR_OK;
}

int swpor_hstream_read(swpor_hstream_t *hs, uint8_t *out, size_t len)
{
    if (hs == NULL || hs->mac == NULL || (out == NULL && len > 0)) {
        return SWPOR_E_INVALID_ARG;
    }
    while (len > 0) {
        if (hs->pos == sizeof(hs->buf)) {
            int rc = hmac_counter(hs->mac, hs->dst, hs->dst_len, hs->ctr, hs->buf, sizeof(hs->buf));
            if (rc != SWPOR_OK) {
                return rc;
            }
            hs->ctr++;
            hs->pos = 0;
        }
        size_t take = sizeof(hs->buf) - hs->pos;
        if (take > len) {
            take = len;
        }
        memcpy(out, hs->buf + hs->pos, take);
        hs->pos += take;
        out += take;
        len -= take;
    }
    return SWPOR_OK;
}

void swpor_hstream_clear(swpor_hstream_t *hs)
{
    if (hs == NULL) {
        return;
    }
    EVP_MAC_CTX_free(hs->mac);
    OPENSSL_cleanse(hs, sizeof(*hs));
}

/* ===================================================================== */
/* HKDF（SPEC 4.1）                                                       */
/* ===================================================================== */

int swpor_hkdf_sha256(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                      const char *info)
{
    if (out == NULL || ikm == NULL || info == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return SWPOR_E_CRYPTO;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx == NULL) {
        return SWPOR_E_CRYPTO;
    }
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info));
    params[3] = OSSL_PARAM_construct_end();
    int rc = EVP_KDF_derive(kctx, out, out_len, params) == 1 ? SWPOR_OK : SWPOR_E_CRYPTO;
    EVP_KDF_CTX_free(kctx);
    return rc;
}

/* ===================================================================== */
/* 随机数（SPEC 11 第 4 条）                                                */
/* ===================================================================== */

#ifdef SWPOR_TESTING
static swpor_hstream_t g_test_rng;
static int g_test_rng_on = 0;
static uint64_t g_test_time = 0;

void swpor_test_rng_seed(const uint8_t *seed, size_t len)
{
    if (g_test_rng_on) {
        swpor_hstream_clear(&g_test_rng);
        g_test_rng_on = 0;
    }
    if (seed != NULL && len > 0) {
        g_test_rng_on = swpor_hstream_init(&g_test_rng, seed, len, "SWPOR-TEST-RNG") == SWPOR_OK;
    }
}

void swpor_test_set_time(uint64_t t)
{
    g_test_time = t;
}
#endif

int swpor_random_bytes(uint8_t *buf, size_t len)
{
    if (buf == NULL && len > 0) {
        return SWPOR_E_INVALID_ARG;
    }
#ifdef SWPOR_TESTING
    if (g_test_rng_on) {
        return swpor_hstream_read(&g_test_rng, buf, len);
    }
#endif
    while (len > 0) {
        int chunk = len > 0x40000000u ? 0x40000000 : (int)len;
        if (RAND_bytes(buf, chunk) != 1) {
            return SWPOR_E_CRYPTO;
        }
        buf += chunk;
        len -= (size_t)chunk;
    }
    return SWPOR_OK;
}

uint64_t swpor_now_unix(void)
{
#ifdef SWPOR_TESTING
    if (g_test_time != 0) {
        return g_test_time;
    }
#endif
    time_t t = time(NULL);
    return t < 0 ? 0u : (uint64_t)t;
}

int swpor_bytes_from_rng(void *user, uint8_t *out, size_t len)
{
    (void)user;
    return swpor_random_bytes(out, len);
}

int swpor_bytes_from_hstream(void *user, uint8_t *out, size_t len)
{
    return swpor_hstream_read((swpor_hstream_t *)user, out, len);
}

int swpor_uniform_u64(swpor_bytes_fn src, void *user, uint64_t bound, uint64_t *out)
{
    if (src == NULL || out == NULL || bound == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    /* limit = ⌊2^64 / bound⌋ · bound，用 (2^64 - 1) 计算并修正 bound 整除 2^64 的情形 */
    uint64_t q = UINT64_MAX / bound;
    uint64_t rem = UINT64_MAX % bound;
    if (rem == bound - 1) {
        q += 1; /* bound 整除 2^64：limit = 2^64，不拒绝任何值 */
    }
    int no_reject = (rem == bound - 1);
    uint64_t limit = q * bound; /* no_reject 时溢出为 0，不使用 */
    for (;;) {
        uint8_t b[8];
        int rc = src(user, b, sizeof(b));
        if (rc != SWPOR_OK) {
            return rc;
        }
        uint64_t x = swpor_load_be64(b);
        if (no_reject || x < limit) {
            *out = x % bound;
            return SWPOR_OK;
        }
    }
}
