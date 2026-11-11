/* Priv：私有验证方案（SPEC 4.1）。 */

#include "swpor/priv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "endian.h"
#include "fr.h"
#include "internal.h"
#include "platform.h"
#include "prf.h"
#include "proof.h"
#include "swpor/error.h"
#include "swpor/params.h"

#define GCM_NONCE_BYTES 12
#define GCM_TAG_BYTES 16

/* ===================================================================== */
/* 用户密钥                                                               */
/* ===================================================================== */

struct swpor_priv_key {
    uint8_t msk[32];
    uint8_t k_tag[32];
};

int swpor_priv_key_from_msk(const uint8_t msk[32], swpor_priv_key_t **out)
{
    if (msk == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_priv_key_t *k = calloc(1, sizeof(*k));
    if (k == NULL) {
        return SWPOR_E_NOMEM;
    }
    memcpy(k->msk, msk, 32);
    /* k_tag = HKDF-SHA-256(IKM = msk, salt = 空, info = "SWPOR-V1-TAGKEY", L = 32) */
    int rc = swpor_hkdf_sha256(k->k_tag, sizeof(k->k_tag), k->msk, sizeof(k->msk),
                               SWPOR_INFO_TAGKEY);
    if (rc != SWPOR_OK) {
        swpor_priv_key_free(k);
        return rc;
    }
    *out = k;
    return SWPOR_OK;
}

int swpor_priv_keygen(swpor_priv_key_t **out)
{
    uint8_t msk[32];
    int rc = swpor_random_bytes(msk, sizeof(msk));
    if (rc == SWPOR_OK) {
        rc = swpor_priv_key_from_msk(msk, out);
    }
    OPENSSL_cleanse(msk, sizeof(msk));
    return rc;
}

void swpor_priv_key_export(const swpor_priv_key_t *key, uint8_t msk[32])
{
    memcpy(msk, key->msk, 32);
}

void swpor_priv_key_free(swpor_priv_key_t *key)
{
    if (key == NULL) {
        return;
    }
    OPENSSL_cleanse(key, sizeof(*key));
    free(key);
}

/* ===================================================================== */
/* 每文件密钥                                                              */
/* ===================================================================== */

int swpor_priv_file_keys_gen(swpor_priv_file_keys_t *fk)
{
    if (fk == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    return swpor_random_bytes((uint8_t *)fk, sizeof(*fk));
}

void swpor_priv_file_keys_cleanse(swpor_priv_file_keys_t *fk)
{
    if (fk != NULL) {
        OPENSSL_cleanse(fk, sizeof(*fk));
    }
}

/* ===================================================================== */
/* 打标签                                                                 */
/* ===================================================================== */

struct swpor_priv_tagger {
    uint16_t s;
    swpor_prf_t *prf;   /* f_{k_prf} */
    swpor_fr_t *alpha;  /* α_0..α_{s-1}（秘密） */
};

/* 派生 α_j = f_{k_alpha}(j)（SPEC 3.3、4.1 第 3 步）。alpha 需容纳 s 个元素 */
static int derive_alpha(const uint8_t k_alpha[32], uint16_t s, swpor_fr_t *alpha)
{
    swpor_prf_t *pa = NULL;
    int rc = swpor_prf_new(k_alpha, SWPOR_DST_ALPHA, &pa);
    for (uint16_t j = 0; rc == SWPOR_OK && j < s; j++) {
        rc = swpor_prf_eval(pa, j, &alpha[j]);
    }
    swpor_prf_free(pa);
    return rc;
}

int swpor_priv_tagger_new(const swpor_priv_file_keys_t *fk, uint16_t s,
                          swpor_priv_tagger_t **out)
{
    if (fk == NULL || s == 0 || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_priv_tagger_t *t = calloc(1, sizeof(*t));
    if (t == NULL) {
        return SWPOR_E_NOMEM;
    }
    t->s = s;
    t->alpha = calloc(s, sizeof(*t->alpha));
    int rc = t->alpha == NULL ? SWPOR_E_NOMEM : SWPOR_OK;
    if (rc == SWPOR_OK) {
        rc = swpor_prf_new(fk->k_prf, SWPOR_DST_PRF, &t->prf);
    }
    if (rc == SWPOR_OK) {
        rc = derive_alpha(fk->k_alpha, s, t->alpha);
    }
    if (rc != SWPOR_OK) {
        swpor_priv_tagger_free(t);
        return rc;
    }
    *out = t;
    return SWPOR_OK;
}

/* σ_i = f_{k_prf}(i) + Σ_{j=0}^{s-1} α_j · m_ij (mod r) */
static int compute_sigma(swpor_priv_tagger_t *t, uint64_t i, const uint8_t *block,
                         swpor_fr_t *sigma)
{
    int rc = swpor_prf_eval(t->prf, i, sigma);
    if (rc != SWPOR_OK) {
        return rc;
    }
    swpor_fr_t m;
    for (uint16_t j = 0; j < t->s; j++) {
        swpor_fr_from_sector(&m, block + (size_t)j * SWPOR_SECTOR_BYTES);
        swpor_fr_muladd(sigma, &t->alpha[j], &m);
    }
    swpor_fr_cleanse(&m, 1);
    return SWPOR_OK;
}

int swpor_priv_tag_block(swpor_priv_tagger_t *t, uint64_t i, const uint8_t *block,
                         uint8_t sigma[32])
{
    if (t == NULL || block == NULL || sigma == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_fr_t sg;
    int rc = compute_sigma(t, i, block, &sg);
    if (rc == SWPOR_OK) {
        swpor_fr_to_bytes(sigma, &sg);
    }
    swpor_fr_cleanse(&sg, 1);
    return rc;
}

int swpor_priv_check_block(swpor_priv_tagger_t *t, uint64_t i, const uint8_t *block,
                           const uint8_t sigma[32], int *ok)
{
    if (t == NULL || block == NULL || sigma == NULL || ok == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t expect[32];
    int rc = swpor_priv_tag_block(t, i, block, expect);
    *ok = rc == SWPOR_OK && CRYPTO_memcmp(expect, sigma, 32) == 0;
    OPENSSL_cleanse(expect, sizeof(expect));
    return rc;
}

void swpor_priv_tagger_free(swpor_priv_tagger_t *t)
{
    if (t == NULL) {
        return;
    }
    swpor_prf_free(t->prf);
    swpor_fr_cleanse(t->alpha, t->s);
    free(t->alpha);
    free(t);
}

/* ===================================================================== */
/* 文件标签（SPEC 4.3）                                                    */
/* ===================================================================== */

static int needs_long_tag(uint16_t flags)
{
    return (flags & (SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT)) != 0;
}

/* AES-256-GCM 加密或解密。enc = 1 加密（输出 tag 到 gtag），0 解密（校验 gtag） */
static int aes_gcm(int enc, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                   size_t aad_len, const uint8_t *in, size_t len, uint8_t *out,
                   uint8_t gtag[16])
{
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c == NULL) {
        return SWPOR_E_NOMEM;
    }
    int rc = SWPOR_E_CRYPTO;
    int outl = 0;
    if (EVP_CipherInit_ex(c, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_BYTES, NULL) != 1 ||
        EVP_CipherInit_ex(c, NULL, NULL, key, nonce, enc) != 1 ||
        EVP_CipherUpdate(c, NULL, &outl, aad, (int)aad_len) != 1 ||
        EVP_CipherUpdate(c, out, &outl, in, (int)len) != 1 || (size_t)outl != len) {
        goto cleanup;
    }
    if (enc) {
        if (EVP_CipherFinal_ex(c, out + outl, &outl) != 1 ||
            EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, gtag) != 1) {
            goto cleanup;
        }
    } else {
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, GCM_TAG_BYTES, gtag) != 1) {
            goto cleanup;
        }
        if (EVP_CipherFinal_ex(c, out + outl, &outl) != 1) {
            rc = SWPOR_E_TAG_AUTH;
            goto cleanup;
        }
    }
    rc = SWPOR_OK;
cleanup:
    EVP_CIPHER_CTX_free(c);
    return rc;
}

int swpor_priv_tag_seal(const swpor_priv_key_t *key, const swpor_tag_header_t *hdr,
                        const swpor_priv_file_keys_t *fk, uint8_t *out, size_t cap,
                        size_t *out_len)
{
    if (key == NULL || hdr == NULL || fk == NULL || out == NULL || out_len == NULL ||
        hdr->scheme != SWPOR_SCHEME_PRIV) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t pt_len = needs_long_tag(hdr->flags) ? 128u : 64u;
    size_t total = SWPOR_TAG_HEADER_BYTES + GCM_NONCE_BYTES + pt_len + GCM_TAG_BYTES;
    if (cap < total) {
        return SWPOR_E_RANGE;
    }
    uint8_t pt[128];
    memcpy(pt, fk->k_prf, 32);
    memcpy(pt + 32, fk->k_alpha, 32);
    memcpy(pt + 64, fk->k_perm, 32);
    memcpy(pt + 96, fk->k_fenc, 32);

    swpor_tag_header_encode(hdr, out);
    uint8_t *nonce = out + SWPOR_TAG_HEADER_BYTES;
    uint8_t *ct = nonce + GCM_NONCE_BYTES;
    int rc = swpor_random_bytes(nonce, GCM_NONCE_BYTES);
    if (rc == SWPOR_OK) {
        rc = aes_gcm(1, key->k_tag, nonce, out, SWPOR_TAG_HEADER_BYTES, pt, pt_len, ct,
                     ct + pt_len);
    }
    OPENSSL_cleanse(pt, sizeof(pt));
    if (rc == SWPOR_OK) {
        *out_len = total;
    }
    return rc;
}

int swpor_priv_tag_open(const swpor_priv_key_t *key, const uint8_t *tag, size_t len,
                        swpor_tag_header_t *hdr, swpor_priv_file_keys_t *fk)
{
    if (key == NULL || tag == NULL || hdr == NULL || fk == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    size_t pt_len;
    if (len == SWPOR_PRIV_TAG_BYTES_SHORT) {
        pt_len = 64;
    } else if (len == SWPOR_PRIV_TAG_BYTES_LONG) {
        pt_len = 128;
    } else {
        return SWPOR_E_PARSE;
    }
    /* 先做 AEAD 认证（AAD 为原始明文头字节），任何字节被篡改都表现为认证失败（T-08） */
    const uint8_t *nonce = tag + SWPOR_TAG_HEADER_BYTES;
    const uint8_t *ct = nonce + GCM_NONCE_BYTES;
    uint8_t gtag[GCM_TAG_BYTES];
    memcpy(gtag, ct + pt_len, GCM_TAG_BYTES);
    uint8_t pt[128];
    memset(pt, 0, sizeof(pt));
    int rc = aes_gcm(0, key->k_tag, nonce, tag, SWPOR_TAG_HEADER_BYTES, ct, pt_len, pt, gtag);
    if (rc != SWPOR_OK) {
        OPENSSL_cleanse(pt, sizeof(pt));
        return rc == SWPOR_E_CRYPTO ? SWPOR_E_TAG_AUTH : rc;
    }
    swpor_tag_header_t h;
    rc = swpor_tag_header_decode(tag, len, &h);
    if (rc == SWPOR_OK && (h.scheme != SWPOR_SCHEME_PRIV ||
                           (pt_len == 128) != (needs_long_tag(h.flags) != 0))) {
        rc = SWPOR_E_PARSE;
    }
    if (rc == SWPOR_OK) {
        *hdr = h;
        memcpy(fk->k_prf, pt, 32);
        memcpy(fk->k_alpha, pt + 32, 32);
        memcpy(fk->k_perm, pt + 64, 32);
        memcpy(fk->k_fenc, pt + 96, 32);
    }
    OPENSSL_cleanse(pt, sizeof(pt));
    return rc;
}

/* ===================================================================== */
/* 验证（SPEC 4.1 Priv.V）                                                 */
/* ===================================================================== */

int swpor_priv_verify(swpor_ctx_t *ctx, const swpor_tag_header_t *hdr,
                      const swpor_priv_file_keys_t *fk, const swpor_chal_t *chal,
                      const uint8_t *proof, size_t proof_len, int *pass)
{
    if (hdr == NULL || fk == NULL || chal == NULL || proof == NULL || pass == NULL ||
        hdr->scheme != SWPOR_SCHEME_PRIV) {
        return SWPOR_E_INVALID_ARG;
    }
    *pass = 0;
    uint64_t t0 = swpor_time_ns();
    const uint16_t s = hdr->s;
    swpor_fr_t *mu = calloc(s, sizeof(*mu));
    swpor_fr_t *alpha = calloc(s, sizeof(*alpha));
    swpor_prf_t *prf = NULL;
    swpor_fr_t sigma, rhs, t, nu;
    int rc = SWPOR_OK;
    if (mu == NULL || alpha == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    /* 第 4 步：解析响应，μ_j 与 σ 都必须是规范编码的 Z_r 元素 */
    rc = swpor_proof_parse_mu(proof, proof_len, SWPOR_SCHEME_PRIV, s, mu);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    rc = swpor_fr_from_canonical(&sigma, proof + 2 + (size_t)SWPOR_FR_BYTES * s);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    rc = derive_alpha(fk->k_alpha, s, alpha);
    if (rc == SWPOR_OK) {
        rc = swpor_prf_new(fk->k_prf, SWPOR_DST_PRF, &prf);
    }
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    /* 第 5 步：rhs = Σ ν_i · f_{k_prf}(i) + Σ_j α_j · μ_j */
    swpor_fr_zero(&rhs);
    for (uint32_t k = 0; k < chal->count; k++) {
        rc = swpor_prf_eval(prf, chal->items[k].index, &t);
        if (rc != SWPOR_OK) {
            goto cleanup;
        }
        swpor_fr_from_be_reduce(&nu, chal->items[k].nu, SWPOR_NU_BYTES);
        swpor_fr_muladd(&rhs, &nu, &t);
    }
    for (uint16_t j = 0; j < s; j++) {
        swpor_fr_muladd(&rhs, &alpha[j], &mu[j]);
    }
    *pass = swpor_fr_equal_ct(&sigma, &rhs);

cleanup:
    if (rc == SWPOR_E_PARSE || rc == SWPOR_OK) {
        char body[96];
        (void)snprintf(body, sizeof(body), "\"result\":\"%s\",\"elapsed_ms\":%.3f",
                       *pass ? "PASS" : "FAIL", (double)(swpor_time_ns() - t0) / 1e6);
        swpor_trace_emit(ctx, SWPOR_EV_VERIFY, body);
    }
    swpor_prf_free(prf);
    swpor_fr_cleanse(alpha, alpha != NULL ? s : 0);
    swpor_fr_cleanse(&rhs, 1);
    swpor_fr_cleanse(&t, 1);
    free(alpha);
    free(mu);
    return rc;
}
