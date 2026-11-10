/*
 * Pub：公开验证方案（SPEC 4.2）。群运算、哈希到曲线、MSM、配对全部调用 blst；
 * 文件标签签名调用 OpenSSL Ed25519（EVP 高层接口）。
 */

#include "swpor/pub.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "blst.h"
#include "endian.h"
#include "fr.h"
#include "internal.h"
#include "platform.h"
#include "prf.h"
#include "proof.h"
#include "swpor/error.h"
#include "swpor/params.h"

/* SPEC 3.4 的域分隔串 */
static const char k_dst_h[] = "SWPOR-V1-H-BLS12381G1_XMD:SHA-256_SSWU_RO_";
static const char k_dst_u[] = "SWPOR-V1-U-BLS12381G1_XMD:SHA-256_SSWU_RO_";

#define ED25519_SIG_BYTES 64

struct swpor_pub_sk {
    blst_scalar x;  /* 小端字节（blst 约定），0 < x < r */
    EVP_PKEY *ed;   /* Ed25519 私钥 */
};

struct swpor_pub_pk {
    blst_p2_affine v;
    EVP_PKEY *ed;   /* Ed25519 公钥 */
};

/* ===================================================================== */
/* 密钥                                                                   */
/* ===================================================================== */

void swpor_pub_sk_free(swpor_pub_sk_t *sk)
{
    if (sk == NULL) {
        return;
    }
    EVP_PKEY_free(sk->ed);
    OPENSSL_cleanse(sk, sizeof(*sk));
    free(sk);
}

void swpor_pub_pk_free(swpor_pub_pk_t *pk)
{
    if (pk == NULL) {
        return;
    }
    EVP_PKEY_free(pk->ed);
    free(pk);
}

/* 生成 x ∈ [1, r)：64 字节随机数模 r（偏差可忽略），为 0 时重抽 */
static int random_nonzero_scalar(blst_scalar *x)
{
    uint8_t buf[64];
    int rc;
    do {
        rc = swpor_random_bytes(buf, sizeof(buf));
        if (rc != SWPOR_OK) {
            break;
        }
        (void)blst_scalar_from_be_bytes(x, buf, sizeof(buf));
    } while (!blst_sk_check(x));
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

int swpor_pub_sk_import(const uint8_t x[32], const uint8_t ed_sk[32], swpor_pub_sk_t **out)
{
    if (x == NULL || ed_sk == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_pub_sk_t *sk = calloc(1, sizeof(*sk));
    if (sk == NULL) {
        return SWPOR_E_NOMEM;
    }
    blst_scalar_from_bendian(&sk->x, x);
    if (!blst_sk_check(&sk->x)) {
        swpor_pub_sk_free(sk);
        return SWPOR_E_PARSE;
    }
    sk->ed = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, ed_sk, 32);
    if (sk->ed == NULL) {
        swpor_pub_sk_free(sk);
        return SWPOR_E_CRYPTO;
    }
    *out = sk;
    return SWPOR_OK;
}

int swpor_pub_sk_export(const swpor_pub_sk_t *sk, uint8_t x[32], uint8_t ed_sk[32])
{
    if (sk == NULL || x == NULL || ed_sk == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    blst_bendian_from_scalar(x, &sk->x);
    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(sk->ed, ed_sk, &len) != 1 || len != 32) {
        return SWPOR_E_CRYPTO;
    }
    return SWPOR_OK;
}

int swpor_pub_pk_from_sk(const swpor_pub_sk_t *sk, swpor_pub_pk_t **out)
{
    if (sk == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_pub_pk_t *pk = calloc(1, sizeof(*pk));
    if (pk == NULL) {
        return SWPOR_E_NOMEM;
    }
    /* v = g2^x */
    blst_p2 v;
    blst_sk_to_pk_in_g2(&v, &sk->x);
    blst_p2_to_affine(&pk->v, &v);
    uint8_t raw[32];
    size_t len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(sk->ed, raw, &len) != 1 || len != 32 ||
        (pk->ed = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, raw, 32)) == NULL) {
        swpor_pub_pk_free(pk);
        return SWPOR_E_CRYPTO;
    }
    *out = pk;
    return SWPOR_OK;
}

int swpor_pub_keygen(swpor_pub_sk_t **sk_out, swpor_pub_pk_t **pk_out)
{
    if (sk_out == NULL || pk_out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t xb[32];
    uint8_t edb[32];
    blst_scalar x;
    swpor_pub_sk_t *sk = NULL;
    /* Ed25519 私钥种子也由 swpor_random_bytes 生成，测试构建中可确定性复现（T-25） */
    int rc = random_nonzero_scalar(&x);
    if (rc == SWPOR_OK) {
        rc = swpor_random_bytes(edb, sizeof(edb));
    }
    if (rc == SWPOR_OK) {
        blst_bendian_from_scalar(xb, &x);
        rc = swpor_pub_sk_import(xb, edb, &sk);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_pub_pk_from_sk(sk, pk_out);
    }
    OPENSSL_cleanse(xb, sizeof(xb));
    OPENSSL_cleanse(edb, sizeof(edb));
    OPENSSL_cleanse(&x, sizeof(x));
    if (rc != SWPOR_OK) {
        swpor_pub_sk_free(sk);
        return rc;
    }
    *sk_out = sk;
    return SWPOR_OK;
}

int swpor_pub_pk_export(const swpor_pub_pk_t *pk, uint8_t v[96], uint8_t ed_pk[32])
{
    if (pk == NULL || v == NULL || ed_pk == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    blst_p2_affine_compress(v, &pk->v);
    size_t len = 32;
    if (EVP_PKEY_get_raw_public_key(pk->ed, ed_pk, &len) != 1 || len != 32) {
        return SWPOR_E_CRYPTO;
    }
    return SWPOR_OK;
}

int swpor_pub_pk_import(const uint8_t v[96], const uint8_t ed_pk[32], swpor_pub_pk_t **out)
{
    if (v == NULL || ed_pk == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_pub_pk_t *pk = calloc(1, sizeof(*pk));
    if (pk == NULL) {
        return SWPOR_E_NOMEM;
    }
    /* SPEC 11 第 1 条：曲线检查 + 子群检查 + 非无穷远点 */
    if (blst_p2_uncompress(&pk->v, v) != BLST_SUCCESS || blst_p2_affine_is_inf(&pk->v) ||
        !blst_p2_affine_in_g2(&pk->v)) {
        swpor_pub_pk_free(pk);
        return SWPOR_E_PARSE;
    }
    pk->ed = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, ed_pk, 32);
    if (pk->ed == NULL) {
        swpor_pub_pk_free(pk);
        return SWPOR_E_PARSE;
    }
    *out = pk;
    return SWPOR_OK;
}

/* ===================================================================== */
/* 哈希到 G1（SPEC 3.4）                                                   */
/* ===================================================================== */

/* H(file_id ‖ i) = hash_to_G1(file_id ‖ I2OSP(i, 8), DST_H) */
static void hash_h(blst_p1_affine *out, const uint8_t file_id[32], uint64_t i)
{
    uint8_t msg[40];
    memcpy(msg, file_id, 32);
    swpor_store_be64(msg + 32, i);
    blst_p1 p;
    blst_hash_to_g1(&p, msg, sizeof(msg), (const byte *)k_dst_h, sizeof(k_dst_h) - 1, NULL, 0);
    blst_p1_to_affine(out, &p);
}

/* u_j = hash_to_G1(u_seed ‖ I2OSP(j, 2), DST_U)，0 <= j < s */
static int derive_u(const uint8_t u_seed[32], uint16_t s, blst_p1_affine **out)
{
    blst_p1_affine *u = malloc((size_t)s * sizeof(*u));
    if (u == NULL) {
        return SWPOR_E_NOMEM;
    }
    uint8_t msg[34];
    memcpy(msg, u_seed, 32);
    for (uint16_t j = 0; j < s; j++) {
        swpor_store_be16(msg + 32, j);
        blst_p1 p;
        blst_hash_to_g1(&p, msg, sizeof(msg), (const byte *)k_dst_u, sizeof(k_dst_u) - 1, NULL,
                        0);
        blst_p1_to_affine(&u[j], &p);
    }
    *out = u;
    return SWPOR_OK;
}

/* 多标量乘：out = Σ scalars[k] · pts[k]，scalars 为 32 字节小端。npoints >= 1 */
static int msm(blst_p1 *out, const blst_p1_affine *const *pts, const uint8_t *const *scalars,
               size_t npoints, size_t nbits)
{
    if (npoints == 1) {
        blst_p1 p;
        blst_p1_from_affine(&p, pts[0]);
        blst_p1_mult(out, &p, scalars[0], nbits);
        return SWPOR_OK;
    }
    limb_t *scratch = malloc(blst_p1s_mult_pippenger_scratch_sizeof(npoints));
    if (scratch == NULL) {
        return SWPOR_E_NOMEM;
    }
    blst_p1s_mult_pippenger(out, pts, npoints, scalars, nbits, scratch);
    free(scratch);
    return SWPOR_OK;
}

/* ===================================================================== */
/* 打标签                                                                 */
/* ===================================================================== */

struct swpor_pub_tagger {
    blst_scalar x;
    uint8_t file_id[32];
    uint16_t s;
    blst_p1_affine *u;
    const blst_p1_affine **u_ptr;
    uint8_t *scalars;          /* s × 32 字节小端 */
    const uint8_t **scalar_ptr;
    limb_t *scratch;
};

void swpor_pub_tagger_free(swpor_pub_tagger_t *t)
{
    if (t == NULL) {
        return;
    }
    free(t->u);
    free(t->u_ptr);
    if (t->scalars != NULL) {
        OPENSSL_cleanse(t->scalars, (size_t)t->s * 32u);
    }
    free(t->scalars);
    free(t->scalar_ptr);
    free(t->scratch);
    OPENSSL_cleanse(&t->x, sizeof(t->x));
    free(t);
}

int swpor_pub_tagger_new(const swpor_pub_sk_t *sk, const uint8_t file_id[32],
                         const uint8_t u_seed[32], uint16_t s, swpor_pub_tagger_t **out)
{
    if (sk == NULL || file_id == NULL || u_seed == NULL || s == 0 || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_pub_tagger_t *t = calloc(1, sizeof(*t));
    if (t == NULL) {
        return SWPOR_E_NOMEM;
    }
    t->x = sk->x;
    memcpy(t->file_id, file_id, 32);
    t->s = s;
    int rc = derive_u(u_seed, s, &t->u);
    if (rc == SWPOR_OK) {
        t->u_ptr = malloc((size_t)s * sizeof(*t->u_ptr));
        t->scalars = calloc(s, 32);
        t->scalar_ptr = malloc((size_t)s * sizeof(*t->scalar_ptr));
        t->scratch = malloc(blst_p1s_mult_pippenger_scratch_sizeof(s));
        if (t->u_ptr == NULL || t->scalars == NULL || t->scalar_ptr == NULL || t->scratch == NULL) {
            rc = SWPOR_E_NOMEM;
        }
    }
    if (rc != SWPOR_OK) {
        swpor_pub_tagger_free(t);
        return rc;
    }
    for (uint16_t j = 0; j < s; j++) {
        t->u_ptr[j] = &t->u[j];
        t->scalar_ptr[j] = t->scalars + (size_t)j * 32u;
    }
    *out = t;
    return SWPOR_OK;
}

int swpor_pub_tag_block(swpor_pub_tagger_t *t, uint64_t i, const uint8_t *block,
                        uint8_t sigma[48])
{
    if (t == NULL || block == NULL || sigma == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    /* m_ij 的 31 字节大端 → 32 字节小端标量 */
    for (uint16_t j = 0; j < t->s; j++) {
        const uint8_t *src = block + (size_t)j * SWPOR_SECTOR_BYTES;
        uint8_t *dst = t->scalars + (size_t)j * 32u;
        for (int b = 0; b < 31; b++) {
            dst[b] = src[30 - b];
        }
        dst[31] = 0;
    }
    /* P = H(file_id ‖ i) + Σ_j m_ij · u_j；σ_i = x · P（m_ij < 2^248） */
    blst_p1 acc;
    if (t->s == 1) {
        blst_p1 p;
        blst_p1_from_affine(&p, &t->u[0]);
        blst_p1_mult(&acc, &p, t->scalars, 248);
    } else {
        blst_p1s_mult_pippenger(&acc, t->u_ptr, t->s, t->scalar_ptr, 248, t->scratch);
    }
    blst_p1_affine h;
    hash_h(&h, t->file_id, i);
    blst_p1_add_or_double_affine(&acc, &acc, &h);
    blst_p1_mult(&acc, &acc, t->x.b, 255);
    blst_p1_compress(sigma, &acc);
    return SWPOR_OK;
}

/* ===================================================================== */
/* 文件标签                                                               */
/* ===================================================================== */

static int ed25519_sign(EVP_PKEY *key, const uint8_t *msg, size_t len, uint8_t sig[64])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == NULL) {
        return SWPOR_E_NOMEM;
    }
    size_t siglen = ED25519_SIG_BYTES;
    int ok = EVP_DigestSignInit(md, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestSign(md, sig, &siglen, msg, len) == 1 && siglen == ED25519_SIG_BYTES;
    EVP_MD_CTX_free(md);
    return ok ? SWPOR_OK : SWPOR_E_CRYPTO;
}

static int ed25519_verify(EVP_PKEY *key, const uint8_t *msg, size_t len, const uint8_t sig[64])
{
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (md == NULL) {
        return SWPOR_E_NOMEM;
    }
    int ok = EVP_DigestVerifyInit(md, NULL, NULL, NULL, key) == 1 &&
             EVP_DigestVerify(md, sig, ED25519_SIG_BYTES, msg, len) == 1;
    EVP_MD_CTX_free(md);
    return ok ? SWPOR_OK : SWPOR_E_TAG_AUTH;
}

int swpor_pub_tag_sign(const swpor_pub_sk_t *sk, const swpor_tag_header_t *hdr,
                       const uint8_t u_seed[32], uint8_t *out, size_t cap, size_t *out_len)
{
    if (sk == NULL || hdr == NULL || u_seed == NULL || out == NULL || out_len == NULL ||
        hdr->scheme != SWPOR_SCHEME_PUB) {
        return SWPOR_E_INVALID_ARG;
    }
    if (cap < SWPOR_PUB_TAG_BYTES) {
        return SWPOR_E_RANGE;
    }
    swpor_tag_header_encode(hdr, out);
    memcpy(out + SWPOR_TAG_HEADER_BYTES, u_seed, 32);
    int rc = ed25519_sign(sk->ed, out, SWPOR_TAG_HEADER_BYTES + 32u,
                          out + SWPOR_TAG_HEADER_BYTES + 32u);
    if (rc == SWPOR_OK) {
        *out_len = SWPOR_PUB_TAG_BYTES;
    }
    return rc;
}

int swpor_pub_tag_open(const swpor_pub_pk_t *pk, const uint8_t *tag, size_t len,
                       swpor_tag_header_t *hdr, uint8_t u_seed[32])
{
    if (pk == NULL || tag == NULL || hdr == NULL || u_seed == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (len != SWPOR_PUB_TAG_BYTES) {
        return SWPOR_E_PARSE;
    }
    /* 先验签：任何字节被篡改都表现为验签失败（T-08 / T-19） */
    int rc = ed25519_verify(pk->ed, tag, SWPOR_TAG_HEADER_BYTES + 32u,
                            tag + SWPOR_TAG_HEADER_BYTES + 32u);
    if (rc != SWPOR_OK) {
        return rc;
    }
    swpor_tag_header_t h;
    rc = swpor_tag_header_decode(tag, len, &h);
    if (rc == SWPOR_OK && h.scheme != SWPOR_SCHEME_PUB) {
        rc = SWPOR_E_PARSE;
    }
    if (rc == SWPOR_OK) {
        *hdr = h;
        memcpy(u_seed, tag + SWPOR_TAG_HEADER_BYTES, 32);
    }
    return rc;
}

/* ===================================================================== */
/* 验证                                                                   */
/* ===================================================================== */

struct swpor_pub_verifier {
    blst_p2_affine v;
    uint8_t file_id[32];
    uint16_t s;
    uint64_t n;
    blst_p1_affine *u;
};

void swpor_pub_verifier_free(swpor_pub_verifier_t *v)
{
    if (v == NULL) {
        return;
    }
    free(v->u);
    free(v);
}

int swpor_pub_verifier_new(const swpor_pub_pk_t *pk, const swpor_tag_header_t *hdr,
                           const uint8_t u_seed[32], swpor_pub_verifier_t **out)
{
    if (pk == NULL || hdr == NULL || u_seed == NULL || out == NULL ||
        hdr->scheme != SWPOR_SCHEME_PUB || hdr->s == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_pub_verifier_t *v = calloc(1, sizeof(*v));
    if (v == NULL) {
        return SWPOR_E_NOMEM;
    }
    v->v = pk->v;
    memcpy(v->file_id, hdr->file_id, 32);
    v->s = hdr->s;
    v->n = hdr->n;
    int rc = derive_u(u_seed, hdr->s, &v->u);
    if (rc != SWPOR_OK) {
        swpor_pub_verifier_free(v);
        return rc;
    }
    *out = v;
    return SWPOR_OK;
}

/* 解析 σ：合法压缩编码、在 G1 子群、非无穷远点（SPEC 4.2 Pub.V 第 4 步） */
static int parse_sigma(const uint8_t in[48], blst_p1_affine *out)
{
    if (blst_p1_uncompress(out, in) != BLST_SUCCESS || blst_p1_affine_is_inf(out) ||
        !blst_p1_affine_in_g1(out)) {
        return SWPOR_E_PARSE;
    }
    return SWPOR_OK;
}

/*
 * 检查 e(σ, g2) == e(X, v)，X = Σ_k c_k · H(file_id ‖ idx_k) + Σ_j d_j · u_j。
 * 以 e(−σ, g2) · e(X, v) == 1 的形式计算：两次 Miller 循环，一次最终幂（SPEC 4.2 实现提示）。
 * hc：count 个 32 字节小端标量；ud：s 个 32 字节小端标量。
 */
static int pairing_check(const swpor_pub_verifier_t *v, const uint64_t *idx, const uint8_t *hc,
                         uint32_t count, const uint8_t *ud, const blst_p1_affine *sigma, int *ok)
{
    const size_t np = (size_t)count + v->s;
    blst_p1_affine *pts = malloc(np * sizeof(*pts));
    const blst_p1_affine **pp = malloc(np * sizeof(*pp));
    const uint8_t **sp = malloc(np * sizeof(*sp));
    int rc = SWPOR_OK;
    if (pts == NULL || pp == NULL || sp == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    for (uint32_t k = 0; k < count; k++) {
        hash_h(&pts[k], v->file_id, idx[k]);
        pp[k] = &pts[k];
        sp[k] = hc + (size_t)k * 32u;
    }
    for (uint16_t j = 0; j < v->s; j++) {
        pp[count + j] = &v->u[j];
        sp[count + j] = ud + (size_t)j * 32u;
    }
    blst_p1 x;
    rc = msm(&x, pp, sp, np, 255);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    blst_p1_affine xa;
    blst_p1_to_affine(&xa, &x);
    blst_p1 neg;
    blst_p1_from_affine(&neg, sigma);
    blst_p1_cneg(&neg, true);
    blst_p1_affine nega;
    blst_p1_to_affine(&nega, &neg);

    blst_fp12 f1, f2, f;
    blst_miller_loop(&f1, blst_p2_affine_generator(), &nega);
    blst_miller_loop(&f2, &v->v, &xa);
    blst_fp12_mul(&f, &f1, &f2);
    blst_final_exp(&f, &f);
    *ok = blst_fp12_is_one(&f) ? 1 : 0;

cleanup:
    free(pts);
    free(pp);
    free(sp);
    return rc;
}

int swpor_pub_verifier_check(swpor_pub_verifier_t *v, swpor_ctx_t *ctx, const swpor_chal_t *chal,
                             const uint8_t *proof, size_t proof_len, int *pass)
{
    if (v == NULL || chal == NULL || proof == NULL || pass == NULL || chal->count == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    *pass = 0;
    uint64_t t0 = swpor_time_ns();
    const uint16_t s = v->s;
    const uint32_t l = chal->count;
    swpor_fr_t *mu = calloc(s, sizeof(*mu));
    uint8_t *ud = calloc(s, 32);
    uint8_t *hc = calloc(l, 32);
    uint64_t *idx = malloc((size_t)l * sizeof(*idx));
    blst_p1_affine sigma;
    int rc = SWPOR_OK;
    if (mu == NULL || ud == NULL || hc == NULL || idx == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    rc = swpor_proof_parse_mu(proof, proof_len, SWPOR_SCHEME_PUB, s, mu);
    if (rc == SWPOR_OK) {
        rc = parse_sigma(proof + 2 + (size_t)SWPOR_FR_BYTES * s, &sigma);
    }
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    for (uint16_t j = 0; j < s; j++) {
        /* μ_j 的大端规范编码 → 小端标量 */
        const uint8_t *src = proof + 2 + (size_t)SWPOR_FR_BYTES * j;
        for (int b = 0; b < 32; b++) {
            ud[(size_t)j * 32u + (size_t)b] = src[31 - b];
        }
    }
    for (uint32_t k = 0; k < l; k++) {
        if (chal->items[k].index >= v->n) {
            rc = SWPOR_E_RANGE;
            goto cleanup;
        }
        idx[k] = chal->items[k].index;
        swpor_nu_to_le(chal->items[k].nu, hc + (size_t)k * 32u); /* 高 16 字节保持为 0 */
    }
    rc = pairing_check(v, idx, hc, l, ud, &sigma, pass);

cleanup:
    if (rc == SWPOR_OK || rc == SWPOR_E_PARSE) {
        char body[96];
        (void)snprintf(body, sizeof(body), "\"result\":\"%s\",\"elapsed_ms\":%.3f",
                       *pass ? "PASS" : "FAIL", (double)(swpor_time_ns() - t0) / 1e6);
        swpor_trace_emit(ctx, SWPOR_EV_VERIFY, body);
    }
    free(mu);
    free(ud);
    free(hc);
    free(idx);
    return rc;
}

int swpor_pub_verifier_check_block(swpor_pub_verifier_t *v, uint64_t i, const uint8_t *block,
                                   const uint8_t sigma[48], int *ok)
{
    if (v == NULL || block == NULL || sigma == NULL || ok == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    *ok = 0;
    if (i >= v->n) {
        return SWPOR_E_RANGE;
    }
    blst_p1_affine sg;
    if (parse_sigma(sigma, &sg) != SWPOR_OK) {
        return SWPOR_OK; /* σ_i 损坏：块视为不完好 */
    }
    uint8_t *ud = calloc(v->s, 32);
    if (ud == NULL) {
        return SWPOR_E_NOMEM;
    }
    for (uint16_t j = 0; j < v->s; j++) {
        const uint8_t *src = block + (size_t)j * SWPOR_SECTOR_BYTES;
        for (int b = 0; b < 31; b++) {
            ud[(size_t)j * 32u + (size_t)b] = src[30 - b];
        }
    }
    uint8_t one[32] = {1};
    int rc = pairing_check(v, &i, one, 1, ud, &sg, ok);
    free(ud);
    return rc;
}

int swpor_pub_verify(swpor_ctx_t *ctx, const swpor_pub_pk_t *pk, const swpor_tag_header_t *hdr,
                     const uint8_t u_seed[32], const swpor_chal_t *chal, const uint8_t *proof,
                     size_t proof_len, int *pass)
{
    if (pass != NULL) {
        *pass = 0;
    }
    swpor_pub_verifier_t *v = NULL;
    int rc = swpor_pub_verifier_new(pk, hdr, u_seed, &v);
    if (rc == SWPOR_OK) {
        rc = swpor_pub_verifier_check(v, ctx, chal, proof, proof_len, pass);
    }
    swpor_pub_verifier_free(v);
    return rc;
}
