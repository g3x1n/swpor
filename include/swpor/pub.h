#ifndef SWPOR_PUB_H
#define SWPOR_PUB_H

/*
 * Pub：公开验证方案（SPEC 4.2，论文 3.3 节，非对称配对版本）。
 *   σ_i ∈ G1，H(·)、u_j ∈ G1，公钥 v = g2^x ∈ G2；文件标签用 Ed25519 签名。
 *
 * 典型流程：
 *   客户端  swpor_pub_keygen → swpor_pub_tagger_new → swpor_pub_tag_block → swpor_pub_tag_sign
 *   服务端  swpor_prove（swpor/por.h）
 *   审计者  swpor_pub_tag_open → swpor_pub_verifier_new → swpor_pub_verifier_check
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"
#include "swpor/por.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct swpor_pub_sk swpor_pub_sk_t; /* sk = (x, ssk) */
typedef struct swpor_pub_pk swpor_pub_pk_t; /* pk = (v, spk) */

/** 生成密钥对（SPEC 4.2 Pub.Kg）：x ∈ Z_r \ {0}，v = g2^x；Ed25519 (spk, ssk)。 */
int swpor_pub_keygen(swpor_pub_sk_t **sk, swpor_pub_pk_t **pk);

/** 由私钥计算公钥。 */
int swpor_pub_pk_from_sk(const swpor_pub_sk_t *sk, swpor_pub_pk_t **pk);

/** 导出私钥：x（32 字节大端）与 Ed25519 私钥种子（32 字节）。调用方用完后清零。 */
int swpor_pub_sk_export(const swpor_pub_sk_t *sk, uint8_t x[32], uint8_t ed_sk[32]);

/** 导入私钥：x 必须满足 0 < x < r。 */
int swpor_pub_sk_import(const uint8_t x[32], const uint8_t ed_sk[32], swpor_pub_sk_t **out);

/** 导出公钥：v（96 字节压缩 G2）与 Ed25519 公钥（32 字节）。 */
int swpor_pub_pk_export(const swpor_pub_pk_t *pk, uint8_t v[96], uint8_t ed_pk[32]);

/** 导入公钥：v 必须通过 G2 曲线检查、子群检查且不是无穷远点。 */
int swpor_pub_pk_import(const uint8_t v[96], const uint8_t ed_pk[32], swpor_pub_pk_t **out);

void swpor_pub_sk_free(swpor_pub_sk_t *sk);
void swpor_pub_pk_free(swpor_pub_pk_t *pk);

/* ---- 打标签（SPEC 4.2 Pub.St） ---- */

typedef struct swpor_pub_tagger swpor_pub_tagger_t;

/** 创建打标签器：派生 u_0..u_{s-1} = hash_to_G1(u_seed ‖ I2OSP(j, 2))（SPEC 3.4）。 */
int swpor_pub_tagger_new(const swpor_pub_sk_t *sk, const uint8_t file_id[32],
                         const uint8_t u_seed[32], uint16_t s, swpor_pub_tagger_t **out);

/** σ_i = (H(file_id ‖ i) · Π_j u_j^{m_ij})^x，输出 48 字节压缩 G1 点。 */
int swpor_pub_tag_block(swpor_pub_tagger_t *t, uint64_t i, const uint8_t *block,
                        uint8_t sigma[48]);

void swpor_pub_tagger_free(swpor_pub_tagger_t *t);

/* ---- 文件标签（SPEC 4.3） ---- */

/** t = hdr ‖ u_seed ‖ Ed25519_Sign(ssk, hdr ‖ u_seed)。 */
int swpor_pub_tag_sign(const swpor_pub_sk_t *sk, const swpor_tag_header_t *hdr,
                       const uint8_t u_seed[32], uint8_t *out, size_t cap, size_t *out_len);

/**
 * 验证 Pub 文件标签签名并解析（SPEC 4.2 Pub.V 第 1、2 步）。
 * @return 签名无效 SWPOR_E_TAG_AUTH；长度错误 SWPOR_E_PARSE
 */
int swpor_pub_tag_open(const swpor_pub_pk_t *pk, const uint8_t *tag, size_t len,
                       swpor_tag_header_t *hdr, uint8_t u_seed[32]);

/* ---- 验证（SPEC 4.2 Pub.V） ---- */

typedef struct swpor_pub_verifier swpor_pub_verifier_t;

/** 创建验证器（缓存 u_j）。 */
int swpor_pub_verifier_new(const swpor_pub_pk_t *pk, const swpor_tag_header_t *hdr,
                           const uint8_t u_seed[32], swpor_pub_verifier_t **out);

/**
 * 验证证明：e(σ, g2) == e(Π H(file_id ‖ i)^{ν_i} · Π u_j^{μ_j}, v)。
 * σ 必须是合法压缩编码、在 G1 子群中且不是无穷远点；μ_j 必须是规范 Z_r 编码。
 * @return SWPOR_OK（结果见 pass）；格式错误返回 SWPOR_E_PARSE 且 pass = 0
 */
int swpor_pub_verifier_check(swpor_pub_verifier_t *v, swpor_ctx_t *ctx, const swpor_chal_t *chal,
                             const uint8_t *proof, size_t proof_len, int *pass);

/** 检查单块：e(σ_i, g2) == e(H(file_id ‖ i) · Π u_j^{m_ij}, v)（检索时使用）。 */
int swpor_pub_verifier_check_block(swpor_pub_verifier_t *v, uint64_t i, const uint8_t *block,
                                   const uint8_t sigma[48], int *ok);

void swpor_pub_verifier_free(swpor_pub_verifier_t *v);

/** 便捷函数：创建验证器、验证、释放。 */
int swpor_pub_verify(swpor_ctx_t *ctx, const swpor_pub_pk_t *pk, const swpor_tag_header_t *hdr,
                     const uint8_t u_seed[32], const swpor_chal_t *chal, const uint8_t *proof,
                     size_t proof_len, int *pass);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_PUB_H */
