#ifndef SWPOR_PRIV_H
#define SWPOR_PRIV_H

/*
 * Priv：私有验证方案（SPEC 4.1，论文 3.2 节）。
 *
 * 典型流程：
 *   客户端  swpor_priv_keygen → swpor_priv_file_keys_gen → swpor_priv_tagger_new
 *           → 对每块 swpor_priv_tag_block → swpor_priv_tag_seal
 *   服务端  swpor_prove（swpor/por.h）
 *   验证    swpor_priv_tag_open → swpor_chal_* → swpor_priv_verify
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"
#include "swpor/por.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 用户密钥 sk = msk（SPEC 4.1 Priv.Kg） ---- */

typedef struct swpor_priv_key swpor_priv_key_t;

/** 生成 32 字节主密钥 msk 并派生 k_tag = HKDF-SHA-256(msk, info="SWPOR-V1-TAGKEY")。 */
int swpor_priv_keygen(swpor_priv_key_t **out);

/** 从 msk 构造密钥（读取密钥文件时使用，SPEC 7）。 */
int swpor_priv_key_from_msk(const uint8_t msk[32], swpor_priv_key_t **out);

/** 导出 msk（写密钥文件时使用）。调用方用完后需清零 msk。 */
void swpor_priv_key_export(const swpor_priv_key_t *key, uint8_t msk[32]);

/** 释放并清零密钥。传入 NULL 安全。 */
void swpor_priv_key_free(swpor_priv_key_t *key);

/* ---- 每文件密钥（SPEC 4.1 Priv.St 第 2 步） ---- */

typedef struct {
    uint8_t k_prf[32];
    uint8_t k_alpha[32];
    uint8_t k_perm[32];  /* 仅在启用置乱或加密时写入标签 */
    uint8_t k_fenc[32];
} swpor_priv_file_keys_t;

/** 随机生成全部每文件密钥。 */
int swpor_priv_file_keys_gen(swpor_priv_file_keys_t *fk);

/** 清零每文件密钥。 */
void swpor_priv_file_keys_cleanse(swpor_priv_file_keys_t *fk);

/* ---- 打标签（SPEC 4.1 Priv.St 第 3、4 步） ---- */

typedef struct swpor_priv_tagger swpor_priv_tagger_t;

/** 创建打标签器：派生 α_j = f_{k_alpha}(j)，0 <= j < s。 */
int swpor_priv_tagger_new(const swpor_priv_file_keys_t *fk, uint16_t s,
                          swpor_priv_tagger_t **out);

/**
 * 计算 σ_i = f_{k_prf}(i) + Σ_j α_j · m_ij (mod r)，输出 32 字节大端。
 * @param block  第 i 块，31·s 字节
 */
int swpor_priv_tag_block(swpor_priv_tagger_t *t, uint64_t i, const uint8_t *block,
                         uint8_t sigma[32]);

/**
 * 检查单块是否完好：重算 σ_i 并与给定值做常数时间比较（检索时使用，SPEC 5）。
 * @param ok  输出：1 完好，0 损坏
 */
int swpor_priv_check_block(swpor_priv_tagger_t *t, uint64_t i, const uint8_t *block,
                           const uint8_t sigma[32], int *ok);

/** 释放并清零。传入 NULL 安全。 */
void swpor_priv_tagger_free(swpor_priv_tagger_t *t);

/* ---- 文件标签（SPEC 4.3） ---- */

/**
 * 生成 Priv 文件标签：hdr ‖ nonce ‖ AES-256-GCM(k_tag, keys, AAD = hdr) ‖ tag。
 * 启用置乱或加密时密文含 k_perm ‖ k_fenc（128 字节），否则 64 字节。
 * @param cap  至少 SWPOR_TAG_MAX_BYTES
 */
int swpor_priv_tag_seal(const swpor_priv_key_t *key, const swpor_tag_header_t *hdr,
                        const swpor_priv_file_keys_t *fk, uint8_t *out, size_t cap,
                        size_t *out_len);

/**
 * 解密并验证 Priv 文件标签（SPEC 4.1 Priv.V 第 1、2 步）。
 * @return SWPOR_OK；认证失败 SWPOR_E_TAG_AUTH；长度错误 SWPOR_E_PARSE
 */
int swpor_priv_tag_open(const swpor_priv_key_t *key, const uint8_t *tag, size_t len,
                        swpor_tag_header_t *hdr, swpor_priv_file_keys_t *fk);

/* ---- 验证（SPEC 4.1 Priv.V 第 4、5 步） ---- */

/**
 * 验证证明：σ == Σ ν_i · f_{k_prf}(i) + Σ_j α_j · μ_j (mod r)（常数时间比较）。
 * @param pass  输出：1 = PASS，0 = FAIL
 * @return SWPOR_OK（结果见 pass）；证明格式错误或非规范编码时返回 SWPOR_E_PARSE 且 pass = 0
 */
int swpor_priv_verify(swpor_ctx_t *ctx, const swpor_tag_header_t *hdr,
                      const swpor_priv_file_keys_t *fk, const swpor_chal_t *chal,
                      const uint8_t *proof, size_t proof_len, int *pass);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_PRIV_H */
