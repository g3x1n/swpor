#ifndef SWPOR_PIPELINE_H
#define SWPOR_PIPELINE_H

/*
 * 端到端流程的组合（不做任何 I/O，存储与传输通过回调完成）：
 *   swpor_st_run        预处理 + 打标签 + 生成文件标签（SPEC 4.1 / 4.2 St，SPEC 5）
 *   swpor_audit_run     打开标签 → 生成挑战 → 调用证明回调 → 验证（SPEC 4.1 / 4.2 V）
 *   swpor_retrieve_run  逐块校验 σ_i → 纠删解码 → 恢复原文（SPEC 5 恢复）
 * porctl 的本地模式与远程模式、porta、porbench 和测试都使用这些函数。
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"
#include "swpor/encode.h"
#include "swpor/por.h"
#include "swpor/priv.h"
#include "swpor/pub.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 密钥 ---- */

typedef struct {
    uint8_t scheme;                    /* SWPOR_SCHEME_PRIV / SWPOR_SCHEME_PUB */
    const swpor_priv_key_t *priv_key;  /* Priv：St、V、检索都需要 */
    const swpor_pub_sk_t *pub_sk;      /* Pub：St 需要 */
    const swpor_pub_pk_t *pub_pk;      /* Pub：V、检索需要 */
} swpor_keys_t;

/* ---- 存储（St） ---- */

typedef struct {
    uint16_t s;
    uint16_t flags;  /* SWPOR_FLAG_*；Pub 方案不支持 PERM / ENCRYPT（返回 SWPOR_E_UNSUPPORTED） */
    uint16_t rs_k;
    uint16_t rs_m;
} swpor_st_params_t;

typedef struct {
    /** 开始上传：文件标签已生成（t 在块之前就已确定，SPEC 8.3 STORE_BEGIN）。 */
    int (*begin)(void *user, const uint8_t *tag, size_t tag_len, const swpor_tag_header_t *hdr);
    /** 写入 M′ 位置 pos 的块及其 σ（可能乱序）。 */
    int (*put)(void *user, uint64_t pos, const uint8_t *block, size_t block_len,
               const uint8_t *sigma, size_t sigma_len);
    /** 全部块写完。 */
    int (*finish)(void *user);
} swpor_st_sink_t;

/**
 * 预处理并打标签，把 M* 与 t 交给 sink。
 * @param length   输入总长度 L（input 必须恰好提供 L 字节）
 * @param tag_out  输出：文件标签（容量至少 SWPOR_TAG_MAX_BYTES）
 */
int swpor_st_run(swpor_ctx_t *ctx, const swpor_keys_t *keys, const swpor_st_params_t *params,
                 uint64_t length, swpor_input_fn input, void *in_user, const swpor_st_sink_t *sink,
                 void *sink_user, uint8_t *tag_out, size_t tag_cap, size_t *tag_len,
                 swpor_tag_header_t *hdr_out);

/**
 * 打开文件标签（Priv 解密 / Pub 验签），只取明文头。
 * 不需要密钥时（如 porctl info）使用 swpor_tag_header_decode。
 */
int swpor_tag_open_any(const swpor_keys_t *keys, const uint8_t *tag, size_t tag_len,
                       swpor_tag_header_t *hdr);

/* ---- 审计（V） ---- */

/** 证明回调：把挑战发给服务端（或本地存储）并取回 PROOF payload。 */
typedef int (*swpor_prove_fn)(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap,
                              size_t *proof_len);

typedef struct {
    int pass;                 /* 1 = PASS */
    int verify_rc;            /* 验证函数的返回码（SWPOR_E_PARSE 表示证明格式错误） */
    uint32_t l;               /* 实际挑战块数 */
    size_t challenge_bytes;   /* CHALLENGE 消息 payload 大小（SPEC 8.3） */
    size_t proof_bytes;       /* PROOF 消息 payload 大小 */
    uint64_t prove_ns;        /* 证明回调耗时（含网络往返） */
    uint64_t verify_ns;       /* 验证耗时 */
    uint64_t total_ns;
} swpor_audit_result_t;

/**
 * 执行一次审计。
 * @param seed_mode  0：显式挑战（SPEC 3.5.1）；1：种子挑战（SPEC 3.5.2）
 * @return SWPOR_OK 表示审计流程完成（结果见 res->pass）；标签无法打开、回调失败等返回错误码
 */
int swpor_audit_run(swpor_ctx_t *ctx, const swpor_keys_t *keys, const uint8_t *tag,
                    size_t tag_len, uint32_t l, int seed_mode, swpor_prove_fn prove, void *user,
                    swpor_audit_result_t *res);

/** CHALLENGE 消息 payload 大小：file_id 32 ‖ mode 1 ‖ l 4 ‖（显式 l × 24 | 种子 32）。 */
size_t swpor_chal_wire_bytes(const swpor_chal_t *chal);

/* ---- 检索 ---- */

/** 读取 M′ 位置 pos 的块与 σ。读取失败（如块已被删除）时返回非 OK，按擦除处理。 */
typedef int (*swpor_get_fn)(void *user, uint64_t pos, uint8_t *block, size_t block_len,
                            uint8_t *sigma, size_t sigma_len);

/**
 * 检索并恢复原文。
 * @param erased  可为 NULL；输出检测到的损坏块数
 * @return 无法恢复返回 SWPOR_E_DECODE（T-12）
 */
int swpor_retrieve_run(swpor_ctx_t *ctx, const swpor_keys_t *keys, const uint8_t *tag,
                       size_t tag_len, swpor_get_fn get, void *get_user, swpor_output_fn output,
                       void *out_user, uint64_t *erased);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_PIPELINE_H */
