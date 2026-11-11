#ifndef SWPOR_POR_H
#define SWPOR_POR_H

/*
 * 两方案共用的数据结构与算法：文件标签明文头（SPEC 4.3）、挑战（SPEC 3.5）、
 * 证明生成 P（SPEC 4.1 Priv.P / 4.2 Pub.P）。
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ===================================================================== */
/* 文件标签明文头（SPEC 4.3）                                               */
/* ===================================================================== */

#define SWPOR_FLAG_RS 0x0001u      /* bit0：启用 RS */
#define SWPOR_FLAG_PERM 0x0002u    /* bit1：启用置乱 */
#define SWPOR_FLAG_ENCRYPT 0x0004u /* bit2：启用文件加密 */
#define SWPOR_FLAGS_KNOWN (SWPOR_FLAG_RS | SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT)

/* Priv 标签：头 72 ‖ nonce 12 ‖ 密文 64/128 ‖ GCM tag 16（SPEC 4.3） */
#define SWPOR_PRIV_TAG_BYTES_SHORT (72u + 12u + 64u + 16u)
#define SWPOR_PRIV_TAG_BYTES_LONG (72u + 12u + 128u + 16u)
/* Pub 标签：头 72 ‖ u_seed 32 ‖ Ed25519 签名 64 */
#define SWPOR_PUB_TAG_BYTES (72u + 32u + 64u)
/* 任何标签的最大长度 */
#define SWPOR_TAG_MAX_BYTES SWPOR_PRIV_TAG_BYTES_LONG

typedef struct {
    uint8_t version;        /* = SWPOR_FORMAT_VERSION */
    uint8_t scheme;         /* SWPOR_SCHEME_PRIV / SWPOR_SCHEME_PUB */
    uint16_t flags;         /* SWPOR_FLAG_* */
    uint8_t file_id[32];
    uint64_t n;             /* 块数 */
    uint16_t s;             /* 每块扇区数 */
    uint16_t rs_k;          /* RS 数据块数（未启用 RS 时为 0） */
    uint16_t rs_m;          /* RS 校验块数（未启用 RS 时为 0） */
    uint64_t length;        /* L：原始文件长度 */
    uint64_t ctime;         /* 创建时间（Unix 秒） */
} swpor_tag_header_t;

/** 编码 72 字节明文头（大端）。 */
void swpor_tag_header_encode(const swpor_tag_header_t *h, uint8_t out[72]);

/**
 * 解析并校验明文头：magic、version、scheme、未知 flag 位、保留字段、
 * 1 <= n < 2^40、s >= 1、RS 参数与 n、L 的一致性。
 * @param in   至少 72 字节
 * @return SWPOR_OK；格式错误 SWPOR_E_PARSE；版本或方案不支持 SWPOR_E_UNSUPPORTED
 */
int swpor_tag_header_decode(const uint8_t *in, size_t len, swpor_tag_header_t *h);

/** 每块数据字节数 BLOCK_BYTES = 31·s（SPEC 3.1）。 */
size_t swpor_block_bytes(uint16_t s);

/** σ_i 的编码长度：Priv 32，Pub 48；未知方案返回 0。 */
size_t swpor_sigma_bytes(uint8_t scheme);

/** 证明（PROOF 消息 payload，SPEC 8.3）长度：2 + 32·s + |σ|。 */
size_t swpor_proof_bytes(uint8_t scheme, uint16_t s);

/** 把 32 字节 file_id 转为 64 个小写十六进制字符（out 至少 65 字节）。 */
void swpor_hex_encode(const uint8_t *in, size_t len, char *out);

/** 解析十六进制串，长度必须恰为 2·len。 */
int swpor_hex_decode(const char *hex, uint8_t *out, size_t len);

/* ===================================================================== */
/* 挑战（SPEC 3.5）                                                        */
/* ===================================================================== */

#define SWPOR_CHAL_EXPLICIT 0u
#define SWPOR_CHAL_SEED 1u

typedef struct {
    uint64_t index;   /* 块下标 i */
    uint8_t nu[16];   /* ν_i，大端，∈ [1, 2^128) */
} swpor_chal_item_t;

typedef struct {
    uint8_t mode;              /* SWPOR_CHAL_EXPLICIT / SWPOR_CHAL_SEED */
    uint32_t l;                /* 请求的挑战块数（线上发送的值） */
    uint8_t seed[32];          /* 种子模式下的种子 */
    uint32_t count;            /* 实际挑战块数 = min(l, n) */
    swpor_chal_item_t *items;  /* 按 index 严格升序 */
} swpor_chal_t;

/**
 * 显式挑战（SPEC 3.5.1）：用安全随机数无放回抽取 min(l, n) 个下标及其 ν_i。
 * @param l  >= 1
 */
int swpor_chal_explicit(uint64_t n, uint32_t l, swpor_chal_t **out);

/** 种子挑战展开（SPEC 3.5.2）：验证方、服务端、审计者共用此确定性过程。 */
int swpor_chal_from_seed(const uint8_t seed[32], uint64_t n, uint32_t l, swpor_chal_t **out);

/** 随机生成种子并展开（验证方使用）。 */
int swpor_chal_random_seed(uint64_t n, uint32_t l, swpor_chal_t **out);

/**
 * 由显式下标列表构造挑战（服务端解析网络消息后使用）。
 * 校验（SPEC 4.1 Priv.P 第 1 步、SPEC 11 第 5 条）：1 <= count <= max_l、下标互不相同且 < n、ν_i ≠ 0。
 * 输出按下标升序排列。
 * @return 校验失败返回 SWPOR_E_RANGE
 */
int swpor_chal_from_items(const swpor_chal_item_t *items, uint32_t count, uint64_t n,
                          uint32_t max_l, swpor_chal_t **out);

/** 释放挑战。传入 NULL 安全。 */
void swpor_chal_free(swpor_chal_t *c);

/* ===================================================================== */
/* 证明生成 P（SPEC 4.1 Priv.P、4.2 Pub.P）                                 */
/* ===================================================================== */

/**
 * 块读取回调：读取第 i 块的数据（block_len = 31·s 字节）与 σ_i（sigma_len 字节）。
 * 服务端从 blocks.dat / sigma.dat 中按需随机读取（SPEC 6）。
 */
typedef int (*swpor_block_reader_fn)(void *user, uint64_t i, uint8_t *block, size_t block_len,
                                     uint8_t *sigma, size_t sigma_len);

/**
 * 计算证明：
 *   μ_j = Σ ν_i · m_ij (mod r)
 *   Priv：σ = Σ ν_i · σ_i (mod r)；Pub：σ = Π σ_i^{ν_i}（MSM）
 * 输出 PROOF payload：s u16 ‖ s × μ_j(32B) ‖ σ。
 * 从磁盘读入的 σ_i 会做规范性 / 曲线与子群检查（SPEC 11 第 1 条），失败返回 SWPOR_E_PARSE。
 * @param ctx    可为 NULL；用于发出 prove_done 事件
 * @param proof  输出缓冲区，容量至少 swpor_proof_bytes(scheme, s)
 */
int swpor_prove(swpor_ctx_t *ctx, const swpor_tag_header_t *hdr, const swpor_chal_t *chal,
                swpor_block_reader_fn reader, void *user, uint8_t *proof, size_t cap,
                size_t *proof_len);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_POR_H */
