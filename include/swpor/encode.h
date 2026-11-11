#ifndef SWPOR_ENCODE_H
#define SWPOR_ENCODE_H

/*
 * 文件预处理流水线（纠删码层，SPEC 5）：
 *   M ──[可选] AES-256-CTR(k_fenc, IV = 0) ──► 切成 BLOCK_BYTES 的数据块
 *     ──► 每 k 块一个条带，RS(k, m) 生成 m 个校验块（ISA-L，Cauchy 系统码）
 *     ──► [可选] 用 k_perm 对全部 n 块做秘密伪随机置换
 *     ──► M′（n 块）
 *
 * 未置换前的块顺序（"原始位置"）：条带 t 占 [t(k+m), (t+1)(k+m))，前 k 块为数据、后 m 块为校验。
 * 置换后位置 pos 存放原始第 P[pos] 块（SPEC 5 置换定义）。
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t length;      /* L：原始文件长度 */
    uint16_t s;           /* 每块扇区数 */
    uint16_t flags;       /* SWPOR_FLAG_*（swpor/por.h） */
    uint16_t rs_k;        /* 启用 RS 时的 k，否则 0 */
    uint16_t rs_m;        /* 启用 RS 时的 m，否则 0 */
    uint64_t data_blocks; /* 承载原文（含末尾补齐）的数据块数 */
    uint64_t stripes;     /* 条带数（未启用 RS 时为 0） */
    uint64_t n;           /* M′ 的块数 */
} swpor_layout_t;

/**
 * 计算分块布局（SPEC 3.2、5）。
 *   data_blocks = max(1, ⌈L / BLOCK_BYTES⌉)
 *   启用 RS：stripes = ⌈data_blocks / k⌉，n = stripes · (k + m)（不足 k 块的条带用全零块补齐）
 *   未启用：n = data_blocks
 * @return 参数非法（s = 0、k = 0、m = 0、k + m > 256）返回 SWPOR_E_INVALID_ARG；n >= 2^40 返回 SWPOR_E_RANGE
 */
int swpor_layout_compute(uint64_t length, uint16_t s, uint16_t flags, uint16_t rs_k,
                         uint16_t rs_m, swpor_layout_t *out);

/** 顺序读取输入：最多读 len 字节到 buf，实际字节数写入 *got；*got = 0 表示输入结束。 */
typedef int (*swpor_input_fn)(void *user, uint8_t *buf, size_t len, size_t *got);

/** 编码输出：把块 block（BLOCK_BYTES 字节）写到 M′ 的位置 pos。 */
typedef int (*swpor_block_sink_fn)(void *user, uint64_t pos, const uint8_t *block);

/**
 * 编码（SPEC 5）。输入必须恰好提供 layout->length 字节，否则返回 SWPOR_E_IO。
 * @param k_perm  启用置乱时使用的 32 字节密钥（未启用可为 NULL）
 * @param k_fenc  启用加密时使用的 32 字节密钥（未启用可为 NULL）
 */
int swpor_encode(swpor_ctx_t *ctx, const swpor_layout_t *layout, const uint8_t *k_perm,
                 const uint8_t *k_fenc, swpor_input_fn input, void *in_user,
                 swpor_block_sink_fn sink, void *sink_user);

/**
 * 解码时读取 M′ 位置 pos 的块，并报告其是否完好（由调用方用 σ_i 校验，SPEC 5）。
 * @param ok  输出：1 完好，0 损坏（按擦除处理）
 */
typedef int (*swpor_block_fetch_fn)(void *user, uint64_t pos, uint8_t *block, int *ok);

/** 解码输出：顺序写出恢复的原文。 */
typedef int (*swpor_output_fn)(void *user, const uint8_t *buf, size_t len);

/**
 * 解码（SPEC 5 恢复）：逆置换 → 每个条带用任意 k 个完好块解码 → 拼接 → 解密 → 按 L 截断。
 * 每个条带先只读取 k 个数据块，全部完好时不读取校验块。
 * @param erased  可为 NULL；输出检测到的损坏块数
 * @return 某条带完好块少于 k（或未启用 RS 时任一块损坏）返回 SWPOR_E_DECODE，
 *         此时可能已经写出部分输出，调用方应丢弃（T-12）
 */
int swpor_decode(swpor_ctx_t *ctx, const swpor_layout_t *layout, const uint8_t *k_perm,
                 const uint8_t *k_fenc, swpor_block_fetch_fn fetch, void *fetch_user,
                 swpor_output_fn output, void *out_user, uint64_t *erased);

/**
 * 计算置换 P（SPEC 5）：位置 i 存放原始第 P[i] 块。仅供测试与工具使用。
 * @param perm  输出数组，n 个元素
 */
int swpor_perm_compute(const uint8_t k_perm[32], uint64_t n, uint64_t *perm);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_ENCODE_H */
