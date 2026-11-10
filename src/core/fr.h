#ifndef SWPOR_CORE_FR_H
#define SWPOR_CORE_FR_H

/*
 * Z_r 域元素封装（r 为 BLS12-381 标量域阶，SPEC 0、3.1）。
 * 内部表示为 blst_fr（Montgomery 形式）；所有运算调用 blst，不手写任何域运算。
 */

#include <stddef.h>
#include <stdint.h>

#include "blst.h"

typedef struct {
    blst_fr v;
} swpor_fr_t;

/** 置零。 */
void swpor_fr_zero(swpor_fr_t *a);

/** out = a + b (mod r) */
void swpor_fr_add(swpor_fr_t *out, const swpor_fr_t *a, const swpor_fr_t *b);

/** out = a · b (mod r) */
void swpor_fr_mul(swpor_fr_t *out, const swpor_fr_t *a, const swpor_fr_t *b);

/** acc += a · b (mod r) */
void swpor_fr_muladd(swpor_fr_t *acc, const swpor_fr_t *a, const swpor_fr_t *b);

/**
 * 从 32 字节大端规范编码解析（SPEC 4.1 V 第 4 步、SPEC 11 第 1 条）。
 * @return 值 >= r 时返回 SWPOR_E_PARSE
 */
int swpor_fr_from_canonical(swpor_fr_t *out, const uint8_t in[32]);

/** 输出 32 字节大端规范编码。 */
void swpor_fr_to_bytes(uint8_t out[32], const swpor_fr_t *a);

/** 把任意长度的大端字节串解释为整数并模 r 规约（PRF 输出、ν_i 用）。 */
void swpor_fr_from_be_reduce(swpor_fr_t *out, const uint8_t *in, size_t len);

/** 扇区编码：31 字节大端 → Z_r（必然 < r，无需规约，SPEC 3.1）。 */
void swpor_fr_from_sector(swpor_fr_t *out, const uint8_t in[31]);

/**
 * 扇区解码：Z_r → 31 字节（SPEC 3.1）。
 * @return 值 >= 2^248 时视为数据损坏，返回 SWPOR_E_PARSE
 */
int swpor_fr_to_sector(uint8_t out[31], const swpor_fr_t *a);

/** 常数时间比较，相等返回 1（SPEC 11 第 2 条）。 */
int swpor_fr_equal_ct(const swpor_fr_t *a, const swpor_fr_t *b);

/** 清零秘密数据（OPENSSL_cleanse）。 */
void swpor_fr_cleanse(swpor_fr_t *a, size_t count);

/**
 * 把一个数据块（31·s 字节）拆成 s 个扇区域元素（SPEC 3.1）。
 * @param block  长度为 31·s 的块
 * @param s      扇区数
 * @param out    输出数组，至少 s 个元素
 */
void swpor_block_to_fr(const uint8_t *block, uint16_t s, swpor_fr_t *out);

#endif /* SWPOR_CORE_FR_H */
