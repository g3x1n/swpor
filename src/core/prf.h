#ifndef SWPOR_CORE_PRF_H
#define SWPOR_CORE_PRF_H

/*
 * 对称原语的组合（全部调用 OpenSSL EVP 高层接口）：
 *   - PRF f_k(i) → Z_r（HMAC-SHA-512，SPEC 3.3）
 *   - HMAC-SHA-256 计数器字节流（种子挑战 SPEC 3.5.2、置换 SPEC 5、测试用确定性随机源）
 *   - HKDF-SHA-256（SPEC 4.1）
 *   - 安全随机数（RAND_bytes，SPEC 11 第 4 条）
 */

#include <stddef.h>
#include <stdint.h>

#include "fr.h"

/* 域分隔串（SPEC 3.3、3.5.2、5） */
#define SWPOR_DST_PRF "SWPOR-PRF-V1"
#define SWPOR_DST_ALPHA "SWPOR-ALPHA-V1"
#define SWPOR_DST_CHAL "SWPOR-CHAL-V1"
#define SWPOR_DST_PERM "SWPOR-PERM-V1"
#define SWPOR_INFO_TAGKEY "SWPOR-V1-TAGKEY"

/* ---- PRF ---- */

typedef struct swpor_prf swpor_prf_t;

/**
 * 创建 PRF 实例：f_k(i) = OS2IP(HMAC-SHA-512(k, dst ‖ I2OSP(i, 8))) mod r（SPEC 3.3）。
 * 实例内部保存密钥，释放时清零。
 * @param key  32 字节密钥
 * @param dst  域分隔串（SWPOR_DST_PRF 或 SWPOR_DST_ALPHA）
 */
int swpor_prf_new(const uint8_t key[32], const char *dst, swpor_prf_t **out);

/** 计算 f_k(i)。 */
int swpor_prf_eval(swpor_prf_t *prf, uint64_t i, swpor_fr_t *out);

/** 释放（并清零）PRF 实例。传入 NULL 安全。 */
void swpor_prf_free(swpor_prf_t *prf);

/* ---- HMAC-SHA-256 计数器字节流 ---- */

/*
 * stream = HMAC-SHA-256(key, dst ‖ I2OSP(ctr, 8))，ctr = 0,1,2,…，各块顺序拼接（SPEC 3.5.2）。
 * 结构体字段为内部状态，调用方不要直接访问。
 */
typedef struct {
    void *mac;          /* EVP_MAC_CTX*，已设置密钥 */
    char dst[32];
    size_t dst_len;
    uint64_t ctr;
    uint8_t buf[32];
    size_t pos;         /* buf 中已消费的字节数，32 表示需要生成下一块 */
} swpor_hstream_t;

/** 初始化字节流。key_len 可为任意正值。 */
int swpor_hstream_init(swpor_hstream_t *hs, const uint8_t *key, size_t key_len, const char *dst);

/** 从字节流中顺序读取 len 字节。 */
int swpor_hstream_read(swpor_hstream_t *hs, uint8_t *out, size_t len);

/** 释放并清零。 */
void swpor_hstream_clear(swpor_hstream_t *hs);

/* ---- HKDF ---- */

/** HKDF-SHA-256(IKM = ikm, salt = 空, info, L = out_len)（SPEC 4.1）。 */
int swpor_hkdf_sha256(uint8_t *out, size_t out_len, const uint8_t *ikm, size_t ikm_len,
                      const char *info);

/* ---- 随机数 ---- */

/**
 * 安全随机数（RAND_bytes）。在 SWPOR_TESTING 构建中，若已调用 swpor_test_rng_seed，
 * 则改为确定性字节流（只用于测试，SPEC 11 第 4 条）。
 */
int swpor_random_bytes(uint8_t *buf, size_t len);

/** 当前 Unix 时间（秒）。SWPOR_TESTING 下可用 swpor_test_set_time 固定（SPEC 10 T-25）。 */
uint64_t swpor_now_unix(void);

#ifdef SWPOR_TESTING
/** 设置确定性随机源（seed 为 NULL 时恢复 RAND_bytes）。仅测试构建可用，非线程安全。 */
void swpor_test_rng_seed(const uint8_t *seed, size_t len);
/** 固定 swpor_now_unix 的返回值（t = 0 表示恢复真实时间）。 */
void swpor_test_set_time(uint64_t t);
#endif

/* ---- 字节源抽象（挑战抽样共用） ---- */

/** 字节源回调：向 out 写入 len 个字节。 */
typedef int (*swpor_bytes_fn)(void *user, uint8_t *out, size_t len);

/** 适配 swpor_random_bytes 的字节源（user 忽略）。 */
int swpor_bytes_from_rng(void *user, uint8_t *out, size_t len);

/** 适配 swpor_hstream_t 的字节源（user 为 swpor_hstream_t*）。 */
int swpor_bytes_from_hstream(void *user, uint8_t *out, size_t len);

/**
 * 用拒绝采样从字节源中取 [0, bound) 内的均匀整数：每次读 8 字节得 x，
 * 拒绝 x >= ⌊2^64 / bound⌋·bound（SPEC 3.5.2、5）。bound 必须 >= 1。
 */
int swpor_uniform_u64(swpor_bytes_fn src, void *user, uint64_t bound, uint64_t *out);

#endif /* SWPOR_CORE_PRF_H */
