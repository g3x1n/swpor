#ifndef SWPOR_H
#define SWPOR_H

/*
 * libswpor 总头文件。应用程序只需 #include "swpor/swpor.h"。
 * 算法与格式定义见仓库根目录的 SPEC.md。
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"
#include "swpor/encode.h"
#include "swpor/error.h"
#include "swpor/keyfile.h"
#include "swpor/params.h"
#include "swpor/pipeline.h"
#include "swpor/por.h"
#include "swpor/priv.h"
#include "swpor/pub.h"
#include "swpor/store.h"
#include "swpor/trace.h"
#include "swpor/version.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 安全随机数（OpenSSL RAND_bytes，SPEC 11 第 4 条）。 */
int swpor_random_bytes(uint8_t *buf, size_t len);

/** 返回库版本字符串，如 "0.0.1"。 */
const char *swpor_version(void);

/** 返回所链接的 OpenSSL 版本字符串。 */
const char *swpor_openssl_version(void);

/**
 * 依赖自检：确认 OpenSSL 与 blst 均已正确链接并工作正常。
 * 检查内容：RAND_bytes、HMAC-SHA-512、哈希到 G1 并做子群检查、配对双线性性
 *   e(a·P, Q) == e(P, a·Q)。
 * 这不是对算法实现的测试，只用于确认构建环境（`porctl doctor`）。
 * @return SWPOR_OK 表示全部通过；否则返回 SWPOR_E_CRYPTO
 */
int swpor_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_H */
