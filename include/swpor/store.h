#ifndef SWPOR_STORE_H
#define SWPOR_STORE_H

/*
 * 磁盘格式（SPEC 6、7）。
 *
 * 每个文件存放在 <root>/<file_id 十六进制>/ 下：
 *   blocks.dat  "SWPB" ‖ version ‖ 3 字节保留 ‖ n × BLOCK_BYTES
 *   sigma.dat   "SWPS" ‖ version ‖ scheme ‖ 2 字节保留 ‖ n × |σ|
 *   tag.bin     文件标签 t
 * 写入时先写 blocks.dat / sigma.dat，最后写 tag.bin；tag.bin 存在即表示文件完整。
 * 服务端（pord）与客户端本地模式使用同一布局。
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/por.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SWPOR_STORE_FILE_HEADER_BYTES 8u

typedef struct swpor_store swpor_store_t;

/**
 * 新建文件目录并创建 blocks.dat / sigma.dat（已存在时截断重写）。
 * @param root     数据根目录（不存在时自动创建）
 * @param file_id  32 字节
 */
int swpor_store_create(const char *root, const uint8_t file_id[32], uint8_t scheme, uint64_t n,
                       uint16_t s, swpor_store_t **out);

/**
 * 打开已完成的文件：读取并解析 tag.bin 的明文头，校验 blocks.dat / sigma.dat 的文件头与长度。
 * @param writable  非 0 时以读写方式打开（tamper 用）
 * @return 不存在返回 SWPOR_E_NOT_FOUND；格式错误返回 SWPOR_E_PARSE
 */
int swpor_store_open(const char *root, const uint8_t file_id[32], int writable,
                     swpor_store_t **out);

/** 写第 i 块（BLOCK_BYTES 字节）。 */
int swpor_store_write_block(swpor_store_t *st, uint64_t i, const uint8_t *block);

/** 写 σ_i。 */
int swpor_store_write_sigma(swpor_store_t *st, uint64_t i, const uint8_t *sigma);

/** 写入文件标签（tag.bin，先写临时文件再改名），完成存储。 */
int swpor_store_write_tag(swpor_store_t *st, const uint8_t *tag, size_t len);

/** 读第 i 块。 */
int swpor_store_read_block(swpor_store_t *st, uint64_t i, uint8_t *block);

/** 读 σ_i。 */
int swpor_store_read_sigma(swpor_store_t *st, uint64_t i, uint8_t *sigma);

/** 返回打开时读取的文件标签（create 后、write_tag 前为空）。 */
const uint8_t *swpor_store_tag(const swpor_store_t *st, size_t *len);

/** 返回明文头（仅 open 或 write_tag 之后有效）。 */
const swpor_tag_header_t *swpor_store_header(const swpor_store_t *st);

/** 块大小与 σ 大小。 */
size_t swpor_store_block_bytes(const swpor_store_t *st);
size_t swpor_store_sigma_bytes(const swpor_store_t *st);
uint64_t swpor_store_n(const swpor_store_t *st);

/** 把数据刷到磁盘。 */
int swpor_store_sync(swpor_store_t *st);

/** 关闭。传入 NULL 安全。 */
void swpor_store_close(swpor_store_t *st);

/** 删除文件目录及其中的三个文件。 */
int swpor_store_delete(const char *root, const uint8_t file_id[32]);

/** 适配 swpor_prove 的块读取回调（user 为 swpor_store_t*）。 */
int swpor_store_reader(void *user, uint64_t i, uint8_t *block, size_t block_len, uint8_t *sigma,
                       size_t sigma_len);

/* ===================================================================== */
/* 密钥文件（SPEC 7）                                                      */
/* ===================================================================== */

/** 读取文件全部内容（上限 max_len，超过返回 SWPOR_E_RANGE）。调用方 free(*out)。 */
int swpor_read_file(const char *path, size_t max_len, uint8_t **out, size_t *len);

/** 写入文件（创建或截断）。 */
int swpor_write_file(const char *path, const uint8_t *data, size_t len);

/**
 * 写秘密密钥文件：权限仅本人可读写，不覆盖已有文件（除非 force，SPEC 7）。
 */
int swpor_write_secret_file(const char *path, const uint8_t *data, size_t len, int force);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_STORE_H */
