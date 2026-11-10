#ifndef SWPOR_PARAMS_H
#define SWPOR_PARAMS_H

#include <stdint.h>

/*
 * 协议常量与默认参数。每一项都注明对应的 SPEC 章节。
 * 注意：除常量外，所有可配置参数都以文件标签头中的值为准（SPEC 3.6），
 * 这里的 DEFAULT_* 只在创建新文件时使用。
 */

/* ---- 编码尺寸 ---- */
#define SWPOR_SECTOR_BYTES 31u          /* 每扇区承载的数据字节数（SPEC 3.1） */
#define SWPOR_FR_BYTES 32u              /* Z_r 元素的规范编码长度，大端（SPEC 4.3、8.3） */
#define SWPOR_G1_COMPRESSED_BYTES 48u   /* 压缩 G1 点 */
#define SWPOR_G2_COMPRESSED_BYTES 96u   /* 压缩 G2 点 */
#define SWPOR_FILE_ID_BYTES 32u         /* file_id / name（SPEC 4.3） */
#define SWPOR_KEY_BYTES 32u             /* 对称密钥长度 */
#define SWPOR_NU_BYTES 16u              /* 挑战系数 ν_i 的字节长度，B = [1, 2^128)（SPEC 3.5） */
#define SWPOR_SEED_BYTES 32u            /* 种子挑战的种子长度（SPEC 3.5.2） */
#define SWPOR_TAG_HEADER_BYTES 72u      /* 文件标签明文头长度（SPEC 4.3） */

/* ---- 上限 ---- */
#define SWPOR_MAX_BLOCKS ((uint64_t)1 << 40)  /* n < 2^40（SPEC 3.2） */

/* ---- 默认参数（SPEC 3.6） ---- */
#define SWPOR_DEFAULT_S 128u            /* 每块扇区数 */
#define SWPOR_DEFAULT_L 128u            /* 每次挑战的块数 */
#define SWPOR_DEFAULT_RS_K 64u          /* RS 数据块数（SPEC 5） */
#define SWPOR_DEFAULT_RS_M 64u          /* RS 校验块数 */

/* ---- 网络（SPEC 8） ---- */
#define SWPOR_DEFAULT_PORT 7878u
#define SWPOR_MAX_FRAME_BYTES (16u * 1024u * 1024u)
#define SWPOR_DEFAULT_MAX_L 4096u       /* 服务端允许的最大 l */
#define SWPOR_DEFAULT_IO_TIMEOUT_MS 30000u

/* ---- 方案标识（SPEC 4.3 scheme 字段） ---- */
#define SWPOR_SCHEME_PRIV 1u
#define SWPOR_SCHEME_PUB 2u

/* ---- 文件格式版本 ---- */
#define SWPOR_FORMAT_VERSION 1u
#define SWPOR_PROTO_VERSION 1u

#endif /* SWPOR_PARAMS_H */
