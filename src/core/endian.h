#ifndef SWPOR_ENDIAN_H
#define SWPOR_ENDIAN_H

/*
 * 大端编解码辅助函数。文件格式与网络协议一律使用大端（SPEC 4.3、8.2），
 * 禁止直接 memcpy 整数。
 */

#include <stdint.h>

static inline void swpor_store_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void swpor_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline void swpor_store_be64(uint8_t *p, uint64_t v)
{
    swpor_store_be32(p, (uint32_t)(v >> 32));
    swpor_store_be32(p + 4, (uint32_t)v);
}

static inline uint16_t swpor_load_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static inline uint32_t swpor_load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static inline uint64_t swpor_load_be64(const uint8_t *p)
{
    return ((uint64_t)swpor_load_be32(p) << 32) | (uint64_t)swpor_load_be32(p + 4);
}

#endif /* SWPOR_ENDIAN_H */
