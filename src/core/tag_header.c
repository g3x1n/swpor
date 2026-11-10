/* 文件标签明文头（SPEC 4.3）与通用工具。 */

#include <string.h>

#include "endian.h"
#include "swpor/error.h"
#include "swpor/params.h"
#include "swpor/por.h"

static const uint8_t k_tag_magic[4] = {'S', 'W', 'P', 'T'};

void swpor_tag_header_encode(const swpor_tag_header_t *h, uint8_t out[72])
{
    memcpy(out, k_tag_magic, 4);
    out[4] = h->version;
    out[5] = h->scheme;
    swpor_store_be16(out + 6, h->flags);
    memcpy(out + 8, h->file_id, 32);
    swpor_store_be64(out + 40, h->n);
    swpor_store_be16(out + 48, h->s);
    swpor_store_be16(out + 50, h->rs_k);
    swpor_store_be16(out + 52, h->rs_m);
    swpor_store_be16(out + 54, 0);
    swpor_store_be64(out + 56, h->length);
    swpor_store_be64(out + 64, h->ctime);
}

int swpor_tag_header_decode(const uint8_t *in, size_t len, swpor_tag_header_t *h)
{
    if (in == NULL || h == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (len < SWPOR_TAG_HEADER_BYTES || memcmp(in, k_tag_magic, 4) != 0) {
        return SWPOR_E_PARSE;
    }
    swpor_tag_header_t t;
    memset(&t, 0, sizeof(t)); /* 填充字节也清零，便于整体比较 */
    t.version = in[4];
    t.scheme = in[5];
    t.flags = swpor_load_be16(in + 6);
    memcpy(t.file_id, in + 8, 32);
    t.n = swpor_load_be64(in + 40);
    t.s = swpor_load_be16(in + 48);
    t.rs_k = swpor_load_be16(in + 50);
    t.rs_m = swpor_load_be16(in + 52);
    uint16_t reserved = swpor_load_be16(in + 54);
    t.length = swpor_load_be64(in + 56);
    t.ctime = swpor_load_be64(in + 64);

    if (t.version != SWPOR_FORMAT_VERSION) {
        return SWPOR_E_UNSUPPORTED;
    }
    if (t.scheme != SWPOR_SCHEME_PRIV && t.scheme != SWPOR_SCHEME_PUB) {
        return SWPOR_E_UNSUPPORTED;
    }
    if ((t.flags & ~SWPOR_FLAGS_KNOWN) != 0 || reserved != 0) {
        return SWPOR_E_PARSE;
    }
    if (t.n == 0 || t.n >= SWPOR_MAX_BLOCKS || t.s == 0) {
        return SWPOR_E_PARSE;
    }
    uint64_t bb = (uint64_t)swpor_block_bytes(t.s);
    /* 可容纳的数据块数：启用 RS 时只有数据块承载原文 */
    uint64_t data_blocks = t.n;
    if (t.flags & SWPOR_FLAG_RS) {
        uint32_t width = (uint32_t)t.rs_k + (uint32_t)t.rs_m;
        if (t.rs_k == 0 || t.rs_m == 0 || width > 256u || t.n % width != 0) {
            return SWPOR_E_PARSE;
        }
        data_blocks = (t.n / width) * t.rs_k;
    } else if (t.rs_k != 0 || t.rs_m != 0) {
        return SWPOR_E_PARSE;
    }
    /* n < 2^40 且 bb < 2^21，乘积不会溢出 */
    if (t.length > data_blocks * bb) {
        return SWPOR_E_PARSE;
    }
    *h = t;
    return SWPOR_OK;
}

size_t swpor_block_bytes(uint16_t s)
{
    return (size_t)SWPOR_SECTOR_BYTES * (size_t)s;
}

size_t swpor_sigma_bytes(uint8_t scheme)
{
    switch (scheme) {
    case SWPOR_SCHEME_PRIV:
        return SWPOR_FR_BYTES;
    case SWPOR_SCHEME_PUB:
        return SWPOR_G1_COMPRESSED_BYTES;
    default:
        return 0;
    }
}

size_t swpor_proof_bytes(uint8_t scheme, uint16_t s)
{
    size_t sb = swpor_sigma_bytes(scheme);
    if (sb == 0) {
        return 0;
    }
    return 2u + (size_t)SWPOR_FR_BYTES * (size_t)s + sb;
}

void swpor_hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int swpor_hex_decode(const char *hex, uint8_t *out, size_t len)
{
    if (hex == NULL || out == NULL || strlen(hex) != 2 * len) {
        return SWPOR_E_PARSE;
    }
    for (size_t i = 0; i < len; i++) {
        int hi = hex_val(hex[2 * i]);
        int lo = hex_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return SWPOR_E_PARSE;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return SWPOR_OK;
}
