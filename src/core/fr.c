/* Z_r 域元素封装（SPEC 3.1）。所有域运算均调用 blst。 */

#include "fr.h"

#include <string.h>

#include <openssl/crypto.h>

#include "swpor/error.h"
#include "swpor/params.h"

void swpor_fr_zero(swpor_fr_t *a)
{
    memset(a, 0, sizeof(*a));
}

void swpor_fr_add(swpor_fr_t *out, const swpor_fr_t *a, const swpor_fr_t *b)
{
    blst_fr_add(&out->v, &a->v, &b->v);
}

void swpor_fr_mul(swpor_fr_t *out, const swpor_fr_t *a, const swpor_fr_t *b)
{
    blst_fr_mul(&out->v, &a->v, &b->v);
}

void swpor_fr_muladd(swpor_fr_t *acc, const swpor_fr_t *a, const swpor_fr_t *b)
{
    blst_fr t;
    blst_fr_mul(&t, &a->v, &b->v);
    blst_fr_add(&acc->v, &acc->v, &t);
}

int swpor_fr_from_canonical(swpor_fr_t *out, const uint8_t in[32])
{
    blst_scalar sc;
    blst_scalar_from_bendian(&sc, in);
    /* blst_scalar_fr_check：值 < r 时为真（0 也合法） */
    if (!blst_scalar_fr_check(&sc)) {
        OPENSSL_cleanse(&sc, sizeof(sc));
        return SWPOR_E_PARSE;
    }
    blst_fr_from_scalar(&out->v, &sc);
    OPENSSL_cleanse(&sc, sizeof(sc));
    return SWPOR_OK;
}

void swpor_fr_to_bytes(uint8_t out[32], const swpor_fr_t *a)
{
    blst_scalar sc;
    blst_scalar_from_fr(&sc, &a->v);
    blst_bendian_from_scalar(out, &sc);
    OPENSSL_cleanse(&sc, sizeof(sc));
}

void swpor_fr_from_be_reduce(swpor_fr_t *out, const uint8_t *in, size_t len)
{
    blst_scalar sc;
    /* blst_scalar_from_be_bytes 对任意长度输入做模 r 规约；返回值只表示结果是否非零，此处不需要 */
    (void)blst_scalar_from_be_bytes(&sc, in, len);
    blst_fr_from_scalar(&out->v, &sc);
    OPENSSL_cleanse(&sc, sizeof(sc));
}

void swpor_fr_from_sector(swpor_fr_t *out, const uint8_t in[31])
{
    uint8_t buf[32];
    buf[0] = 0;
    memcpy(buf + 1, in, SWPOR_SECTOR_BYTES);
    blst_scalar sc;
    blst_scalar_from_bendian(&sc, buf);
    blst_fr_from_scalar(&out->v, &sc);
    OPENSSL_cleanse(&sc, sizeof(sc));
    OPENSSL_cleanse(buf, sizeof(buf));
}

int swpor_fr_to_sector(uint8_t out[31], const swpor_fr_t *a)
{
    uint8_t buf[32];
    swpor_fr_to_bytes(buf, a);
    int rc = SWPOR_OK;
    if (buf[0] != 0) {
        rc = SWPOR_E_PARSE; /* m >= 2^248：数据损坏 */
    } else {
        memcpy(out, buf + 1, SWPOR_SECTOR_BYTES);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

int swpor_fr_equal_ct(const swpor_fr_t *a, const swpor_fr_t *b)
{
    uint8_t x[32];
    uint8_t y[32];
    swpor_fr_to_bytes(x, a);
    swpor_fr_to_bytes(y, b);
    int eq = CRYPTO_memcmp(x, y, sizeof(x)) == 0;
    OPENSSL_cleanse(x, sizeof(x));
    OPENSSL_cleanse(y, sizeof(y));
    return eq;
}

void swpor_fr_cleanse(swpor_fr_t *a, size_t count)
{
    if (a != NULL && count > 0) {
        OPENSSL_cleanse(a, count * sizeof(*a));
    }
}

void swpor_block_to_fr(const uint8_t *block, uint16_t s, swpor_fr_t *out)
{
    for (uint16_t j = 0; j < s; j++) {
        swpor_fr_from_sector(&out[j], block + (size_t)j * SWPOR_SECTOR_BYTES);
    }
}
