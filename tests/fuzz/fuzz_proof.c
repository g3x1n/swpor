/*
 * libFuzzer 目标：PROOF 解析与验证（SPEC 4.1 V 第 4 步、4.2 V 第 4 步、10.4）。
 * 输入的第一个字节选择方案，其余字节作为 PROOF payload。
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "swpor/swpor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static swpor_pub_sk_t *g_sk;
static swpor_pub_pk_t *g_pk;
static swpor_chal_t *g_chal;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (g_sk == NULL) {
        uint8_t seed[32] = {9};
        if (swpor_pub_keygen(&g_sk, &g_pk) != SWPOR_OK ||
            swpor_chal_from_seed(seed, 16, 4, &g_chal) != SWPOR_OK) {
            abort();
        }
    }
    if (size < 1) {
        return 0;
    }
    swpor_tag_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = SWPOR_FORMAT_VERSION;
    h.n = 16;
    h.s = 2; /* 证明长度：Priv 2+64+32，Pub 2+64+48 */
    int pass = 0;
    if (data[0] & 1) {
        h.scheme = SWPOR_SCHEME_PUB;
        uint8_t u_seed[32] = {0};
        (void)swpor_pub_verify(NULL, g_pk, &h, u_seed, g_chal, data + 1, size - 1, &pass);
    } else {
        h.scheme = SWPOR_SCHEME_PRIV;
        swpor_priv_file_keys_t fk;
        memset(&fk, 7, sizeof(fk));
        (void)swpor_priv_verify(NULL, &h, &fk, g_chal, data + 1, size - 1, &pass);
    }
    if (pass) {
        abort(); /* 随机输入不可能通过验证 */
    }
    return 0;
}
