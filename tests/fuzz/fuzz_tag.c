/* libFuzzer 目标：文件标签解析（明文头、Priv AEAD 解密、Pub 验签；SPEC 4.3、10.4）。 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "swpor/swpor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static swpor_priv_key_t *g_priv;
static swpor_pub_sk_t *g_sk;
static swpor_pub_pk_t *g_pk;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (g_priv == NULL) {
        uint8_t msk[32] = {1, 2, 3};
        if (swpor_priv_key_from_msk(msk, &g_priv) != SWPOR_OK ||
            swpor_pub_keygen(&g_sk, &g_pk) != SWPOR_OK) {
            abort();
        }
    }
    swpor_tag_header_t h;
    (void)swpor_tag_header_decode(data, size, &h);
    swpor_priv_file_keys_t fk;
    (void)swpor_priv_tag_open(g_priv, data, size, &h, &fk);
    uint8_t u_seed[32];
    (void)swpor_pub_tag_open(g_pk, data, size, &h, u_seed);
    return 0;
}
