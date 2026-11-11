/* libFuzzer 目标：CHALLENGE 消息解析（SPEC 8.3、10.4）。 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "swpor/net.h"
#include "swpor/swpor.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* 用若干个 n 解析同一输入：覆盖越界、重复下标、l >= n 等分支 */
    static const uint64_t ns[] = {1, 7, 1000, (uint64_t)1 << 39};
    for (size_t k = 0; k < sizeof(ns) / sizeof(ns[0]); k++) {
        swpor_chal_t *c = NULL;
        if (swpor_chal_decode_wire(data, size, ns[k], 64, &c) == SWPOR_OK) {
            /* 成功时必须满足：下标严格升序、< n、ν ≠ 0 */
            for (uint32_t i = 0; i < c->count; i++) {
                if (c->items[i].index >= ns[k] || (i > 0 && c->items[i].index <= c->items[i - 1].index)) {
                    abort();
                }
            }
            swpor_chal_free(c);
        }
    }
    return 0;
}
