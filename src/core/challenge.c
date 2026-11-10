/*
 * 挑战生成（SPEC 3.5）。显式挑战与种子挑战共用同一个抽样过程，只是字节源不同：
 *   显式：RAND_bytes；种子：HMAC-SHA-256(seed, "SWPOR-CHAL-V1" ‖ I2OSP(ctr, 8)) 字节流。
 * 本文件是该过程的唯一实现（SPEC 3.5.2 要求），客户端、服务端、审计者共用。
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "prf.h"
#include "swpor/error.h"
#include "swpor/params.h"
#include "swpor/por.h"

static int cmp_item(const void *a, const void *b)
{
    const swpor_chal_item_t *x = a;
    const swpor_chal_item_t *y = b;
    return (x->index > y->index) - (x->index < y->index);
}

static int nu_is_zero(const uint8_t nu[16])
{
    uint8_t acc = 0;
    for (int i = 0; i < 16; i++) {
        acc |= nu[i];
    }
    return acc == 0;
}

/* 在升序数组 sorted[0..cnt) 中查找 v；找到返回 1，否则返回 0 并给出插入位置 */
static int sorted_find(const uint64_t *sorted, size_t cnt, uint64_t v, size_t *pos)
{
    size_t lo = 0;
    size_t hi = cnt;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (sorted[mid] < v) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    *pos = lo;
    return lo < cnt && sorted[lo] == v;
}

/*
 * 核心抽样过程（SPEC 3.5.1 / 3.5.2）：
 *   1. 若 l >= n，I = {0..n-1}（不消耗字节源）；否则用拒绝采样依次取 l 个互不相同的下标
 *      （重复的候选值丢弃并重取）。
 *   2. 依次取 count 个 16 字节 ν，全 0 则跳过；第 k 个 ν 属于第 k 个取得的下标。
 *   3. 按下标升序排列。
 */
static int sample(swpor_bytes_fn src, void *user, uint64_t n, uint32_t l, swpor_chal_t *c)
{
    uint32_t count = (uint64_t)l >= n ? (uint32_t)n : l;
    swpor_chal_item_t *items = calloc(count, sizeof(*items));
    uint64_t *sorted = NULL;
    int rc = SWPOR_OK;
    if (items == NULL) {
        return SWPOR_E_NOMEM;
    }
    if ((uint64_t)l >= n) {
        for (uint32_t k = 0; k < count; k++) {
            items[k].index = k;
        }
    } else {
        sorted = malloc((size_t)count * sizeof(*sorted));
        if (sorted == NULL) {
            rc = SWPOR_E_NOMEM;
            goto cleanup;
        }
        uint32_t got = 0;
        while (got < count) {
            uint64_t v;
            rc = swpor_uniform_u64(src, user, n, &v);
            if (rc != SWPOR_OK) {
                goto cleanup;
            }
            size_t pos;
            if (sorted_find(sorted, got, v, &pos)) {
                continue; /* 重复下标：丢弃 */
            }
            memmove(sorted + pos + 1, sorted + pos, (got - pos) * sizeof(*sorted));
            sorted[pos] = v;
            items[got].index = v;
            got++;
        }
    }
    for (uint32_t k = 0; k < count; k++) {
        do {
            rc = src(user, items[k].nu, SWPOR_NU_BYTES);
            if (rc != SWPOR_OK) {
                goto cleanup;
            }
        } while (nu_is_zero(items[k].nu));
    }
    qsort(items, count, sizeof(*items), cmp_item);
    c->count = count;
    c->items = items;
    items = NULL;

cleanup:
    free(sorted);
    free(items);
    return rc;
}

static int chal_alloc(uint8_t mode, uint32_t l, swpor_chal_t **out)
{
    swpor_chal_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return SWPOR_E_NOMEM;
    }
    c->mode = mode;
    c->l = l;
    *out = c;
    return SWPOR_OK;
}

int swpor_chal_explicit(uint64_t n, uint32_t l, swpor_chal_t **out)
{
    if (out == NULL || n == 0 || n >= SWPOR_MAX_BLOCKS || l == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_chal_t *c = NULL;
    int rc = chal_alloc(SWPOR_CHAL_EXPLICIT, l, &c);
    if (rc != SWPOR_OK) {
        return rc;
    }
    rc = sample(swpor_bytes_from_rng, NULL, n, l, c);
    if (rc != SWPOR_OK) {
        swpor_chal_free(c);
        return rc;
    }
    *out = c;
    return SWPOR_OK;
}

int swpor_chal_from_seed(const uint8_t seed[32], uint64_t n, uint32_t l, swpor_chal_t **out)
{
    if (seed == NULL || out == NULL || n == 0 || n >= SWPOR_MAX_BLOCKS || l == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_chal_t *c = NULL;
    int rc = chal_alloc(SWPOR_CHAL_SEED, l, &c);
    if (rc != SWPOR_OK) {
        return rc;
    }
    memcpy(c->seed, seed, SWPOR_SEED_BYTES);
    swpor_hstream_t hs;
    rc = swpor_hstream_init(&hs, seed, SWPOR_SEED_BYTES, SWPOR_DST_CHAL);
    if (rc == SWPOR_OK) {
        rc = sample(swpor_bytes_from_hstream, &hs, n, l, c);
        swpor_hstream_clear(&hs);
    }
    if (rc != SWPOR_OK) {
        swpor_chal_free(c);
        return rc;
    }
    *out = c;
    return SWPOR_OK;
}

int swpor_chal_random_seed(uint64_t n, uint32_t l, swpor_chal_t **out)
{
    uint8_t seed[SWPOR_SEED_BYTES];
    int rc = swpor_random_bytes(seed, sizeof(seed));
    if (rc != SWPOR_OK) {
        return rc;
    }
    return swpor_chal_from_seed(seed, n, l, out);
}

int swpor_chal_from_items(const swpor_chal_item_t *items, uint32_t count, uint64_t n,
                          uint32_t max_l, swpor_chal_t **out)
{
    if (items == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (count == 0 || count > max_l || (uint64_t)count > n) {
        return SWPOR_E_RANGE;
    }
    swpor_chal_t *c = NULL;
    int rc = chal_alloc(SWPOR_CHAL_EXPLICIT, count, &c);
    if (rc != SWPOR_OK) {
        return rc;
    }
    c->items = malloc((size_t)count * sizeof(*c->items));
    if (c->items == NULL) {
        swpor_chal_free(c);
        return SWPOR_E_NOMEM;
    }
    memcpy(c->items, items, (size_t)count * sizeof(*c->items));
    c->count = count;
    qsort(c->items, count, sizeof(*c->items), cmp_item);
    for (uint32_t k = 0; k < count; k++) {
        /* SPEC 11 第 5 条：下标不重复、在范围内；ν_i ∈ B = [1, 2^128) */
        if (c->items[k].index >= n || nu_is_zero(c->items[k].nu) ||
            (k > 0 && c->items[k].index == c->items[k - 1].index)) {
            swpor_chal_free(c);
            return SWPOR_E_RANGE;
        }
    }
    *out = c;
    return SWPOR_OK;
}

void swpor_chal_free(swpor_chal_t *c)
{
    if (c == NULL) {
        return;
    }
    free(c->items);
    OPENSSL_cleanse(c, sizeof(*c));
    free(c);
}
