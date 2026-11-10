#ifndef SWPOR_TEST_MEM_BACKEND_H
#define SWPOR_TEST_MEM_BACKEND_H

/*
 * 测试用的内存"服务端"：实现 swpor_st_sink_t、swpor_get_fn、swpor_prove_fn，
 * 以及内存输入 / 输出。只用于单元测试（头文件内 static 函数）。
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "swpor/swpor.h"

typedef struct {
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    swpor_tag_header_t hdr;
    uint64_t n;
    size_t bb;
    size_t sb;
    uint8_t *blocks;
    uint8_t *sigmas;
    uint8_t *written; /* 每个位置是否写过（检查编码器恰好写满 n 个位置） */
    int finished;
    uint8_t *deleted; /* 测试：被删除的块，get 时返回 SWPOR_E_IO */
} mem_backend_t;

static int mem_begin(void *user, const uint8_t *tag, size_t tag_len, const swpor_tag_header_t *hdr)
{
    mem_backend_t *m = user;
    memcpy(m->tag, tag, tag_len);
    m->tag_len = tag_len;
    m->hdr = *hdr;
    m->n = hdr->n;
    m->bb = swpor_block_bytes(hdr->s);
    m->sb = swpor_sigma_bytes(hdr->scheme);
    m->blocks = calloc((size_t)m->n, m->bb);
    m->sigmas = calloc((size_t)m->n, m->sb);
    m->written = calloc((size_t)m->n, 1);
    m->deleted = calloc((size_t)m->n, 1);
    return (m->blocks && m->sigmas && m->written && m->deleted) ? SWPOR_OK : SWPOR_E_NOMEM;
}

static int mem_put(void *user, uint64_t pos, const uint8_t *block, size_t bl, const uint8_t *sigma,
                   size_t sl)
{
    mem_backend_t *m = user;
    if (pos >= m->n || bl != m->bb || sl != m->sb || m->written[pos]) {
        return SWPOR_E_RANGE;
    }
    memcpy(m->blocks + pos * m->bb, block, bl);
    memcpy(m->sigmas + pos * m->sb, sigma, sl);
    m->written[pos] = 1;
    return SWPOR_OK;
}

static int mem_finish(void *user)
{
    mem_backend_t *m = user;
    for (uint64_t i = 0; i < m->n; i++) {
        if (!m->written[i]) {
            return SWPOR_E_RANGE;
        }
    }
    m->finished = 1;
    return SWPOR_OK;
}

static const swpor_st_sink_t k_mem_sink = {mem_begin, mem_put, mem_finish};

static int mem_get(void *user, uint64_t pos, uint8_t *block, size_t bl, uint8_t *sigma, size_t sl)
{
    mem_backend_t *m = user;
    if (pos >= m->n || bl != m->bb || sl != m->sb) {
        return SWPOR_E_RANGE;
    }
    if (m->deleted[pos]) {
        return SWPOR_E_IO;
    }
    memcpy(block, m->blocks + pos * m->bb, bl);
    memcpy(sigma, m->sigmas + pos * m->sb, sl);
    return SWPOR_OK;
}

static int mem_reader(void *user, uint64_t i, uint8_t *block, size_t bl, uint8_t *sigma, size_t sl)
{
    return mem_get(user, i, block, bl, sigma, sl);
}

static int mem_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap, size_t *len)
{
    mem_backend_t *m = user;
    return swpor_prove(NULL, &m->hdr, chal, mem_reader, m, proof, cap, len);
}

static void mem_backend_free(mem_backend_t *m)
{
    free(m->blocks);
    free(m->sigmas);
    free(m->written);
    free(m->deleted);
    memset(m, 0, sizeof(*m));
}

/* 内存输入 */
typedef struct {
    const uint8_t *data;
    size_t len;
    size_t pos;
} mem_input_t;

static int mem_input(void *user, uint8_t *buf, size_t len, size_t *got)
{
    mem_input_t *in = user;
    size_t take = in->len - in->pos;
    if (take > len) {
        take = len;
    }
    memcpy(buf, in->data + in->pos, take);
    in->pos += take;
    *got = take;
    return SWPOR_OK;
}

/* 内存输出 */
typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} mem_output_t;

static int mem_output(void *user, const uint8_t *buf, size_t len)
{
    mem_output_t *o = user;
    if (o->len + len > o->cap) {
        size_t nc = (o->cap + len) * 2 + 16;
        uint8_t *p = realloc(o->data, nc);
        if (p == NULL) {
            return SWPOR_E_NOMEM;
        }
        o->data = p;
        o->cap = nc;
    }
    memcpy(o->data + o->len, buf, len);
    o->len += len;
    return SWPOR_OK;
}

#endif /* SWPOR_TEST_MEM_BACKEND_H */
