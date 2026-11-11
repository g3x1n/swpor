/* 远程模式适配器：把 swpor/pipeline.h 的回调映射到网络客户端（SPEC 8.3）。 */

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "swpor/error.h"
#include "swpor/net.h"
#include "swpor/params.h"
#include "swpor/pipeline.h"
#include "swpor/store.h"

/* 一批最多发送的块数：64 × 3968 B ≈ 254 KiB，远小于 16 MiB 帧上限 */
#define BATCH_BLOCKS 64u

struct swpor_remote {
    swpor_client_t *c;
    uint8_t file_id[32];
    size_t bb;
    size_t sb;
    /* 正在积累的连续块 [run_start, run_start + run_len) */
    uint64_t run_start;
    uint32_t run_len;
    uint32_t run_cap;
    uint8_t *blocks;
    uint8_t *sigmas;
};

int swpor_remote_new(swpor_client_t *client, swpor_remote_t **out)
{
    if (client == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_remote_t *r = calloc(1, sizeof(*r));
    if (r == NULL) {
        return SWPOR_E_NOMEM;
    }
    r->c = client;
    *out = r;
    return SWPOR_OK;
}

void swpor_remote_free(swpor_remote_t *r)
{
    if (r == NULL) {
        return;
    }
    free(r->blocks);
    free(r->sigmas);
    free(r);
}

const uint8_t *swpor_remote_file_id(const swpor_remote_t *r)
{
    return r->file_id;
}

void swpor_remote_set_file_id(swpor_remote_t *r, const uint8_t file_id[32])
{
    memcpy(r->file_id, file_id, 32);
}

static int r_flush(swpor_remote_t *r)
{
    if (r->run_len == 0) {
        return SWPOR_OK;
    }
    int rc = swpor_client_store_blocks(r->c, r->run_start, r->run_len, r->blocks,
                                       (size_t)r->run_len * r->bb);
    if (rc == SWPOR_OK) {
        rc = swpor_client_store_sigmas(r->c, r->run_start, r->run_len, r->sigmas,
                                       (size_t)r->run_len * r->sb);
    }
    r->run_len = 0;
    return rc;
}

static int r_begin(void *user, const uint8_t *tag, size_t tag_len, const swpor_tag_header_t *h)
{
    swpor_remote_t *r = user;
    r->bb = swpor_block_bytes(h->s);
    r->sb = swpor_sigma_bytes(h->scheme);
    memcpy(r->file_id, h->file_id, 32);
    r->run_cap = BATCH_BLOCKS;
    free(r->blocks);
    free(r->sigmas);
    r->blocks = malloc((size_t)r->run_cap * r->bb);
    r->sigmas = malloc((size_t)r->run_cap * r->sb);
    if (r->blocks == NULL || r->sigmas == NULL) {
        return SWPOR_E_NOMEM;
    }
    r->run_len = 0;
    return swpor_client_store_begin(r->c, tag, tag_len, h->n, (uint32_t)r->bb, (uint8_t)r->sb);
}

static int r_put(void *user, uint64_t pos, const uint8_t *block, size_t bl, const uint8_t *sigma,
                 size_t sl)
{
    swpor_remote_t *r = user;
    if (bl != r->bb || sl != r->sb) {
        return SWPOR_E_INVALID_ARG;
    }
    /* 不连续或批已满：先发出当前批（启用置乱时块是乱序到达的） */
    if (r->run_len > 0 && (pos != r->run_start + r->run_len || r->run_len == r->run_cap)) {
        int rc = r_flush(r);
        if (rc != SWPOR_OK) {
            return rc;
        }
    }
    if (r->run_len == 0) {
        r->run_start = pos;
    }
    memcpy(r->blocks + (size_t)r->run_len * r->bb, block, bl);
    memcpy(r->sigmas + (size_t)r->run_len * r->sb, sigma, sl);
    r->run_len++;
    return SWPOR_OK;
}

static int r_finish(void *user)
{
    swpor_remote_t *r = user;
    int rc = r_flush(r);
    if (rc == SWPOR_OK) {
        uint8_t fid[32];
        rc = swpor_client_store_end(r->c, fid);
        if (rc == SWPOR_OK && memcmp(fid, r->file_id, 32) != 0) {
            rc = SWPOR_E_PARSE;
        }
    }
    return rc;
}

static const swpor_st_sink_t k_remote_sink = {r_begin, r_put, r_finish};

const struct swpor_st_sink_s *swpor_remote_sink(void)
{
    return &k_remote_sink;
}

int swpor_remote_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap,
                       size_t *proof_len)
{
    swpor_remote_t *r = user;
    return swpor_client_challenge(r->c, r->file_id, chal, proof, cap, proof_len);
}

int swpor_remote_download(swpor_client_t *client, const uint8_t file_id[32], const char *root)
{
    if (client == NULL || file_id == NULL || root == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    int rc = swpor_client_get_tag(client, file_id, tag, sizeof(tag), &tag_len);
    if (rc != SWPOR_OK) {
        return rc;
    }
    swpor_tag_header_t h;
    rc = swpor_tag_header_decode(tag, tag_len, &h);
    if (rc != SWPOR_OK) {
        return rc;
    }
    if (memcmp(h.file_id, file_id, 32) != 0) {
        return SWPOR_E_PARSE;
    }
    const size_t bb = swpor_block_bytes(h.s);
    const size_t sb = swpor_sigma_bytes(h.scheme);
    swpor_store_t *st = NULL;
    uint8_t *blocks = malloc((size_t)BATCH_BLOCKS * bb);
    uint8_t *sigmas = malloc((size_t)BATCH_BLOCKS * sb);
    if (blocks == NULL || sigmas == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    rc = swpor_store_create(root, file_id, h.scheme, h.n, h.s, &st);
    for (uint64_t start = 0; rc == SWPOR_OK && start < h.n; start += BATCH_BLOCKS) {
        uint32_t cnt = (uint32_t)(h.n - start < BATCH_BLOCKS ? h.n - start : BATCH_BLOCKS);
        rc = swpor_client_get_blocks(client, file_id, start, cnt, blocks, (size_t)cnt * bb);
        if (rc == SWPOR_OK) {
            rc = swpor_client_get_sigmas(client, file_id, start, cnt, sigmas, (size_t)cnt * sb);
        }
        for (uint32_t k = 0; rc == SWPOR_OK && k < cnt; k++) {
            rc = swpor_store_write_block(st, start + k, blocks + (size_t)k * bb);
            if (rc == SWPOR_OK) {
                rc = swpor_store_write_sigma(st, start + k, sigmas + (size_t)k * sb);
            }
        }
    }
    if (rc == SWPOR_OK) {
        rc = swpor_store_write_tag(st, tag, tag_len);
    }

cleanup:
    swpor_store_close(st);
    if (blocks != NULL) {
        OPENSSL_cleanse(blocks, (size_t)BATCH_BLOCKS * bb);
    }
    free(blocks);
    free(sigmas);
    return rc;
}
