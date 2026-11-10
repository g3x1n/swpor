/* 端到端流程组合（见 swpor/pipeline.h）。本文件不做任何 I/O。 */

#include "swpor/pipeline.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "internal.h"
#include "platform.h"
#include "prf.h"
#include "swpor/error.h"
#include "swpor/params.h"

/* ===================================================================== */
/* 存储                                                                   */
/* ===================================================================== */

typedef struct {
    swpor_ctx_t *ctx;
    uint8_t scheme;
    swpor_priv_tagger_t *pt;
    swpor_pub_tagger_t *ut;
    const swpor_st_sink_t *sink;
    void *sink_user;
    size_t bb;
    size_t sb;
    uint64_t n;
    uint64_t tagged;
    uint64_t trace_every;
} st_state_t;

/* 编码器输出的每个块：计算 σ_pos 后交给 sink */
static int st_block(void *user, uint64_t pos, const uint8_t *block)
{
    st_state_t *st = user;
    uint8_t sigma[SWPOR_G1_COMPRESSED_BYTES];
    int rc = st->scheme == SWPOR_SCHEME_PRIV ? swpor_priv_tag_block(st->pt, pos, block, sigma)
                                             : swpor_pub_tag_block(st->ut, pos, block, sigma);
    if (rc == SWPOR_OK) {
        rc = st->sink->put(st->sink_user, pos, block, st->bb, sigma, st->sb);
    }
    st->tagged++;
    if (rc == SWPOR_OK && st->tagged % st->trace_every == 0) {
        char body[48];
        (void)snprintf(body, sizeof(body), "\"i\":%" PRIu64, pos);
        swpor_trace_emit(st->ctx, SWPOR_EV_TAG_BLOCK, body);
    }
    return rc;
}

int swpor_st_run(swpor_ctx_t *ctx, const swpor_keys_t *keys, const swpor_st_params_t *params,
                 uint64_t length, swpor_input_fn input, void *in_user, const swpor_st_sink_t *sink,
                 void *sink_user, uint8_t *tag_out, size_t tag_cap, size_t *tag_len,
                 swpor_tag_header_t *hdr_out)
{
    if (keys == NULL || params == NULL || input == NULL || sink == NULL || sink->begin == NULL ||
        sink->put == NULL || sink->finish == NULL || tag_out == NULL || tag_len == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    const uint8_t scheme = keys->scheme;
    if (scheme == SWPOR_SCHEME_PRIV ? keys->priv_key == NULL
                                    : (scheme != SWPOR_SCHEME_PUB || keys->pub_sk == NULL)) {
        return SWPOR_E_INVALID_ARG;
    }
    if (scheme == SWPOR_SCHEME_PUB &&
        (params->flags & (SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT)) != 0) {
        /* Pub 标签不含 k_perm / k_fenc，无处保存（见 SPEC 5 安全性说明） */
        return SWPOR_E_UNSUPPORTED;
    }
    uint16_t k = (params->flags & SWPOR_FLAG_RS) ? params->rs_k : 0;
    uint16_t m = (params->flags & SWPOR_FLAG_RS) ? params->rs_m : 0;
    swpor_layout_t lay;
    int rc = swpor_layout_compute(length, params->s, params->flags, k, m, &lay);
    if (rc != SWPOR_OK) {
        return rc;
    }

    uint64_t t0 = swpor_time_ns();
    swpor_tag_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = SWPOR_FORMAT_VERSION;
    h.scheme = scheme;
    h.flags = params->flags;
    h.n = lay.n;
    h.s = lay.s;
    h.rs_k = lay.rs_k;
    h.rs_m = lay.rs_m;
    h.length = length;
    h.ctime = swpor_now_unix();

    st_state_t st;
    memset(&st, 0, sizeof(st));
    st.ctx = ctx;
    st.scheme = scheme;
    st.sink = sink;
    st.sink_user = sink_user;
    st.bb = swpor_block_bytes(lay.s);
    st.sb = swpor_sigma_bytes(scheme);
    st.n = lay.n;
    st.trace_every = lay.n > 1024 ? lay.n / 1024 : 1;

    swpor_priv_file_keys_t fk;
    uint8_t u_seed[32];
    memset(&fk, 0, sizeof(fk));
    rc = swpor_random_bytes(h.file_id, sizeof(h.file_id));
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    if (scheme == SWPOR_SCHEME_PRIV) {
        rc = swpor_priv_file_keys_gen(&fk);
        if (rc == SWPOR_OK) {
            rc = swpor_priv_tagger_new(&fk, lay.s, &st.pt);
        }
        if (rc == SWPOR_OK) {
            rc = swpor_priv_tag_seal(keys->priv_key, &h, &fk, tag_out, tag_cap, tag_len);
        }
    } else {
        rc = swpor_random_bytes(u_seed, sizeof(u_seed));
        if (rc == SWPOR_OK) {
            rc = swpor_pub_tagger_new(keys->pub_sk, h.file_id, u_seed, lay.s, &st.ut);
        }
        if (rc == SWPOR_OK) {
            rc = swpor_pub_tag_sign(keys->pub_sk, &h, u_seed, tag_out, tag_cap, tag_len);
        }
    }
    if (rc == SWPOR_OK) {
        rc = sink->begin(sink_user, tag_out, *tag_len, &h);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_encode(ctx, &lay, fk.k_perm, fk.k_fenc, input, in_user, st_block, &st);
    }
    if (rc == SWPOR_OK) {
        rc = sink->finish(sink_user);
    }
    if (rc == SWPOR_OK) {
        char body[96];
        (void)snprintf(body, sizeof(body), "\"n\":%" PRIu64 ",\"elapsed_ms\":%.3f", lay.n,
                       (double)(swpor_time_ns() - t0) / 1e6);
        swpor_trace_emit(ctx, SWPOR_EV_TAG_DONE, body);
        if (hdr_out != NULL) {
            *hdr_out = h;
        }
    }

cleanup:
    swpor_priv_file_keys_cleanse(&fk);
    swpor_priv_tagger_free(st.pt);
    swpor_pub_tagger_free(st.ut);
    return rc;
}

/* ===================================================================== */
/* 打开标签                                                               */
/* ===================================================================== */

/* 打开标签：Priv 输出每文件密钥，Pub 输出 u_seed */
static int open_tag(const swpor_keys_t *keys, const uint8_t *tag, size_t tag_len,
                    swpor_tag_header_t *hdr, swpor_priv_file_keys_t *fk, uint8_t u_seed[32])
{
    if (keys == NULL || tag == NULL || tag_len < SWPOR_TAG_HEADER_BYTES) {
        return SWPOR_E_INVALID_ARG;
    }
    if (tag[5] != keys->scheme) {
        return SWPOR_E_UNSUPPORTED; /* 标签方案与密钥方案不一致 */
    }
    if (keys->scheme == SWPOR_SCHEME_PRIV) {
        if (keys->priv_key == NULL) {
            return SWPOR_E_INVALID_ARG;
        }
        return swpor_priv_tag_open(keys->priv_key, tag, tag_len, hdr, fk);
    }
    if (keys->scheme == SWPOR_SCHEME_PUB) {
        if (keys->pub_pk == NULL) {
            return SWPOR_E_INVALID_ARG;
        }
        return swpor_pub_tag_open(keys->pub_pk, tag, tag_len, hdr, u_seed);
    }
    return SWPOR_E_UNSUPPORTED;
}

int swpor_tag_open_any(const swpor_keys_t *keys, const uint8_t *tag, size_t tag_len,
                       swpor_tag_header_t *hdr)
{
    swpor_priv_file_keys_t fk;
    uint8_t u_seed[32];
    int rc = open_tag(keys, tag, tag_len, hdr, &fk, u_seed);
    swpor_priv_file_keys_cleanse(&fk);
    return rc;
}

/* ===================================================================== */
/* 审计                                                                   */
/* ===================================================================== */

size_t swpor_chal_wire_bytes(const swpor_chal_t *chal)
{
    return 32u + 1u + 4u + (chal->mode == SWPOR_CHAL_SEED ? 32u : (size_t)chal->count * 24u);
}

static void trace_challenge(swpor_ctx_t *ctx, const swpor_chal_t *c)
{
    /* indices 只输出前 64 个（SPEC 9.4）；下标不是秘密 */
    char body[900];
    int off = snprintf(body, sizeof(body), "\"l\":%" PRIu32 ",\"mode\":\"%s\",\"indices\":[",
                       c->count, c->mode == SWPOR_CHAL_SEED ? "seed" : "explicit");
    for (uint32_t k = 0; k < c->count && k < 64 && off > 0 && (size_t)off < sizeof(body) - 32;
         k++) {
        off += snprintf(body + off, sizeof(body) - (size_t)off, "%s%" PRIu64, k ? "," : "",
                        c->items[k].index);
    }
    if (off > 0 && (size_t)off < sizeof(body) - 2) {
        body[off++] = ']';
        body[off] = '\0';
        swpor_trace_emit(ctx, SWPOR_EV_CHALLENGE, body);
    }
}

int swpor_audit_run(swpor_ctx_t *ctx, const swpor_keys_t *keys, const uint8_t *tag,
                    size_t tag_len, uint32_t l, int seed_mode, swpor_prove_fn prove, void *user,
                    swpor_audit_result_t *res)
{
    if (prove == NULL || res == NULL || l == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    memset(res, 0, sizeof(*res));
    uint64_t t0 = swpor_time_ns();
    swpor_tag_header_t hdr;
    swpor_priv_file_keys_t fk;
    uint8_t u_seed[32];
    swpor_chal_t *chal = NULL;
    uint8_t *proof = NULL;
    memset(&fk, 0, sizeof(fk));
    int rc = open_tag(keys, tag, tag_len, &hdr, &fk, u_seed);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    rc = seed_mode ? swpor_chal_random_seed(hdr.n, l, &chal) : swpor_chal_explicit(hdr.n, l, &chal);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    trace_challenge(ctx, chal);
    res->l = chal->count;
    res->challenge_bytes = swpor_chal_wire_bytes(chal);

    size_t cap = swpor_proof_bytes(hdr.scheme, hdr.s);
    proof = malloc(cap);
    if (proof == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    size_t plen = 0;
    uint64_t t1 = swpor_time_ns();
    rc = prove(user, chal, proof, cap, &plen);
    res->prove_ns = swpor_time_ns() - t1;
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    res->proof_bytes = plen;
    uint64_t t2 = swpor_time_ns();
    if (hdr.scheme == SWPOR_SCHEME_PRIV) {
        res->verify_rc = swpor_priv_verify(ctx, &hdr, &fk, chal, proof, plen, &res->pass);
    } else {
        res->verify_rc =
            swpor_pub_verify(ctx, keys->pub_pk, &hdr, u_seed, chal, proof, plen, &res->pass);
    }
    res->verify_ns = swpor_time_ns() - t2;
    /* 证明格式错误是"审计不通过"，不是流程错误 */
    if (res->verify_rc != SWPOR_OK && res->verify_rc != SWPOR_E_PARSE) {
        rc = res->verify_rc;
    }

cleanup:
    res->total_ns = swpor_time_ns() - t0;
    swpor_priv_file_keys_cleanse(&fk);
    swpor_chal_free(chal);
    free(proof);
    return rc;
}

/* ===================================================================== */
/* 检索                                                                   */
/* ===================================================================== */

typedef struct {
    uint8_t scheme;
    swpor_priv_tagger_t *pt;
    swpor_pub_verifier_t *pv;
    swpor_get_fn get;
    void *user;
    size_t bb;
    size_t sb;
} rt_state_t;

static int rt_fetch(void *user, uint64_t pos, uint8_t *block, int *ok)
{
    rt_state_t *rt = user;
    uint8_t sigma[SWPOR_G1_COMPRESSED_BYTES];
    *ok = 0;
    int rc = rt->get(rt->user, pos, block, rt->bb, sigma, rt->sb);
    if (rc == SWPOR_E_NOMEM || rc == SWPOR_E_NET || rc == SWPOR_E_TIMEOUT) {
        return rc; /* 资源或网络错误：中止 */
    }
    if (rc != SWPOR_OK) {
        memset(block, 0, rt->bb);
        return SWPOR_OK; /* 读不到：按擦除处理 */
    }
    if (rt->scheme == SWPOR_SCHEME_PRIV) {
        return swpor_priv_check_block(rt->pt, pos, block, sigma, ok);
    }
    return swpor_pub_verifier_check_block(rt->pv, pos, block, sigma, ok);
}

int swpor_retrieve_run(swpor_ctx_t *ctx, const swpor_keys_t *keys, const uint8_t *tag,
                       size_t tag_len, swpor_get_fn get, void *get_user, swpor_output_fn output,
                       void *out_user, uint64_t *erased)
{
    if (get == NULL || output == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_tag_header_t hdr;
    swpor_priv_file_keys_t fk;
    uint8_t u_seed[32];
    rt_state_t rt;
    memset(&rt, 0, sizeof(rt));
    memset(&fk, 0, sizeof(fk));
    int rc = open_tag(keys, tag, tag_len, &hdr, &fk, u_seed);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    rt.scheme = hdr.scheme;
    rt.get = get;
    rt.user = get_user;
    rt.bb = swpor_block_bytes(hdr.s);
    rt.sb = swpor_sigma_bytes(hdr.scheme);
    if (hdr.scheme == SWPOR_SCHEME_PRIV) {
        rc = swpor_priv_tagger_new(&fk, hdr.s, &rt.pt);
    } else {
        rc = swpor_pub_verifier_new(keys->pub_pk, &hdr, u_seed, &rt.pv);
    }
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    swpor_layout_t lay;
    rc = swpor_layout_compute(hdr.length, hdr.s, hdr.flags, hdr.rs_k, hdr.rs_m, &lay);
    if (rc == SWPOR_OK && lay.n != hdr.n) {
        rc = SWPOR_E_PARSE; /* 标签头与布局不一致 */
    }
    if (rc == SWPOR_OK) {
        rc = swpor_decode(ctx, &lay, fk.k_perm, fk.k_fenc, rt_fetch, &rt, output, out_user,
                          erased);
    }

cleanup:
    swpor_priv_file_keys_cleanse(&fk);
    swpor_priv_tagger_free(rt.pt);
    swpor_pub_verifier_free(rt.pv);
    return rc;
}
