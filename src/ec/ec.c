/*
 * 纠删码层（SPEC 5）：条带 RS（Intel ISA-L，Cauchy 系统码）+ 秘密置换 + 可选 AES-256-CTR。
 * RS 运算全部调用 ISA-L；CTR 调用 OpenSSL EVP；置换的随机源为 HMAC-SHA-256 字节流。
 */

#include "swpor/encode.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include "erasure_code.h"
#include "internal.h"
#include "prf.h"
#include "swpor/error.h"
#include "swpor/params.h"
#include "swpor/por.h"

/* ===================================================================== */
/* 布局                                                                   */
/* ===================================================================== */

int swpor_layout_compute(uint64_t length, uint16_t s, uint16_t flags, uint16_t rs_k,
                         uint16_t rs_m, swpor_layout_t *out)
{
    if (out == NULL || s == 0 || (flags & ~SWPOR_FLAGS_KNOWN) != 0) {
        return SWPOR_E_INVALID_ARG;
    }
    const uint64_t bb = (uint64_t)swpor_block_bytes(s);
    memset(out, 0, sizeof(*out));
    out->length = length;
    out->s = s;
    out->flags = flags;
    /* data_blocks = max(1, ⌈L / bb⌉)；先除后加避免溢出 */
    uint64_t d = length / bb + (length % bb != 0);
    if (d == 0) {
        d = 1;
    }
    if (d >= SWPOR_MAX_BLOCKS) {
        return SWPOR_E_RANGE;
    }
    out->data_blocks = d;
    if (flags & SWPOR_FLAG_RS) {
        if (rs_k == 0 || rs_m == 0 || (uint32_t)rs_k + rs_m > 256u) {
            return SWPOR_E_INVALID_ARG;
        }
        out->rs_k = rs_k;
        out->rs_m = rs_m;
        out->stripes = d / rs_k + (d % rs_k != 0);
        /* stripes < 2^40，(k+m) <= 256，乘积不溢出 */
        out->n = out->stripes * ((uint64_t)rs_k + rs_m);
    } else {
        out->n = d;
    }
    if (out->n >= SWPOR_MAX_BLOCKS) {
        return SWPOR_E_RANGE;
    }
    return SWPOR_OK;
}

/* ===================================================================== */
/* 置换（SPEC 5）                                                          */
/* ===================================================================== */

int swpor_perm_compute(const uint8_t k_perm[32], uint64_t n, uint64_t *perm)
{
    if (k_perm == NULL || perm == NULL || n == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    for (uint64_t i = 0; i < n; i++) {
        perm[i] = i;
    }
    swpor_hstream_t hs;
    int rc = swpor_hstream_init(&hs, k_perm, 32, SWPOR_DST_PERM);
    if (rc != SWPOR_OK) {
        return rc;
    }
    /* Fisher–Yates：i 从 n-1 递减到 1，j ← 均匀 [0, i]，交换 P[i] 与 P[j] */
    for (uint64_t i = n - 1; i >= 1; i--) {
        uint64_t j;
        rc = swpor_uniform_u64(swpor_bytes_from_hstream, &hs, i + 1, &j);
        if (rc != SWPOR_OK) {
            break;
        }
        uint64_t tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
    swpor_hstream_clear(&hs);
    return rc;
}

/* 计算逆置换：inv[P[pos]] = pos，即原始块 orig 存放在位置 inv[orig] */
static int perm_inverse(const uint8_t k_perm[32], uint64_t n, uint64_t **out)
{
    uint64_t *p = malloc((size_t)n * sizeof(*p));
    uint64_t *inv = malloc((size_t)n * sizeof(*inv));
    int rc = (p == NULL || inv == NULL) ? SWPOR_E_NOMEM : SWPOR_OK;
    if (rc == SWPOR_OK) {
        rc = swpor_perm_compute(k_perm, n, p);
    }
    if (rc == SWPOR_OK) {
        for (uint64_t pos = 0; pos < n; pos++) {
            inv[p[pos]] = pos;
        }
        *out = inv;
        inv = NULL;
    }
    free(p);
    free(inv);
    return rc;
}

/* ===================================================================== */
/* AES-256-CTR（SPEC 5，IV = 16 字节 0）                                    */
/* ===================================================================== */

static EVP_CIPHER_CTX *ctr_new(const uint8_t key[32])
{
    static const uint8_t iv[16] = {0};
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (c != NULL && EVP_EncryptInit_ex(c, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(c);
        c = NULL;
    }
    return c;
}

/* CTR 模式加密与解密相同：buf ^= keystream，原地进行 */
static int ctr_apply(EVP_CIPHER_CTX *c, uint8_t *buf, size_t len)
{
    while (len > 0) {
        int chunk = len > (1u << 30) ? (1 << 30) : (int)len;
        int outl = 0;
        if (EVP_EncryptUpdate(c, buf, &outl, buf, chunk) != 1 || outl != chunk) {
            return SWPOR_E_CRYPTO;
        }
        buf += chunk;
        len -= (size_t)chunk;
    }
    return SWPOR_OK;
}

/* ===================================================================== */
/* 公共状态                                                               */
/* ===================================================================== */

typedef struct {
    const swpor_layout_t *lay;
    size_t bb;
    uint32_t width;       /* 条带宽度 k + m；未启用 RS 时为 1 */
    uint32_t k;           /* 每条带数据块数；未启用 RS 时为 1 */
    uint32_t m;
    uint64_t groups;      /* 条带数；未启用 RS 时为 data_blocks */
    uint64_t *inv;        /* 逆置换（未启用置乱时为 NULL） */
    EVP_CIPHER_CTX *ctr;  /* 文件加密（未启用时为 NULL） */
    uint8_t *buf;         /* width × bb */
    uint8_t *a;           /* (k+m) × k Cauchy 矩阵 */
    uint8_t *tbls;        /* 32 · k · m */
} ec_state_t;

static void ec_state_free(ec_state_t *st)
{
    free(st->inv);
    EVP_CIPHER_CTX_free(st->ctr);
    if (st->buf != NULL) {
        OPENSSL_cleanse(st->buf, (size_t)st->width * st->bb);
    }
    free(st->buf);
    free(st->a);
    free(st->tbls);
}

static int ec_state_init(ec_state_t *st, const swpor_layout_t *lay, const uint8_t *k_perm,
                         const uint8_t *k_fenc)
{
    memset(st, 0, sizeof(*st));
    st->lay = lay;
    st->bb = swpor_block_bytes(lay->s);
    if (lay->flags & SWPOR_FLAG_RS) {
        st->k = lay->rs_k;
        st->m = lay->rs_m;
        st->groups = lay->stripes;
    } else {
        st->k = 1;
        st->m = 0;
        st->groups = lay->data_blocks;
    }
    st->width = st->k + st->m;
    int rc = SWPOR_OK;
    st->buf = calloc(st->width, st->bb);
    if (st->buf == NULL) {
        return SWPOR_E_NOMEM;
    }
    if (st->m > 0) {
        st->a = malloc((size_t)st->width * st->k);
        st->tbls = malloc((size_t)32 * st->k * st->m);
        if (st->a == NULL || st->tbls == NULL) {
            return SWPOR_E_NOMEM;
        }
        gf_gen_cauchy1_matrix(st->a, (int)st->width, (int)st->k);
        ec_init_tables((int)st->k, (int)st->m, st->a + (size_t)st->k * st->k, st->tbls);
    }
    if (lay->flags & SWPOR_FLAG_PERM) {
        if (k_perm == NULL) {
            return SWPOR_E_INVALID_ARG;
        }
        rc = perm_inverse(k_perm, lay->n, &st->inv);
        if (rc != SWPOR_OK) {
            return rc;
        }
    }
    if (lay->flags & SWPOR_FLAG_ENCRYPT) {
        if (k_fenc == NULL) {
            return SWPOR_E_INVALID_ARG;
        }
        st->ctr = ctr_new(k_fenc);
        if (st->ctr == NULL) {
            return SWPOR_E_CRYPTO;
        }
    }
    return SWPOR_OK;
}

/* 原始位置 → M′ 中的位置 */
static uint64_t ec_pos(const ec_state_t *st, uint64_t orig)
{
    return st->inv != NULL ? st->inv[orig] : orig;
}

/* ===================================================================== */
/* 编码                                                                   */
/* ===================================================================== */

/* 从输入读满 len 字节（不足时补 0），返回实际读到的字节数 */
static int read_fill(swpor_input_fn input, void *user, uint8_t *buf, size_t len, size_t *got)
{
    size_t done = 0;
    while (done < len) {
        size_t g = 0;
        int rc = input(user, buf + done, len - done, &g);
        if (rc != SWPOR_OK) {
            return rc;
        }
        if (g == 0) {
            break;
        }
        done += g;
    }
    memset(buf + done, 0, len - done);
    *got = done;
    return SWPOR_OK;
}

int swpor_encode(swpor_ctx_t *ctx, const swpor_layout_t *layout, const uint8_t *k_perm,
                 const uint8_t *k_fenc, swpor_input_fn input, void *in_user,
                 swpor_block_sink_fn sink, void *sink_user)
{
    if (layout == NULL || input == NULL || sink == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    ec_state_t st;
    int rc = ec_state_init(&st, layout, k_perm, k_fenc);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    {
        char body[160];
        (void)snprintf(body, sizeof(body),
                       "\"n\":%" PRIu64 ",\"s\":%u,\"L\":%" PRIu64 ",\"block_bytes\":%zu",
                       layout->n, (unsigned)layout->s, layout->length, st.bb);
        swpor_trace_emit(ctx, SWPOR_EV_FILE_SPLIT, body);
    }

    uint64_t consumed = 0;
    uint8_t **data = NULL;
    uint8_t **coding = NULL;
    if (st.m > 0) {
        data = malloc(st.k * sizeof(*data));
        coding = malloc(st.m * sizeof(*coding));
        if (data == NULL || coding == NULL) {
            free(data);
            free(coding);
            rc = SWPOR_E_NOMEM;
            goto cleanup;
        }
        for (uint32_t j = 0; j < st.k; j++) {
            data[j] = st.buf + (size_t)j * st.bb;
        }
        for (uint32_t j = 0; j < st.m; j++) {
            coding[j] = st.buf + (size_t)(st.k + j) * st.bb;
        }
    }
    for (uint64_t g = 0; g < st.groups && rc == SWPOR_OK; g++) {
        /* 读入 k 个数据块（末尾不足部分及补齐块为全 0） */
        for (uint32_t j = 0; j < st.k && rc == SWPOR_OK; j++) {
            uint8_t *blk = st.buf + (size_t)j * st.bb;
            uint64_t remain = layout->length - consumed;
            size_t want = remain < st.bb ? (size_t)remain : st.bb;
            size_t got = 0;
            rc = read_fill(input, in_user, blk, want, &got);
            if (rc == SWPOR_OK && got != want) {
                rc = SWPOR_E_IO; /* 输入比声明的 L 短 */
            }
            if (rc == SWPOR_OK) {
                memset(blk + want, 0, st.bb - want);
                if (st.ctr != NULL && want > 0) {
                    rc = ctr_apply(st.ctr, blk, want); /* 只加密原文，不加密补齐的 0 */
                }
                consumed += want;
            }
        }
        if (rc != SWPOR_OK) {
            break;
        }
        if (st.m > 0) {
            ec_encode_data((int)st.bb, (int)st.k, (int)st.m, st.tbls, data, coding);
        }
        for (uint32_t j = 0; j < st.width && rc == SWPOR_OK; j++) {
            uint64_t orig = g * st.width + j;
            rc = sink(sink_user, ec_pos(&st, orig), st.buf + (size_t)j * st.bb);
        }
        if (rc == SWPOR_OK && st.m > 0) {
            char body[96];
            (void)snprintf(body, sizeof(body), "\"stripe\":%" PRIu64 ",\"k\":%u,\"m\":%u", g,
                           (unsigned)st.k, (unsigned)st.m);
            swpor_trace_emit(ctx, SWPOR_EV_EC_STRIPE, body);
        }
    }
    free(data);
    free(coding);
    if (rc == SWPOR_OK) {
        /* 输入不得比 L 长 */
        uint8_t extra;
        size_t g = 0;
        rc = input(in_user, &extra, 1, &g);
        if (rc == SWPOR_OK && g != 0) {
            rc = SWPOR_E_IO;
        }
    }

cleanup:
    ec_state_free(&st);
    return rc;
}

/* ===================================================================== */
/* 解码                                                                   */
/* ===================================================================== */

/*
 * 用 present[0..k) 指示的 k 个完好块（行号为条带内下标，升序）恢复缺失的数据块。
 * 恢复矩阵 = (A 中这 k 行组成的子矩阵)^-1 中对应缺失数据块的行。
 */
static int rs_recover(ec_state_t *st, const uint32_t *src_rows, const uint32_t *missing,
                      uint32_t nmiss)
{
    const uint32_t k = st->k;
    int rc = SWPOR_OK;
    uint8_t *b = malloc((size_t)k * k);
    uint8_t *d = malloc((size_t)k * k);
    uint8_t *c = malloc((size_t)nmiss * k);
    uint8_t *tb = malloc((size_t)32 * k * nmiss);
    uint8_t **srcs = malloc(k * sizeof(*srcs));
    uint8_t **outs = malloc(nmiss * sizeof(*outs));
    uint8_t *tmp = malloc((size_t)nmiss * st->bb);
    if (b == NULL || d == NULL || c == NULL || tb == NULL || srcs == NULL || outs == NULL ||
        tmp == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    for (uint32_t r = 0; r < k; r++) {
        memcpy(b + (size_t)r * k, st->a + (size_t)src_rows[r] * k, k);
        srcs[r] = st->buf + (size_t)src_rows[r] * st->bb;
    }
    if (gf_invert_matrix(b, d, (int)k) != 0) {
        rc = SWPOR_E_DECODE; /* Cauchy 矩阵任意 k 行可逆，正常不会发生 */
        goto cleanup;
    }
    for (uint32_t e = 0; e < nmiss; e++) {
        memcpy(c + (size_t)e * k, d + (size_t)missing[e] * k, k);
        outs[e] = tmp + (size_t)e * st->bb;
    }
    ec_init_tables((int)k, (int)nmiss, c, tb);
    ec_encode_data((int)st->bb, (int)k, (int)nmiss, tb, srcs, outs);
    for (uint32_t e = 0; e < nmiss; e++) {
        memcpy(st->buf + (size_t)missing[e] * st->bb, outs[e], st->bb);
    }
cleanup:
    free(b);
    free(d);
    free(c);
    free(tb);
    free(srcs);
    free(outs);
    if (tmp != NULL) {
        OPENSSL_cleanse(tmp, (size_t)nmiss * st->bb);
    }
    free(tmp);
    return rc;
}

int swpor_decode(swpor_ctx_t *ctx, const swpor_layout_t *layout, const uint8_t *k_perm,
                 const uint8_t *k_fenc, swpor_block_fetch_fn fetch, void *fetch_user,
                 swpor_output_fn output, void *out_user, uint64_t *erased)
{
    (void)ctx;
    if (layout == NULL || fetch == NULL || output == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    ec_state_t st;
    uint32_t *ok_rows = NULL;
    uint32_t *missing = NULL;
    uint8_t *okflag = NULL;
    uint64_t bad = 0;
    int rc = ec_state_init(&st, layout, k_perm, k_fenc);
    if (rc != SWPOR_OK) {
        goto cleanup;
    }
    ok_rows = malloc(st.width * sizeof(*ok_rows));
    missing = malloc(st.k * sizeof(*missing));
    okflag = malloc(st.width);
    if (ok_rows == NULL || missing == NULL || okflag == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }

    uint64_t emitted = 0;
    for (uint64_t g = 0; g < st.groups; g++) {
        uint32_t nok = 0;
        uint32_t nmiss = 0;
        /* 先读 k 个数据块 */
        for (uint32_t j = 0; j < st.k; j++) {
            int ok = 0;
            rc = fetch(fetch_user, ec_pos(&st, g * st.width + j), st.buf + (size_t)j * st.bb, &ok);
            if (rc != SWPOR_OK) {
                goto cleanup;
            }
            okflag[j] = (uint8_t)(ok != 0);
            if (ok) {
                ok_rows[nok++] = j;
            } else {
                missing[nmiss++] = j;
                bad++;
            }
        }
        if (nmiss > 0) {
            if (st.m == 0) {
                rc = SWPOR_E_DECODE; /* 未启用 RS：任一块损坏都无法恢复 */
                goto cleanup;
            }
            /* 再读校验块，直到凑够 k 个完好块 */
            for (uint32_t j = st.k; j < st.width && nok < st.k; j++) {
                int ok = 0;
                rc = fetch(fetch_user, ec_pos(&st, g * st.width + j),
                           st.buf + (size_t)j * st.bb, &ok);
                if (rc != SWPOR_OK) {
                    goto cleanup;
                }
                if (ok) {
                    ok_rows[nok++] = j;
                } else {
                    bad++;
                }
            }
            if (nok < st.k) {
                rc = SWPOR_E_DECODE; /* T-12：报告失败而不是输出错误数据 */
                goto cleanup;
            }
            rc = rs_recover(&st, ok_rows, missing, nmiss);
            if (rc != SWPOR_OK) {
                goto cleanup;
            }
        }
        /* 输出本条带的数据块：解密并按 L 截断 */
        for (uint32_t j = 0; j < st.k && emitted < layout->length; j++) {
            uint64_t remain = layout->length - emitted;
            size_t take = remain < st.bb ? (size_t)remain : st.bb;
            uint8_t *blk = st.buf + (size_t)j * st.bb;
            if (st.ctr != NULL) {
                rc = ctr_apply(st.ctr, blk, take);
                if (rc != SWPOR_OK) {
                    goto cleanup;
                }
            }
            rc = output(out_user, blk, take);
            if (rc != SWPOR_OK) {
                goto cleanup;
            }
            emitted += take;
        }
    }
    (void)okflag;

cleanup:
    if (erased != NULL) {
        *erased = bad;
    }
    free(ok_rows);
    free(missing);
    free(okflag);
    ec_state_free(&st);
    return rc;
}
