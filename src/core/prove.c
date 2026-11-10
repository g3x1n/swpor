/*
 * 证明生成 P（SPEC 4.1 Priv.P、4.2 Pub.P）。两方案的 μ_j 计算相同，σ 的聚合不同：
 *   Priv：σ = Σ ν_i · σ_i (mod r)
 *   Pub ：σ = Π σ_i^{ν_i}，用 blst 的 Pippenger 多标量乘（MSM）
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blst.h"
#include "endian.h"
#include "fr.h"
#include "internal.h"
#include "platform.h"
#include "proof.h"
#include "swpor/error.h"
#include "swpor/params.h"
#include "swpor/por.h"

int swpor_proof_parse_mu(const uint8_t *proof, size_t len, uint8_t scheme, uint16_t s,
                         swpor_fr_t *mu)
{
    if (proof == NULL || mu == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (len != swpor_proof_bytes(scheme, s) || swpor_load_be16(proof) != s) {
        return SWPOR_E_PARSE;
    }
    for (uint16_t j = 0; j < s; j++) {
        int rc = swpor_fr_from_canonical(&mu[j], proof + 2 + (size_t)SWPOR_FR_BYTES * j);
        if (rc != SWPOR_OK) {
            return rc;
        }
    }
    return SWPOR_OK;
}

void swpor_nu_to_le(const uint8_t be[16], uint8_t le[16])
{
    for (int k = 0; k < 16; k++) {
        le[k] = be[15 - k];
    }
}

int swpor_prove(swpor_ctx_t *ctx, const swpor_tag_header_t *hdr, const swpor_chal_t *chal,
                swpor_block_reader_fn reader, void *user, uint8_t *proof, size_t cap,
                size_t *proof_len)
{
    if (hdr == NULL || chal == NULL || reader == NULL || proof == NULL || proof_len == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    const uint8_t scheme = hdr->scheme;
    const uint16_t s = hdr->s;
    const size_t need = swpor_proof_bytes(scheme, s);
    const size_t bb = swpor_block_bytes(s);
    const size_t sb = swpor_sigma_bytes(scheme);
    if (need == 0 || s == 0) {
        return SWPOR_E_UNSUPPORTED;
    }
    if (cap < need) {
        return SWPOR_E_RANGE;
    }
    if (chal->count == 0 || chal->items == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint64_t t0 = swpor_time_ns();
    const uint32_t l = chal->count;
    int rc = SWPOR_OK;

    uint8_t *block = malloc(bb);
    swpor_fr_t *mu = calloc(s, sizeof(*mu));
    /* Pub：保存 l 个 σ_i 仿射点与小端 ν，最后一次 MSM */
    blst_p1_affine *pts = NULL;
    const blst_p1_affine **pts_ptr = NULL;
    uint8_t *nus_le = NULL;
    const uint8_t **nus_ptr = NULL;
    limb_t *scratch = NULL;
    swpor_fr_t sigma_acc;
    swpor_fr_zero(&sigma_acc);

    if (block == NULL || mu == NULL) {
        rc = SWPOR_E_NOMEM;
        goto cleanup;
    }
    if (scheme == SWPOR_SCHEME_PUB) {
        pts = malloc((size_t)l * sizeof(*pts));
        pts_ptr = malloc((size_t)l * sizeof(*pts_ptr));
        nus_le = malloc((size_t)l * 16u);
        nus_ptr = malloc((size_t)l * sizeof(*nus_ptr));
        if (pts == NULL || pts_ptr == NULL || nus_le == NULL || nus_ptr == NULL) {
            rc = SWPOR_E_NOMEM;
            goto cleanup;
        }
    }

    uint8_t sigma_raw[SWPOR_G1_COMPRESSED_BYTES];
    swpor_fr_t nu, m;
    for (uint32_t k = 0; k < l; k++) {
        const uint64_t i = chal->items[k].index;
        if (i >= hdr->n) {
            rc = SWPOR_E_RANGE;
            goto cleanup;
        }
        rc = reader(user, i, block, bb, sigma_raw, sb);
        if (rc != SWPOR_OK) {
            goto cleanup;
        }
        swpor_fr_from_be_reduce(&nu, chal->items[k].nu, SWPOR_NU_BYTES);
        /* μ_j += ν_i · m_ij */
        for (uint16_t j = 0; j < s; j++) {
            swpor_fr_from_sector(&m, block + (size_t)j * SWPOR_SECTOR_BYTES);
            swpor_fr_muladd(&mu[j], &nu, &m);
        }
        if (scheme == SWPOR_SCHEME_PRIV) {
            swpor_fr_t sg;
            rc = swpor_fr_from_canonical(&sg, sigma_raw);
            if (rc != SWPOR_OK) {
                goto cleanup;
            }
            swpor_fr_muladd(&sigma_acc, &nu, &sg);
        } else {
            /* 从磁盘读入的群元素：曲线检查 + 子群检查 + 非无穷远点（SPEC 11 第 1 条） */
            if (blst_p1_uncompress(&pts[k], sigma_raw) != BLST_SUCCESS ||
                blst_p1_affine_is_inf(&pts[k]) || !blst_p1_affine_in_g1(&pts[k])) {
                rc = SWPOR_E_PARSE;
                goto cleanup;
            }
            pts_ptr[k] = &pts[k];
            swpor_nu_to_le(chal->items[k].nu, nus_le + (size_t)k * 16u);
            nus_ptr[k] = nus_le + (size_t)k * 16u;
        }
    }

    /* 输出：s u16 ‖ μ_0..μ_{s-1} ‖ σ */
    swpor_store_be16(proof, s);
    for (uint16_t j = 0; j < s; j++) {
        swpor_fr_to_bytes(proof + 2 + (size_t)SWPOR_FR_BYTES * j, &mu[j]);
    }
    uint8_t *sig_out = proof + 2 + (size_t)SWPOR_FR_BYTES * s;
    if (scheme == SWPOR_SCHEME_PRIV) {
        swpor_fr_to_bytes(sig_out, &sigma_acc);
    } else {
        blst_p1 acc;
        if (l == 1) {
            blst_p1_from_affine(&acc, &pts[0]);
            blst_p1_mult(&acc, &acc, nus_ptr[0], 128);
        } else {
            scratch = malloc(blst_p1s_mult_pippenger_scratch_sizeof(l));
            if (scratch == NULL) {
                rc = SWPOR_E_NOMEM;
                goto cleanup;
            }
            blst_p1s_mult_pippenger(&acc, pts_ptr, l, nus_ptr, 128, scratch);
        }
        blst_p1_compress(sig_out, &acc);
    }
    *proof_len = need;

    {
        char body[128];
        (void)snprintf(body, sizeof(body),
                       "\"l\":%" PRIu32 ",\"s\":%u,\"elapsed_ms\":%.3f,\"proof_bytes\":%zu", l,
                       (unsigned)s, (double)(swpor_time_ns() - t0) / 1e6, need);
        swpor_trace_emit(ctx, SWPOR_EV_PROVE_DONE, body);
    }

cleanup:
    free(scratch);
    free(nus_ptr);
    free(nus_le);
    free(pts_ptr);
    free(pts);
    free(mu);
    free(block);
    return rc;
}
