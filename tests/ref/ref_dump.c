/*
 * 差分测试 T-03 的 C 端：对给定输入运行 C 实现，把中间结果按行输出，
 * 由 tests/ref/run_diff.py 与 Python 参考实现 priv_ref.py 逐字节比较。
 *
 * 用法：ref_dump <k_prf hex> <k_alpha hex> <s> <n> <seed hex> <l> <data 文件>
 *   data 文件长度必须为 n · 31 · s 字节。
 * 输出（每行一个，十六进制小写）：
 *   sigma <i> <σ_i>
 *   chal <i> <ν_i>
 *   mu <j> <μ_j>
 *   proof_sigma <σ>
 *   verify <PASS|FAIL>
 *
 * 仅用于测试：输出包含 σ_i 等值，不得用于真实数据。
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "swpor/priv.h"
#include "swpor/swpor.h"

typedef struct {
    size_t bb;
    uint64_t n;
    uint8_t *blocks;
    uint8_t *sigmas;
} mem_t;

static int reader(void *user, uint64_t i, uint8_t *block, size_t block_len, uint8_t *sigma,
                  size_t sigma_len)
{
    mem_t *m = user;
    if (i >= m->n || block_len != m->bb || sigma_len != 32) {
        return SWPOR_E_RANGE;
    }
    memcpy(block, m->blocks + i * m->bb, m->bb);
    memcpy(sigma, m->sigmas + i * 32, 32);
    return SWPOR_OK;
}

static void print_hex(const char *label, int64_t idx, const uint8_t *b, size_t len)
{
    char hex[2 * 64 + 1];
    swpor_hex_encode(b, len, hex);
    if (idx >= 0) {
        printf("%s %" PRId64 " %s\n", label, idx, hex);
    } else {
        printf("%s %s\n", label, hex);
    }
}

int main(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: ref_dump k_prf k_alpha s n seed l datafile\n");
        return 2;
    }
    swpor_priv_file_keys_t fk;
    memset(&fk, 0, sizeof(fk));
    uint8_t seed[32];
    if (swpor_hex_decode(argv[1], fk.k_prf, 32) != SWPOR_OK ||
        swpor_hex_decode(argv[2], fk.k_alpha, 32) != SWPOR_OK ||
        swpor_hex_decode(argv[5], seed, 32) != SWPOR_OK) {
        fprintf(stderr, "bad hex\n");
        return 2;
    }
    unsigned long s = strtoul(argv[3], NULL, 10);
    unsigned long long n = strtoull(argv[4], NULL, 10);
    unsigned long l = strtoul(argv[6], NULL, 10);
    if (s == 0 || s > 65535 || n == 0 || n > 100000 || l == 0 || l > 100000) {
        fprintf(stderr, "bad params\n");
        return 2;
    }
    mem_t m;
    m.bb = swpor_block_bytes((uint16_t)s);
    m.n = n;
    m.blocks = malloc((size_t)n * m.bb);
    m.sigmas = malloc((size_t)n * 32);
    if (m.blocks == NULL || m.sigmas == NULL) {
        return 3;
    }
    swpor_file_t *f = NULL;
    if (swpor_file_open(argv[7], SWPOR_FILE_READ, &f) != SWPOR_OK ||
        swpor_file_pread(f, m.blocks, (size_t)n * m.bb, 0) != SWPOR_OK) {
        fprintf(stderr, "cannot read data\n");
        return 3;
    }
    swpor_file_close(f);

    swpor_priv_tagger_t *t = NULL;
    if (swpor_priv_tagger_new(&fk, (uint16_t)s, &t) != SWPOR_OK) {
        return 5;
    }
    for (uint64_t i = 0; i < n; i++) {
        if (swpor_priv_tag_block(t, i, m.blocks + i * m.bb, m.sigmas + i * 32) != SWPOR_OK) {
            return 5;
        }
        print_hex("sigma", (int64_t)i, m.sigmas + i * 32, 32);
    }
    swpor_priv_tagger_free(t);

    swpor_chal_t *c = NULL;
    if (swpor_chal_from_seed(seed, n, (uint32_t)l, &c) != SWPOR_OK) {
        return 5;
    }
    for (uint32_t k = 0; k < c->count; k++) {
        print_hex("chal", (int64_t)c->items[k].index, c->items[k].nu, 16);
    }

    swpor_tag_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = SWPOR_FORMAT_VERSION;
    h.scheme = SWPOR_SCHEME_PRIV;
    h.n = n;
    h.s = (uint16_t)s;
    size_t cap = swpor_proof_bytes(SWPOR_SCHEME_PRIV, (uint16_t)s);
    uint8_t *proof = malloc(cap);
    size_t plen = 0;
    if (proof == NULL || swpor_prove(NULL, &h, c, reader, &m, proof, cap, &plen) != SWPOR_OK) {
        return 5;
    }
    for (unsigned long j = 0; j < s; j++) {
        print_hex("mu", (int64_t)j, proof + 2 + 32 * j, 32);
    }
    print_hex("proof_sigma", -1, proof + 2 + 32 * s, 32);
    int pass = 0;
    if (swpor_priv_verify(NULL, &h, &fk, c, proof, plen, &pass) != SWPOR_OK) {
        return 5;
    }
    printf("verify %s\n", pass ? "PASS" : "FAIL");

    free(proof);
    swpor_chal_free(c);
    free(m.blocks);
    free(m.sigmas);
    return 0;
}
