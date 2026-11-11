/*
 * porbench：基准测试工具（SPEC 10.2、10.3）。输出 CSV，每行都记录运行环境
 * （CPU 型号、核数、内存、OS、编译器、构建类型、git commit，SPEC 10.3）。
 *
 *   porbench run    --scheme priv|pub|mac --size <bytes> [--s 128] [--l 128] [--rs k:m | --no-rs]
 *                   [--reps 10] [--audits 10] [--dir <tmp>] [--out <csv>]
 *   porbench sweep  --scheme priv,pub,mac --sizes 1M,16M --s 1,16,64,128,256 --l 64,128,460
 *                   [--reps 10] [--audits 10] [--rs k:m | --no-rs] [--dir <tmp>] [--out <csv>]
 *   porbench detect [--n 10000] [--s 1] [--l 128] [--ratios 0.001,0.005,0.01,0.05,0.1]
 *                   [--trials 1000] [--out <csv>]
 *
 * 计时都在进程内完成（不经过网络），数据写在 --dir 指定的临时目录（默认 bench/tmp）。
 * "mac" 是 Simple-MAC 对比基线（论文第 5 节思路）：σ_i = HMAC-SHA-256(k, file_id ‖ i ‖ m_i)，
 * 证明直接返回被挑战的 l 个块及其 MAC。该基线只在本工具内实现，不进入 libswpor 与协议。
 */

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "cli.h"
#include "platform.h"
#include "swpor/buildinfo.h"
#include "swpor/swpor.h"

#define PROG "porbench"

#ifndef SWPOR_COMPILER_INFO
#define SWPOR_COMPILER_INFO "unknown"
#endif
#ifndef SWPOR_BUILD_TYPE_INFO
#define SWPOR_BUILD_TYPE_INFO "unknown"
#endif

/* ===================================================================== */
/* 环境与 CSV                                                              */
/* ===================================================================== */

typedef struct {
    char date[32];
    char cpu[256];
    unsigned cores;
    uint64_t mem;
} env_t;

static void env_init(env_t *e)
{
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    if (tm == NULL || strftime(e->date, sizeof(e->date), "%Y-%m-%dT%H:%M:%SZ", tm) == 0) {
        (void)snprintf(e->date, sizeof(e->date), "unknown");
    }
    swpor_cpu_model(e->cpu, sizeof(e->cpu));
    for (char *p = e->cpu; *p != '\0'; p++) {
        if (*p == ',' || *p == '"') {
            *p = ' '; /* 保持 CSV 简单 */
        }
    }
    e->cores = swpor_cpu_count();
    e->mem = swpor_mem_total();
}

static const char *k_env_cols = "date,commit,cpu,cores,mem_bytes,os,compiler,build_type";

static void env_print(FILE *f, const env_t *e)
{
    fprintf(f, "%s,%s,%s,%u,%" PRIu64 ",%s,%s,%s", e->date, SWPOR_GIT_COMMIT, e->cpu, e->cores,
            e->mem, swpor_platform_name(), SWPOR_COMPILER_INFO, SWPOR_BUILD_TYPE_INFO);
}

/* 打开 CSV 输出：文件不存在或为空时写表头；path 为 NULL 时写 stdout */
static FILE *csv_open(const char *path, const char *cols)
{
    FILE *f = stdout;
    int need_header = 1;
    if (path != NULL) {
        FILE *probe = fopen(path, "rb");
        if (probe != NULL) {
            need_header = fgetc(probe) == EOF;
            fclose(probe);
        }
        f = fopen(path, "ab");
        if (f == NULL) {
            return NULL;
        }
    }
    if (need_header) {
        fprintf(f, "%s,%s\n", k_env_cols, cols);
    }
    return f;
}

static void csv_close(FILE *f)
{
    if (f != NULL && f != stdout) {
        fclose(f);
    }
}

/* ===================================================================== */
/* 输入：确定长度的随机数据流                                                */
/* ===================================================================== */

typedef struct {
    uint64_t remain;
} rand_input_t;

static int rand_input(void *user, uint8_t *buf, size_t len, size_t *got)
{
    rand_input_t *ri = user;
    size_t take = ri->remain < len ? (size_t)ri->remain : len;
    int rc = swpor_random_bytes(buf, take);
    if (rc == SWPOR_OK) {
        ri->remain -= take;
        *got = take;
    }
    return rc;
}

/* 只做预处理（纠删编码），丢弃输出：用于单独测量预处理时间 */
static int discard_sink(void *user, uint64_t pos, const uint8_t *block)
{
    (void)user;
    (void)pos;
    (void)block;
    return SWPOR_OK;
}

/* ===================================================================== */
/* Simple-MAC 基线                                                         */
/* ===================================================================== */

typedef struct {
    uint8_t key[32];
    uint8_t file_id[32];
    swpor_store_t *st;
    size_t bb;
    uint64_t n;
} mac_file_t;

static int mac_block(const mac_file_t *m, uint64_t i, const uint8_t *block, uint8_t out[32])
{
    uint8_t idx[8];
    for (int k = 0; k < 8; k++) {
        idx[k] = (uint8_t)(i >> (56 - 8 * k));
    }
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    EVP_MAC_CTX *c = mac != NULL ? EVP_MAC_CTX_new(mac) : NULL;
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    size_t outl = 0;
    int ok = c != NULL && EVP_MAC_init(c, m->key, 32, params) == 1 &&
             EVP_MAC_update(c, m->file_id, 32) == 1 && EVP_MAC_update(c, idx, 8) == 1 &&
             EVP_MAC_update(c, block, m->bb) == 1 && EVP_MAC_final(c, out, &outl, 32) == 1;
    EVP_MAC_CTX_free(c);
    EVP_MAC_free(mac);
    return ok ? SWPOR_OK : SWPOR_E_CRYPTO;
}

static int mac_put(void *user, uint64_t pos, const uint8_t *block)
{
    mac_file_t *m = user;
    uint8_t t[32];
    int rc = mac_block(m, pos, block, t);
    if (rc == SWPOR_OK) {
        rc = swpor_store_write_block(m->st, pos, block);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_store_write_sigma(m->st, pos, t);
    }
    return rc;
}

/* ===================================================================== */
/* 单组基准                                                               */
/* ===================================================================== */

typedef struct {
    const char *scheme;   /* "priv" / "pub" / "mac" */
    uint64_t size;
    uint16_t s;
    uint32_t l;
    uint16_t flags;
    uint16_t rs_k, rs_m;
    unsigned reps;
    unsigned audits;
    const char *dir;
} bench_cfg_t;

static const char *k_run_cols =
    "scheme,size_bytes,s,l,rs_k,rs_m,n,rep,preprocess_ms,tag_ms,tag_mb_s,prove_ms,verify_ms,"
    "challenge_bytes,proof_bytes,storage_bytes,storage_overhead,pass";

typedef struct {
    swpor_keys_t keys;
    swpor_priv_key_t *priv;
    swpor_pub_sk_t *psk;
    swpor_pub_pk_t *ppk;
} bench_keys_t;

static int prove_local(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap,
                       size_t *len)
{
    swpor_store_t *st = user;
    return swpor_prove(NULL, swpor_store_header(st), chal, swpor_store_reader, st, proof, cap, len);
}

/* 一次 Simple-MAC 审计：服务端读出 l 个块与 MAC，验证方重算比较 */
static int mac_audit(mac_file_t *m, uint32_t l, uint64_t *prove_ns, uint64_t *verify_ns,
                     size_t *chal_bytes, size_t *proof_bytes, int *pass)
{
    swpor_chal_t *c = NULL;
    int rc = swpor_chal_explicit(m->n, l, &c);
    if (rc != SWPOR_OK) {
        return rc;
    }
    uint8_t *resp = malloc((size_t)c->count * (m->bb + 32u));
    if (resp == NULL) {
        swpor_chal_free(c);
        return SWPOR_E_NOMEM;
    }
    uint64_t t0 = swpor_time_ns();
    for (uint32_t k = 0; rc == SWPOR_OK && k < c->count; k++) {
        uint8_t *p = resp + (size_t)k * (m->bb + 32u);
        rc = swpor_store_read_block(m->st, c->items[k].index, p);
        if (rc == SWPOR_OK) {
            rc = swpor_store_read_sigma(m->st, c->items[k].index, p + m->bb);
        }
    }
    uint64_t t1 = swpor_time_ns();
    int ok = 1;
    for (uint32_t k = 0; rc == SWPOR_OK && k < c->count; k++) {
        uint8_t t[32];
        uint8_t *p = resp + (size_t)k * (m->bb + 32u);
        rc = mac_block(m, c->items[k].index, p, t);
        ok &= rc == SWPOR_OK && CRYPTO_memcmp(t, p + m->bb, 32) == 0;
    }
    uint64_t t2 = swpor_time_ns();
    *prove_ns = t1 - t0;
    *verify_ns = t2 - t1;
    *chal_bytes = 37u + (size_t)c->count * 8u; /* 只需发送下标 */
    *proof_bytes = (size_t)c->count * (m->bb + 32u);
    *pass = ok;
    free(resp);
    swpor_chal_free(c);
    return rc;
}

static int run_one(const bench_cfg_t *cfg, const bench_keys_t *bk, const env_t *env, FILE *csv)
{
    const int is_mac = strcmp(cfg->scheme, "mac") == 0;
    const int is_pub = strcmp(cfg->scheme, "pub") == 0;
    swpor_layout_t lay;
    int rc = swpor_layout_compute(cfg->size, cfg->s, cfg->flags, cfg->rs_k, cfg->rs_m, &lay);
    if (rc != SWPOR_OK) {
        return rc;
    }
    const size_t bb = swpor_block_bytes(cfg->s);
    const size_t sb = is_pub ? 48u : 32u;
    for (unsigned rep = 0; rep < cfg->reps; rep++) {
        /* 1. 预处理（纠删编码）单独计时 */
        rand_input_t ri = {cfg->size};
        uint64_t t0 = swpor_time_ns();
        rc = swpor_encode(NULL, &lay, NULL, NULL, rand_input, &ri, discard_sink, NULL);
        uint64_t pre_ns = swpor_time_ns() - t0;
        if (rc != SWPOR_OK) {
            return rc;
        }
        /* 2. 预处理 + 打标签 + 写盘 */
        ri.remain = cfg->size;
        uint8_t tag[SWPOR_TAG_MAX_BYTES];
        size_t tag_len = 0;
        swpor_tag_header_t h;
        swpor_store_t *st = NULL;
        mac_file_t mf;
        memset(&mf, 0, sizeof(mf));
        uint64_t t1 = swpor_time_ns();
        if (is_mac) {
            mf.bb = bb;
            mf.n = lay.n;
            rc = swpor_random_bytes(mf.key, 32);
            if (rc == SWPOR_OK) {
                rc = swpor_random_bytes(mf.file_id, 32);
            }
            if (rc == SWPOR_OK) {
                rc = swpor_store_create(cfg->dir, mf.file_id, SWPOR_SCHEME_PRIV, lay.n, cfg->s,
                                        &mf.st);
            }
            if (rc == SWPOR_OK) {
                rc = swpor_encode(NULL, &lay, NULL, NULL, rand_input, &ri, mac_put, &mf);
            }
            st = mf.st;
        } else {
            cli_local_sink_t ls = {cfg->dir, NULL};
            swpor_st_params_t p = {cfg->s, cfg->flags, cfg->rs_k, cfg->rs_m};
            rc = swpor_st_run(NULL, &bk->keys, &p, cfg->size, rand_input, &ri, &cli_local_sink, &ls,
                              tag, sizeof(tag), &tag_len, &h);
            if (rc == SWPOR_OK) {
                rc = swpor_store_write_tag(ls.st, tag, tag_len);
            }
            st = ls.st;
        }
        uint64_t tag_total_ns = swpor_time_ns() - t1;
        if (rc != SWPOR_OK) {
            swpor_store_close(st);
            return rc;
        }
        /* 打标签时间 = 总时间 − 预处理时间（写盘时间计入打标签） */
        uint64_t tag_ns = tag_total_ns > pre_ns ? tag_total_ns - pre_ns : 0;

        /* 3. 审计若干次，取平均 */
        uint64_t prove_sum = 0;
        uint64_t verify_sum = 0;
        size_t chal_bytes = 0;
        size_t proof_bytes = 0;
        int all_pass = 1;
        for (unsigned a = 0; rc == SWPOR_OK && a < cfg->audits; a++) {
            int pass = 0;
            if (is_mac) {
                uint64_t pn, vn;
                rc = mac_audit(&mf, cfg->l, &pn, &vn, &chal_bytes, &proof_bytes, &pass);
                prove_sum += pn;
                verify_sum += vn;
            } else {
                swpor_audit_result_t res;
                rc = swpor_audit_run(NULL, &bk->keys, tag, tag_len, cfg->l, is_pub, prove_local, st,
                                     &res);
                prove_sum += res.prove_ns;
                verify_sum += res.verify_ns;
                chal_bytes = res.challenge_bytes;
                proof_bytes = res.proof_bytes;
                pass = res.pass;
            }
            all_pass &= pass;
        }
        swpor_store_close(st);
        (void)swpor_store_delete(cfg->dir, is_mac ? mf.file_id : h.file_id);
        if (rc != SWPOR_OK) {
            return rc;
        }
        const double audits = cfg->audits > 0 ? (double)cfg->audits : 1.0;
        const uint64_t storage = lay.n * (uint64_t)(bb + sb) + (is_mac ? 0u : (uint64_t)tag_len);
        const double mb = (double)cfg->size / (1024.0 * 1024.0);
        env_print(csv, env);
        fprintf(csv,
                ",%s,%" PRIu64 ",%u,%" PRIu32 ",%u,%u,%" PRIu64 ",%u,%.3f,%.3f,%.3f,%.4f,%.4f,%zu,"
                "%zu,%" PRIu64 ",%.6f,%d\n",
                cfg->scheme, cfg->size, (unsigned)cfg->s, cfg->l, (unsigned)cfg->rs_k,
                (unsigned)cfg->rs_m, lay.n, rep, cli_ms(pre_ns), cli_ms(tag_ns),
                tag_ns > 0 ? mb / ((double)tag_ns / 1e9) : 0.0, cli_ms(prove_sum) / audits,
                cli_ms(verify_sum) / audits, chal_bytes, proof_bytes, storage,
                cfg->size > 0 ? (double)storage / (double)cfg->size : 0.0, all_pass);
        fflush(csv);
        fprintf(stderr, "  %s size=%" PRIu64 " s=%u l=%" PRIu32 " rep %u/%u: tag %.1f ms, prove %.3f ms, verify %.3f ms\n",
                cfg->scheme, cfg->size, (unsigned)cfg->s, cfg->l, rep + 1, cfg->reps,
                cli_ms(tag_ns), cli_ms(prove_sum) / audits, cli_ms(verify_sum) / audits);
    }
    return SWPOR_OK;
}

static int bench_keys_init(bench_keys_t *bk)
{
    memset(bk, 0, sizeof(*bk));
    int rc = swpor_priv_keygen(&bk->priv);
    if (rc == SWPOR_OK) {
        rc = swpor_pub_keygen(&bk->psk, &bk->ppk);
    }
    return rc;
}

static void bench_keys_set(bench_keys_t *bk, const char *scheme)
{
    memset(&bk->keys, 0, sizeof(bk->keys));
    if (strcmp(scheme, "pub") == 0) {
        bk->keys.scheme = SWPOR_SCHEME_PUB;
        bk->keys.pub_sk = bk->psk;
        bk->keys.pub_pk = bk->ppk;
    } else {
        bk->keys.scheme = SWPOR_SCHEME_PRIV;
        bk->keys.priv_key = bk->priv;
    }
}

static void bench_keys_free(bench_keys_t *bk)
{
    swpor_priv_key_free(bk->priv);
    swpor_pub_sk_free(bk->psk);
    swpor_pub_pk_free(bk->ppk);
}

/* ===================================================================== */
/* 参数解析                                                               */
/* ===================================================================== */

/* 解析大小：数字后可带 K / M / G（1024 进制） */
static int parse_size(const char *s, uint64_t *out)
{
    char buf[32];
    size_t len = strlen(s);
    if (len == 0 || len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, s, len + 1);
    uint64_t mul = 1;
    char last = buf[len - 1];
    if (last == 'K' || last == 'k') {
        mul = 1024u;
    } else if (last == 'M' || last == 'm') {
        mul = 1024u * 1024u;
    } else if (last == 'G' || last == 'g') {
        mul = 1024u * 1024u * 1024u;
    }
    if (mul != 1) {
        buf[len - 1] = '\0';
    }
    uint64_t v;
    if (cli_parse_u64(buf, 0, UINT64_MAX / mul, &v) != 0) {
        return -1;
    }
    *out = v * mul;
    return 0;
}

/* 逗号分隔列表的第 idx 项，写入 out；不存在返回 -1 */
static int list_item(const char *list, int idx, char *out, size_t cap)
{
    const char *p = list;
    for (int k = 0; k < idx; k++) {
        p = strchr(p, ',');
        if (p == NULL) {
            return -1;
        }
        p++;
    }
    const char *e = strchr(p, ',');
    size_t len = e != NULL ? (size_t)(e - p) : strlen(p);
    if (len == 0 || len >= cap) {
        return -1;
    }
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static int parse_common(const cli_opts_t *o, bench_cfg_t *cfg)
{
    uint64_t v;
    cfg->s = SWPOR_DEFAULT_S;
    cfg->l = SWPOR_DEFAULT_L;
    cfg->flags = SWPOR_FLAG_RS;
    cfg->rs_k = SWPOR_DEFAULT_RS_K;
    cfg->rs_m = SWPOR_DEFAULT_RS_M;
    cfg->reps = 10;
    cfg->audits = 10;
    cfg->dir = cli_get(o, "--dir") != NULL ? cli_get(o, "--dir") : "bench/tmp";
    if (cli_get(o, "--reps") && cli_parse_u64(cli_get(o, "--reps"), 1, 100000, &v) == 0) {
        cfg->reps = (unsigned)v;
    } else if (cli_get(o, "--reps")) {
        return -1;
    }
    if (cli_get(o, "--audits") && cli_parse_u64(cli_get(o, "--audits"), 1, 100000, &v) == 0) {
        cfg->audits = (unsigned)v;
    } else if (cli_get(o, "--audits")) {
        return -1;
    }
    if (cli_has(o, "--no-rs")) {
        cfg->flags = 0;
        cfg->rs_k = cfg->rs_m = 0;
    } else if (cli_get(o, "--rs")) {
        unsigned k, m;
        if (sscanf(cli_get(o, "--rs"), "%u:%u", &k, &m) != 2 || k == 0 || m == 0 || k + m > 256) {
            return -1;
        }
        cfg->rs_k = (uint16_t)k;
        cfg->rs_m = (uint16_t)m;
    }
    return 0;
}

static int cmd_run(int argc, char **argv, int sweep)
{
    static const cli_opt_spec_t spec[] = {
        {"--scheme", 1}, {"--size", 1}, {"--sizes", 1}, {"--s", 1},     {"--l", 1},
        {"--rs", 1},     {"--no-rs", 0}, {"--reps", 1}, {"--audits", 1}, {"--dir", 1},
        {"--out", 1},    {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    bench_cfg_t base;
    memset(&base, 0, sizeof(base));
    if (parse_common(&o, &base) != 0) {
        fprintf(stderr, PROG ": invalid option value\n");
        return CLI_EXIT_USAGE;
    }
    const char *schemes = cli_get(&o, "--scheme") ? cli_get(&o, "--scheme") : "priv";
    const char *sizes = sweep ? cli_get(&o, "--sizes") : cli_get(&o, "--size");
    const char *ss = cli_get(&o, "--s") ? cli_get(&o, "--s") : "128";
    const char *ls = cli_get(&o, "--l") ? cli_get(&o, "--l") : "128";
    if (sizes == NULL) {
        fprintf(stderr, PROG ": %s is required\n", sweep ? "--sizes" : "--size");
        return CLI_EXIT_USAGE;
    }
    if (!sweep && (strchr(schemes, ',') || strchr(sizes, ',') || strchr(ss, ',') || strchr(ls, ','))) {
        fprintf(stderr, PROG " run: lists are only accepted by 'porbench sweep'\n");
        return CLI_EXIT_USAGE;
    }
    int rc = swpor_mkdir_p(base.dir);
    if (rc != SWPOR_OK) {
        return cli_fail(0, PROG, "cannot create --dir", rc);
    }
    env_t env;
    env_init(&env);
    FILE *csv = csv_open(cli_get(&o, "--out"), k_run_cols);
    if (csv == NULL) {
        fprintf(stderr, PROG ": cannot open --out\n");
        return CLI_EXIT_IO;
    }
    bench_keys_t bk;
    rc = bench_keys_init(&bk);
    char item[64];
    for (int a = 0; rc == SWPOR_OK && list_item(schemes, a, item, sizeof(item)) == 0; a++) {
        char scheme[sizeof(item)]; /* 与 item 等长，避免 -Wformat-truncation */
        (void)snprintf(scheme, sizeof(scheme), "%s", item);
        if (strcmp(scheme, "priv") != 0 && strcmp(scheme, "pub") != 0 && strcmp(scheme, "mac") != 0) {
            fprintf(stderr, PROG ": unknown scheme %s\n", scheme);
            rc = SWPOR_E_INVALID_ARG;
            break;
        }
        bench_keys_set(&bk, scheme);
        for (int b = 0; rc == SWPOR_OK && list_item(sizes, b, item, sizeof(item)) == 0; b++) {
            uint64_t size;
            if (parse_size(item, &size) != 0) {
                rc = SWPOR_E_INVALID_ARG;
                break;
            }
            for (int c = 0; rc == SWPOR_OK && list_item(ss, c, item, sizeof(item)) == 0; c++) {
                uint64_t s;
                if (cli_parse_u64(item, 1, 65535, &s) != 0) {
                    rc = SWPOR_E_INVALID_ARG;
                    break;
                }
                for (int d = 0; rc == SWPOR_OK && list_item(ls, d, item, sizeof(item)) == 0; d++) {
                    uint64_t l;
                    if (cli_parse_u64(item, 1, SWPOR_DEFAULT_MAX_L, &l) != 0) {
                        rc = SWPOR_E_INVALID_ARG;
                        break;
                    }
                    bench_cfg_t cfg = base;
                    cfg.scheme = scheme;
                    cfg.size = size;
                    cfg.s = (uint16_t)s;
                    cfg.l = (uint32_t)l;
                    rc = run_one(&cfg, &bk, &env, csv);
                }
            }
        }
    }
    bench_keys_free(&bk);
    csv_close(csv);
    if (rc != SWPOR_OK) {
        return cli_fail(0, PROG, "benchmark failed", rc);
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* T-22：篡改检测率实验                                                     */
/* ===================================================================== */

/* 理论检测率 1 − C(n−d, l) / C(n, l)，用 lgamma 计算避免溢出 */
static double theory_rate(uint64_t n, uint64_t d, uint64_t l)
{
    if (l >= n) {
        return d > 0 ? 1.0 : 0.0;
    }
    if (d == 0) {
        return 0.0;
    }
    if (n - d < l) {
        return 1.0;
    }
    double lg = lgamma((double)(n - d + 1)) - lgamma((double)(n - d - l + 1)) -
                lgamma((double)(n + 1)) + lgamma((double)(n - l + 1));
    return 1.0 - exp(lg);
}

static int cmd_detect(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {{"--n", 1},      {"--s", 1},   {"--l", 1},
                                          {"--ratios", 1}, {"--trials", 1}, {"--out", 1},
                                          {"--dir", 1},    {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    uint64_t n = 10000, s = 1, l = SWPOR_DEFAULT_L, trials = 1000;
    if ((cli_get(&o, "--n") && cli_parse_u64(cli_get(&o, "--n"), 1, 1u << 24, &n) != 0) ||
        (cli_get(&o, "--s") && cli_parse_u64(cli_get(&o, "--s"), 1, 65535, &s) != 0) ||
        (cli_get(&o, "--l") && cli_parse_u64(cli_get(&o, "--l"), 1, SWPOR_DEFAULT_MAX_L, &l) != 0) ||
        (cli_get(&o, "--trials") && cli_parse_u64(cli_get(&o, "--trials"), 1, 10000000, &trials) != 0)) {
        fprintf(stderr, PROG ": invalid option value\n");
        return CLI_EXIT_USAGE;
    }
    const char *ratios = cli_get(&o, "--ratios") ? cli_get(&o, "--ratios") : "0.001,0.005,0.01,0.05,0.1";
    const char *dir = cli_get(&o, "--dir") ? cli_get(&o, "--dir") : "bench/tmp";
    env_t env;
    env_init(&env);
    FILE *csv = csv_open(cli_get(&o, "--out"),
                         "scheme,n,s,l,ratio,corrupted,trials,detected,rate,theory");
    if (csv == NULL) {
        return CLI_EXIT_IO;
    }
    bench_keys_t bk;
    int rc = bench_keys_init(&bk);
    if (rc == SWPOR_OK) {
        rc = swpor_mkdir_p(dir);
    }
    bench_keys_set(&bk, "priv");
    char item[64];
    for (int a = 0; rc == SWPOR_OK && list_item(ratios, a, item, sizeof(item)) == 0; a++) {
        double ratio;
        if (cli_parse_ratio(item, &ratio) != 0) {
            rc = SWPOR_E_INVALID_ARG;
            break;
        }
        /* 每个比例重新生成文件（不启用 RS：块与位置一一对应，便于计数） */
        const uint64_t size = n * swpor_block_bytes((uint16_t)s);
        rand_input_t ri = {size};
        cli_local_sink_t ls = {dir, NULL};
        swpor_st_params_t p = {(uint16_t)s, 0, 0, 0};
        uint8_t tag[SWPOR_TAG_MAX_BYTES];
        size_t tag_len;
        swpor_tag_header_t h;
        rc = swpor_st_run(NULL, &bk.keys, &p, size, rand_input, &ri, &cli_local_sink, &ls, tag,
                          sizeof(tag), &tag_len, &h);
        if (rc == SWPOR_OK) {
            rc = swpor_store_write_tag(ls.st, tag, tag_len);
        }
        /* 随机选 d 个块，各翻转 1 个比特 */
        uint64_t d = (uint64_t)(ratio * (double)n + 0.5);
        swpor_chal_t *sel = NULL;
        if (rc == SWPOR_OK && d > 0) {
            rc = swpor_chal_explicit(n, (uint32_t)d, &sel);
        }
        uint8_t *blk = malloc(swpor_block_bytes((uint16_t)s));
        for (uint32_t k = 0; rc == SWPOR_OK && sel != NULL && k < sel->count; k++) {
            rc = swpor_store_read_block(ls.st, sel->items[k].index, blk);
            if (rc == SWPOR_OK) {
                blk[sel->items[k].nu[0] % swpor_block_bytes((uint16_t)s)] ^= 0x01;
                rc = swpor_store_write_block(ls.st, sel->items[k].index, blk);
            }
        }
        free(blk);
        swpor_chal_free(sel);
        uint64_t detected = 0;
        for (uint64_t t = 0; rc == SWPOR_OK && t < trials; t++) {
            swpor_audit_result_t res;
            rc = swpor_audit_run(NULL, &bk.keys, tag, tag_len, (uint32_t)l, 0, prove_local, ls.st,
                                 &res);
            detected += rc == SWPOR_OK && !res.pass;
        }
        swpor_store_close(ls.st);
        if (rc == SWPOR_OK) {
            (void)swpor_store_delete(dir, h.file_id);
            env_print(csv, &env);
            fprintf(csv, ",priv,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%g,%" PRIu64 ",%" PRIu64
                         ",%" PRIu64 ",%.6f,%.6f\n",
                    n, s, l, ratio, d, trials, detected, (double)detected / (double)trials,
                    theory_rate(n, d, l));
            fflush(csv);
            fprintf(stderr, "  ratio %g: %" PRIu64 "/%" PRIu64 " detected (theory %.4f)\n", ratio,
                    detected, trials, theory_rate(n, d, l));
        }
    }
    bench_keys_free(&bk);
    csv_close(csv);
    if (rc != SWPOR_OK) {
        return cli_fail(0, PROG, "detection experiment failed", rc);
    }
    return CLI_EXIT_OK;
}

static void usage(FILE *f)
{
    fprintf(f,
            "porbench %s - benchmarks for swpor (SPEC 10.2 / 10.3)\n"
            "\n"
            "usage:\n"
            "  porbench run    --scheme priv|pub|mac --size <bytes[K|M|G]> [--s 128] [--l 128]\n"
            "                  [--rs k:m | --no-rs] [--reps 10] [--audits 10] [--dir bench/tmp]\n"
            "                  [--out <csv>]\n"
            "  porbench sweep  --scheme priv,pub,mac --sizes 1M,16M --s 1,16,64,128,256\n"
            "                  --l 64,128,460 [same options as run]\n"
            "  porbench detect [--n 10000] [--s 1] [--l 128] [--ratios 0.001,0.005,0.01,0.05,0.1]\n"
            "                  [--trials 1000] [--out <csv>]\n"
            "\n"
            "Use a Release build for numbers you report (cmake --preset release).\n",
            swpor_version());
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(stderr);
        return CLI_EXIT_USAGE;
    }
    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0) {
        printf("porbench %s (%s, commit %s, %s %s)\n", swpor_version(), swpor_platform_name(),
               SWPOR_GIT_COMMIT, SWPOR_COMPILER_INFO, SWPOR_BUILD_TYPE_INFO);
        return CLI_EXIT_OK;
    }
    if (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return CLI_EXIT_OK;
    }
    if (strcmp(argv[1], "run") == 0) {
        return cmd_run(argc, argv, 0);
    }
    if (strcmp(argv[1], "sweep") == 0) {
        return cmd_run(argc, argv, 1);
    }
    if (strcmp(argv[1], "detect") == 0) {
        return cmd_detect(argc, argv);
    }
    usage(stderr);
    return CLI_EXIT_USAGE;
}
