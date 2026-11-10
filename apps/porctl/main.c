/*
 * porctl：数据所有者客户端（SPEC 9.2）。
 *
 *   porctl keygen   --scheme priv|pub --out <dir> [--force]
 *   porctl store    --key <keyfile> --in <file> [--s 128] [--rs 64:64] [--no-rs] [--perm] [--encrypt]
 *                   [--tag-out <path>] (--local <dir> | --server <host:port>)
 *   porctl audit    --key <keyfile> --tag <tagfile> [--l 128] [--seed-mode]
 *                   (--local <dir> | --server <host:port>)
 *   porctl retrieve --key <keyfile> --tag <tagfile> --out <file> (--local <dir> | --server <host:port>)
 *   porctl info     --tag <tagfile>
 *   porctl tamper   --local <dir> --file-id <hex> --mode flip|zero|delete --ratio <0..1> [--seed N]
 *   porctl delete   --tag <tagfile> (--local <dir> | --server <host:port>)
 *   porctl doctor | version | help
 *
 * 所有子命令支持 --json；store / audit / retrieve / tamper 支持 --trace <file|->（SPEC 9.4）。
 * 退出码：0 成功/PASS，1 审计 FAIL，2 参数错误，3 I/O 错误，4 网络错误，5 密码学/格式错误。
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli.h"
#include "platform.h"
#include "swpor/net.h"
#include "swpor/swpor.h"

#define PROG "porctl"
#define PATH_CAP 4096

/* 公共选项 */
#define OPT_COMMON {"--json", 0}, {"--trace", 1}
#define OPT_BACKEND {"--local", 1}, {"--server", 1}, {"--timeout", 1}

static void print_usage(FILE *out)
{
    fprintf(out,
            "porctl %s - proof-of-retrievability client (Shacham-Waters)\n"
            "\n"
            "usage:\n"
            "  porctl keygen   --scheme priv|pub --out <dir> [--force]\n"
            "  porctl store    --key <keyfile> --in <file> [--s 128] [--rs 64:64] [--no-rs]\n"
            "                  [--perm] [--encrypt] [--tag-out <path>]\n"
            "                  (--local <dir> | --server <host:port>)\n"
            "  porctl audit    --key <keyfile> --tag <tagfile> [--l 128] [--seed-mode]\n"
            "                  (--local <dir> | --server <host:port>)\n"
            "  porctl retrieve --key <keyfile> --tag <tagfile> --out <file>\n"
            "                  (--local <dir> | --server <host:port>)\n"
            "  porctl info     --tag <tagfile>\n"
            "  porctl tamper   --local <dir> --file-id <hex> --mode flip|zero|delete\n"
            "                  --ratio <0..1> [--seed N]      (testing only)\n"
            "  porctl delete   --tag <tagfile> (--local <dir> | --server <host:port>)\n"
            "  porctl doctor | version | help\n"
            "\n"
            "common options: --json (machine-readable output), --trace <file|-> (NDJSON events;\n"
            "  '-' writes to stderr), --timeout <ms> (network I/O timeout, default 30000)\n"
            "\n"
            "exit codes: 0 ok/PASS, 1 audit FAIL, 2 usage, 3 I/O, 4 network, 5 crypto/format\n",
            swpor_version());
}

/* ===================================================================== */
/* 通用：后端（本地目录 / 远程服务端）                                       */
/* ===================================================================== */

typedef struct {
    const char *local;     /* --local 目录 */
    swpor_client_t *client;
    swpor_remote_t *remote;
} backend_t;

static int backend_open(const cli_opts_t *o, backend_t *b)
{
    memset(b, 0, sizeof(*b));
    const char *local = cli_get(o, "--local");
    const char *server = cli_get(o, "--server");
    if ((local == NULL) == (server == NULL)) {
        fprintf(stderr, PROG ": exactly one of --local or --server is required\n");
        return SWPOR_E_INVALID_ARG;
    }
    if (local != NULL) {
        b->local = local;
        return SWPOR_OK;
    }
    uint64_t timeout = SWPOR_DEFAULT_IO_TIMEOUT_MS;
    const char *ts = cli_get(o, "--timeout");
    if (ts != NULL && cli_parse_u64(ts, 1, 3600000, &timeout) != 0) {
        fprintf(stderr, PROG ": invalid --timeout\n");
        return SWPOR_E_INVALID_ARG;
    }
    char host[256];
    uint16_t port = 0;
    int rc = swpor_parse_hostport(server, host, sizeof(host), &port);
    if (rc != SWPOR_OK) {
        fprintf(stderr, PROG ": invalid --server address\n");
        return rc;
    }
    rc = swpor_client_connect(host, port, (uint32_t)timeout, &b->client);
    if (rc == SWPOR_OK) {
        rc = swpor_remote_new(b->client, &b->remote);
    }
    return rc;
}

static void backend_close(backend_t *b)
{
    swpor_remote_free(b->remote);
    swpor_client_close(b->client);
    memset(b, 0, sizeof(*b));
}

/* 打印网络错误的服务端说明 */
static void backend_note(const backend_t *b)
{
    if (b->client != NULL && swpor_client_last_error(b->client)[0] != '\0') {
        fprintf(stderr, PROG ": server says: %s\n", swpor_client_last_error(b->client));
    }
}

static int read_tag_file(const char *path, uint8_t *tag, size_t *tag_len)
{
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = swpor_read_file(path, SWPOR_TAG_MAX_BYTES, &buf, &len);
    if (rc == SWPOR_E_RANGE) {
        rc = SWPOR_E_PARSE;
    }
    if (rc == SWPOR_OK) {
        memcpy(tag, buf, len);
        *tag_len = len;
    }
    free(buf);
    return rc;
}

typedef struct {
    swpor_ctx_t *ctx;
    FILE *trace;
} session_t;

static int session_open(const cli_opts_t *o, session_t *s)
{
    memset(s, 0, sizeof(*s));
    int rc = swpor_ctx_new(&s->ctx);
    if (rc != SWPOR_OK) {
        return rc;
    }
    const char *tp = cli_get(o, "--trace");
    if (tp != NULL) {
        s->trace = cli_trace_open(tp);
        if (s->trace == NULL) {
            fprintf(stderr, PROG ": cannot open trace output %s\n", tp);
            return SWPOR_E_IO;
        }
        swpor_set_trace(s->ctx, cli_trace_cb, s->trace);
    }
    return SWPOR_OK;
}

static void session_close(session_t *s)
{
    swpor_ctx_free(s->ctx);
    if (s->trace != NULL) {
        cli_trace_close(s->trace);
    }
}

static const char *scheme_name(uint8_t scheme)
{
    return scheme == SWPOR_SCHEME_PRIV ? "priv" : scheme == SWPOR_SCHEME_PUB ? "pub" : "unknown";
}

/* ===================================================================== */
/* keygen                                                                 */
/* ===================================================================== */

static int cmd_keygen(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {
        {"--scheme", 1}, {"--out", 1}, {"--force", 0}, {"--json", 0}, {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *scheme = cli_get(&o, "--scheme");
    const char *dir = cli_get(&o, "--out");
    const int force = cli_has(&o, "--force");
    if (scheme == NULL || dir == NULL ||
        (strcmp(scheme, "priv") != 0 && strcmp(scheme, "pub") != 0)) {
        fprintf(stderr, PROG " keygen: --scheme priv|pub and --out <dir> are required\n");
        return CLI_EXIT_USAGE;
    }
    int rc = swpor_mkdir_p(dir);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG, "cannot create output directory", rc);
    }
    char p1[PATH_CAP];
    char p2[PATH_CAP] = "";
    if (strcmp(scheme, "priv") == 0) {
        swpor_priv_key_t *k = NULL;
        rc = swpor_path_join(p1, sizeof(p1), dir, "priv.key");
        if (rc == SWPOR_OK) {
            rc = swpor_priv_keygen(&k);
        }
        if (rc == SWPOR_OK) {
            rc = swpor_keyfile_save_priv(p1, k, force);
        }
        swpor_priv_key_free(k);
    } else {
        swpor_pub_sk_t *sk = NULL;
        swpor_pub_pk_t *pk = NULL;
        rc = swpor_path_join(p1, sizeof(p1), dir, "pub.sk");
        if (rc == SWPOR_OK) {
            rc = swpor_path_join(p2, sizeof(p2), dir, "pub.pk");
        }
        if (rc == SWPOR_OK) {
            rc = swpor_pub_keygen(&sk, &pk);
        }
        if (rc == SWPOR_OK && !force && (swpor_path_exists(p1) || swpor_path_exists(p2))) {
            rc = SWPOR_E_EXISTS;
        }
        if (rc == SWPOR_OK) {
            rc = swpor_keyfile_save_pub_sk(p1, sk, force);
        }
        if (rc == SWPOR_OK) {
            rc = swpor_keyfile_save_pub_pk(p2, pk, force);
        }
        swpor_pub_sk_free(sk);
        swpor_pub_pk_free(pk);
    }
    if (rc != SWPOR_OK) {
        if (rc == SWPOR_E_EXISTS && !json) {
            fprintf(stderr, PROG " keygen: key file exists (use --force to overwrite)\n");
            return cli_exit_code(rc);
        }
        return cli_fail(json, PROG " keygen", "key generation failed", rc);
    }
    if (json) {
        printf("{\"scheme\":\"%s\",\"files\":[", scheme);
        cli_json_str(stdout, p1);
        if (p2[0] != '\0') {
            printf(",");
            cli_json_str(stdout, p2);
        }
        printf("]}\n");
    } else {
        printf("generated %s key: %s\n", scheme, p1);
        if (p2[0] != '\0') {
            printf("public key:       %s\n", p2);
        }
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* store                                                                  */
/* ===================================================================== */

static int parse_rs(const char *s, uint16_t *k, uint16_t *m)
{
    const char *colon = strchr(s, ':');
    if (colon == NULL || colon - s > 10) {
        return -1;
    }
    char kb[16];
    memcpy(kb, s, (size_t)(colon - s));
    kb[colon - s] = '\0';
    uint64_t kv;
    uint64_t mv;
    if (cli_parse_u64(kb, 1, 255, &kv) != 0 || cli_parse_u64(colon + 1, 1, 255, &mv) != 0 ||
        kv + mv > 256) {
        return -1;
    }
    *k = (uint16_t)kv;
    *m = (uint16_t)mv;
    return 0;
}

static int cmd_store(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {
        {"--key", 1},  {"--in", 1},      {"--s", 1},       {"--rs", 1},      {"--no-rs", 0},
        {"--perm", 0}, {"--encrypt", 0}, {"--tag-out", 1}, OPT_BACKEND,      OPT_COMMON,
        {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *keyp = cli_get(&o, "--key");
    const char *inp = cli_get(&o, "--in");
    if (keyp == NULL || inp == NULL) {
        fprintf(stderr, PROG " store: --key and --in are required\n");
        return CLI_EXIT_USAGE;
    }
    swpor_st_params_t p = {SWPOR_DEFAULT_S, SWPOR_FLAG_RS, SWPOR_DEFAULT_RS_K, SWPOR_DEFAULT_RS_M};
    uint64_t v;
    if (cli_get(&o, "--s") != NULL) {
        if (cli_parse_u64(cli_get(&o, "--s"), 1, 65535, &v) != 0) {
            fprintf(stderr, PROG " store: --s must be in [1, 65535]\n");
            return CLI_EXIT_USAGE;
        }
        p.s = (uint16_t)v;
    }
    if (cli_has(&o, "--no-rs") && cli_has(&o, "--rs")) {
        fprintf(stderr, PROG " store: --rs and --no-rs are mutually exclusive\n");
        return CLI_EXIT_USAGE;
    }
    if (cli_get(&o, "--rs") != NULL && parse_rs(cli_get(&o, "--rs"), &p.rs_k, &p.rs_m) != 0) {
        fprintf(stderr, PROG " store: --rs must be k:m with k, m >= 1 and k + m <= 256\n");
        return CLI_EXIT_USAGE;
    }
    if (cli_has(&o, "--no-rs")) {
        p.flags = 0;
        p.rs_k = p.rs_m = 0;
    }
    if (cli_has(&o, "--perm")) {
        p.flags |= SWPOR_FLAG_PERM;
    }
    if (cli_has(&o, "--encrypt")) {
        p.flags |= SWPOR_FLAG_ENCRYPT;
    }

    cli_keys_t keys;
    int rc = cli_keys_load(keyp, &keys);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " store", "cannot load key", rc);
    }
    if ((keys.keys.scheme == SWPOR_SCHEME_PRIV && keys.priv == NULL) ||
        (keys.keys.scheme == SWPOR_SCHEME_PUB && keys.psk == NULL)) {
        cli_keys_free(&keys);
        fprintf(stderr, PROG " store: a secret key (priv.key or pub.sk) is required\n");
        return CLI_EXIT_USAGE;
    }
    if (keys.keys.scheme == SWPOR_SCHEME_PUB && (p.flags & (SWPOR_FLAG_PERM | SWPOR_FLAG_ENCRYPT))) {
        cli_keys_free(&keys);
        fprintf(stderr, PROG " store: --perm/--encrypt are only supported with the priv scheme\n");
        return CLI_EXIT_USAGE;
    }

    session_t ss;
    backend_t b;
    cli_infile_t in;
    memset(&in, 0, sizeof(in));
    memset(&b, 0, sizeof(b));
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    swpor_tag_header_t h;
    char tag_path[PATH_CAP];
    const char *what = "store failed";
    rc = session_open(&o, &ss);
    if (rc == SWPOR_OK) {
        rc = cli_infile_open(inp, &in);
        if (rc != SWPOR_OK) {
            what = "cannot open input file";
        }
    }
    if (rc == SWPOR_OK) {
        rc = backend_open(&o, &b);
        if (rc != SWPOR_OK) {
            what = "cannot connect to server";
        }
    }
    uint64_t t0 = swpor_time_ns();
    if (rc == SWPOR_OK) {
        if (b.local != NULL) {
            cli_local_sink_t ls = {b.local, NULL};
            rc = swpor_st_run(ss.ctx, &keys.keys, &p, in.size, cli_infile_read, &in,
                              &cli_local_sink, &ls, tag, sizeof(tag), &tag_len, &h);
            if (rc == SWPOR_OK) {
                rc = swpor_store_write_tag(ls.st, tag, tag_len);
            }
            swpor_store_close(ls.st);
        } else {
            rc = swpor_st_run(ss.ctx, &keys.keys, &p, in.size, cli_infile_read, &in,
                              swpor_remote_sink(), b.remote, tag, sizeof(tag), &tag_len, &h);
            if (rc != SWPOR_OK) {
                backend_note(&b);
            }
        }
    }
    uint64_t elapsed = swpor_time_ns() - t0;
    char hex[65] = "";
    if (rc == SWPOR_OK) {
        swpor_hex_encode(h.file_id, 32, hex);
        const char *tp = cli_get(&o, "--tag-out");
        if (tp == NULL) {
            (void)snprintf(tag_path, sizeof(tag_path), "%s.tag", hex);
            tp = tag_path;
        } else {
            (void)snprintf(tag_path, sizeof(tag_path), "%s", tp);
        }
        rc = swpor_write_file(tag_path, tag, tag_len);
        if (rc != SWPOR_OK) {
            what = "cannot write tag file";
        }
    }
    cli_infile_close(&in);
    backend_close(&b);
    session_close(&ss);
    cli_keys_free(&keys);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " store", what, rc);
    }
    double mb = (double)h.length / (1024.0 * 1024.0);
    if (json) {
        printf("{\"file_id\":\"%s\",\"tag\":", hex);
        cli_json_str(stdout, tag_path);
        printf(",\"scheme\":\"%s\",\"mode\":\"%s\",\"n\":%" PRIu64 ",\"s\":%u,\"L\":%" PRIu64
               ",\"flags\":%u,\"rs_k\":%u,\"rs_m\":%u,\"elapsed_ms\":%.3f}\n",
               scheme_name(h.scheme), cli_get(&o, "--local") ? "local" : "remote", h.n,
               (unsigned)h.s, h.length, (unsigned)h.flags, (unsigned)h.rs_k, (unsigned)h.rs_m,
               cli_ms(elapsed));
    } else {
        printf("file_id: %s\n", hex);
        printf("tag:     %s\n", tag_path);
        printf("blocks:  %" PRIu64 " (s = %u, %.2f MiB in %.1f ms)\n", h.n, (unsigned)h.s, mb,
               cli_ms(elapsed));
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* audit                                                                  */
/* ===================================================================== */

static int cmd_audit(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {{"--key", 1},       {"--tag", 1}, {"--l", 1},
                                          {"--seed-mode", 0}, OPT_BACKEND,  OPT_COMMON,
                                          {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *keyp = cli_get(&o, "--key");
    const char *tagp = cli_get(&o, "--tag");
    if (keyp == NULL || tagp == NULL) {
        fprintf(stderr, PROG " audit: --key and --tag are required\n");
        return CLI_EXIT_USAGE;
    }
    uint64_t l = SWPOR_DEFAULT_L;
    if (cli_get(&o, "--l") != NULL && cli_parse_u64(cli_get(&o, "--l"), 1, UINT32_MAX, &l) != 0) {
        fprintf(stderr, PROG " audit: invalid --l\n");
        return CLI_EXIT_USAGE;
    }
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    int rc = read_tag_file(tagp, tag, &tag_len);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " audit", "cannot read tag file", rc);
    }
    swpor_tag_header_t h;
    rc = swpor_tag_header_decode(tag, tag_len, &h);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " audit", "invalid tag file", rc);
    }
    cli_keys_t keys;
    rc = cli_keys_load(keyp, &keys);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " audit", "cannot load key", rc);
    }
    session_t ss;
    backend_t b;
    swpor_store_t *st = NULL;
    swpor_audit_result_t res;
    memset(&res, 0, sizeof(res));
    memset(&b, 0, sizeof(b));
    const char *what = "audit failed";
    rc = session_open(&o, &ss);
    if (rc == SWPOR_OK) {
        rc = backend_open(&o, &b);
        if (rc != SWPOR_OK) {
            what = "cannot connect to server";
        }
    }
    if (rc == SWPOR_OK) {
        if (b.local != NULL) {
            rc = swpor_store_open(b.local, h.file_id, 0, &st);
            if (rc != SWPOR_OK) {
                what = "cannot open local store";
            } else {
                rc = swpor_audit_run(ss.ctx, &keys.keys, tag, tag_len, (uint32_t)l,
                                     cli_has(&o, "--seed-mode"), cli_local_prove, st, &res);
            }
        } else {
            swpor_remote_set_file_id(b.remote, h.file_id);
            rc = swpor_audit_run(ss.ctx, &keys.keys, tag, tag_len, (uint32_t)l,
                                 cli_has(&o, "--seed-mode"), swpor_remote_prove, b.remote, &res);
            if (rc != SWPOR_OK) {
                backend_note(&b);
            }
        }
    }
    swpor_store_close(st);
    backend_close(&b);
    session_close(&ss);
    cli_keys_free(&keys);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " audit", what, rc);
    }
    const char *result = res.pass ? "PASS" : "FAIL";
    if (json) {
        printf("{\"result\":\"%s\",\"scheme\":\"%s\",\"mode\":\"%s\",\"l\":%" PRIu32
               ",\"challenge\":\"%s\",\"elapsed_ms\":%.3f,\"prove_ms\":%.3f,\"verify_ms\":%.3f,"
               "\"challenge_bytes\":%zu,\"proof_bytes\":%zu}\n",
               result, scheme_name(h.scheme), cli_get(&o, "--local") ? "local" : "remote", res.l,
               cli_has(&o, "--seed-mode") ? "seed" : "explicit", cli_ms(res.total_ns),
               cli_ms(res.prove_ns), cli_ms(res.verify_ns), res.challenge_bytes, res.proof_bytes);
    } else {
        printf("%s  (l = %" PRIu32 ", %.2f ms total, prove %.2f ms, verify %.2f ms, "
               "challenge %zu B, proof %zu B)\n",
               result, res.l, cli_ms(res.total_ns), cli_ms(res.prove_ns), cli_ms(res.verify_ns),
               res.challenge_bytes, res.proof_bytes);
    }
    return res.pass ? CLI_EXIT_OK : CLI_EXIT_AUDIT_FAIL;
}

/* ===================================================================== */
/* retrieve                                                               */
/* ===================================================================== */

/* 远程检索时下载到的临时目录：<out>.swpor-dl */
static int rm_tree(const char *root, const uint8_t file_id[32])
{
    int rc = swpor_store_delete(root, file_id);
    (void)swpor_remove_dir(root);
    return rc;
}

static int cmd_retrieve(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {
        {"--key", 1}, {"--tag", 1}, {"--out", 1}, OPT_BACKEND, OPT_COMMON, {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *keyp = cli_get(&o, "--key");
    const char *tagp = cli_get(&o, "--tag");
    const char *outp = cli_get(&o, "--out");
    if (keyp == NULL || tagp == NULL || outp == NULL) {
        fprintf(stderr, PROG " retrieve: --key, --tag and --out are required\n");
        return CLI_EXIT_USAGE;
    }
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    int rc = read_tag_file(tagp, tag, &tag_len);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " retrieve", "cannot read tag file", rc);
    }
    swpor_tag_header_t h;
    rc = swpor_tag_header_decode(tag, tag_len, &h);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " retrieve", "invalid tag file", rc);
    }
    cli_keys_t keys;
    rc = cli_keys_load(keyp, &keys);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " retrieve", "cannot load key", rc);
    }
    char part[PATH_CAP];
    char dl[PATH_CAP];
    (void)snprintf(part, sizeof(part), "%s.part", outp);
    (void)snprintf(dl, sizeof(dl), "%s.swpor-dl", outp);
    session_t ss;
    backend_t b;
    swpor_store_t *st = NULL;
    cli_outfile_t out;
    memset(&out, 0, sizeof(out));
    memset(&b, 0, sizeof(b));
    const char *root = NULL;
    int downloaded = 0;
    uint64_t erased = 0;
    const char *what = "retrieve failed";
    uint64_t t0 = swpor_time_ns();
    rc = session_open(&o, &ss);
    if (rc == SWPOR_OK) {
        rc = backend_open(&o, &b);
        if (rc != SWPOR_OK) {
            what = "cannot connect to server";
        }
    }
    if (rc == SWPOR_OK) {
        if (b.local != NULL) {
            root = b.local;
        } else {
            /* 远程：先把全部块与 σ 下载到临时目录，再按本地模式解码 */
            root = dl;
            rc = swpor_remote_download(b.client, h.file_id, dl);
            downloaded = 1;
            if (rc != SWPOR_OK) {
                backend_note(&b);
                what = "download failed";
            }
        }
    }
    if (rc == SWPOR_OK) {
        rc = swpor_store_open(root, h.file_id, 0, &st);
        if (rc != SWPOR_OK) {
            what = "cannot open store";
        }
    }
    if (rc == SWPOR_OK) {
        rc = cli_outfile_open(part, &out);
        if (rc != SWPOR_OK) {
            what = "cannot create output file";
        }
    }
    if (rc == SWPOR_OK) {
        rc = swpor_retrieve_run(ss.ctx, &keys.keys, tag, tag_len, swpor_store_reader, st,
                                cli_outfile_write, &out, &erased);
        if (rc == SWPOR_E_DECODE) {
            what = "file is not recoverable (too many corrupted blocks)";
        }
    }
    int crc = cli_outfile_close(&out);
    if (rc == SWPOR_OK) {
        rc = crc;
    }
    swpor_store_close(st);
    if (downloaded) {
        (void)rm_tree(dl, h.file_id);
    }
    /* 只有完整恢复成功才把 .part 改名为目标文件，失败时不留下错误数据（T-12） */
    if (rc == SWPOR_OK) {
        rc = swpor_rename(part, outp);
    } else {
        (void)swpor_remove_file(part);
    }
    uint64_t elapsed = swpor_time_ns() - t0;
    backend_close(&b);
    session_close(&ss);
    cli_keys_free(&keys);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " retrieve", what, rc);
    }
    if (json) {
        printf("{\"result\":\"OK\",\"out\":");
        cli_json_str(stdout, outp);
        printf(",\"bytes\":%" PRIu64 ",\"erased_blocks\":%" PRIu64 ",\"elapsed_ms\":%.3f}\n",
               h.length, erased, cli_ms(elapsed));
    } else {
        printf("recovered %" PRIu64 " bytes to %s (%" PRIu64 " corrupted blocks repaired, %.1f ms)\n",
               h.length, outp, erased, cli_ms(elapsed));
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* info                                                                   */
/* ===================================================================== */

static int cmd_info(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {{"--tag", 1}, {"--json", 0}, {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *tagp = cli_get(&o, "--tag");
    if (tagp == NULL) {
        fprintf(stderr, PROG " info: --tag is required\n");
        return CLI_EXIT_USAGE;
    }
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    int rc = read_tag_file(tagp, tag, &tag_len);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " info", "cannot read tag file", rc);
    }
    swpor_tag_header_t h;
    rc = swpor_tag_header_decode(tag, tag_len, &h);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " info", "invalid tag file", rc);
    }
    char hex[65];
    swpor_hex_encode(h.file_id, 32, hex);
    if (json) {
        printf("{\"file_id\":\"%s\",\"version\":%u,\"scheme\":\"%s\",\"flags\":{\"rs\":%s,"
               "\"perm\":%s,\"encrypt\":%s},\"n\":%" PRIu64 ",\"s\":%u,\"block_bytes\":%zu,"
               "\"rs_k\":%u,\"rs_m\":%u,\"L\":%" PRIu64 ",\"ctime\":%" PRIu64
               ",\"tag_bytes\":%zu}\n",
               hex, (unsigned)h.version, scheme_name(h.scheme),
               (h.flags & SWPOR_FLAG_RS) ? "true" : "false",
               (h.flags & SWPOR_FLAG_PERM) ? "true" : "false",
               (h.flags & SWPOR_FLAG_ENCRYPT) ? "true" : "false", h.n, (unsigned)h.s,
               swpor_block_bytes(h.s), (unsigned)h.rs_k, (unsigned)h.rs_m, h.length, h.ctime,
               tag_len);
    } else {
        printf("file_id:     %s\n", hex);
        printf("scheme:      %s (format v%u)\n", scheme_name(h.scheme), (unsigned)h.version);
        printf("length L:    %" PRIu64 " bytes\n", h.length);
        printf("blocks n:    %" PRIu64 "  (s = %u sectors, %zu bytes/block)\n", h.n,
               (unsigned)h.s, swpor_block_bytes(h.s));
        if (h.flags & SWPOR_FLAG_RS) {
            printf("erasure:     RS(k = %u, m = %u)\n", (unsigned)h.rs_k, (unsigned)h.rs_m);
        } else {
            printf("erasure:     none\n");
        }
        printf("permutation: %s\n", (h.flags & SWPOR_FLAG_PERM) ? "yes" : "no");
        printf("encryption:  %s\n", (h.flags & SWPOR_FLAG_ENCRYPT) ? "yes" : "no");
        printf("created:     %" PRIu64 " (unix time)\n", h.ctime);
        printf("tag size:    %zu bytes\n", tag_len);
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* tamper（仅测试与演示）                                                   */
/* ===================================================================== */

static int cmd_tamper(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {{"--local", 1}, {"--file-id", 1}, {"--mode", 1},
                                          {"--ratio", 1}, {"--seed", 1},    OPT_COMMON,
                                          {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *dir = cli_get(&o, "--local");
    const char *fidhex = cli_get(&o, "--file-id");
    const char *mode = cli_get(&o, "--mode");
    double ratio = 0;
    uint8_t fid[32];
    if (dir == NULL || fidhex == NULL || mode == NULL || cli_get(&o, "--ratio") == NULL) {
        fprintf(stderr, PROG " tamper: --local, --file-id, --mode and --ratio are required\n");
        return CLI_EXIT_USAGE;
    }
    if (swpor_hex_decode(fidhex, fid, 32) != SWPOR_OK) {
        fprintf(stderr, PROG " tamper: --file-id must be 64 hex characters\n");
        return CLI_EXIT_USAGE;
    }
    if (cli_parse_ratio(cli_get(&o, "--ratio"), &ratio) != 0) {
        fprintf(stderr, PROG " tamper: --ratio must be in [0, 1]\n");
        return CLI_EXIT_USAGE;
    }
    int m;
    if (strcmp(mode, "flip") == 0) {
        m = 0;
    } else if (strcmp(mode, "zero") == 0) {
        m = 1;
    } else if (strcmp(mode, "delete") == 0) {
        m = 2;
    } else {
        fprintf(stderr, PROG " tamper: --mode must be flip, zero or delete\n");
        return CLI_EXIT_USAGE;
    }
    uint64_t seed = 0;
    const int seeded = cli_get(&o, "--seed") != NULL;
    if (seeded && cli_parse_u64(cli_get(&o, "--seed"), 0, UINT64_MAX, &seed) != 0) {
        fprintf(stderr, PROG " tamper: invalid --seed\n");
        return CLI_EXIT_USAGE;
    }

    session_t ss;
    swpor_store_t *st = NULL;
    swpor_chal_t *sel = NULL;
    uint8_t *block = NULL;
    int rc = session_open(&o, &ss);
    if (rc == SWPOR_OK) {
        rc = swpor_store_open(dir, fid, 1, &st);
    }
    if (rc != SWPOR_OK) {
        session_close(&ss);
        return cli_fail(json, PROG " tamper", "cannot open local store", rc);
    }
    const uint64_t n = swpor_store_n(st);
    const size_t bb = swpor_store_block_bytes(st);
    /* d = round(ratio · n) 个互不相同的块 */
    uint64_t d = (uint64_t)(ratio * (double)n + 0.5);
    if (d > n) {
        d = n;
    }
    if (d > UINT32_MAX) {
        d = UINT32_MAX;
    }
    if (d > 0) {
        /* 复用挑战抽样过程选块：--seed 时用确定性种子（可复现实验），否则用安全随机数 */
        if (seeded) {
            uint8_t s32[32] = {0};
            for (int k = 0; k < 8; k++) {
                s32[k] = (uint8_t)(seed >> (56 - 8 * k));
            }
            rc = swpor_chal_from_seed(s32, n, (uint32_t)d, &sel);
        } else {
            rc = swpor_chal_explicit(n, (uint32_t)d, &sel);
        }
    }
    block = malloc(bb);
    if (block == NULL) {
        rc = SWPOR_E_NOMEM;
    }
    for (uint32_t k = 0; rc == SWPOR_OK && sel != NULL && k < sel->count; k++) {
        uint64_t i = sel->items[k].index;
        if (m == 0) {
            rc = swpor_store_read_block(st, i, block);
            if (rc == SWPOR_OK) {
                /* 用 ν 的字节决定翻转哪一位（ν 本身是均匀随机的） */
                uint64_t bit = (((uint64_t)sel->items[k].nu[0] << 24) |
                                ((uint64_t)sel->items[k].nu[1] << 16) |
                                ((uint64_t)sel->items[k].nu[2] << 8) | sel->items[k].nu[3]) %
                               ((uint64_t)bb * 8u);
                block[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
            }
        } else {
            memset(block, 0, bb);
        }
        if (rc == SWPOR_OK) {
            rc = swpor_store_write_block(st, i, block);
        }
    }
    if (rc == SWPOR_OK) {
        rc = swpor_store_sync(st);
    }
    if (rc == SWPOR_OK && sel != NULL) {
        char body[900];
        int off = snprintf(body, sizeof(body), "\"mode\":\"%s\",\"count\":%" PRIu32 ",\"indices\":[",
                           mode, sel->count);
        for (uint32_t k = 0; k < sel->count && k < 64 && off > 0 && (size_t)off < sizeof(body) - 32;
             k++) {
            off += snprintf(body + off, sizeof(body) - (size_t)off, "%s%" PRIu64, k ? "," : "",
                            sel->items[k].index);
        }
        if (off > 0 && (size_t)off < sizeof(body) - 2) {
            body[off++] = ']';
            body[off] = '\0';
            if (ss.trace != NULL) {
                swpor_event_t ev;
                char line[1000];
                (void)snprintf(line, sizeof(line), "{\"type\":\"tamper\",%s}", body);
                ev.type = SWPOR_EV_TAMPER;
                ev.name = "tamper";
                ev.json = line;
                cli_trace_cb(&ev, ss.trace);
            }
        }
    }
    uint32_t count = sel != NULL ? sel->count : 0;
    free(block);
    swpor_chal_free(sel);
    swpor_store_close(st);
    session_close(&ss);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " tamper", "tamper failed", rc);
    }
    if (json) {
        printf("{\"modified\":%" PRIu32 ",\"n\":%" PRIu64 ",\"mode\":\"%s\"}\n", count, n, mode);
    } else {
        printf("tampered %" PRIu32 " of %" PRIu64 " blocks (mode %s)\n", count, n, mode);
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* delete                                                                 */
/* ===================================================================== */

static int cmd_delete(int argc, char **argv)
{
    static const cli_opt_spec_t spec[] = {{"--tag", 1}, OPT_BACKEND, {"--json", 0}, {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 2, spec, &o) != 0) {
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    const char *tagp = cli_get(&o, "--tag");
    if (tagp == NULL) {
        fprintf(stderr, PROG " delete: --tag is required\n");
        return CLI_EXIT_USAGE;
    }
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len = 0;
    swpor_tag_header_t h;
    int rc = read_tag_file(tagp, tag, &tag_len);
    if (rc == SWPOR_OK) {
        rc = swpor_tag_header_decode(tag, tag_len, &h);
    }
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " delete", "cannot read tag file", rc);
    }
    backend_t b;
    rc = backend_open(&o, &b);
    if (rc == SWPOR_OK) {
        rc = b.local != NULL ? swpor_store_delete(b.local, h.file_id)
                             : swpor_client_delete(b.client, h.file_id);
    }
    backend_close(&b);
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG " delete", "delete failed", rc);
    }
    char hex[65];
    swpor_hex_encode(h.file_id, 32, hex);
    if (json) {
        printf("{\"deleted\":\"%s\"}\n", hex);
    } else {
        printf("deleted %s\n", hex);
    }
    return CLI_EXIT_OK;
}

/* ===================================================================== */
/* doctor / version                                                       */
/* ===================================================================== */

static int cmd_version(void)
{
    printf("porctl %s\n", swpor_version());
    printf("platform: %s\n", swpor_platform_name());
    printf("openssl:  %s\n", swpor_openssl_version());
    return CLI_EXIT_OK;
}

static int cmd_doctor(int argc, char **argv)
{
    int json = argc >= 3 && strcmp(argv[2], "--json") == 0;
    int rc = swpor_selftest();
    if (json) {
        printf("{\"doctor\":\"%s\"}\n", rc == SWPOR_OK ? "OK" : "FAILED");
        return rc == SWPOR_OK ? CLI_EXIT_OK : CLI_EXIT_CRYPTO;
    }
    if (rc != SWPOR_OK) {
        fprintf(stderr, "doctor: FAILED (%s)\n", swpor_strerror(rc));
        return CLI_EXIT_CRYPTO;
    }
    printf("doctor: OK (OpenSSL RAND/HMAC, blst hash-to-G1/pairing)\n");
    return CLI_EXIT_OK;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(stderr);
        return CLI_EXIT_USAGE;
    }
    const char *cmd = argv[1];
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(stdout);
        return CLI_EXIT_OK;
    }
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        return cmd_version();
    }
    if (swpor_platform_init() != SWPOR_OK) {
        fprintf(stderr, PROG ": platform init failed\n");
        return CLI_EXIT_NET;
    }
    int rc;
    if (strcmp(cmd, "doctor") == 0) {
        rc = cmd_doctor(argc, argv);
    } else if (strcmp(cmd, "keygen") == 0) {
        rc = cmd_keygen(argc, argv);
    } else if (strcmp(cmd, "store") == 0) {
        rc = cmd_store(argc, argv);
    } else if (strcmp(cmd, "audit") == 0) {
        rc = cmd_audit(argc, argv);
    } else if (strcmp(cmd, "retrieve") == 0) {
        rc = cmd_retrieve(argc, argv);
    } else if (strcmp(cmd, "info") == 0) {
        rc = cmd_info(argc, argv);
    } else if (strcmp(cmd, "tamper") == 0) {
        rc = cmd_tamper(argc, argv);
    } else if (strcmp(cmd, "delete") == 0) {
        rc = cmd_delete(argc, argv);
    } else {
        fprintf(stderr, PROG ": unknown command '%s'\n\n", cmd);
        print_usage(stderr);
        rc = CLI_EXIT_USAGE;
    }
    swpor_platform_cleanup();
    return rc;
}
