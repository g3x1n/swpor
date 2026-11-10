/*
 * porta：第三方审计者（SPEC 9.1）。
 * 只持有公钥 pk 与文件标签 t，对 Pub 方案的文件定期发起审计（默认种子挑战，SPEC 3.5.2），
 * 每次审计结果以 NDJSON 写入审计日志。
 *
 *   porta --pk <pub.pk> --tag <t1[,t2,...]> (--server <host:port> | --local <dir>)
 *         [--l 128] [--explicit] [--interval <秒>] [--count N] [--log <file>] [--json]
 *
 * --count 0 表示一直运行（直到 Ctrl-C）；默认只审计一轮。
 * 退出码：全部 PASS 为 0，有 FAIL 为 1，其他错误见 SPEC 9.2。
 */

#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cli.h"
#include "platform.h"
#include "swpor/net.h"
#include "swpor/swpor.h"

#define PROG "porta"
#define MAX_TAGS 256

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

typedef struct {
    char path[1024];
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t len;
    swpor_tag_header_t hdr;
} tag_entry_t;

static void usage(FILE *f)
{
    fprintf(f,
            "porta %s - third-party auditor (public verification, Pub scheme)\n"
            "\n"
            "usage: porta --pk <pub.pk> --tag <t1[,t2,...]> (--server <host:port> | --local <dir>)\n"
            "             [--l 128] [--explicit] [--interval <seconds>] [--count N]\n"
            "             [--log <file>] [--json] [--timeout ms]\n"
            "\n"
            "  --count 0 runs until interrupted; default is a single round.\n",
            swpor_version());
}

/* 拆分逗号分隔的标签列表并读取、校验每个标签（只需公钥，SPEC 4.2 Pub.V 第 1 步） */
static int load_tags(const char *list, const swpor_keys_t *keys, tag_entry_t *tags, int *count)
{
    *count = 0;
    const char *p = list;
    while (*p != '\0') {
        const char *comma = strchr(p, ',');
        size_t len = comma != NULL ? (size_t)(comma - p) : strlen(p);
        if (len == 0 || len >= sizeof(tags[0].path) || *count >= MAX_TAGS) {
            return SWPOR_E_INVALID_ARG;
        }
        tag_entry_t *t = &tags[*count];
        memcpy(t->path, p, len);
        t->path[len] = '\0';
        uint8_t *buf = NULL;
        size_t bl = 0;
        int rc = swpor_read_file(t->path, SWPOR_TAG_MAX_BYTES, &buf, &bl);
        if (rc != SWPOR_OK) {
            fprintf(stderr, PROG ": cannot read tag %s: %s\n", t->path, swpor_strerror(rc));
            return rc;
        }
        memcpy(t->tag, buf, bl);
        t->len = bl;
        free(buf);
        rc = swpor_tag_open_any(keys, t->tag, t->len, &t->hdr);
        if (rc != SWPOR_OK) {
            fprintf(stderr, PROG ": tag %s does not verify under this public key: %s\n", t->path,
                    swpor_strerror(rc));
            return rc;
        }
        (*count)++;
        p += len;
        if (*p == ',') {
            p++;
        }
    }
    return *count > 0 ? SWPOR_OK : SWPOR_E_INVALID_ARG;
}

static void utc_now(char *buf, size_t cap)
{
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    if (tm == NULL || strftime(buf, cap, "%Y-%m-%dT%H:%M:%SZ", tm) == 0) {
        (void)snprintf(buf, cap, "unknown");
    }
}

/* 审计一个文件，返回 1 = PASS，0 = FAIL，负数 = 错误码 */
static int audit_one(const cli_opts_t *o, const swpor_keys_t *keys, const tag_entry_t *t,
                     uint32_t l, int seed, FILE *log, int json)
{
    swpor_audit_result_t res;
    memset(&res, 0, sizeof(res));
    swpor_client_t *c = NULL;
    swpor_remote_t *r = NULL;
    swpor_store_t *st = NULL;
    int rc;
    const char *local = cli_get(o, "--local");
    if (local != NULL) {
        rc = swpor_store_open(local, t->hdr.file_id, 0, &st);
        if (rc == SWPOR_OK) {
            rc = swpor_audit_run(NULL, keys, t->tag, t->len, l, seed, cli_local_prove, st, &res);
        }
    } else {
        char host[256];
        uint16_t port;
        uint64_t timeout = SWPOR_DEFAULT_IO_TIMEOUT_MS;
        if (cli_get(o, "--timeout") != NULL) {
            (void)cli_parse_u64(cli_get(o, "--timeout"), 1, 3600000, &timeout);
        }
        rc = swpor_parse_hostport(cli_get(o, "--server"), host, sizeof(host), &port);
        if (rc == SWPOR_OK) {
            rc = swpor_client_connect(host, port, (uint32_t)timeout, &c);
        }
        if (rc == SWPOR_OK) {
            rc = swpor_remote_new(c, &r);
        }
        if (rc == SWPOR_OK) {
            swpor_remote_set_file_id(r, t->hdr.file_id);
            rc = swpor_audit_run(NULL, keys, t->tag, t->len, l, seed, swpor_remote_prove, r, &res);
        }
    }
    swpor_store_close(st);
    swpor_remote_free(r);
    swpor_client_close(c);

    char hex[65];
    char ts[32];
    swpor_hex_encode(t->hdr.file_id, 32, hex);
    utc_now(ts, sizeof(ts));
    const char *result = rc != SWPOR_OK ? "ERROR" : res.pass ? "PASS" : "FAIL";
    /* 审计日志：每行一个 JSON 对象 */
    FILE *outs[2] = {log, json ? stdout : NULL};
    for (int k = 0; k < 2; k++) {
        if (outs[k] == NULL) {
            continue;
        }
        fprintf(outs[k],
                "{\"time\":\"%s\",\"file_id\":\"%s\",\"result\":\"%s\",\"l\":%" PRIu32
                ",\"challenge\":\"%s\",\"elapsed_ms\":%.3f,\"proof_bytes\":%zu",
                ts, hex, result, res.l, seed ? "seed" : "explicit", cli_ms(res.total_ns),
                res.proof_bytes);
        if (rc != SWPOR_OK) {
            fprintf(outs[k], ",\"error\":");
            cli_json_str(outs[k], swpor_strerror(rc));
        }
        fprintf(outs[k], "}\n");
        fflush(outs[k]);
    }
    if (!json) {
        printf("%s  %s  %s  (l = %" PRIu32 ", %.2f ms)%s%s\n", ts, hex, result, res.l,
               cli_ms(res.total_ns), rc != SWPOR_OK ? "  " : "",
               rc != SWPOR_OK ? swpor_strerror(rc) : "");
        fflush(stdout);
    }
    return rc != SWPOR_OK ? rc : res.pass;
}

int main(int argc, char **argv)
{
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("porta %s (%s)\n", swpor_version(), swpor_platform_name());
        return CLI_EXIT_OK;
    }
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
        usage(stdout);
        return CLI_EXIT_OK;
    }
    static const cli_opt_spec_t spec[] = {
        {"--pk", 1},       {"--tag", 1},   {"--server", 1}, {"--local", 1},
        {"--l", 1},        {"--explicit", 0}, {"--interval", 1}, {"--count", 1},
        {"--log", 1},      {"--json", 0},  {"--timeout", 1}, {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 1, spec, &o) != 0) {
        usage(stderr);
        return CLI_EXIT_USAGE;
    }
    const int json = cli_has(&o, "--json");
    if (cli_get(&o, "--pk") == NULL || cli_get(&o, "--tag") == NULL ||
        (cli_get(&o, "--server") == NULL) == (cli_get(&o, "--local") == NULL)) {
        usage(stderr);
        return CLI_EXIT_USAGE;
    }
    uint64_t l = SWPOR_DEFAULT_L;
    uint64_t interval = 60;
    uint64_t count = 1;
    if ((cli_get(&o, "--l") && cli_parse_u64(cli_get(&o, "--l"), 1, UINT32_MAX, &l) != 0) ||
        (cli_get(&o, "--interval") &&
         cli_parse_u64(cli_get(&o, "--interval"), 0, 86400u * 365u, &interval) != 0) ||
        (cli_get(&o, "--count") && cli_parse_u64(cli_get(&o, "--count"), 0, UINT32_MAX, &count) != 0)) {
        fprintf(stderr, PROG ": invalid numeric option\n");
        return CLI_EXIT_USAGE;
    }
    if (swpor_platform_init() != SWPOR_OK) {
        return CLI_EXIT_NET;
    }

    /* 第三方审计者只能持有公钥：拒绝私钥文件 */
    int kind = 0;
    uint8_t scheme = 0;
    int rc = swpor_keyfile_probe(cli_get(&o, "--pk"), &kind, &scheme);
    if (rc == SWPOR_OK && (kind != SWPOR_KEYFILE_PUBLIC || scheme != SWPOR_SCHEME_PUB)) {
        fprintf(stderr, PROG ": --pk must be a Pub public key file (pub.pk)\n");
        return CLI_EXIT_USAGE;
    }
    cli_keys_t keys;
    if (rc == SWPOR_OK) {
        rc = cli_keys_load(cli_get(&o, "--pk"), &keys);
    }
    if (rc != SWPOR_OK) {
        return cli_fail(json, PROG, "cannot load public key", rc);
    }
    tag_entry_t *tags = calloc(MAX_TAGS, sizeof(*tags));
    int ntags = 0;
    if (tags == NULL) {
        cli_keys_free(&keys);
        return CLI_EXIT_IO;
    }
    rc = load_tags(cli_get(&o, "--tag"), &keys.keys, tags, &ntags);
    if (rc != SWPOR_OK) {
        free(tags);
        cli_keys_free(&keys);
        return cli_fail(json, PROG, "cannot load tags", rc);
    }
    FILE *log = NULL;
    if (cli_get(&o, "--log") != NULL) {
        log = fopen(cli_get(&o, "--log"), "ab");
        if (log == NULL) {
            free(tags);
            cli_keys_free(&keys);
            fprintf(stderr, PROG ": cannot open log file\n");
            return CLI_EXIT_IO;
        }
    }
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    const int seed = !cli_has(&o, "--explicit");
    int any_fail = 0;
    int worst_err = SWPOR_OK;
    for (uint64_t round = 0; !g_stop && (count == 0 || round < count); round++) {
        for (int k = 0; k < ntags && !g_stop; k++) {
            int r = audit_one(&o, &keys.keys, &tags[k], (uint32_t)l, seed, log, json);
            if (r == 0) {
                any_fail = 1;
            } else if (r < 0) {
                worst_err = r;
            }
        }
        if (count != 0 && round + 1 >= count) {
            break;
        }
        for (uint64_t s = 0; s < interval * 10u && !g_stop; s++) {
            swpor_sleep_ms(100);
        }
    }
    if (log != NULL) {
        fclose(log);
    }
    free(tags);
    cli_keys_free(&keys);
    swpor_platform_cleanup();
    if (any_fail) {
        return CLI_EXIT_AUDIT_FAIL;
    }
    return cli_exit_code(worst_err);
}
