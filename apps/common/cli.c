/* 命令行程序公共工具（见 cli.h）。 */

#include "cli.h"

#include <stdlib.h>
#include <string.h>

#include "platform.h"

int cli_exit_code(int err)
{
    switch (err) {
    case SWPOR_OK:
        return CLI_EXIT_OK;
    case SWPOR_E_INVALID_ARG:
    case SWPOR_E_RANGE:
        return CLI_EXIT_USAGE;
    case SWPOR_E_IO:
    case SWPOR_E_EXISTS:
    case SWPOR_E_NOT_FOUND:
    case SWPOR_E_NOMEM:
        return CLI_EXIT_IO;
    case SWPOR_E_NET:
    case SWPOR_E_TIMEOUT:
    case SWPOR_E_BUSY:
        return CLI_EXIT_NET;
    default:
        return CLI_EXIT_CRYPTO; /* PARSE、TAG_AUTH、CRYPTO、UNSUPPORTED、DECODE 等 */
    }
}

/* ===================================================================== */
/* 选项                                                                   */
/* ===================================================================== */

int cli_parse(int argc, char **argv, int first, const cli_opt_spec_t *spec, cli_opts_t *out)
{
    memset(out, 0, sizeof(*out));
    for (int i = first; i < argc; i++) {
        const char *a = argv[i];
        const cli_opt_spec_t *s = NULL;
        for (const cli_opt_spec_t *p = spec; p->name != NULL; p++) {
            if (strcmp(p->name, a) == 0) {
                s = p;
                break;
            }
        }
        if (s == NULL) {
            fprintf(stderr, "unknown option: %s\n", a);
            return -1;
        }
        if (cli_get(out, s->name) != NULL) {
            fprintf(stderr, "duplicate option: %s\n", a);
            return -1;
        }
        if (out->count >= CLI_MAX_OPTS) {
            fprintf(stderr, "too many options\n");
            return -1;
        }
        const char *v = "";
        if (s->has_value) {
            if (i + 1 >= argc) {
                fprintf(stderr, "option %s requires a value\n", a);
                return -1;
            }
            v = argv[++i];
        }
        out->names[out->count] = s->name;
        out->values[out->count] = v;
        out->count++;
    }
    return 0;
}

const char *cli_get(const cli_opts_t *o, const char *name)
{
    for (int i = 0; i < o->count; i++) {
        if (strcmp(o->names[i], name) == 0) {
            return o->values[i];
        }
    }
    return NULL;
}

int cli_has(const cli_opts_t *o, const char *name)
{
    return cli_get(o, name) != NULL;
}

int cli_parse_u64(const char *s, uint64_t lo, uint64_t hi, uint64_t *out)
{
    if (s == NULL || *s == '\0') {
        return -1;
    }
    uint64_t v = 0;
    for (const char *p = s; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        uint64_t d = (uint64_t)(*p - '0');
        if (v > (UINT64_MAX - d) / 10u) {
            return -1;
        }
        v = v * 10u + d;
    }
    if (v < lo || v > hi) {
        return -1;
    }
    *out = v;
    return 0;
}

int cli_parse_ratio(const char *s, double *out)
{
    if (s == NULL || *s == '\0') {
        return -1;
    }
    char *end = NULL;
    double v = strtod(s, &end);
    if (end == NULL || *end != '\0' || !(v >= 0.0 && v <= 1.0)) {
        return -1;
    }
    *out = v;
    return 0;
}

/* ===================================================================== */
/* JSON                                                                   */
/* ===================================================================== */

void cli_json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            if (*p < 0x20) {
                fprintf(f, "\\u%04x", (unsigned)*p);
            } else {
                fputc(*p, f);
            }
        }
    }
    fputc('"', f);
}

int cli_fail(int json, const char *prog, const char *what, int err)
{
    int code = cli_exit_code(err);
    if (json) {
        printf("{\"error\":");
        cli_json_str(stdout, what);
        printf(",\"detail\":");
        cli_json_str(stdout, swpor_strerror(err));
        printf(",\"code\":%d,\"exit\":%d}\n", err, code);
    } else {
        fprintf(stderr, "%s: %s: %s\n", prog, what, swpor_strerror(err));
    }
    return code;
}

/* ===================================================================== */
/* trace                                                                  */
/* ===================================================================== */

static swpor_mutex_t *g_trace_mu;

FILE *cli_trace_open(const char *path)
{
    if (path == NULL) {
        return NULL;
    }
    if (g_trace_mu == NULL && swpor_mutex_new(&g_trace_mu) != SWPOR_OK) {
        return NULL;
    }
    if (strcmp(path, "-") == 0) {
        return stderr;
    }
    return fopen(path, "ab");
}

void cli_trace_close(FILE *f)
{
    if (f != NULL && f != stderr) {
        fclose(f);
    }
    swpor_mutex_free(g_trace_mu);
    g_trace_mu = NULL;
}

void cli_trace_cb(const swpor_event_t *ev, void *user)
{
    FILE *f = user;
    if (f == NULL) {
        return;
    }
    if (g_trace_mu != NULL) {
        swpor_mutex_lock(g_trace_mu);
    }
    fputs(ev->json, f);
    fputc('\n', f);
    fflush(f);
    if (g_trace_mu != NULL) {
        swpor_mutex_unlock(g_trace_mu);
    }
}

/* ===================================================================== */
/* 文件                                                                   */
/* ===================================================================== */

int cli_infile_open(const char *path, cli_infile_t *in)
{
    memset(in, 0, sizeof(*in));
    swpor_file_t *f = NULL;
    int rc = swpor_file_open(path, SWPOR_FILE_READ, &f);
    if (rc != SWPOR_OK) {
        return rc;
    }
    rc = swpor_file_size(f, &in->size);
    if (rc != SWPOR_OK) {
        swpor_file_close(f);
        return rc;
    }
    in->file = f;
    return SWPOR_OK;
}

void cli_infile_close(cli_infile_t *in)
{
    swpor_file_close(in->file);
    in->file = NULL;
}

int cli_infile_read(void *user, uint8_t *buf, size_t len, size_t *got)
{
    cli_infile_t *in = user;
    int rc = swpor_file_pread_some(in->file, buf, len, in->off, got);
    if (rc == SWPOR_OK) {
        in->off += *got;
    }
    return rc;
}

int cli_outfile_open(const char *path, cli_outfile_t *out)
{
    memset(out, 0, sizeof(*out));
    swpor_file_t *f = NULL;
    int rc = swpor_file_open(path, SWPOR_FILE_CREATE, &f);
    if (rc == SWPOR_OK) {
        out->file = f;
    }
    return rc;
}

int cli_outfile_close(cli_outfile_t *out)
{
    int rc = SWPOR_OK;
    if (out->file != NULL) {
        rc = swpor_file_sync(out->file);
        swpor_file_close(out->file);
        out->file = NULL;
    }
    return rc;
}

int cli_outfile_write(void *user, const uint8_t *buf, size_t len)
{
    cli_outfile_t *out = user;
    int rc = swpor_file_pwrite(out->file, buf, len, out->off);
    if (rc == SWPOR_OK) {
        out->off += len;
    }
    return rc;
}

/* ===================================================================== */
/* 本地存储                                                               */
/* ===================================================================== */

static int ls_begin(void *user, const uint8_t *tag, size_t tag_len, const swpor_tag_header_t *h)
{
    (void)tag;
    (void)tag_len;
    cli_local_sink_t *ls = user;
    return swpor_store_create(ls->root, h->file_id, h->scheme, h->n, h->s, &ls->st);
}

static int ls_put(void *user, uint64_t pos, const uint8_t *block, size_t bl, const uint8_t *sigma,
                  size_t sl)
{
    (void)bl;
    (void)sl;
    cli_local_sink_t *ls = user;
    int rc = swpor_store_write_block(ls->st, pos, block);
    return rc == SWPOR_OK ? swpor_store_write_sigma(ls->st, pos, sigma) : rc;
}

static int ls_finish(void *user)
{
    (void)user;
    return SWPOR_OK; /* 标签由调用方在 swpor_st_run 返回后写入 */
}

const swpor_st_sink_t cli_local_sink = {ls_begin, ls_put, ls_finish};

int cli_local_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap,
                    size_t *proof_len)
{
    swpor_store_t *st = user;
    /* 本地模式模拟服务端：同样校验挑战上限 */
    if (chal->count > SWPOR_DEFAULT_MAX_L) {
        return SWPOR_E_RANGE;
    }
    return swpor_prove(NULL, swpor_store_header(st), chal, swpor_store_reader, st, proof, cap,
                       proof_len);
}

/* ===================================================================== */
/* 密钥                                                                   */
/* ===================================================================== */

int cli_keys_load(const char *path, cli_keys_t *k)
{
    memset(k, 0, sizeof(*k));
    int kind = 0;
    uint8_t scheme = 0;
    int rc = swpor_keyfile_probe(path, &kind, &scheme);
    if (rc != SWPOR_OK) {
        return rc;
    }
    k->keys.scheme = scheme;
    if (scheme == SWPOR_SCHEME_PRIV) {
        if (kind != SWPOR_KEYFILE_SECRET) {
            return SWPOR_E_PARSE;
        }
        rc = swpor_keyfile_load_priv(path, &k->priv);
        k->keys.priv_key = k->priv;
    } else if (kind == SWPOR_KEYFILE_SECRET) {
        rc = swpor_keyfile_load_pub_sk(path, &k->psk);
        if (rc == SWPOR_OK) {
            rc = swpor_pub_pk_from_sk(k->psk, &k->ppk);
        }
        k->keys.pub_sk = k->psk;
        k->keys.pub_pk = k->ppk;
    } else {
        rc = swpor_keyfile_load_pub_pk(path, &k->ppk);
        k->keys.pub_pk = k->ppk;
    }
    if (rc != SWPOR_OK) {
        cli_keys_free(k);
    }
    return rc;
}

void cli_keys_free(cli_keys_t *k)
{
    swpor_priv_key_free(k->priv);
    swpor_pub_sk_free(k->psk);
    swpor_pub_pk_free(k->ppk);
    memset(k, 0, sizeof(*k));
}

double cli_ms(uint64_t ns)
{
    return (double)ns / 1e6;
}
