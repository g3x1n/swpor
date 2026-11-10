/*
 * pord：存储服务端（SPEC 8、9.3）。
 *   pord --listen 0.0.0.0:7878 --data-dir <dir> [--max-l 4096] [--threads N] [--log <file>]
 *        [--timeout ms] [--trace <file|->]
 * 只在 macOS / Linux 上构建（SPEC 2.1：Windows 不部署服务端）。
 * 收到 SIGINT / SIGTERM 后停止接受新连接，处理完已排队的连接后退出。
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "cli.h"
#include "platform.h"
#include "swpor/net.h"
#include "swpor/swpor.h"

#define PROG "pord"

static FILE *g_log;
static swpor_mutex_t *g_log_mu;
static volatile sig_atomic_t g_stop;

static void log_cb(void *user, int level, const char *msg)
{
    (void)user;
    static const char *const names[] = {"info", "warn", "error"};
    char ts[32];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    if (tm == NULL || strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm) == 0) {
        ts[0] = '\0';
    }
    swpor_mutex_lock(g_log_mu);
    fprintf(g_log, "%s [%s] %s\n", ts, names[level < 0 || level > 2 ? 2 : level], msg);
    fflush(g_log);
    swpor_mutex_unlock(g_log_mu);
}

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

/* 等待信号的线程：主线程阻塞在 accept 上，信号处理函数里只能置标志，由此线程调用 stop */
static void watcher(void *arg)
{
    swpor_server_t *srv = arg;
    while (!g_stop) {
        swpor_sleep_ms(200);
    }
    swpor_server_stop(srv);
}

static void usage(FILE *f)
{
    fprintf(f,
            "pord %s - proof-of-retrievability storage server\n"
            "\n"
            "usage: pord --data-dir <dir> [--listen 0.0.0.0:7878] [--max-l 4096] [--threads N]\n"
            "            [--timeout ms] [--log <file>] [--trace <file|->]\n",
            swpor_version());
}

int main(int argc, char **argv)
{
    if (argc >= 2 && (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "version") == 0)) {
        printf("pord %s (%s)\n", swpor_version(), swpor_platform_name());
        return CLI_EXIT_OK;
    }
    if (argc >= 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0)) {
        usage(stdout);
        return CLI_EXIT_OK;
    }
    static const cli_opt_spec_t spec[] = {{"--listen", 1}, {"--data-dir", 1}, {"--max-l", 1},
                                          {"--threads", 1}, {"--log", 1},     {"--timeout", 1},
                                          {"--trace", 1},   {NULL, 0}};
    cli_opts_t o;
    if (cli_parse(argc, argv, 1, spec, &o) != 0) {
        usage(stderr);
        return CLI_EXIT_USAGE;
    }
    swpor_server_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.data_dir = cli_get(&o, "--data-dir");
    if (cfg.data_dir == NULL) {
        usage(stderr);
        return CLI_EXIT_USAGE;
    }
    char host[256] = "0.0.0.0";
    cfg.port = SWPOR_DEFAULT_PORT;
    if (cli_get(&o, "--listen") != NULL &&
        swpor_parse_hostport(cli_get(&o, "--listen"), host, sizeof(host), &cfg.port) != SWPOR_OK) {
        fprintf(stderr, PROG ": invalid --listen address\n");
        return CLI_EXIT_USAGE;
    }
    cfg.host = host;
    uint64_t v;
    if (cli_get(&o, "--max-l") != NULL) {
        if (cli_parse_u64(cli_get(&o, "--max-l"), 1, 1u << 20, &v) != 0) {
            fprintf(stderr, PROG ": invalid --max-l\n");
            return CLI_EXIT_USAGE;
        }
        cfg.max_l = (uint32_t)v;
    }
    if (cli_get(&o, "--threads") != NULL) {
        if (cli_parse_u64(cli_get(&o, "--threads"), 1, 1024, &v) != 0) {
            fprintf(stderr, PROG ": invalid --threads\n");
            return CLI_EXIT_USAGE;
        }
        cfg.threads = (unsigned)v;
    }
    if (cli_get(&o, "--timeout") != NULL) {
        if (cli_parse_u64(cli_get(&o, "--timeout"), 1, 3600000, &v) != 0) {
            fprintf(stderr, PROG ": invalid --timeout\n");
            return CLI_EXIT_USAGE;
        }
        cfg.timeout_ms = (uint32_t)v;
    }
    if (swpor_platform_init() != SWPOR_OK || swpor_mutex_new(&g_log_mu) != SWPOR_OK) {
        return CLI_EXIT_NET;
    }
    g_log = stderr;
    if (cli_get(&o, "--log") != NULL) {
        g_log = fopen(cli_get(&o, "--log"), "ab");
        if (g_log == NULL) {
            fprintf(stderr, PROG ": cannot open log file\n");
            return CLI_EXIT_IO;
        }
    }
    FILE *trace = NULL;
    if (cli_get(&o, "--trace") != NULL) {
        trace = cli_trace_open(cli_get(&o, "--trace"));
        if (trace == NULL) {
            fprintf(stderr, PROG ": cannot open trace output\n");
            return CLI_EXIT_IO;
        }
        cfg.trace = cli_trace_cb;
        cfg.trace_user = trace;
    }
    cfg.log = log_cb;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    swpor_server_t *srv = NULL;
    int rc = swpor_server_new(&cfg, &srv);
    if (rc != SWPOR_OK) {
        fprintf(stderr, PROG ": cannot start server on %s:%u: %s\n", host, (unsigned)cfg.port,
                swpor_strerror(rc));
        return cli_exit_code(rc);
    }
    char msg[512];
    (void)snprintf(msg, sizeof(msg), "pord %s listening on %s:%u, data dir %s", swpor_version(),
                   host, (unsigned)swpor_server_port(srv), cfg.data_dir);
    log_cb(NULL, 0, msg);
    swpor_thread_t *w = NULL;
    if (swpor_thread_create(watcher, srv, &w) != SWPOR_OK) {
        swpor_server_free(srv);
        return CLI_EXIT_IO;
    }
    rc = swpor_server_run(srv);
    g_stop = 1;
    swpor_thread_join(w);
    swpor_server_free(srv);
    log_cb(NULL, 0, "pord stopped");
    if (trace != NULL) {
        cli_trace_close(trace);
    }
    if (g_log != stderr) {
        fclose(g_log);
    }
    swpor_mutex_free(g_log_mu);
    swpor_platform_cleanup();
    return cli_exit_code(rc);
}
