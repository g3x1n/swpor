#ifndef SWPOR_APPS_CLI_H
#define SWPOR_APPS_CLI_H

/*
 * 命令行程序的公共工具（porctl / pord / porta / porbench 共用）：
 * 选项解析、退出码映射（SPEC 9.2）、JSON 输出、trace NDJSON 输出（SPEC 9.4）、文件输入输出适配。
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "swpor/swpor.h"

/* 退出码（SPEC 9.2） */
enum {
    CLI_EXIT_OK = 0,
    CLI_EXIT_AUDIT_FAIL = 1,
    CLI_EXIT_USAGE = 2,
    CLI_EXIT_IO = 3,
    CLI_EXIT_NET = 4,
    CLI_EXIT_CRYPTO = 5
};

/** 把库错误码映射为退出码。 */
int cli_exit_code(int err);

/* ---- 选项解析 ---- */

typedef struct {
    const char *name;   /* 如 "--key" */
    int has_value;      /* 1：需要参数；0：开关 */
} cli_opt_spec_t;

#define CLI_MAX_OPTS 32

typedef struct {
    const char *names[CLI_MAX_OPTS];
    const char *values[CLI_MAX_OPTS]; /* 开关为 "" */
    int count;
} cli_opts_t;

/**
 * 解析 argv[first..argc)。遇到未知选项、缺少参数或重复选项时向 stderr 打印说明并返回 -1。
 */
int cli_parse(int argc, char **argv, int first, const cli_opt_spec_t *spec, cli_opts_t *out);

/** 取选项值；不存在返回 NULL。 */
const char *cli_get(const cli_opts_t *o, const char *name);

/** 开关是否出现。 */
int cli_has(const cli_opts_t *o, const char *name);

/** 解析无符号整数（十进制），范围 [lo, hi]。失败返回 -1。 */
int cli_parse_u64(const char *s, uint64_t lo, uint64_t hi, uint64_t *out);

/** 解析 [0, 1] 之间的小数。 */
int cli_parse_ratio(const char *s, double *out);

/* ---- JSON 输出 ---- */

/** 打印 JSON 字符串（带引号与转义）。 */
void cli_json_str(FILE *f, const char *s);

/** 以 JSON 或文本形式报告错误到 stdout / stderr，返回退出码。 */
int cli_fail(int json, const char *prog, const char *what, int err);

/* ---- trace（SPEC 9.4） ---- */

/**
 * 打开 trace 输出：path 为 "-" 时写到 stderr（避免与 --json 的 stdout 输出混在一起），否则写文件。
 * 返回的 FILE* 作为 trace 回调的 user。
 */
FILE *cli_trace_open(const char *path);
void cli_trace_close(FILE *f);
/** 线程安全的 NDJSON 写出回调（user = FILE*）。 */
void cli_trace_cb(const swpor_event_t *ev, void *user);

/* ---- 文件适配 ---- */

typedef struct {
    void *file;      /* swpor_file_t* */
    uint64_t off;
    uint64_t size;
} cli_infile_t;

/** 打开输入文件（UTF-8 路径）。 */
int cli_infile_open(const char *path, cli_infile_t *in);
void cli_infile_close(cli_infile_t *in);
/** swpor_input_fn 适配（user = cli_infile_t*）。 */
int cli_infile_read(void *user, uint8_t *buf, size_t len, size_t *got);

typedef struct {
    void *file;      /* swpor_file_t* */
    uint64_t off;
} cli_outfile_t;

int cli_outfile_open(const char *path, cli_outfile_t *out);
int cli_outfile_close(cli_outfile_t *out);
/** swpor_output_fn 适配（user = cli_outfile_t*）。 */
int cli_outfile_write(void *user, const uint8_t *buf, size_t len);

/* ---- 本地存储适配 ---- */

typedef struct {
    const char *root;
    swpor_store_t *st;
} cli_local_sink_t;

/** 写入本地目录的 swpor_st_sink_t（user = cli_local_sink_t*）。 */
extern const swpor_st_sink_t cli_local_sink;

/** swpor_prove_fn 适配（user = swpor_store_t*）。 */
int cli_local_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap,
                    size_t *proof_len);

/* ---- 密钥 ---- */

typedef struct {
    swpor_keys_t keys;
    swpor_priv_key_t *priv;
    swpor_pub_sk_t *psk;
    swpor_pub_pk_t *ppk;
} cli_keys_t;

/**
 * 按文件头自动识别并加载密钥文件（priv.key / pub.sk / pub.pk）。
 * 加载 pub.sk 时同时计算公钥。
 */
int cli_keys_load(const char *path, cli_keys_t *k);
void cli_keys_free(cli_keys_t *k);

/** 毫秒（double）。 */
double cli_ms(uint64_t ns);

#endif /* SWPOR_APPS_CLI_H */
