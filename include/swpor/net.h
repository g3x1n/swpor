#ifndef SWPOR_NET_H
#define SWPOR_NET_H

/*
 * 网络协议（SPEC 8）：帧格式、客户端、线程池服务端。
 * 属于 swpor_net 库（libswpor 本身不含网络代码，SPEC 9.1）。
 *
 * 帧：| length: u32（不含本字段）| type: u8 | payload: length-1 字节 |，单帧上限 16 MiB。
 */

#include <stddef.h>
#include <stdint.h>

#include "swpor/ctx.h"
#include "swpor/por.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- 消息类型（SPEC 8.3） ---- */
#define SWPOR_MSG_HELLO 0x01u
#define SWPOR_MSG_HELLO_OK 0x02u
#define SWPOR_MSG_STORE_BEGIN 0x10u
#define SWPOR_MSG_STORE_BLOCKS 0x11u
#define SWPOR_MSG_STORE_SIGMAS 0x12u
#define SWPOR_MSG_STORE_END 0x13u
#define SWPOR_MSG_STORE_OK 0x14u
#define SWPOR_MSG_CHALLENGE 0x20u
#define SWPOR_MSG_PROOF 0x21u
#define SWPOR_MSG_GET_TAG 0x30u
#define SWPOR_MSG_TAG 0x31u
#define SWPOR_MSG_GET_BLOCKS 0x32u
#define SWPOR_MSG_BLOCKS 0x33u
#define SWPOR_MSG_GET_SIGMAS 0x34u
#define SWPOR_MSG_SIGMAS 0x35u
#define SWPOR_MSG_DELETE 0x40u
#define SWPOR_MSG_OK 0x41u
#define SWPOR_MSG_ERROR 0x7Fu

/* ---- 帧 ---- */

/**
 * 发送一帧。payload_len + 1 不得超过 SWPOR_MAX_FRAME_BYTES。
 * 为减少系统调用，帧头与 payload 合并发送（payload 较小时）。
 */
int swpor_frame_send(void *sock, uint8_t type, const uint8_t *payload, size_t payload_len);

/**
 * 接收一帧。payload 由本函数分配，调用方 free。
 * @param max_len  允许的最大帧长度（length 字段）；超过返回 SWPOR_E_RANGE（SPEC 8.2）
 */
int swpor_frame_recv(void *sock, size_t max_len, uint8_t *type, uint8_t **payload,
                     size_t *payload_len);

/** 解析 "host:port"（port 省略时为 7878）。 */
int swpor_parse_hostport(const char *s, char *host, size_t host_cap, uint16_t *port);

/* ---- 客户端 ---- */

typedef struct swpor_client swpor_client_t;

/** 连接服务端并完成 HELLO 握手。timeout_ms 为读写超时（0 = 不超时）。 */
int swpor_client_connect(const char *host, uint16_t port, uint32_t timeout_ms,
                         swpor_client_t **out);

/** 关闭连接。传入 NULL 安全。 */
void swpor_client_close(swpor_client_t *c);

/** 上一次 ERROR 消息中的文字说明（无则为空串）。 */
const char *swpor_client_last_error(const swpor_client_t *c);

/** STORE_BEGIN：tag_len ‖ tag ‖ n ‖ block_bytes ‖ sigma_bytes。 */
int swpor_client_store_begin(swpor_client_t *c, const uint8_t *tag, size_t tag_len, uint64_t n,
                             uint32_t block_bytes, uint8_t sigma_bytes);

/** STORE_BLOCKS：start_index ‖ count ‖ 块数据（count · block_bytes 字节）。 */
int swpor_client_store_blocks(swpor_client_t *c, uint64_t start, uint32_t count,
                              const uint8_t *data, size_t len);

/** STORE_SIGMAS：start_index ‖ count ‖ σ 数据。 */
int swpor_client_store_sigmas(swpor_client_t *c, uint64_t start, uint32_t count,
                              const uint8_t *data, size_t len);

/** STORE_END，等待 STORE_OK，输出服务端确认的 file_id。 */
int swpor_client_store_end(swpor_client_t *c, uint8_t file_id[32]);

/** CHALLENGE → PROOF。proof 为 PROOF payload（s ‖ μ ‖ σ）。 */
int swpor_client_challenge(swpor_client_t *c, const uint8_t file_id[32], const swpor_chal_t *chal,
                           uint8_t *proof, size_t cap, size_t *proof_len);

/** GET_TAG → TAG。 */
int swpor_client_get_tag(swpor_client_t *c, const uint8_t file_id[32], uint8_t *tag, size_t cap,
                         size_t *tag_len);

/** GET_BLOCKS → BLOCKS。out 容量必须恰为 count · block_bytes。 */
int swpor_client_get_blocks(swpor_client_t *c, const uint8_t file_id[32], uint64_t start,
                            uint32_t count, uint8_t *out, size_t len);

/** GET_SIGMAS → SIGMAS。 */
int swpor_client_get_sigmas(swpor_client_t *c, const uint8_t file_id[32], uint64_t start,
                            uint32_t count, uint8_t *out, size_t len);

/** DELETE → OK。 */
int swpor_client_delete(swpor_client_t *c, const uint8_t file_id[32]);

/* ---- 远程模式适配器（供 swpor/pipeline.h 使用） ---- */

typedef struct swpor_remote swpor_remote_t;

/** 基于已连接的客户端创建适配器（不接管 client 的所有权）。 */
int swpor_remote_new(swpor_client_t *client, swpor_remote_t **out);
void swpor_remote_free(swpor_remote_t *r);

/** 上传用的 swpor_st_sink_t（user = swpor_remote_t*）：连续的块会合并成批发送。 */
const struct swpor_st_sink_s *swpor_remote_sink(void);

/** 上传完成后服务端确认的 file_id。 */
const uint8_t *swpor_remote_file_id(const swpor_remote_t *r);

/** 设置后续 prove 使用的 file_id。 */
void swpor_remote_set_file_id(swpor_remote_t *r, const uint8_t file_id[32]);

/** swpor_prove_fn 适配（user = swpor_remote_t*）。 */
int swpor_remote_prove(void *user, const swpor_chal_t *chal, uint8_t *proof, size_t cap,
                       size_t *proof_len);

/**
 * 把服务端上的文件（标签、全部块与 σ）下载到本地目录 root（SPEC 6 布局），
 * 之后可用本地模式检索。按批顺序下载。
 */
int swpor_remote_download(swpor_client_t *client, const uint8_t file_id[32], const char *root);

/* ---- 服务端（SPEC 8.4 线程池） ---- */

typedef struct swpor_server swpor_server_t;

/** 日志回调：level 0 = info，1 = warn，2 = error。必须线程安全。 */
typedef void (*swpor_log_fn)(void *user, int level, const char *msg);

typedef struct {
    const char *data_dir;       /* 存储根目录 */
    const char *host;           /* 监听地址，NULL = 0.0.0.0 */
    uint16_t port;              /* 0 = 由系统分配（测试用） */
    uint32_t max_l;             /* CHALLENGE 的 l 上限，0 = SWPOR_DEFAULT_MAX_L */
    unsigned threads;           /* 工作线程数，0 = CPU 核数 */
    unsigned queue_cap;         /* 有界任务队列容量，0 = 4 × threads */
    uint32_t timeout_ms;        /* 每连接读写超时，0 = SWPOR_DEFAULT_IO_TIMEOUT_MS */
    swpor_log_fn log;           /* 可为 NULL */
    void *log_user;
    swpor_trace_fn trace;       /* 可为 NULL；每个工作线程的 ctx 使用此回调（必须线程安全） */
    void *trace_user;
} swpor_server_config_t;

/** 创建服务端并开始监听。 */
int swpor_server_new(const swpor_server_config_t *cfg, swpor_server_t **out);

/** 实际监听端口。 */
uint16_t swpor_server_port(const swpor_server_t *s);

/** 运行 accept 循环，直到 swpor_server_stop 被调用。 */
int swpor_server_run(swpor_server_t *s);

/** 请求停止（线程安全）。 */
void swpor_server_stop(swpor_server_t *s);

/** 释放（必须在 run 返回之后调用）。 */
void swpor_server_free(swpor_server_t *s);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_NET_H */
