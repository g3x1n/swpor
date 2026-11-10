#ifndef SWPOR_CTX_H
#define SWPOR_CTX_H

#include "swpor/trace.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 库上下文。保存与单次会话相关的设置（例如 trace 回调）。
 * 一个上下文不应被多个线程同时使用；不同线程请各自创建上下文。
 */
typedef struct swpor_ctx swpor_ctx_t;

/**
 * 创建上下文。
 * @param out  输出：新建的上下文
 * @return SWPOR_OK；out 为 NULL 时返回 SWPOR_E_INVALID_ARG；内存不足返回 SWPOR_E_NOMEM
 */
int swpor_ctx_new(swpor_ctx_t **out);

/** 释放上下文。传入 NULL 安全。 */
void swpor_ctx_free(swpor_ctx_t *ctx);

/**
 * 设置执行轨迹回调（SPEC 9.4）。fn 为 NULL 时关闭 trace。
 * @param ctx   上下文
 * @param fn    回调函数
 * @param user  原样传给回调的用户指针
 */
void swpor_set_trace(swpor_ctx_t *ctx, swpor_trace_fn fn, void *user);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_CTX_H */
