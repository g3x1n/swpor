#ifndef SWPOR_INTERNAL_H
#define SWPOR_INTERNAL_H

/* libswpor 内部头文件，不对外安装。 */

#include "swpor/ctx.h"
#include "swpor/trace.h"

struct swpor_ctx {
    swpor_trace_fn trace_fn;
    void *trace_user;
};

/**
 * 发出一个 trace 事件。未设置回调时直接返回（零开销，SPEC 9.4）。
 * @param ctx        上下文，可为 NULL
 * @param type       事件类型
 * @param json_body  不含外层大括号和 type 字段的 JSON 片段，如 "\"n\":128,\"s\":4"；
 *                   可为 NULL 或空串。调用方负责保证其中不含秘密数据。
 */
void swpor_trace_emit(const swpor_ctx_t *ctx, swpor_event_type_t type, const char *json_body);

#endif /* SWPOR_INTERNAL_H */
