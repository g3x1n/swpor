/* 库上下文与 trace 事件分发（SPEC 9.4）。 */

#include <stdio.h>
#include <stdlib.h>

#include "internal.h"
#include "swpor/error.h"

/* 单个事件 JSON 的最大长度。事件只含少量元数据，足够使用；超长时截断为合法 JSON。 */
#define SWPOR_TRACE_JSON_MAX 1024

int swpor_ctx_new(swpor_ctx_t **out)
{
    if (out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return SWPOR_E_NOMEM;
    }
    *out = ctx;
    return SWPOR_OK;
}

void swpor_ctx_free(swpor_ctx_t *ctx)
{
    free(ctx);
}

void swpor_set_trace(swpor_ctx_t *ctx, swpor_trace_fn fn, void *user)
{
    if (ctx == NULL) {
        return;
    }
    ctx->trace_fn = fn;
    ctx->trace_user = user;
}

const char *swpor_event_name(swpor_event_type_t type)
{
    switch (type) {
    case SWPOR_EV_FILE_SPLIT:
        return "file_split";
    case SWPOR_EV_EC_STRIPE:
        return "ec_stripe";
    case SWPOR_EV_TAG_BLOCK:
        return "tag_block";
    case SWPOR_EV_TAG_DONE:
        return "tag_done";
    case SWPOR_EV_CHALLENGE:
        return "challenge";
    case SWPOR_EV_PROVE_DONE:
        return "prove_done";
    case SWPOR_EV_VERIFY:
        return "verify";
    case SWPOR_EV_TAMPER:
        return "tamper";
    default:
        return "unknown";
    }
}

void swpor_trace_emit(const swpor_ctx_t *ctx, swpor_event_type_t type, const char *json_body)
{
    if (ctx == NULL || ctx->trace_fn == NULL) {
        return;
    }
    char buf[SWPOR_TRACE_JSON_MAX];
    const char *name = swpor_event_name(type);
    int n;
    if (json_body != NULL && json_body[0] != '\0') {
        n = snprintf(buf, sizeof(buf), "{\"type\":\"%s\",%s}", name, json_body);
    } else {
        n = snprintf(buf, sizeof(buf), "{\"type\":\"%s\"}", name);
    }
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        /* 截断后不再是合法 JSON，改为发出带截断标记的最小事件 */
        (void)snprintf(buf, sizeof(buf), "{\"type\":\"%s\",\"truncated\":true}", name);
    }
    swpor_event_t ev = {type, name, buf};
    ctx->trace_fn(&ev, ctx->trace_user);
}
