#ifndef SWPOR_TRACE_H
#define SWPOR_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 执行轨迹事件（SPEC 9.4）。
 * 事件只包含可公开的元数据；任何事件都不得包含秘密数据、完整块内容或 σ_i 值。
 */
typedef enum {
    SWPOR_EV_FILE_SPLIT = 1,
    SWPOR_EV_EC_STRIPE,
    SWPOR_EV_TAG_BLOCK,
    SWPOR_EV_TAG_DONE,
    SWPOR_EV_CHALLENGE,
    SWPOR_EV_PROVE_DONE,
    SWPOR_EV_VERIFY,
    SWPOR_EV_TAMPER
} swpor_event_type_t;

typedef struct {
    swpor_event_type_t type;
    const char *name;   /* 事件名，如 "tag_done"，与 SPEC 9.4 表格一致 */
    const char *json;   /* 完整的单行 JSON 对象，形如 {"type":"tag_done","n":128,...}；
                           仅在回调期间有效，需要保留请自行复制 */
} swpor_event_t;

typedef void (*swpor_trace_fn)(const swpor_event_t *ev, void *user);

/** 返回事件类型对应的名称；未知类型返回 "unknown"。 */
const char *swpor_event_name(swpor_event_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_TRACE_H */
