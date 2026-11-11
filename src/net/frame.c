/* 帧格式（SPEC 8.2）与地址解析。 */

#include <stdlib.h>
#include <string.h>

#include "endian.h"
#include "platform.h"
#include "swpor/error.h"
#include "swpor/net.h"
#include "swpor/params.h"

/* 小于此长度的 payload 与帧头合并为一次发送 */
#define COALESCE_LIMIT 65536u

int swpor_frame_send(void *sockp, uint8_t type, const uint8_t *payload, size_t payload_len)
{
    swpor_sock_t *sock = sockp;
    if (sock == NULL || (payload == NULL && payload_len > 0)) {
        return SWPOR_E_INVALID_ARG;
    }
    if (payload_len >= SWPOR_MAX_FRAME_BYTES) {
        return SWPOR_E_RANGE;
    }
    uint8_t head[5];
    swpor_store_be32(head, (uint32_t)(payload_len + 1u));
    head[4] = type;
    if (payload_len <= COALESCE_LIMIT) {
        uint8_t *buf = malloc(5u + payload_len);
        if (buf == NULL) {
            return SWPOR_E_NOMEM;
        }
        memcpy(buf, head, 5);
        if (payload_len > 0) {
            memcpy(buf + 5, payload, payload_len);
        }
        int rc = swpor_sock_send_all(sock, buf, 5u + payload_len);
        free(buf);
        return rc;
    }
    int rc = swpor_sock_send_all(sock, head, sizeof(head));
    if (rc == SWPOR_OK) {
        rc = swpor_sock_send_all(sock, payload, payload_len);
    }
    return rc;
}

int swpor_frame_recv(void *sockp, size_t max_len, uint8_t *type, uint8_t **payload,
                     size_t *payload_len)
{
    swpor_sock_t *sock = sockp;
    if (sock == NULL || type == NULL || payload == NULL || payload_len == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    *payload = NULL;
    *payload_len = 0;
    uint8_t head[5];
    int rc = swpor_sock_recv_all(sock, head, 4);
    if (rc != SWPOR_OK) {
        return rc;
    }
    uint32_t len = swpor_load_be32(head);
    if (max_len > SWPOR_MAX_FRAME_BYTES) {
        max_len = SWPOR_MAX_FRAME_BYTES;
    }
    if (len == 0) {
        return SWPOR_E_PARSE;
    }
    if (len > max_len) {
        return SWPOR_E_RANGE; /* 超长帧（SPEC 8.2） */
    }
    rc = swpor_sock_recv_all(sock, head + 4, 1);
    if (rc != SWPOR_OK) {
        return rc;
    }
    size_t plen = (size_t)len - 1u;
    uint8_t *buf = malloc(plen > 0 ? plen : 1u);
    if (buf == NULL) {
        return SWPOR_E_NOMEM;
    }
    if (plen > 0) {
        rc = swpor_sock_recv_all(sock, buf, plen);
        if (rc != SWPOR_OK) {
            free(buf);
            return rc;
        }
    }
    *type = head[4];
    *payload = buf;
    *payload_len = plen;
    return SWPOR_OK;
}

int swpor_parse_hostport(const char *s, char *host, size_t host_cap, uint16_t *port)
{
    if (s == NULL || host == NULL || port == NULL || host_cap == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    const char *colon = strrchr(s, ':');
    size_t hl = colon != NULL ? (size_t)(colon - s) : strlen(s);
    if (hl == 0 || hl >= host_cap) {
        return SWPOR_E_INVALID_ARG;
    }
    memcpy(host, s, hl);
    host[hl] = '\0';
    if (colon == NULL) {
        *port = SWPOR_DEFAULT_PORT;
        return SWPOR_OK;
    }
    const char *p = colon + 1;
    if (*p == '\0') {
        return SWPOR_E_INVALID_ARG;
    }
    unsigned long v = 0;
    for (; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return SWPOR_E_INVALID_ARG;
        }
        v = v * 10u + (unsigned long)(*p - '0');
        if (v > 65535u) {
            return SWPOR_E_INVALID_ARG;
        }
    }
    *port = (uint16_t)v;
    return SWPOR_OK;
}

/* ===================================================================== */
/* CHALLENGE 消息解析（SPEC 8.3）                                           */
/* ===================================================================== */

int swpor_chal_peek_wire(const uint8_t *p, size_t len, uint32_t max_l, uint8_t file_id[32],
                         uint8_t *mode, uint32_t *l)
{
    if (p == NULL || file_id == NULL || mode == NULL || l == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (len < 37) {
        return SWPOR_E_PARSE;
    }
    const uint8_t m = p[32];
    const uint32_t lv = swpor_load_be32(p + 33);
    if (lv == 0 || lv > max_l) {
        return SWPOR_E_RANGE; /* SPEC 8.3：l 上限，防止资源耗尽 */
    }
    if (m == SWPOR_CHAL_SEED) {
        if (len != 37u + 32u) {
            return SWPOR_E_PARSE;
        }
    } else if (m == SWPOR_CHAL_EXPLICIT) {
        if (len != 37u + (size_t)lv * 24u) {
            return SWPOR_E_PARSE;
        }
    } else {
        return SWPOR_E_PARSE;
    }
    memcpy(file_id, p, 32);
    *mode = m;
    *l = lv;
    return SWPOR_OK;
}

int swpor_chal_decode_wire(const uint8_t *p, size_t len, uint64_t n, uint32_t max_l,
                           swpor_chal_t **out)
{
    uint8_t fid[32];
    uint8_t mode = 0;
    uint32_t l = 0;
    int rc = swpor_chal_peek_wire(p, len, max_l, fid, &mode, &l);
    if (rc != SWPOR_OK) {
        return rc;
    }
    if (n == 0 || n >= SWPOR_MAX_BLOCKS || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    if (mode == SWPOR_CHAL_SEED) {
        return swpor_chal_from_seed(p + 37, n, l, out);
    }
    swpor_chal_item_t *items = malloc((size_t)l * sizeof(*items));
    if (items == NULL) {
        return SWPOR_E_NOMEM;
    }
    for (uint32_t k = 0; k < l; k++) {
        items[k].index = swpor_load_be64(p + 37 + (size_t)k * 24u);
        memcpy(items[k].nu, p + 45 + (size_t)k * 24u, 16);
    }
    rc = swpor_chal_from_items(items, l, n, max_l, out);
    free(items);
    return rc;
}
