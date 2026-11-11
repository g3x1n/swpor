/* 网络客户端（SPEC 8.3）。 */

#include <stdlib.h>
#include <string.h>

#include "endian.h"
#include "platform.h"
#include "swpor/error.h"
#include "swpor/net.h"
#include "swpor/params.h"

struct swpor_client {
    swpor_sock_t *sock;
    char last_error[256];
};

const char *swpor_client_last_error(const swpor_client_t *c)
{
    return c != NULL ? c->last_error : "";
}

void swpor_client_close(swpor_client_t *c)
{
    if (c == NULL) {
        return;
    }
    swpor_sock_close(c->sock);
    free(c);
}

/* 解析 ERROR 消息：code u16 ‖ msg_len u16 ‖ msg。返回对应的（负）错误码 */
static int handle_error(swpor_client_t *c, const uint8_t *p, size_t len)
{
    if (len < 4) {
        return SWPOR_E_PARSE;
    }
    uint16_t code = swpor_load_be16(p);
    uint16_t ml = swpor_load_be16(p + 2);
    if ((size_t)ml + 4u > len) {
        return SWPOR_E_PARSE;
    }
    size_t n = ml < sizeof(c->last_error) - 1 ? ml : sizeof(c->last_error) - 1;
    memcpy(c->last_error, p + 4, n);
    c->last_error[n] = '\0';
    /* 线上的 code 是错误码的绝对值；未知或为 0 时视为网络错误 */
    int err = -(int)code;
    if (code == 0 || err < SWPOR_E_NOT_IMPLEMENTED) {
        return SWPOR_E_NET;
    }
    return err;
}

/* 发送请求并接收应答，应答类型必须为 expect（或 ERROR）。payload 由调用方 free */
static int request(swpor_client_t *c, uint8_t type, const uint8_t *req, size_t req_len,
                   uint8_t expect, uint8_t **resp, size_t *resp_len)
{
    c->last_error[0] = '\0';
    int rc = swpor_frame_send(c->sock, type, req, req_len);
    if (rc != SWPOR_OK) {
        return rc;
    }
    uint8_t rtype = 0;
    rc = swpor_frame_recv(c->sock, SWPOR_MAX_FRAME_BYTES, &rtype, resp, resp_len);
    if (rc != SWPOR_OK) {
        return rc == SWPOR_E_TIMEOUT ? rc : SWPOR_E_NET;
    }
    if (rtype == SWPOR_MSG_ERROR) {
        rc = handle_error(c, *resp, *resp_len);
        free(*resp);
        *resp = NULL;
        return rc;
    }
    if (rtype != expect) {
        free(*resp);
        *resp = NULL;
        return SWPOR_E_PARSE;
    }
    return SWPOR_OK;
}

int swpor_client_connect(const char *host, uint16_t port, uint32_t timeout_ms,
                         swpor_client_t **out)
{
    if (host == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_client_t *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return SWPOR_E_NOMEM;
    }
    int rc = swpor_sock_connect(host, port, &c->sock);
    if (rc == SWPOR_OK && timeout_ms > 0) {
        rc = swpor_sock_set_timeout(c->sock, timeout_ms);
    }
    if (rc == SWPOR_OK) {
        uint8_t hello[2];
        swpor_store_be16(hello, SWPOR_PROTO_VERSION);
        uint8_t *resp = NULL;
        size_t rl = 0;
        rc = request(c, SWPOR_MSG_HELLO, hello, sizeof(hello), SWPOR_MSG_HELLO_OK, &resp, &rl);
        if (rc == SWPOR_OK && (rl != 6 || swpor_load_be16(resp) != SWPOR_PROTO_VERSION)) {
            rc = SWPOR_E_UNSUPPORTED;
        }
        free(resp);
    }
    if (rc != SWPOR_OK) {
        swpor_client_close(c);
        return rc;
    }
    *out = c;
    return SWPOR_OK;
}

int swpor_client_store_begin(swpor_client_t *c, const uint8_t *tag, size_t tag_len, uint64_t n,
                             uint32_t block_bytes, uint8_t sigma_bytes)
{
    if (c == NULL || tag == NULL || tag_len > SWPOR_TAG_MAX_BYTES) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t buf[4 + SWPOR_TAG_MAX_BYTES + 8 + 4 + 1];
    size_t off = 0;
    swpor_store_be32(buf, (uint32_t)tag_len);
    off += 4;
    memcpy(buf + off, tag, tag_len);
    off += tag_len;
    swpor_store_be64(buf + off, n);
    off += 8;
    swpor_store_be32(buf + off, block_bytes);
    off += 4;
    buf[off++] = sigma_bytes;
    return swpor_frame_send(c->sock, SWPOR_MSG_STORE_BEGIN, buf, off);
}

/* STORE_BLOCKS / STORE_SIGMAS：start ‖ count ‖ 数据（无应答） */
static int send_range(swpor_client_t *c, uint8_t type, uint64_t start, uint32_t count,
                      const uint8_t *data, size_t len)
{
    if (c == NULL || data == NULL || len + 13u >= SWPOR_MAX_FRAME_BYTES) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t *buf = malloc(12u + len);
    if (buf == NULL) {
        return SWPOR_E_NOMEM;
    }
    swpor_store_be64(buf, start);
    swpor_store_be32(buf + 8, count);
    memcpy(buf + 12, data, len);
    int rc = swpor_frame_send(c->sock, type, buf, 12u + len);
    free(buf);
    return rc;
}

int swpor_client_store_blocks(swpor_client_t *c, uint64_t start, uint32_t count,
                              const uint8_t *data, size_t len)
{
    return send_range(c, SWPOR_MSG_STORE_BLOCKS, start, count, data, len);
}

int swpor_client_store_sigmas(swpor_client_t *c, uint64_t start, uint32_t count,
                              const uint8_t *data, size_t len)
{
    return send_range(c, SWPOR_MSG_STORE_SIGMAS, start, count, data, len);
}

int swpor_client_store_end(swpor_client_t *c, uint8_t file_id[32])
{
    if (c == NULL || file_id == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t *resp = NULL;
    size_t rl = 0;
    int rc = request(c, SWPOR_MSG_STORE_END, NULL, 0, SWPOR_MSG_STORE_OK, &resp, &rl);
    if (rc == SWPOR_OK) {
        if (rl == 32) {
            memcpy(file_id, resp, 32);
        } else {
            rc = SWPOR_E_PARSE;
        }
    }
    free(resp);
    return rc;
}

int swpor_client_challenge(swpor_client_t *c, const uint8_t file_id[32], const swpor_chal_t *chal,
                           uint8_t *proof, size_t cap, size_t *proof_len)
{
    if (c == NULL || file_id == NULL || chal == NULL || proof == NULL || proof_len == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    /* file_id ‖ mode ‖ l ‖ [显式：l × (index ‖ ν)] 或 [种子：seed] */
    const int seed = chal->mode == SWPOR_CHAL_SEED;
    const uint32_t l = seed ? chal->l : chal->count;
    size_t len = 37u + (seed ? 32u : (size_t)l * 24u);
    if (len >= SWPOR_MAX_FRAME_BYTES) {
        return SWPOR_E_RANGE;
    }
    uint8_t *buf = malloc(len);
    if (buf == NULL) {
        return SWPOR_E_NOMEM;
    }
    memcpy(buf, file_id, 32);
    buf[32] = seed ? SWPOR_CHAL_SEED : SWPOR_CHAL_EXPLICIT;
    swpor_store_be32(buf + 33, l);
    if (seed) {
        memcpy(buf + 37, chal->seed, 32);
    } else {
        for (uint32_t k = 0; k < l; k++) {
            swpor_store_be64(buf + 37 + (size_t)k * 24u, chal->items[k].index);
            memcpy(buf + 45 + (size_t)k * 24u, chal->items[k].nu, 16);
        }
    }
    uint8_t *resp = NULL;
    size_t rl = 0;
    int rc = request(c, SWPOR_MSG_CHALLENGE, buf, len, SWPOR_MSG_PROOF, &resp, &rl);
    free(buf);
    if (rc == SWPOR_OK) {
        if (rl > cap) {
            rc = SWPOR_E_PARSE; /* 长度由验证方再次检查 */
        } else {
            memcpy(proof, resp, rl);
            *proof_len = rl;
        }
    }
    free(resp);
    return rc;
}

int swpor_client_get_tag(swpor_client_t *c, const uint8_t file_id[32], uint8_t *tag, size_t cap,
                         size_t *tag_len)
{
    if (c == NULL || file_id == NULL || tag == NULL || tag_len == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t *resp = NULL;
    size_t rl = 0;
    int rc = request(c, SWPOR_MSG_GET_TAG, file_id, 32, SWPOR_MSG_TAG, &resp, &rl);
    if (rc == SWPOR_OK) {
        uint32_t tl = rl >= 4 ? swpor_load_be32(resp) : 0;
        if (rl < 4 || (size_t)tl + 4u != rl || tl > cap) {
            rc = SWPOR_E_PARSE;
        } else {
            memcpy(tag, resp + 4, tl);
            *tag_len = tl;
        }
    }
    free(resp);
    return rc;
}

/* GET_BLOCKS / GET_SIGMAS：应答 start ‖ count ‖ 数据，三者都必须与请求一致 */
static int get_range(swpor_client_t *c, uint8_t type, uint8_t expect, const uint8_t file_id[32],
                     uint64_t start, uint32_t count, uint8_t *out, size_t len)
{
    if (c == NULL || file_id == NULL || out == NULL || count == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t req[44];
    memcpy(req, file_id, 32);
    swpor_store_be64(req + 32, start);
    swpor_store_be32(req + 40, count);
    uint8_t *resp = NULL;
    size_t rl = 0;
    int rc = request(c, type, req, sizeof(req), expect, &resp, &rl);
    if (rc == SWPOR_OK) {
        if (rl != 12u + len || swpor_load_be64(resp) != start || swpor_load_be32(resp + 8) != count) {
            rc = SWPOR_E_PARSE;
        } else {
            memcpy(out, resp + 12, len);
        }
    }
    free(resp);
    return rc;
}

int swpor_client_get_blocks(swpor_client_t *c, const uint8_t file_id[32], uint64_t start,
                            uint32_t count, uint8_t *out, size_t len)
{
    return get_range(c, SWPOR_MSG_GET_BLOCKS, SWPOR_MSG_BLOCKS, file_id, start, count, out, len);
}

int swpor_client_get_sigmas(swpor_client_t *c, const uint8_t file_id[32], uint64_t start,
                            uint32_t count, uint8_t *out, size_t len)
{
    return get_range(c, SWPOR_MSG_GET_SIGMAS, SWPOR_MSG_SIGMAS, file_id, start, count, out, len);
}

int swpor_client_delete(swpor_client_t *c, const uint8_t file_id[32])
{
    if (c == NULL || file_id == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t *resp = NULL;
    size_t rl = 0;
    int rc = request(c, SWPOR_MSG_DELETE, file_id, 32, SWPOR_MSG_OK, &resp, &rl);
    free(resp);
    return rc;
}
