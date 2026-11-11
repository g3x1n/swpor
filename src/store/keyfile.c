/* 密钥文件（SPEC 7）。 */

#include "swpor/keyfile.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "platform.h"
#include "swpor/error.h"
#include "swpor/params.h"
#include "swpor/store.h"

#define PRIV_KEY_BYTES (6u + 32u)
#define PUB_SK_BYTES (6u + 32u + 32u)
#define PUB_PK_BYTES (6u + 96u + 32u)

static void put_head(uint8_t *out, int secret, uint8_t scheme)
{
    memcpy(out, secret ? "SWSK" : "SWPK", 4);
    out[4] = SWPOR_FORMAT_VERSION;
    out[5] = scheme;
}

/* 读取并校验文件头与长度。成功时 *buf 由调用方清零并释放 */
static int load(const char *path, int secret, uint8_t scheme, size_t expect, uint8_t **buf)
{
    size_t len = 0;
    int rc = swpor_read_file(path, 1024, buf, &len);
    if (rc == SWPOR_E_RANGE) {
        return SWPOR_E_PARSE;
    }
    if (rc != SWPOR_OK) {
        return rc;
    }
    uint8_t head[6];
    put_head(head, secret, scheme);
    if (len != expect || memcmp(*buf, head, 6) != 0) {
        OPENSSL_cleanse(*buf, len);
        free(*buf);
        *buf = NULL;
        return SWPOR_E_PARSE;
    }
    return SWPOR_OK;
}

int swpor_keyfile_probe(const char *path, int *kind, uint8_t *scheme)
{
    if (path == NULL || kind == NULL || scheme == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t *buf = NULL;
    size_t len = 0;
    int rc = swpor_read_file(path, 1024, &buf, &len);
    if (rc == SWPOR_E_RANGE) {
        return SWPOR_E_PARSE;
    }
    if (rc != SWPOR_OK) {
        return rc;
    }
    rc = SWPOR_E_PARSE;
    if (len >= 6 && buf[4] == SWPOR_FORMAT_VERSION) {
        if (memcmp(buf, "SWSK", 4) == 0) {
            *kind = SWPOR_KEYFILE_SECRET;
            rc = SWPOR_OK;
        } else if (memcmp(buf, "SWPK", 4) == 0) {
            *kind = SWPOR_KEYFILE_PUBLIC;
            rc = SWPOR_OK;
        }
        *scheme = buf[5];
        if (*scheme != SWPOR_SCHEME_PRIV && *scheme != SWPOR_SCHEME_PUB) {
            rc = SWPOR_E_UNSUPPORTED;
        }
    }
    OPENSSL_cleanse(buf, len);
    free(buf);
    return rc;
}

int swpor_keyfile_save_priv(const char *path, const swpor_priv_key_t *key, int force)
{
    if (path == NULL || key == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t buf[PRIV_KEY_BYTES];
    put_head(buf, 1, SWPOR_SCHEME_PRIV);
    swpor_priv_key_export(key, buf + 6);
    int rc = swpor_write_secret_file(path, buf, sizeof(buf), force);
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

int swpor_keyfile_load_priv(const char *path, swpor_priv_key_t **out)
{
    uint8_t *buf = NULL;
    int rc = load(path, 1, SWPOR_SCHEME_PRIV, PRIV_KEY_BYTES, &buf);
    if (rc != SWPOR_OK) {
        return rc;
    }
    rc = swpor_priv_key_from_msk(buf + 6, out);
    OPENSSL_cleanse(buf, PRIV_KEY_BYTES);
    free(buf);
    return rc;
}

int swpor_keyfile_save_pub_sk(const char *path, const swpor_pub_sk_t *sk, int force)
{
    if (path == NULL || sk == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t buf[PUB_SK_BYTES];
    put_head(buf, 1, SWPOR_SCHEME_PUB);
    int rc = swpor_pub_sk_export(sk, buf + 6, buf + 38);
    if (rc == SWPOR_OK) {
        rc = swpor_write_secret_file(path, buf, sizeof(buf), force);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

int swpor_keyfile_save_pub_pk(const char *path, const swpor_pub_pk_t *pk, int force)
{
    if (path == NULL || pk == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    uint8_t buf[PUB_PK_BYTES];
    put_head(buf, 0, SWPOR_SCHEME_PUB);
    int rc = swpor_pub_pk_export(pk, buf + 6, buf + 102);
    if (rc != SWPOR_OK) {
        return rc;
    }
    if (!force && swpor_path_exists(path)) {
        return SWPOR_E_EXISTS;
    }
    return swpor_write_file(path, buf, sizeof(buf));
}

int swpor_keyfile_load_pub_sk(const char *path, swpor_pub_sk_t **out)
{
    uint8_t *buf = NULL;
    int rc = load(path, 1, SWPOR_SCHEME_PUB, PUB_SK_BYTES, &buf);
    if (rc != SWPOR_OK) {
        return rc;
    }
    rc = swpor_pub_sk_import(buf + 6, buf + 38, out);
    OPENSSL_cleanse(buf, PUB_SK_BYTES);
    free(buf);
    return rc;
}

int swpor_keyfile_load_pub_pk(const char *path, swpor_pub_pk_t **out)
{
    uint8_t *buf = NULL;
    int rc = load(path, 0, SWPOR_SCHEME_PUB, PUB_PK_BYTES, &buf);
    if (rc != SWPOR_OK) {
        return rc;
    }
    rc = swpor_pub_pk_import(buf + 6, buf + 102, out);
    free(buf);
    return rc;
}
