/* 磁盘格式（SPEC 6）与通用文件读写（SPEC 7）。 */

#include "swpor/store.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>

#include "platform.h"
#include "swpor/error.h"
#include "swpor/params.h"

#define PATH_CAP 4096

struct swpor_store {
    char dir[PATH_CAP];
    swpor_file_t *blocks;
    swpor_file_t *sigmas;
    uint8_t scheme;
    uint64_t n;
    uint16_t s;
    size_t bb;
    size_t sb;
    uint8_t tag[SWPOR_TAG_MAX_BYTES];
    size_t tag_len;
    swpor_tag_header_t hdr;
};

static int file_dir(const char *root, const uint8_t file_id[32], char *out)
{
    char hex[65];
    swpor_hex_encode(file_id, 32, hex);
    return swpor_path_join(out, PATH_CAP, root, hex);
}

static int sub_path(const swpor_store_t *st, const char *name, char *out)
{
    return swpor_path_join(out, PATH_CAP, st->dir, name);
}

static void encode_file_header(uint8_t out[8], int is_sigma, uint8_t scheme)
{
    memcpy(out, is_sigma ? "SWPS" : "SWPB", 4);
    out[4] = SWPOR_FORMAT_VERSION;
    out[5] = is_sigma ? scheme : 0;
    out[6] = 0;
    out[7] = 0;
}

void swpor_store_close(swpor_store_t *st)
{
    if (st == NULL) {
        return;
    }
    swpor_file_close(st->blocks);
    swpor_file_close(st->sigmas);
    free(st);
}

int swpor_store_create(const char *root, const uint8_t file_id[32], uint8_t scheme, uint64_t n,
                       uint16_t s, swpor_store_t **out)
{
    if (root == NULL || file_id == NULL || out == NULL || n == 0 || n >= SWPOR_MAX_BLOCKS ||
        s == 0 || swpor_sigma_bytes(scheme) == 0) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_store_t *st = calloc(1, sizeof(*st));
    if (st == NULL) {
        return SWPOR_E_NOMEM;
    }
    st->scheme = scheme;
    st->n = n;
    st->s = s;
    st->bb = swpor_block_bytes(s);
    st->sb = swpor_sigma_bytes(scheme);
    char path[PATH_CAP];
    uint8_t fh[8];
    int rc = file_dir(root, file_id, st->dir);
    if (rc == SWPOR_OK) {
        rc = swpor_mkdir_p(st->dir);
    }
    /* 若已存在旧的 tag.bin，先删除，保证"tag.bin 存在即完整" */
    if (rc == SWPOR_OK && (rc = sub_path(st, "tag.bin", path)) == SWPOR_OK) {
        int r2 = swpor_remove_file(path);
        if (r2 != SWPOR_OK && r2 != SWPOR_E_NOT_FOUND) {
            rc = r2;
        }
    }
    if (rc == SWPOR_OK && (rc = sub_path(st, "blocks.dat", path)) == SWPOR_OK) {
        rc = swpor_file_open(path, SWPOR_FILE_CREATE, &st->blocks);
    }
    if (rc == SWPOR_OK) {
        encode_file_header(fh, 0, scheme);
        rc = swpor_file_pwrite(st->blocks, fh, sizeof(fh), 0);
    }
    if (rc == SWPOR_OK && (rc = sub_path(st, "sigma.dat", path)) == SWPOR_OK) {
        rc = swpor_file_open(path, SWPOR_FILE_CREATE, &st->sigmas);
    }
    if (rc == SWPOR_OK) {
        encode_file_header(fh, 1, scheme);
        rc = swpor_file_pwrite(st->sigmas, fh, sizeof(fh), 0);
    }
    if (rc != SWPOR_OK) {
        swpor_store_close(st);
        return rc;
    }
    *out = st;
    return SWPOR_OK;
}

static int check_file(swpor_file_t *f, int is_sigma, uint8_t scheme, uint64_t payload)
{
    uint8_t fh[8];
    uint8_t expect[8];
    uint64_t size = 0;
    int rc = swpor_file_pread(f, fh, sizeof(fh), 0);
    if (rc != SWPOR_OK) {
        return SWPOR_E_PARSE;
    }
    encode_file_header(expect, is_sigma, scheme);
    if (memcmp(fh, expect, sizeof(fh)) != 0) {
        return SWPOR_E_PARSE;
    }
    rc = swpor_file_size(f, &size);
    if (rc != SWPOR_OK) {
        return rc;
    }
    return size == SWPOR_STORE_FILE_HEADER_BYTES + payload ? SWPOR_OK : SWPOR_E_PARSE;
}

int swpor_store_open(const char *root, const uint8_t file_id[32], int writable,
                     swpor_store_t **out)
{
    if (root == NULL || file_id == NULL || out == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_store_t *st = calloc(1, sizeof(*st));
    if (st == NULL) {
        return SWPOR_E_NOMEM;
    }
    char path[PATH_CAP];
    uint8_t *tag = NULL;
    size_t tag_len = 0;
    const swpor_file_mode_t mode = writable ? SWPOR_FILE_RDWR : SWPOR_FILE_READ;
    int rc = file_dir(root, file_id, st->dir);
    if (rc == SWPOR_OK && (rc = sub_path(st, "tag.bin", path)) == SWPOR_OK) {
        rc = swpor_read_file(path, SWPOR_TAG_MAX_BYTES, &tag, &tag_len);
        if (rc == SWPOR_E_RANGE) {
            rc = SWPOR_E_PARSE;
        }
    }
    if (rc == SWPOR_OK) {
        rc = swpor_tag_header_decode(tag, tag_len, &st->hdr);
    }
    if (rc == SWPOR_OK && memcmp(st->hdr.file_id, file_id, 32) != 0) {
        rc = SWPOR_E_PARSE;
    }
    if (rc == SWPOR_OK) {
        memcpy(st->tag, tag, tag_len);
        st->tag_len = tag_len;
        st->scheme = st->hdr.scheme;
        st->n = st->hdr.n;
        st->s = st->hdr.s;
        st->bb = swpor_block_bytes(st->s);
        st->sb = swpor_sigma_bytes(st->scheme);
    }
    if (rc == SWPOR_OK && (rc = sub_path(st, "blocks.dat", path)) == SWPOR_OK) {
        rc = swpor_file_open(path, mode, &st->blocks);
    }
    if (rc == SWPOR_OK) {
        rc = check_file(st->blocks, 0, st->scheme, st->n * st->bb);
    }
    if (rc == SWPOR_OK && (rc = sub_path(st, "sigma.dat", path)) == SWPOR_OK) {
        rc = swpor_file_open(path, mode, &st->sigmas);
    }
    if (rc == SWPOR_OK) {
        rc = check_file(st->sigmas, 1, st->scheme, st->n * st->sb);
    }
    free(tag);
    if (rc != SWPOR_OK) {
        swpor_store_close(st);
        return rc;
    }
    *out = st;
    return SWPOR_OK;
}

int swpor_store_write_block(swpor_store_t *st, uint64_t i, const uint8_t *block)
{
    if (st == NULL || block == NULL || i >= st->n) {
        return SWPOR_E_INVALID_ARG;
    }
    return swpor_file_pwrite(st->blocks, block, st->bb, SWPOR_STORE_FILE_HEADER_BYTES + i * st->bb);
}

int swpor_store_write_sigma(swpor_store_t *st, uint64_t i, const uint8_t *sigma)
{
    if (st == NULL || sigma == NULL || i >= st->n) {
        return SWPOR_E_INVALID_ARG;
    }
    return swpor_file_pwrite(st->sigmas, sigma, st->sb, SWPOR_STORE_FILE_HEADER_BYTES + i * st->sb);
}

int swpor_store_write_tag(swpor_store_t *st, const uint8_t *tag, size_t len)
{
    if (st == NULL || tag == NULL || len > SWPOR_TAG_MAX_BYTES) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_tag_header_t h;
    int rc = swpor_tag_header_decode(tag, len, &h);
    if (rc != SWPOR_OK) {
        return rc;
    }
    if (h.n != st->n || h.s != st->s || h.scheme != st->scheme) {
        return SWPOR_E_INVALID_ARG;
    }
    rc = swpor_store_sync(st);
    char tmp[PATH_CAP];
    char path[PATH_CAP];
    if (rc == SWPOR_OK && (rc = sub_path(st, "tag.bin.tmp", tmp)) == SWPOR_OK &&
        (rc = sub_path(st, "tag.bin", path)) == SWPOR_OK) {
        rc = swpor_write_file(tmp, tag, len);
    }
    if (rc == SWPOR_OK) {
        rc = swpor_rename(tmp, path);
    }
    if (rc == SWPOR_OK) {
        memcpy(st->tag, tag, len);
        st->tag_len = len;
        st->hdr = h;
    }
    return rc;
}

int swpor_store_read_block(swpor_store_t *st, uint64_t i, uint8_t *block)
{
    if (st == NULL || block == NULL || i >= st->n) {
        return SWPOR_E_RANGE;
    }
    return swpor_file_pread(st->blocks, block, st->bb, SWPOR_STORE_FILE_HEADER_BYTES + i * st->bb);
}

int swpor_store_read_sigma(swpor_store_t *st, uint64_t i, uint8_t *sigma)
{
    if (st == NULL || sigma == NULL || i >= st->n) {
        return SWPOR_E_RANGE;
    }
    return swpor_file_pread(st->sigmas, sigma, st->sb, SWPOR_STORE_FILE_HEADER_BYTES + i * st->sb);
}

const uint8_t *swpor_store_tag(const swpor_store_t *st, size_t *len)
{
    if (len != NULL) {
        *len = st->tag_len;
    }
    return st->tag_len > 0 ? st->tag : NULL;
}

const swpor_tag_header_t *swpor_store_header(const swpor_store_t *st)
{
    return &st->hdr;
}

size_t swpor_store_block_bytes(const swpor_store_t *st)
{
    return st->bb;
}

size_t swpor_store_sigma_bytes(const swpor_store_t *st)
{
    return st->sb;
}

uint64_t swpor_store_n(const swpor_store_t *st)
{
    return st->n;
}

int swpor_store_sync(swpor_store_t *st)
{
    if (st == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    int rc = swpor_file_sync(st->blocks);
    if (rc == SWPOR_OK) {
        rc = swpor_file_sync(st->sigmas);
    }
    return rc;
}

int swpor_store_delete(const char *root, const uint8_t file_id[32])
{
    if (root == NULL || file_id == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    char dir[PATH_CAP];
    char path[PATH_CAP];
    int rc = file_dir(root, file_id, dir);
    if (rc != SWPOR_OK) {
        return rc;
    }
    if (!swpor_path_exists(dir)) {
        return SWPOR_E_NOT_FOUND;
    }
    static const char *const names[] = {"tag.bin", "tag.bin.tmp", "blocks.dat", "sigma.dat"};
    for (size_t k = 0; k < sizeof(names) / sizeof(names[0]); k++) {
        if (swpor_path_join(path, sizeof(path), dir, names[k]) != SWPOR_OK) {
            return SWPOR_E_RANGE;
        }
        int r2 = swpor_remove_file(path);
        if (r2 != SWPOR_OK && r2 != SWPOR_E_NOT_FOUND) {
            return r2;
        }
    }
    return swpor_remove_dir(dir);
}

int swpor_store_reader(void *user, uint64_t i, uint8_t *block, size_t block_len, uint8_t *sigma,
                       size_t sigma_len)
{
    swpor_store_t *st = user;
    if (st == NULL || block_len != st->bb || sigma_len != st->sb) {
        return SWPOR_E_INVALID_ARG;
    }
    int rc = swpor_store_read_block(st, i, block);
    if (rc == SWPOR_OK) {
        rc = swpor_store_read_sigma(st, i, sigma);
    }
    return rc;
}

/* ===================================================================== */
/* 通用文件读写                                                            */
/* ===================================================================== */

int swpor_read_file(const char *path, size_t max_len, uint8_t **out, size_t *len)
{
    if (path == NULL || out == NULL || len == NULL) {
        return SWPOR_E_INVALID_ARG;
    }
    swpor_file_t *f = NULL;
    int rc = swpor_file_open(path, SWPOR_FILE_READ, &f);
    if (rc != SWPOR_OK) {
        return rc;
    }
    uint64_t size = 0;
    uint8_t *buf = NULL;
    rc = swpor_file_size(f, &size);
    if (rc == SWPOR_OK && size > max_len) {
        rc = SWPOR_E_RANGE;
    }
    if (rc == SWPOR_OK) {
        buf = malloc(size > 0 ? (size_t)size : 1u);
        rc = buf == NULL ? SWPOR_E_NOMEM : swpor_file_pread(f, buf, (size_t)size, 0);
    }
    swpor_file_close(f);
    if (rc != SWPOR_OK) {
        free(buf);
        return rc;
    }
    *out = buf;
    *len = (size_t)size;
    return SWPOR_OK;
}

int swpor_write_file(const char *path, const uint8_t *data, size_t len)
{
    swpor_file_t *f = NULL;
    int rc = swpor_file_open(path, SWPOR_FILE_CREATE, &f);
    if (rc == SWPOR_OK) {
        rc = swpor_file_pwrite(f, data, len, 0);
        if (rc == SWPOR_OK) {
            rc = swpor_file_sync(f);
        }
        swpor_file_close(f);
    }
    return rc;
}

int swpor_write_secret_file(const char *path, const uint8_t *data, size_t len, int force)
{
    swpor_file_t *f = NULL;
    int rc = swpor_file_create_private(path, force, &f);
    if (rc == SWPOR_OK) {
        rc = swpor_file_pwrite(f, data, len, 0);
        if (rc == SWPOR_OK) {
            rc = swpor_file_sync(f);
        }
        swpor_file_close(f);
    }
    return rc;
}
