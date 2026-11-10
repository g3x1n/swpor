#ifndef SWPOR_KEYFILE_H
#define SWPOR_KEYFILE_H

/*
 * 密钥文件格式（SPEC 7）：
 *   priv.key  "SWSK" ‖ version ‖ scheme=1 ‖ msk(32)                       权限 0600
 *   pub.sk    "SWSK" ‖ version ‖ scheme=2 ‖ x(32, 大端) ‖ ed25519_sk(32)    权限 0600
 *   pub.pk    "SWPK" ‖ version ‖ scheme=2 ‖ v(96, 压缩 G2) ‖ ed25519_pk(32) 权限 0644
 */

#include <stdint.h>

#include "swpor/priv.h"
#include "swpor/pub.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SWPOR_KEYFILE_SECRET 1
#define SWPOR_KEYFILE_PUBLIC 2

/**
 * 读取密钥文件的类型。
 * @param kind    输出：SWPOR_KEYFILE_SECRET / SWPOR_KEYFILE_PUBLIC
 * @param scheme  输出：SWPOR_SCHEME_PRIV / SWPOR_SCHEME_PUB
 */
int swpor_keyfile_probe(const char *path, int *kind, uint8_t *scheme);

/** 保存 Priv 密钥（priv.key）。force = 0 时不覆盖已有文件。 */
int swpor_keyfile_save_priv(const char *path, const swpor_priv_key_t *key, int force);

/** 读取 Priv 密钥。 */
int swpor_keyfile_load_priv(const char *path, swpor_priv_key_t **out);

/** 保存 Pub 私钥（pub.sk）。 */
int swpor_keyfile_save_pub_sk(const char *path, const swpor_pub_sk_t *sk, int force);

/** 保存 Pub 公钥（pub.pk，权限 0644，可覆盖由 force 控制）。 */
int swpor_keyfile_save_pub_pk(const char *path, const swpor_pub_pk_t *pk, int force);

/** 读取 Pub 私钥。 */
int swpor_keyfile_load_pub_sk(const char *path, swpor_pub_sk_t **out);

/** 读取 Pub 公钥（v 做 G2 曲线与子群检查）。 */
int swpor_keyfile_load_pub_pk(const char *path, swpor_pub_pk_t **out);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_KEYFILE_H */
