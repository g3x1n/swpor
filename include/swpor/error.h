#ifndef SWPOR_ERROR_H
#define SWPOR_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 错误码约定（见 CLAUDE.md "编码规范"）：
 *   - 成功返回 SWPOR_OK（0），失败返回负值。
 *   - 注意："审计不通过"不是错误。验证函数正常执行完毕时返回 SWPOR_OK，
 *     审计结果（PASS/FAIL）通过输出参数返回。
 */
typedef enum {
    SWPOR_OK = 0,
    SWPOR_E_INVALID_ARG = -1,      /* 参数非法（空指针、参数越界等） */
    SWPOR_E_NOMEM = -2,            /* 内存分配失败 */
    SWPOR_E_IO = -3,               /* 文件读写失败 */
    SWPOR_E_PARSE = -4,            /* 格式解析失败、非规范编码（如域元素 >= r） */
    SWPOR_E_TAG_AUTH = -5,         /* 文件标签认证失败（Priv 解密失败 / Pub 验签失败） */
    SWPOR_E_CRYPTO = -6,           /* 底层密码库调用失败 */
    SWPOR_E_RANGE = -7,            /* 下标或长度越界（如 n 过大、挑战下标 >= n） */
    SWPOR_E_UNSUPPORTED = -8,      /* 不支持的版本、方案或参数 */
    SWPOR_E_NET = -9,              /* 网络错误 */
    SWPOR_E_TIMEOUT = -10,         /* 超时 */
    SWPOR_E_BUSY = -11,            /* 服务端繁忙（任务队列已满，见 SPEC 8.4） */
    SWPOR_E_EXISTS = -12,          /* 目标已存在（如密钥文件，未指定 --force） */
    SWPOR_E_NOT_FOUND = -13,       /* 目标不存在（如 file_id 未知） */
    SWPOR_E_DECODE = -14,          /* 纠删码解码失败（损坏块超过可恢复上限） */
    SWPOR_E_NOT_IMPLEMENTED = -99  /* 尚未实现（骨架阶段占位） */
} swpor_err_t;

/**
 * 返回错误码对应的英文描述字符串（静态存储，调用方不得释放）。
 * 未知错误码返回 "unknown error"。
 */
const char *swpor_strerror(int err);

#ifdef __cplusplus
}
#endif

#endif /* SWPOR_ERROR_H */
