#ifndef SWPOR_CORE_PROOF_H
#define SWPOR_CORE_PROOF_H

/* 证明编码的内部辅助函数（SPEC 8.3 PROOF：s u16 ‖ s × μ_j(32B) ‖ σ）。 */

#include <stddef.h>
#include <stdint.h>

#include "fr.h"

/**
 * 校验证明总长度与 s 字段，并解析 s 个 μ_j（必须是规范 Z_r 编码）。
 * σ 部分由调用方按方案解析，位于 proof + 2 + 32·s。
 * @return 格式错误返回 SWPOR_E_PARSE
 */
int swpor_proof_parse_mu(const uint8_t *proof, size_t len, uint8_t scheme, uint16_t s,
                         swpor_fr_t *mu);

/** 把 16 字节大端 ν 转为 blst 多标量乘需要的小端字节序。 */
void swpor_nu_to_le(const uint8_t be[16], uint8_t le[16]);

#endif /* SWPOR_CORE_PROOF_H */
