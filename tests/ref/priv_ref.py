#!/usr/bin/env python3
"""
Priv 方案的 Python 参考实现（SPEC 3.1、3.3、3.5.2、4.1），用于差分测试 T-03。

只用 Python 标准库和大整数，逐条照抄 SPEC 公式，刻意不做任何优化，
以便与 C 实现（blst Montgomery 域运算）独立对照。

仅用于测试：不做常数时间处理，不得用于实际数据。
"""

import hashlib
import hmac

# BLS12-381 标量域阶 r（SPEC 0）
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

SECTOR_BYTES = 31


def i2osp(x: int, k: int) -> bytes:
    return x.to_bytes(k, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def prf(key: bytes, i: int, dst: bytes = b"SWPOR-PRF-V1") -> int:
    """f_k(i) = OS2IP(HMAC-SHA-512(k, dst ‖ I2OSP(i, 8))) mod r（SPEC 3.3）"""
    return os2ip(hmac.new(key, dst + i2osp(i, 8), hashlib.sha512).digest()) % R


def alphas(k_alpha: bytes, s: int) -> list:
    """α_j = f_{k_alpha}(j)，域分隔串 SWPOR-ALPHA-V1（SPEC 3.3）"""
    return [prf(k_alpha, j, b"SWPOR-ALPHA-V1") for j in range(s)]


def sectors(block: bytes, s: int) -> list:
    """31 字节大端扇区 → Z_r（SPEC 3.1）"""
    assert len(block) == SECTOR_BYTES * s
    return [os2ip(block[j * SECTOR_BYTES:(j + 1) * SECTOR_BYTES]) for j in range(s)]


def tag_block(k_prf: bytes, alpha: list, i: int, block: bytes) -> int:
    """σ_i = f_{k_prf}(i) + Σ α_j · m_ij (mod r)（SPEC 4.1 Priv.St 第 4 步）"""
    m = sectors(block, len(alpha))
    return (prf(k_prf, i) + sum(a * x for a, x in zip(alpha, m))) % R


class HStream:
    """stream = HMAC-SHA-256(key, dst ‖ I2OSP(ctr, 8))，ctr = 0,1,2,… 顺序拼接（SPEC 3.5.2）"""

    def __init__(self, key: bytes, dst: bytes):
        self.key, self.dst, self.ctr, self.buf = key, dst, 0, b""

    def read(self, n: int) -> bytes:
        while len(self.buf) < n:
            self.buf += hmac.new(self.key, self.dst + i2osp(self.ctr, 8), hashlib.sha256).digest()
            self.ctr += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def uniform(stream: HStream, bound: int) -> int:
    """拒绝 x >= ⌊2^64 / bound⌋·bound 后取模（SPEC 3.5.2）"""
    limit = (2 ** 64 // bound) * bound
    while True:
        x = os2ip(stream.read(8))
        if x < limit:
            return x % bound


def seed_challenge(seed: bytes, n: int, l: int) -> list:
    """种子挑战展开（SPEC 3.5.2），返回按下标升序的 [(i, ν_i)]"""
    st = HStream(seed, b"SWPOR-CHAL-V1")
    if l >= n:
        idx = list(range(n))
    else:
        idx, seen = [], set()
        while len(idx) < l:
            v = uniform(st, n)
            if v not in seen:
                seen.add(v)
                idx.append(v)
    nus = []
    for _ in idx:
        while True:
            nu = os2ip(st.read(16))
            if nu != 0:
                break
        nus.append(nu)
    return sorted(zip(idx, nus))


def prove(blocks: list, sigmas: list, chal: list, s: int):
    """μ_j = Σ ν_i · m_ij，σ = Σ ν_i · σ_i (mod r)（SPEC 4.1 Priv.P）"""
    mu = [0] * s
    sig = 0
    for i, nu in chal:
        m = sectors(blocks[i], s)
        for j in range(s):
            mu[j] = (mu[j] + nu * m[j]) % R
        sig = (sig + nu * sigmas[i]) % R
    return mu, sig


def verify(k_prf: bytes, alpha: list, chal: list, mu: list, sig: int) -> bool:
    """σ == Σ ν_i · f(i) + Σ α_j · μ_j (mod r)（SPEC 4.1 Priv.V 第 5 步）"""
    rhs = (sum(nu * prf(k_prf, i) for i, nu in chal) +
           sum(a * m for a, m in zip(alpha, mu))) % R
    return rhs == sig
