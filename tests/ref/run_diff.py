#!/usr/bin/env python3
"""
差分测试 T-03：C 实现（tests/ref_dump）与 Python 参考实现（priv_ref.py）逐字节对比。

用法：python3 tests/ref/run_diff.py <构建目录，如 build/debug/> [--cases N] [--seed S]

每组用例随机生成 k_prf、k_alpha、挑战种子、文件数据及 (n, s, l)，比较：
  每个 σ_i、种子挑战展开的 (i, ν_i)、每个 μ_j、聚合 σ，以及验证结果。
随机参数由 --seed 决定，便于复现失败用例。退出码 0 表示全部一致。
"""

import argparse
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import priv_ref as ref  # noqa: E402


def find_dump(build_dir: str) -> str:
    for cand in ("tests/ref_dump", "tests/ref_dump.exe", "tests/Debug/ref_dump.exe",
                 "tests/Release/ref_dump.exe"):
        p = os.path.join(build_dir, cand)
        if os.path.exists(p):
            return p
    sys.exit(f"找不到 ref_dump，请先构建：{build_dir}")


def run_case(dump: str, rng: random.Random, n: int, s: int, l: int) -> list:
    k_prf = rng.randbytes(32)
    k_alpha = rng.randbytes(32)
    seed = rng.randbytes(32)
    data = rng.randbytes(n * 31 * s)
    if rng.random() < 0.2:  # 边界值：全 0xFF 扇区
        data = b"\xff" * len(data)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        out = subprocess.run(
            [dump, k_prf.hex(), k_alpha.hex(), str(s), str(n), seed.hex(), str(l), path],
            check=True, capture_output=True, text=True).stdout
    finally:
        os.unlink(path)

    # Python 参考结果
    alpha = ref.alphas(k_alpha, s)
    blocks = [data[i * 31 * s:(i + 1) * 31 * s] for i in range(n)]
    sigmas = [ref.tag_block(k_prf, alpha, i, blocks[i]) for i in range(n)]
    chal = ref.seed_challenge(seed, n, l)
    mu, sig = ref.prove(blocks, sigmas, chal, s)
    ok = ref.verify(k_prf, alpha, chal, mu, sig)

    expect = [f"sigma {i} {v:064x}" for i, v in enumerate(sigmas)]
    expect += [f"chal {i} {nu:032x}" for i, nu in chal]
    expect += [f"mu {j} {v:064x}" for j, v in enumerate(mu)]
    expect += [f"proof_sigma {sig:064x}", f"verify {'PASS' if ok else 'FAIL'}"]

    got = out.strip().splitlines()
    errors = []
    if len(got) != len(expect):
        errors.append(f"行数不同：C={len(got)} Python={len(expect)}")
    for a, b in zip(got, expect):
        if a != b:
            errors.append(f"C: {a}\n    Py: {b}")
            break
    if not ok:
        errors.append("Python 参考实现验证未通过")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("build_dir")
    ap.add_argument("--cases", type=int, default=30)
    ap.add_argument("--seed", type=int, default=20261110)
    args = ap.parse_args()

    dump = find_dump(args.build_dir)
    rng = random.Random(args.seed)
    fixed = [(1, 1, 1), (1, 4, 3), (5, 2, 5), (5, 2, 100), (64, 8, 16), (10, 128, 4)]
    cases = fixed + [(rng.randint(1, 60), rng.randint(1, 40), rng.randint(1, 70))
                     for _ in range(args.cases)]
    failed = 0
    for idx, (n, s, l) in enumerate(cases):
        errs = run_case(dump, rng, n, s, l)
        if errs:
            failed += 1
            print(f"[FAIL] case {idx}: n={n} s={s} l={l}")
            for e in errs:
                print("    " + e)
    print(f"T-03 差分测试：{len(cases) - failed}/{len(cases)} 组一致（seed={args.seed}）")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
