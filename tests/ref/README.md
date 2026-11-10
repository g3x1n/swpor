# tests/ref — Python 参考实现（差分测试，T-03）

用 Python 标准库（大整数、`hmac`、`hashlib`）按 SPEC 3、4.1 独立实现 Priv 方案的
σ_i、μ_j、σ 计算，与 C 实现对同一输入的输出逐字节比对。

文件：
- `priv_ref.py`：参考实现
- `run_diff.py`：生成随机测试向量，调用 C 程序，比对结果；用法 `python3 tests/ref/run_diff.py build/debug/ [--cases N] [--seed S]`
- `ref_dump.c`：C 端，输出 σ_i、挑战展开、μ_j、σ 与验证结果（仅测试用）

参考实现只用于测试，不追求性能。
