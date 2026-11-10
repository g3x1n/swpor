# src/ec — 文件预处理流水线（M2）

实现 SPEC 5：可选的 AES-256-CTR 文件加密 → 条带 RS(k, m) 纠删码（ISA-L）→ 可选的秘密置乱，以及逆过程（文件恢复）。
ISA-L 依赖在 M2 开始时加入 `vcpkg.json` 与 CMake。对应测试：T-10～T-13。
注意 SPEC 5 中的安全性说明与 OPEN-1。
