# tests/fuzz — 模糊测试（SPEC 10.4）

三个 libFuzzer 目标：

| 目标 | 内容 |
|---|---|
| `fuzz_proof` | PROOF 解析与验证（Priv / Pub，含 G1 点解压与子群检查） |
| `fuzz_challenge` | CHALLENGE 消息解析与挑战展开（`swpor_chal_decode_wire`） |
| `fuzz_tag` | 文件标签解析：明文头、Priv AES-GCM 解密、Pub Ed25519 验签 |

## 冒烟测试（任何编译器）

默认构建会生成 `fuzz_*_smoke` 程序（同样的目标 + `standalone_main.c` 驱动），由 ctest 每次运行
2000 个随机输入。也可以把崩溃用例文件作为参数复现：`build/debug/tests/fuzz_tag_smoke crash-xxx`。

## 正式模糊测试（libFuzzer）

macOS 上需要 Homebrew 的 LLVM（Apple Clang 不带 libFuzzer）：

```bash
cmake -S . -B build/fuzz -G Ninja -DCMAKE_BUILD_TYPE=Debug -DSWPOR_FUZZ=ON \
      -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang
cmake --build build/fuzz
./build/fuzz/tests/fuzz_proof -max_total_time=3600 corpus/proof/
```

SPEC 10.4 要求每个目标至少运行 1 小时无崩溃，结果记入测试报告。
