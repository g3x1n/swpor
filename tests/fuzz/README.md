# tests/fuzz — 模糊测试（M3 起）

libFuzzer 目标：`PROOF` 解析、`CHALLENGE` 解析、文件标签解析（SPEC 10.4）。
macOS 上需要使用 Homebrew 的 LLVM 编译（Apple Clang 不带 libFuzzer）：

```bash
cmake -S . -B build/fuzz -DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang -DSWPOR_FUZZ=ON
```

（`SWPOR_FUZZ` 选项在添加第一个 fuzz 目标时加入 CMake。）
