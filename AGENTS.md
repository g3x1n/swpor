# CLAUDE.md

本文件写给在本仓库中工作的 coding agent。环境配置、发布流程、报告要求见文末「其他文档」。

## 项目概述

**swpor**：用 C11 实现 Shacham–Waters《Compact Proofs of Retrievability》（Asiacrypt 2008）的私有验证方案（Priv）和公开验证方案（Pub），并构建三方数据审计系统：

- `libswpor`（`src/`）：核心算法库
- `porctl`：数据所有者客户端；`pord`：存储服务端；`porta`：第三方审计者；`porbench`：基准测试

代码将用于课程作业、软件著作权申请和论文实验，因此要求注释完整、实验可复现。

## 事实来源

- **`SPEC.md` 是唯一的事实来源**：算法公式、参数、文件格式、网络协议、命令行接口都以它为准。开始任务前阅读与任务相关的 SPEC 章节。
- 论文 PDF 在 `docs/paper/`。SPEC 与论文不一致时以 SPEC 为准（有意的偏离和勘误记录在 SPEC 第 2、12 节）。
- 发现 SPEC 有错误、歧义或需要改动时：**停下来，向用户说明问题并提出修改方案**。用户确认后先改 SPEC（在第 14 节登记），再改代码。
- SPEC 第 13 节的 OPEN 问题，没有用户的决定不要自行拍板。

## 硬性规则（不可违反）

1. **不手写密码学原语。** 域/群运算、配对、哈希到曲线、HMAC、HKDF、AES-GCM、Ed25519、随机数一律调用 blst 或 OpenSSL。本项目只写把原语按 SPEC 组合起来的协议逻辑。
2. **随机数只用 `RAND_bytes`。** 不用 `rand()`、`random()`、`time()` 作随机源。测试用的确定性随机数只能在 `SWPOR_TESTING` 宏下编译。
3. **外部输入都不可信。** 网络、磁盘、命令行数据都要做长度和范围检查；域元素检查规范性（< r）；群元素做曲线检查和子群检查（SPEC 第 11 节）。
4. **秘密数据**用完后用 `OPENSSL_cleanse` 清零，不得出现在日志、错误信息、`--json` 输出或测试快照中。
5. **秘密数据的比较用 `CRYPTO_memcmp`**，不用 `memcmp`。避免依赖秘密值的分支和查表。
6. **不提供去掉挑战系数 ν_i 的"优化"**（论文附录 B 有攻击）。
7. **不得为了让测试通过而修改测试的期望值。** 测试失败时先判断是实现错还是测试错，向用户说明理由。
8. **不编造参考文献、数据或实验结果。** 性能数字只能来自实际运行的 `porbench` 输出。
9. **不要调用或"补造"尚不存在的脚本、文件和命令。** 本文件中标注「待实现」的内容，需要时先问用户。

## 平台与依赖

- 平台：macOS arm64、Linux x86_64 为 Tier 1；Windows x64 为 Tier 2（只做客户端，不构建 `pord`）。改动不能破坏任何平台的构建。
- **平台抽象层**：只有 `src/platform/` 可以包含操作系统头文件（`<unistd.h>`、`<pthread.h>`、`<sys/socket.h>`、`<windows.h>`、`<winsock2.h>` 等），也只有这里可以出现 `#ifdef _WIN32` / `__APPLE__` / `__linux__`。其他代码通过 `swpor_sock_*`、`swpor_thread_*`、`swpor_file_*` 等接口使用系统功能。
- 禁用：`epoll`、`kqueue`、`getrandom`、`fork`、`mmap`、C11 `<threads.h>`、变长数组（VLA）、`ssize_t`（用 `int64_t`）。
- 二进制文件用 `"rb"` / `"wb"` 打开；打印 `uint64_t` 用 `PRIu64`。
- 依赖：
  - **blst**（git submodule，`third_party/blst`）：调用前查阅 `third_party/blst/bindings/blst.h`，以头文件为准，不要凭记忆写函数签名。
  - **OpenSSL 3.x**：只用 EVP 高层接口，不用已弃用的底层接口。
  - **ISA-L**：Reed–Solomon 纠删码。
  - **cmocka**：单元测试。Python 参考实现只用标准库。
  - 除 blst 外，依赖由 vcpkg 清单模式（`vcpkg.json`）管理。**引入新依赖前先问用户。**

## 目录与分层

```
include/swpor/   公开头文件          src/platform/  平台抽象层（POSIX / Win32）
src/core/        域封装、PRF、编码、挑战生成、错误码
src/priv/  src/pub/  两个方案       src/ec/  纠删码与置乱
src/store/       磁盘格式（SPEC 6、7） src/net/  帧格式与消息编解码（SPEC 8）
apps/            四个可执行程序      tests/unit|ref|integration|fuzz/
bench/           基准脚本与 CSV      docs/  third_party/  docker/  ui/（选做）
```

- `src/` 不依赖 `apps/`。
- `src/core`、`src/priv`、`src/pub` 不做任何网络和文件 I/O；I/O 只在 `src/store` 和 `src/net` 中进行。

## 编码规范

- 命名：公开符号前缀 `swpor_`，类型以 `_t` 结尾，宏全大写并加前缀 `SWPOR_`。
- 错误处理：返回 `int` 错误码（`SWPOR_OK = 0`，失败为负值，见 `include/swpor/error.h`），输出参数用指针。库代码不调用 `exit()`/`abort()`，不打印到 stdout/stderr。
- 资源：用 `goto cleanup` 风格释放；每个 `*_new` 对应 `*_free`，且 `*_free(NULL)` 安全。
- 整数：长度和下标用 `size_t` / `uint64_t`，可能溢出的加法、乘法显式检查。
- 字节序：文件和网络格式一律大端，用 `src/core/endian.h` 的辅助函数。
- 注释：公开函数在头文件写中文文档注释（功能、参数、返回值、对应 SPEC 章节，如 `/* 见 SPEC 4.1 Priv.St */`）；关键公式旁写出公式。
- 格式化：按根目录 `.clang-format`（LLVM 风格，缩进 4，列宽 100）。
- 编译选项已在 CMake 中设置（GCC/Clang `-Wall -Wextra -Wpedantic -Werror -Wconversion -Wshadow`，MSVC `/W4 /WX`）。不要通过关闭警告来消除警告；第三方头文件以 `SYSTEM` 方式包含。

## 工作流程

1. **动手前先说计划。** 跨多个文件或修改接口的任务，先列出要改的文件、新增的函数、测试方法，用户确认后再写。小修小改可以直接做。
2. **测试先行。** 实现某个 SPEC 小节时先写对应测试（SPEC 第 10 节的编号），测试名带编号，如 `test_T04_honest_prover_passes`。
3. **每次改动后本地跑通：**
   ```
   cmake --preset debug && cmake --build --preset debug && ctest --preset debug
   ```
   - 涉及 Priv 算法：再跑差分测试 `python3 tests/ref/run_diff.py build/debug/`（待实现）。
   - 涉及 `src/platform/` 或 CMake：提醒用户 Windows 只能靠 CI 验证，推送后需确认 `windows-x64` 任务通过。
4. **小步提交。** 一次提交只做一件事，格式 `<模块>: <做了什么>`，如 `priv: implement Priv.St tag generation (SPEC 4.1)`。不要在 `main` 上直接提交。
5. **完成里程碑**（SPEC 1.3 的 M0～M5）后：更新 `README.md` 进度，列出通过的测试编号，提醒用户打 tag 并更新 `CHANGELOG.md`。
6. **不确定就问。** 尤其是密码学细节、SPEC 未覆盖的情况、会改变文件格式或协议的修改、引入新依赖。

## 其他文档

按需阅读，不必每次都读：

- 配置开发环境、macOS / Linux / Windows 平台问题、sanitizer 与 valgrind、模糊测试 → `docs/dev-setup.md`
- 分支、发布、版本号规则，测试报告与基准数据要求 → `docs/dev-setup.md` 的对应章节
- 命令行接口 → SPEC 第 9 节
