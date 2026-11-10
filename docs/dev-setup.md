# 开发环境与流程说明

本文档面向协作者（以及需要处理环境问题的 coding agent）。日常编码规则见根目录 `CLAUDE.md`，算法与接口以 `SPEC.md` 为准。

标注「待实现」的脚本和命令目前尚不存在，实现后请删除标注。

## 1. 依赖管理

依赖按平台分别获取（SPEC 2.1），CI 与本地开发使用同一条路径：

| 平台 | 安装依赖 | 预设 |
|---|---|---|
| Linux | `sudo apt install build-essential cmake ninja-build libssl-dev libcmocka-dev libisal-dev` | `debug` / `release` |
| macOS | `brew install cmake ninja openssl@3 cmocka isa-l`（CMake 会自动找到 keg-only 的 OpenSSL） | `debug` / `release` |
| Windows | Visual Studio 2022 + vcpkg，设置 `VCPKG_ROOT`，依赖由 `vcpkg.json` 自动安装 | `windows-debug` / `windows-release` |

- **blst** 作为 git submodule 放在 `third_party/blst`，不经过任何包管理器。
- `vcpkg-debug` / `vcpkg-release` 预设仍可在 Linux / macOS 上使用，但 vcpkg 的 `isal` 端口不支持 arm64 macOS，
  在 Mac 上需另用 Homebrew 安装 `isa-l`。

## 2. 构建命令

```
# 首次初始化：git init、拉取 blst 子模块、首次提交
./scripts/bootstrap.sh

# Debug（带 sanitizer）
cmake --preset debug && cmake --build --preset debug && ctest --preset debug

# Release（基准测试用）
cmake --preset release && cmake --build --preset release

# 可选：用 vcpkg 获取依赖（Windows 的主路径；Linux / macOS 上可选）
cmake --preset vcpkg-debug && cmake --build --preset vcpkg-debug && ctest --preset vcpkg-debug

# 依赖自检
./build/debug/apps/porctl doctor

# 差分测试 T-03（ctest 中也会运行）
python3 tests/ref/run_diff.py build/debug/
```

CMake 选项：

| 选项 | 说明 |
|---|---|
| `SWPOR_BUILD_SERVER` | 是否构建 `pord`，Windows 默认 OFF |
| `SWPOR_BUILD_TESTS` | 是否构建测试 |
| `SWPOR_WERROR` | 警告视为错误 |
| `SWPOR_SANITIZE` | 开启 sanitizer（Debug 默认开） |
| `SWPOR_TESTING` | 测试用确定性随机数，**发布构建禁止开启** |

本地模式端到端演示（M2 实现后可用）：

```
./build/debug/apps/porctl keygen --scheme priv --out keys/
./build/debug/apps/porctl store  --key keys/priv.key --in sample.bin --local store/
./build/debug/apps/porctl audit  --key keys/priv.key --tag <tag 路径> --local store/
```

## 3. 平台说明

### macOS（Apple Silicon）

- 基础工具：`brew install cmake ninja llvm`。
- `/usr/lib/libcrypto` 是系统私有的 LibreSSL，**不要链接它**。
- `gcc` 命令实际是 Apple Clang 的别名。
- 内存检查：macOS arm64 没有 valgrind，Apple Clang 的 ASan 不支持泄漏检测。本地用 ASan + UBSan，泄漏用 `leaks --atExit -- <程序>`；valgrind 在 Linux 上跑。
- 模糊测试：Apple Clang 不带 libFuzzer，用 Homebrew LLVM 编译 fuzz 目标：
  `-DCMAKE_C_COMPILER=$(brew --prefix llvm)/bin/clang`。

### Linux

- 编译器：GCC ≥ 11 或 Clang ≥ 14。
- valgrind 检查、正式基准测试在 Linux 上进行。本地没有 Linux 时，用 `docker/Dockerfile.dev` 启动 Ubuntu 容器。

### Windows（Tier 2，仅客户端）

- 编译器：MSVC 2022，警告选项 `/W4 /WX`，Debug 开启 `/fsanitize=address`。
- 主要依赖 CI（`windows-latest`）验证。需要本地调试时，可在 Mac 上用 UTM / Parallels 运行 Windows 11 ARM 虚拟机。
- 路径在内部统一使用 UTF-8，调用系统 API 前转为 UTF-16 并使用 `*W` 版本函数（只在 `src/platform/` 中处理）。
- 常见移植问题：MSVC 不支持 VLA；没有 `ssize_t`；`-W...` 选项只对 GCC/Clang 有效，CMake 中需按编译器分别设置。

## 4. 开发环境分工

| 环境 | 用途 |
|---|---|
| 本地 Mac | 日常编码、编译、单元测试、本地模式端到端测试、UI 开发 |
| Linux 服务器 | 长时间运行 `pord`、跨机器网络测试（Mac 客户端 → Linux 服务端）、valgrind、正式基准测试 |
| GitHub Actions | 三平台构建与测试；打 tag 后自动构建发布包 |

代码同步只通过 git：本地提交并推送，服务器上 `git pull` 后构建。不要在服务器上直接改代码，也不要用 scp 拷贝源码。

## 5. 分支与发布

- `main` 始终可构建、测试全部通过。
- 每个功能在独立分支开发（如 `feat/priv-tag`），完成后开 Pull Request，CI 三平台全部通过后合并。
- 完成里程碑后打 tag（如 `v0.1.0` 对应 M1），CI 自动构建三平台发布包并上传 GitHub Releases。
- 版本号遵循 SemVer：文件格式或协议的不兼容变更必须提升主版本号（1.0 之前提升次版本号）。
- `CHANGELOG.md` 记录每个版本的用户可见变更。

## 6. CI 自动检查（建议）

以下规则写在 `CLAUDE.md` 中，同时应由 CI 自动检查（脚本 `scripts/check_rules.sh`，待实现）：

- `src/platform/` 以外不得出现操作系统头文件和 `#ifdef _WIN32` / `__APPLE__` / `__linux__`。
- 不得出现 `rand(`、`random(`、`srand(`。
- 涉及 tag、MAC、密钥的源文件中不得使用 `memcmp(`（应使用 `CRYPTO_memcmp`）。
- `clang-format --dry-run --Werror` 通过。
- 发布构建中 `SWPOR_TESTING` 必须关闭。

## 7. 文档与报告

- 需求分析报告、测试报告、用户手册放在 `docs/reports/`，用中文 Markdown 编写。
- 测试报告中每项结果都要对应 SPEC 第 10 节的测试编号，并注明运行环境和 git commit。
- 基准数据只能来自 `porbench` 的实际输出，保存在 `bench/results/` 的 CSV 中。作图脚本放在 `bench/plot/`，从 CSV 读取数据，不得硬编码数字。
- 软著材料需要源代码（按申请要求提取页数）和用户手册。代码注释和用户手册从一开始就保持完整，不要等到最后补。
