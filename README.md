# swpor

基于 Shacham–Waters《Compact Proofs of Retrievability》（Asiacrypt 2008）的云存储数据可恢复性审计系统，C 语言实现。

- 算法与系统规格：[`SPEC.md`](SPEC.md)
- 开发约定（含给 coding agent 的规则）：[`CLAUDE.md`](CLAUDE.md)
- 论文：[`docs/paper/`](docs/paper/)

## 组件

| 组件 | 作用 | 平台 |
|---|---|---|
| `libswpor` | 核心算法库 | macOS / Linux / Windows |
| `porctl` | 数据所有者客户端 | macOS / Linux / Windows |
| `porta` | 第三方审计者 | macOS / Linux / Windows |
| `porbench` | 基准测试工具 | macOS / Linux / Windows |
| `pord` | 存储服务端 | macOS / Linux |

## 快速开始（macOS）

```bash
brew install cmake ninja openssl@3 cmocka
./scripts/bootstrap.sh            # 首次：git init + blst 子模块 + 首次提交
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
./build/debug/apps/porctl doctor  # 确认 OpenSSL 与 blst 工作正常
```

Linux（Ubuntu）：`sudo apt install build-essential cmake ninja-build libssl-dev libcmocka-dev`，其余步骤相同。

Windows：安装 Visual Studio 2022（含 C++ 桌面开发组件）和 [vcpkg](https://github.com/microsoft/vcpkg)，设置环境变量 `VCPKG_ROOT`，然后：

```powershell
git submodule update --init --recursive
cmake --preset windows-debug
cmake --build --preset windows-debug
ctest --preset windows-debug
```

### CMake 预设

| 预设 | 用途 |
|---|---|
| `debug` / `release` | 使用系统依赖（Homebrew / apt） |
| `vcpkg-debug` / `vcpkg-release` | 使用 vcpkg 依赖（需设置 `VCPKG_ROOT`），与 CI 一致 |
| `windows-debug` / `windows-release` | Windows + MSVC + vcpkg |

基准测试请使用 `release` 预设。

## 进度

| 里程碑 | 内容 | 状态 |
|---|---|---|
| 骨架 | 构建系统、目录结构、CI、依赖自检 | ✅ 完成 |
| M0 | 底层封装（域运算、PRF、编码格式） | ⏳ |
| M1 | Priv 方案核心库 | ⏳ |
| M2 | `porctl` 本地模式 + 纠删码 + 文件恢复 | ⏳ |
| M3 | 网络化（`pord`、远程模式） | ⏳ |
| M4 | Pub 方案、`porta`、基准测试 | ⏳ |
| M5 / M-UI | 选做 | ⏳ |
