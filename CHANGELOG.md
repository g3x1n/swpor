# Changelog

本文件记录用户可见的变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

## [0.5.0] - 2026-11-11

完成里程碑 M-UI（SPEC v0.9）。核心库、文件格式与网络协议与 0.4.0 相同。

### 新增
- 本机 Web 控制台（M-UI，SPEC 9.5，v0.9）：`ui/server.py`（Python 标准库）+ `ui/web/`（HTML、CSS、原生 JS），按三方角色完成存储、审计、篡改实验、恢复，并展示执行轨迹；测试 T-27。

### 变更
- SPEC 9.5 改为本机 Web 控制台，去掉教学模式；桌面封装延期（OPEN-6 保留）。

### 已知限制
- 0.4.0 的已知限制仍然存在：Pub 不支持 `--perm` / `--encrypt`，网络为明文 TCP（TLS 计划在 M5），T-22～T-24 正式性能数据与 1 小时 libFuzzer 运行尚未进行。
- Web 控制台只监听 127.0.0.1，供本机单用户使用；Windows 上不能启动托管的 `pord`。

## [0.4.0] - 2026-11-11

首个发布版本，完成 SPEC 1.3 的里程碑 M0～M4（SPEC v0.8）。

### 新增
- 核心库：Z_r 域封装（blst）、PRF / HKDF / HMAC 字节流、显式与种子挑战、文件标签明文头（SPEC 3、4.3）。
- Priv 方案（SPEC 4.1）：打标签、AES-256-GCM 文件标签、证明与验证；Python 参考实现与差分测试（T-03）。
- Pub 方案（SPEC 4.2）：BLS12-381 非对称配对、Pippenger MSM、Ed25519 文件标签、单块校验。
- 纠删码层（SPEC 5）：ISA-L 条带 RS、秘密置换、AES-256-CTR 文件加密、按擦除恢复。
- 磁盘格式与密钥文件（SPEC 6、7）。
- 网络协议（SPEC 8）：帧格式、客户端、固定线程池服务端（有界队列、BUSY、每文件读写锁、读写超时）。
- `porctl`：keygen / store / audit / retrieve / info / tamper / delete / doctor / version，本地与远程模式，`--json`、`--trace`。
- `pord` 存储服务端、`porta` 第三方审计者、`porbench` 基准与篡改检测实验（含 Simple-MAC 基线）。
- 平台抽象层：文件、目录、线程与锁、套接字（POSIX / Win32），CPU 与内存信息。
- 测试：T-01～T-21、T-25（确定性输出黄金摘要，三平台一致）、T-26（非 ASCII 路径）；三个 fuzz 目标的冒烟测试；CLI 集成测试（T-14、T-21）。
- 文档：用户手册（`docs/reports/user-manual.md`）、基准结果汇总脚本（`bench/summarize.py`）。

### 变更
- 依赖按平台获取（SPEC 2.1，v0.8）：Linux 用 apt，macOS 用 Homebrew，Windows 用 vcpkg；vcpkg 的 `isal` 在 arm64 macOS 上不可用。
- CI 的 Windows 运行器固定为 `windows-2022`（SPEC 2.1，v0.7）。
- Windows 可执行文件嵌入 UTF-8 活动代码页清单，命令行参数中的中文路径可正常使用。
- MSVC 上 blst 改用 MASM 汇编构建（blst 的纯 C 路径依赖 VLA，MSVC 不支持）。

### 已知限制
- Pub 方案不支持 `--perm` / `--encrypt`（SPEC 5）。
- 网络协议为明文 TCP，TLS 计划在 M5 实现。
- T-22～T-24 的正式性能数据尚未测量（需在 Linux x86_64 Release 构建上运行 `porbench`）；SPEC 10.4 要求的 1 小时 libFuzzer 运行尚未进行。

[Unreleased]: https://github.com/g3x1n/swpor/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/g3x1n/swpor/releases/tag/v0.5.0
[0.4.0]: https://github.com/g3x1n/swpor/releases/tag/v0.4.0
