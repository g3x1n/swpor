# Changelog

本文件记录用户可见的变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

### 新增
- 核心库：Z_r 域封装（blst）、PRF / HKDF / HMAC 字节流、显式与种子挑战、文件标签明文头（SPEC 3、4.3）。
- Priv 方案（SPEC 4.1）：打标签、AES-256-GCM 文件标签、证明与验证；Python 参考实现与差分测试（T-03）。
- Pub 方案（SPEC 4.2）：BLS12-381 非对称配对、Pippenger MSM、Ed25519 文件标签、单块校验。
- 纠删码层（SPEC 5）：ISA-L 条带 RS、秘密置换、AES-256-CTR 文件加密、按擦除恢复。
- 磁盘格式与密钥文件（SPEC 6、7）。
- 网络协议（SPEC 8）：帧格式、客户端、固定线程池服务端（有界队列、每文件读写锁、超时）。
- `porctl`：keygen / store / audit / retrieve / info / tamper / delete，本地与远程模式，`--json`、`--trace`。
- `pord` 存储服务端、`porta` 第三方审计者、`porbench` 基准与篡改检测实验（含 Simple-MAC 基线）。
- 测试：T-01～T-21、T-25（库层面）、T-26；三个 fuzz 目标的冒烟测试；CLI 集成测试。
- 项目骨架：CMake 构建系统与预设、vcpkg 清单、三平台 CI。
- `libswpor`：错误码、上下文与 trace 事件分发、依赖自检 `swpor_selftest`。
- 平台抽象层：进程初始化、高精度计时（POSIX / Win32）。
- `porctl`：`version`、`doctor`、`help` 子命令；其余子命令为占位。
- `pord`、`porta`、`porbench`：占位程序。
