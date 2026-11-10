# Changelog

本文件记录用户可见的变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循语义化版本。

## [Unreleased]

### 新增
- 项目骨架：CMake 构建系统与预设、vcpkg 清单、三平台 CI。
- `libswpor`：错误码、上下文与 trace 事件分发、依赖自检 `swpor_selftest`。
- 平台抽象层：进程初始化、高精度计时（POSIX / Win32）。
- `porctl`：`version`、`doctor`、`help` 子命令；其余子命令为占位。
- `pord`、`porta`、`porbench`：占位程序。
