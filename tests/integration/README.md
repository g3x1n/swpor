# tests/integration — 端到端测试

通过 `porctl` / `porta` / `pord` 的命令行和 `--json` 输出做端到端测试。
脚本用 Python 3 标准库编写，以保证在 macOS、Linux、Windows 上都能运行（不要写成 bash 脚本）。

- `test_cli.py`：T-14（退出码与 `--json`）、T-21（`porta` 只用 pk 与 t 审计）、T-26（非 ASCII 路径），
  以及本地 / 远程模式完整流程。没有 `pord` 的平台（Windows）自动跳过远程部分。
  用法：`python3 tests/integration/test_cli.py build/debug`（ctest 中名为 `T14_T21_cli_integration`）。

网络层的 T-15～T-18 在 `tests/unit/test_net.c` 中用进程内服务端完成。
