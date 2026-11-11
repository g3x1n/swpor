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
brew install cmake ninja openssl@3 cmocka isa-l
./scripts/bootstrap.sh            # 首次：git init + blst 子模块 + 首次提交
cmake --preset debug
cmake --build --preset debug
ctest --preset debug
./build/debug/apps/porctl doctor  # 确认 OpenSSL 与 blst 工作正常
```

Linux（Ubuntu）：`sudo apt install build-essential cmake ninja-build libssl-dev libcmocka-dev libisal-dev`，其余步骤相同。

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
| `debug` / `release` | 使用系统依赖（Homebrew / apt），Linux / macOS 的主路径，与 CI 一致 |
| `vcpkg-debug` / `vcpkg-release` | 使用 vcpkg 依赖（需设置 `VCPKG_ROOT`）；Linux / macOS 上可选，arm64 macOS 需另用 Homebrew 安装 isa-l |
| `windows-debug` / `windows-release` | Windows + MSVC + vcpkg |

基准测试请使用 `release` 预设。

## 使用示例

```bash
B=build/debug/apps
# 1. 密钥
$B/porctl keygen --scheme priv --out keys          # keys/priv.key
$B/porctl keygen --scheme pub  --out keys          # keys/pub.sk、keys/pub.pk

# 2. 本地模式：存储 → 审计 → 篡改 → 再审计 → 恢复
$B/porctl store    --key keys/priv.key --in report.pdf --local store/ --perm --encrypt --tag-out report.tag
$B/porctl audit    --key keys/priv.key --tag report.tag --local store/          # PASS，退出码 0
$B/porctl tamper   --local store/ --file-id <file_id> --mode zero --ratio 0.1
$B/porctl audit    --key keys/priv.key --tag report.tag --local store/          # 多半 FAIL，退出码 1
$B/porctl retrieve --key keys/priv.key --tag report.tag --local store/ --out report.out.pdf

# 3. 远程模式 + 第三方审计（Pub 方案，审计者只需要公钥）
$B/pord   --listen 0.0.0.0:7878 --data-dir /srv/swpor &
$B/porctl store --key keys/pub.sk --in data.bin --server 127.0.0.1:7878 --tag-out data.tag
$B/porta  --pk keys/pub.pk --tag data.tag --server 127.0.0.1:7878 --interval 3600 --count 0 --log audit.log
```

### Web 控制台（M-UI）

```bash
python3 ui/server.py --bin build/debug/apps --workspace ~/swpor-ws --open
```

在浏览器中按数据所有者、存储服务端、第三方审计者三方角色完成存储、审计、篡改实验、恢复，
并查看每个任务的执行轨迹。只监听 127.0.0.1，需要启动时打印的带令牌地址（SPEC 9.5，用户手册第 8 节）。

所有子命令都支持 `--json`；`--trace <file|->` 输出 NDJSON 执行轨迹（SPEC 9.4）。
完整说明见 [`docs/reports/user-manual.md`](docs/reports/user-manual.md)。

## 进度

| 里程碑 | 内容 | 状态 | 通过的测试 |
|---|---|---|---|
| 骨架 | 构建系统、目录结构、CI、依赖自检 | ✅ 完成 | — |
| M0 | 底层封装（域运算、PRF、挑战、编码格式、平台层） | ✅ 完成 | T-01、T-02、T-03 |
| M1 | Priv 方案核心库 | ✅ 完成 | T-04～T-08 |
| M2 | `porctl` 本地模式 + 纠删码 + 文件恢复 | ✅ 完成 | T-09～T-14、T-26 |
| M3 | 网络化（`pord`、远程模式） | ✅ 完成 | T-15～T-18 |
| M4 | Pub 方案、`porta`、Simple-MAC 基线、`porbench` | ✅ 代码完成 | T-19～T-21；T-22～T-24 工具已就绪，正式数据待在 Linux Release 构建上测量 |
| M-UI | 本机 Web 控制台（`ui/`） | ✅ 完成 | T-27 |
| M5 | 选做（RSA 变体、TLS、提取器演示） | ⏳ | — |

另外：T-25 的库层面部分（确定性输出的黄金摘要 `test_golden`）已实现，跨平台结论以 CI 三平台结果为准；
SPEC 10.4 的三个 fuzz 目标已实现（ctest 中运行冒烟版本），正式的 1 小时 libFuzzer 运行尚未进行。
