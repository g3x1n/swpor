# swpor 用户手册

swpor 是基于 Shacham–Waters《Compact Proofs of Retrievability》（Asiacrypt 2008）的云存储数据可恢复性审计系统。
数据所有者把文件交给不完全可信的存储服务端之后，可以随时用很小的通信量（几 KB）检查服务端是否仍完整地保存着文件；
在需要时还可以从服务端（即使有部分数据损坏）恢复出原文件。

本手册对应软件版本 0.5.0。算法与格式的权威定义见仓库根目录 `SPEC.md`。

---

## 1. 组件

| 程序 | 角色 | 说明 |
|---|---|---|
| `porctl` | 数据所有者客户端 | 生成密钥、预处理并上传文件、审计、检索、查看标签、（测试用）篡改 |
| `pord` | 存储服务端 | 保存数据块、认证标签与文件标签；响应挑战与检索请求（仅 macOS / Linux） |
| `porta` | 第三方审计者 | 只持有公钥与文件标签，定期审计 Pub 方案的文件并记录日志 |
| `porbench` | 基准测试工具 | 测量打标签、证明、验证的耗时与通信量，运行篡改检测率实验，输出 CSV |
| Web 控制台 | 图形界面（选做） | `ui/server.py`：在浏览器中按三方角色操作上述程序，见第 8 节 |

两种方案：

- **Priv（私有验证）**：基于 PRF，速度快、证明小（Priv 证明约 4 KB）；只有持有密钥的数据所有者能审计。
- **Pub（公开验证）**：基于 BLS12-381 双线性对；任何持有公钥的第三方（`porta`）都能审计，不需要数据所有者在线。

## 2. 安装

### macOS（Apple Silicon）

```bash
brew install cmake ninja openssl@3 cmocka isa-l
./scripts/bootstrap.sh        # 首次：git 仓库与 blst 子模块
cmake --preset release && cmake --build --preset release
./build/release/apps/porctl doctor
```

### Linux（Ubuntu / Debian）

```bash
sudo apt install build-essential cmake ninja-build libssl-dev libcmocka-dev libisal-dev
git submodule update --init --recursive
cmake --preset release && cmake --build --preset release
```

### Windows（只有客户端）

安装 Visual Studio 2022 与 vcpkg，设置环境变量 `VCPKG_ROOT`，然后
`cmake --preset windows-release && cmake --build --preset windows-release`。Windows 上不构建 `pord`。

程序位于 `build/<预设>/apps/`。`porctl doctor` 输出 `doctor: OK` 表示 OpenSSL 与 blst 工作正常。

## 3. 快速上手

```bash
# 生成 Priv 密钥
porctl keygen --scheme priv --out keys

# 存储到本地目录（模拟服务端），默认 s = 128、RS(64, 64)
porctl store --key keys/priv.key --in 论文.pdf --local store --tag-out 论文.tag

# 审计
porctl audit --key keys/priv.key --tag 论文.tag --local store
# 输出：PASS  (l = 128, ... challenge 3109 B, proof 4130 B)

# 恢复
porctl retrieve --key keys/priv.key --tag 论文.tag --local store --out 论文.恢复.pdf
```

把 `--local <目录>` 换成 `--server <主机:端口>` 即为远程模式（需要先运行 `pord`）。

## 4. `porctl` 命令参考

所有子命令都支持 `--json`（输出一行机器可读的 JSON）。`store`、`audit`、`retrieve`、`tamper`
支持 `--trace <文件|->`，按行输出执行轨迹事件（NDJSON；`-` 表示写到标准错误）。
远程模式支持 `--timeout <毫秒>`（网络读写超时，默认 30000）。

### 4.1 `keygen` — 生成密钥

```
porctl keygen --scheme priv|pub --out <目录> [--force]
```

- `priv`：生成 `<目录>/priv.key`（权限 0600）。
- `pub`：生成 `<目录>/pub.sk`（私钥，0600）与 `<目录>/pub.pk`（公钥，可以分发给审计者）。
- 已有同名文件时拒绝覆盖，除非指定 `--force`。

**请妥善备份私钥。** 丢失 `priv.key` 后将无法审计或恢复 Priv 方案存储的文件。

### 4.2 `store` — 预处理、打标签并存储

```
porctl store --key <私钥文件> --in <文件> [--s 128] [--rs 64:64 | --no-rs] [--perm] [--encrypt]
             [--tag-out <路径>] (--local <目录> | --server <主机:端口>)
```

| 选项 | 含义 |
|---|---|
| `--s` | 每块扇区数（每扇区 31 字节）。越大存储开销越小（1 + 1/s），证明越大（约 32·s 字节） |
| `--rs k:m` | 纠删码参数：每 k 个数据块生成 m 个校验块，任一条带丢失不超过 m 块仍可恢复 |
| `--no-rs` | 不做纠删编码（只能检测损坏，不能修复） |
| `--perm` | 用秘密置换打乱块的位置，使服务端无法识别条带结构（仅 Priv） |
| `--encrypt` | 用 AES-256-CTR 加密文件内容（仅 Priv） |
| `--tag-out` | 文件标签保存路径，默认 `<file_id>.tag` |

输出 `file_id` 和文件标签路径。**文件标签（.tag）需要保存好**，审计与恢复都需要它
（Priv 标签是加密的，泄露不会暴露密钥；Pub 标签是公开的）。

### 4.3 `audit` — 审计

```
porctl audit --key <密钥文件> --tag <标签文件> [--l 128] [--seed-mode]
             (--local <目录> | --server <主机:端口>)
```

- `--l`：每次随机挑战的块数。若服务端损坏了比例为 x 的块，一次审计发现损坏的概率约为 1 − (1 − x)^l。
- `--seed-mode`：只发送 32 字节种子，由双方展开成挑战（挑战消息更小）。
- Priv 方案使用 `priv.key`；Pub 方案可使用 `pub.pk`（或 `pub.sk`）。
- 退出码 0 表示 PASS，1 表示 FAIL。

### 4.4 `retrieve` — 检索并恢复

```
porctl retrieve --key <密钥文件> --tag <标签文件> --out <输出文件> (--local <目录> | --server <主机:端口>)
```

逐块用认证标签检查完好性，损坏的块按擦除处理并用纠删码修复。远程模式会先把数据下载到
`<输出文件>.swpor-dl` 临时目录，完成后删除。只有完整恢复成功才会生成输出文件；
无法恢复时（某个条带损坏超过 m 块）报错退出，不会留下错误的数据。

### 4.5 `info` — 查看文件标签

```
porctl info --tag <标签文件>
```

显示 file_id、方案、原始长度、块数、纠删码参数、是否置换 / 加密、创建时间。不需要密钥。

### 4.6 `tamper` — 篡改本地存储（仅用于测试与演示）

```
porctl tamper --local <目录> --file-id <十六进制> --mode flip|zero|delete --ratio <0..1> [--seed N]
```

按比例随机选择块：`flip` 翻转每块中的 1 个比特，`zero` / `delete` 把整块置 0。
`--seed` 使选择可复现。

### 4.7 `delete` — 删除存储的文件

```
porctl delete --tag <标签文件> (--local <目录> | --server <主机:端口>)
```

### 4.8 其他

`porctl doctor`（依赖自检）、`porctl version`、`porctl help`。

### 4.9 退出码

| 退出码 | 含义 |
|---|---|
| 0 | 成功 / 审计 PASS |
| 1 | 审计 FAIL |
| 2 | 参数错误 |
| 3 | I/O 错误（文件不存在、权限、服务端上没有该文件等） |
| 4 | 网络错误（连接失败、超时、服务端繁忙） |
| 5 | 密码学或格式错误（标签认证失败、密钥不匹配、数据无法恢复等） |

## 5. `pord` — 存储服务端

```
pord --data-dir <目录> [--listen 0.0.0.0:7878] [--max-l 4096] [--threads N]
     [--timeout 毫秒] [--log <文件>] [--trace <文件|->]
```

- 每个文件保存在 `<目录>/<file_id>/` 下（`blocks.dat`、`sigma.dat`、`tag.bin`）。
- `--threads`：工作线程数，默认等于 CPU 核数；连接排队已满时新连接收到 BUSY 错误。
- `--max-l`：单次挑战的块数上限，防止资源耗尽。
- Ctrl-C（SIGINT）或 SIGTERM 时停止接受新连接并退出。
- 当前协议为明文 TCP（TLS 计划在 M5 实现）。PoR 的安全性不依赖信道保密，但请勿把服务端暴露在不可信网络上作为生产服务。

## 6. `porta` — 第三方审计者

```
porta --pk <pub.pk> --tag <t1[,t2,...]> (--server <主机:端口> | --local <目录>)
      [--l 128] [--explicit] [--interval <秒>] [--count N] [--log <文件>] [--json]
```

- 只接受公钥文件 `pub.pk`，拒绝私钥。
- 默认只审计一轮；`--count 0 --interval 3600` 表示每小时审计一次，一直运行。
- `--log` 追加写入审计日志，每行一个 JSON 对象（时间、file_id、结果、耗时、证明大小）。
- 有任一文件审计 FAIL 时退出码为 1。

## 7. `porbench` — 基准测试

```
porbench run    --scheme priv|pub|mac --size 16M [--s 128] [--l 128] [--reps 10] [--out 结果.csv]
porbench sweep  --scheme priv,pub,mac --sizes 1M,16M --s 1,16,64,128,256 --l 64,128,460 --out 结果.csv
porbench detect --n 10000 --l 128 --ratios 0.001,0.005,0.01,0.05,0.1 --trials 1000 --out 检测率.csv
```

- 每行 CSV 都记录日期、git commit、CPU 型号、核数、内存、操作系统、编译器与构建类型。
- `mac` 是 Simple-MAC 对比基线：每块一个 HMAC，审计时服务端返回被挑战的块本身。
- 正式数据请使用 Release 构建在 Linux x86_64 上测量，结果保存到 `bench/results/<日期>_<commit>.csv`；
  `python3 bench/summarize.py <csv>` 输出各组参数的中位数与四分位数。

## 8. Web 控制台（M-UI）

控制台是 `porctl` / `porta` / `pord` 的图形界面（SPEC 9.5）：后端 `ui/server.py` 只用 Python 3.9+ 标准库，
以子进程调用这些程序；前端为纯 HTML / CSS / JavaScript，不需要安装或构建。

```bash
python3 ui/server.py --bin build/debug/apps --workspace ~/swpor-ws [--port 8787] [--max-upload 1024] [--open]
# 输出：swpor console listening: http://127.0.0.1:8787/#token=…
```

- 用启动时打印的完整地址打开（`--open` 自动打开默认浏览器）。令牌在每次启动时重新生成。
- 页面：
  - **概览**：三方模型、演示流程进度、最近审计。
  - **数据所有者**：生成密钥、上传文件、存储（s、RS、置乱、加密，本地或远程），对已存储的文件审计、恢复（可下载）、删除。
  - **存储服务端**：启动 / 停止本机 `pord`（只监听 127.0.0.1），查看服务端存储的文件、执行轨迹和日志。Windows 上没有 `pord`，只能连接远程服务端。
  - **第三方审计者**：用 `pub.pk` 调用 `porta` 审计一个或多个 Pub 文件，可多轮运行、随时停止。
  - **篡改实验**：对本地存储调用 `tamper`，显示理论检测率与块状态图，可立即审计或尝试恢复。
  - **工作区**：查看、下载、删除工作区中的文件。
- 右侧"任务与执行轨迹"列出每个任务的命令行、退出码、`--json` 结果，以及按时间线展示的 trace 事件（分块 → 纠删码 → 打标签 → 挑战 → 验证）。
- 工作区目录结构：`keys/`（密钥）、`data/`（上传的文件）、`tags/`（文件标签）、`store/`（本地存储）、`srv/`（控制台启动的 `pord` 的数据目录）、`out/`（恢复结果）、`logs/`。
- 安全：只监听 127.0.0.1；API 需要令牌并校验 Host / Origin；只能访问工作区固定子目录中的文件；私钥内容不会发送到浏览器。不要把控制台端口转发到其他机器。

## 9. 安全提示

- 私钥文件只有本人可读；请勿把 `priv.key`、`pub.sk` 上传到服务端或提交到 git。
- 纠删码采用"条带 RS + 秘密置换"的折中方案：只有启用 `--perm`（最好同时 `--encrypt`）时，
  服务端才无法针对单个条带集中删除数据（见 SPEC 5 安全性说明）。Pub 方案不支持置换，因此只能抵抗随机损坏。
- `tamper` 子命令只用于测试与演示，会直接破坏数据。
