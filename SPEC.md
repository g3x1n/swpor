# SPEC.md — swpor：基于 Shacham–Waters 紧凑可恢复性证明的数据审计系统

> 版本：v0.4（草案） · 状态：待评审
> 依据论文：H. Shacham, B. Waters. *Compact Proofs of Retrievability*. Asiacrypt 2008（本仓库所附 PDF 为完整版）。
> 本文件是实现的**唯一事实来源**。代码与本文件不一致时，以本文件为准；需要偏离时，先改本文件（并在第 12 节"变更记录"登记），再改代码。

---

## 0. 术语与记号

| 记号 | 含义 |
|---|---|
| λ | 安全参数，本项目取 **λ = 128**（论文当年取 80） |
| M | 用户原始文件，长度 L 字节 |
| M′ | 纠删编码（及可选加密、置乱）后的文件 |
| n | M′ 的块（block）数 |
| s | 每块的扇区（sector）数；每个扇区是一个 Z_p 元素 |
| m_ij | 第 i 块第 j 个扇区，0 ≤ i < n，0 ≤ j < s（**实现中下标从 0 开始**，论文从 1 开始） |
| σ_i | 第 i 块的认证标签（authenticator） |
| t | 文件标签（file tag），包含文件元数据与验证所需的（加密/签名）信息 |
| Q = {(i, ν_i)} | 挑战：l 个互不相同的块下标及其系数 |
| l | 每次挑战的块数 |
| B | 挑战系数取值集合，本项目 B = [1, 2^128) |
| ρ | 纠删码码率：任意 ρ 比例的块即可恢复原文件 |
| p / r | 有限域阶。本项目统一使用 BLS12-381 的标量域阶 r（255 bit）作为 p |
| G1, G2, GT | BLS12-381 的三个群；e: G1 × G2 → GT |
| g2 | G2 的标准生成元 |
| ‖ | 字节串拼接 |
| I2OSP(x, k) | 整数 x 转为 k 字节**大端**字节串 |
| OS2IP(b) | 大端字节串转整数 |

---

## 1. 目标与范围

### 1.1 目标
1. 用 C 语言正确实现论文第 3 节的两种方案：
   - **Priv**：私有验证方案（基于 PRF，标准模型下可证安全）。
   - **Pub**：公开验证方案（基于 BLS 签名与双线性对，随机预言机模型）。
2. 在算法库之上构建一个可用的"三方"审计软件：客户端（数据所有者）、存储服务端、第三方审计者。
3. 提供可复现的正确性测试、篡改检测实验与性能基准，直接支撑《测试报告》与后续论文实验章节。

### 1.2 非目标（v1 不做）
- 动态数据（插入、删除、修改块）。动态 PoR 留作后续研究方向。
- 论文第 6 节的 RSA 变体（列入 M5 选做，仅用于性能对比）。
- 论文第 5 节的简单 MAC 方案（仅作为对比基线实现，见 M4）。
- 生产级的访问控制、多租户、计费。

### 1.3 里程碑

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M0** | 底层封装：域运算、PRF、随机数、编码格式、错误码 | 单元测试全部通过；差分测试与 Python 参考实现一致 |
| **M1** | Priv 方案核心库（不含纠删码），本地进程内完成"打标签→挑战→证明→验证" | 第 10 节 T-01～T-08 通过 |
| **M2** | `porctl` 命令行（本地模式）+ 纠删码层 + 文件检索/恢复 | T-09～T-14 通过；可对任意文件完成完整流程 |
| **M3** | 网络化：`pord` 服务端、`porctl` 远程模式、TCP 协议 | T-15～T-18 通过；**课程作业二最低交付到此为止** |
| **M4** | Pub 方案、第三方审计者 `porta`、Simple-MAC 基线、基准测试脚本 | T-19～T-24 通过；产出性能数据表 |
| **M5**（选做） | RSA 变体、TLS、提取器（extractor）演示 | 按需 |
| **M-UI**（选做，与 M2 之后任意阶段并行） | 算法可视化界面，见第 9.5 节 | 能完整演示"分块→打标签→挑战→聚合→验证→篡改检测"全过程 |

---

## 2. 依赖与密码学原语选择

**原则：所有密码学原语均调用成熟库，项目内不手写任何原语。**

| 用途 | 选择 | 来源库 |
|---|---|---|
| 域 Z_r 运算 | BLS12-381 标量域（Montgomery 形式） | blst |
| G1/G2 群运算、多标量乘（MSM）、配对 | BLS12-381 | blst |
| 哈希到曲线 H: {0,1}* → G1 | RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` | blst |
| PRF f | HMAC-SHA-512，输出模 r 规约（见 3.3） | OpenSSL 3.x |
| 文件标签的加密 + 认证 | AES-256-GCM（AEAD），见 4.2 | OpenSSL 3.x |
| 文件标签签名 SSig | Ed25519 | OpenSSL 3.x |
| 密钥派生 | HKDF-SHA-256 | OpenSSL 3.x |
| 文件内容加密（可选） | AES-256-CTR | OpenSSL 3.x |
| 安全随机数 | `RAND_bytes`（OpenSSL） | OpenSSL 3.x |
| 纠删码 | Reed–Solomon over GF(2^8)，系统码 | Intel ISA-L（BSD-3） |
| 大数（仅 M5 RSA 变体） | `BIGNUM` | OpenSSL 3.x |

**与论文的参数差异：**
- 论文取 λ = 80、私有方案 p 为 80 bit 素数、公开方案用 BN 曲线。本项目取 λ = 128，两方案统一使用 BLS12-381 的 r（255 bit）。这样两方案共享同一种文件分块格式，便于对比实验。
- 私有方案若想追求速度，可在后续引入 p = 2^127 − 1 的变体（登记为 OPEN-3），v1 不做。
- 论文用对称配对 e: G × G → GT 描述公开方案；本项目按论文脚注 19 改为非对称配对：σ_i、H(·)、u_j ∈ G1，公钥 v ∈ G2，安全性规约到 co-CDH。

### 2.1 构建与目标平台
- 构建系统：**CMake ≥ 3.21**（`CMakePresets.json` 需要）；依赖管理用 **vcpkg 清单模式**（仓库根目录 `vcpkg.json`），三个平台用同一份依赖声明。vcpkg 中没有的依赖（如 blst）以 git submodule 方式放在 `third_party/`，由 CMake 直接编译。
- 支持平台分两级：

| 级别 | 平台 | 要求 |
|---|---|---|
| Tier 1 | macOS arm64（主要开发平台）、Linux x86_64（部署与基准测试平台） | 全部组件可构建，全部测试通过，每次提交都由 CI 检查 |
| Tier 2 | Windows x64（MSVC 2022） | 只做客户端：`libswpor`、`porctl`、`porta`、`porbench`（以及 M-UI）可构建，并通过单元测试、本地模式端到端测试，以及连接 Linux/macOS 上 `pord` 的远程测试。**`pord` 不在 Windows 上构建与发布**（CMake 选项 `SWPOR_BUILD_SERVER` 在 Windows 上默认关闭） |
| 尽力而为 | Linux arm64、macOS x86_64、Windows arm64 | 不进 CI，有问题再修 |

- **平台抽象层**：算法代码（`src/core`、`src/priv`、`src/pub`、`src/ec`）只用标准 C11，不调用任何操作系统接口。所有平台相关功能集中在 `src/platform/`，对外提供统一接口，内部分别用 POSIX 和 Win32 实现：

| 功能 | 统一接口 | POSIX 实现 | Windows 实现 |
|---|---|---|---|
| 套接字 | `swpor_sock_*` | BSD socket | Winsock2（需 `WSAStartup`；Windows 上只需客户端功能 connect/send/recv，listen/accept 可不实现） |
| 线程、互斥锁、读写锁、条件变量 | `swpor_thread_*`、`swpor_mutex_*`、`swpor_rwlock_*`、`swpor_cond_*` | pthreads | Win32 线程、`SRWLOCK`、`CONDITION_VARIABLE` |
| 文件随机读（pread） | `swpor_file_pread` | `pread` | `ReadFile` + `OVERLAPPED` 偏移 |
| 创建仅本人可读的密钥文件 | `swpor_file_create_private` | `open(O_CREAT\|O_EXCL, 0600)` | `CreateFileW(CREATE_NEW)` + 仅当前用户的 ACL |
| 路径与目录 | `swpor_path_*`、`swpor_mkdir_p` | `/` 分隔，`mkdir` | UTF-8 与 UTF-16 互转，`CreateDirectoryW` |
| 高精度计时 | `swpor_time_ns` | `clock_gettime(CLOCK_MONOTONIC)` | `QueryPerformanceCounter` |

- 不得使用 `epoll`、`kqueue`、`getrandom`、`fork`、`mmap` 等只在部分平台存在的接口；不使用 C11 `<threads.h>`（macOS 不支持）。网络并发模型因此选用线程池（见 8.4）。
- 文件格式与网络协议在三个平台上逐字节一致；跨平台互通是测试项（T-25）。
- 论文用的性能数据以 Linux 上的 Release 构建为准，并注明 CPU 型号；其他平台的数据只作参考。
- CI：GitHub Actions 在 `ubuntu-latest`、`macos-latest`、`windows-latest` 三个平台上构建与测试。
- 发布：打 git tag（如 `v0.3.0`）后，CI 自动为三个平台构建 Release 版本，打包上传到 GitHub Releases（CPack 生成 `.tar.gz` / `.zip`）。

---

## 3. 公共构件

### 3.1 扇区编码（字节 ↔ Z_r）
- 每个扇区承载 **31 字节**数据（248 bit < 255 bit，保证 < r，无需规约）。
- 字节 → 域元素：把 31 字节按**大端**解释为整数 x，m = x（必然 < r）。
- 域元素 → 字节（仅在恢复文件时用）：必须满足 m < 2^248，否则视为数据损坏。
- 每块数据载荷大小 `BLOCK_BYTES = 31 × s`。
- 默认 s = 128，即 `BLOCK_BYTES = 3968`。

### 3.2 分块与填充
- M′ 的长度若不是 `BLOCK_BYTES` 的整数倍，末尾用 0x00 填充。
- 原始长度 L 记录在文件标签头中，恢复时据此截断。
- n = ⌈|M′| / BLOCK_BYTES⌉。要求 1 ≤ n < 2^40。

### 3.3 PRF：f_k(i) → Z_r
```
f_k(i) = OS2IP( HMAC-SHA-512(k, "SWPOR-PRF-V1" ‖ I2OSP(i, 8)) ) mod r
```
- k 为 32 字节密钥。512 bit 输出模 255 bit 的 r，偏差可忽略（< 2^-256）。
- 同一构造用于派生 α_j（见 4.1），使用不同的域分隔串。

### 3.4 哈希到 G1
```
H(name ‖ i) = hash_to_G1( name ‖ I2OSP(i, 8),  DST = "SWPOR-V1-H-BLS12381G1_XMD:SHA-256_SSWU_RO_" )
u_j         = hash_to_G1( u_seed ‖ I2OSP(j, 2), DST = "SWPOR-V1-U-BLS12381G1_XMD:SHA-256_SSWU_RO_" )
```
- name 为 32 字节文件标识（file_id）。
- 用种子派生 u_j 的做法是论文 1.1 节"Compressing the request"一段明确允许的（随机预言机模型下），这样文件标签只需存 32 字节种子，不必存 s 个群元素。

### 3.5 挑战生成

**3.5.1 显式挑战（默认，Priv 方案在标准模型下使用此模式）**
1. 若 l ≥ n，则 I = {0, …, n−1}（挑战全部块），否则用安全随机数**无放回**均匀抽取 l 个下标（拒绝采样，禁止取模带来的偏差）。
2. 对每个 i ∈ I，独立均匀抽取 ν_i ∈ [1, 2^128)（16 字节随机数，若为全 0 则重抽）。
3. Q 按 i 升序排列后发送（便于服务端顺序读盘；顺序不影响安全性）。

**3.5.2 种子挑战（Pub 方案默认；Priv 方案可选，此时安全性依赖随机预言机）**
- 验证方只发送 32 字节随机种子 seed 和 l。
- 双方用以下确定性过程展开得到同一个 Q：
```
stream = HMAC-SHA-256(seed, "SWPOR-CHAL-V1" ‖ I2OSP(ctr, 8))，ctr = 0,1,2,…
```
  从 stream 中依次读取：先用拒绝采样取 l 个互不相同、落在 [0, n) 的下标（每次取 8 字节，取模前先拒绝 ≥ ⌊2^64 / n⌋·n 的值），再依次取 l 个 16 字节的 ν_i（全 0 则跳过）。
- 这一过程必须在 `src/core/challenge.c` 中只实现一次，客户端、服务端、审计者共用。

### 3.6 默认参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| λ | 128 | |
| s | 128 | 存储开销 (1 + 1/s)，响应大小 (s+1) 个域元素 |
| l | 128 | 论文的保守取值 l = λ；可配置 |
| ν_i 位长 | 128 | 论文证明表明 λ 位系数即可 |
| ρ | 1/2 | RS(k=64, m=64)，见第 5 节 |

所有参数都必须写入文件标签头，验证时以标签为准，不允许依赖全局默认值。

---

## 4. 方案定义

### 4.1 Priv：私有验证方案（论文 3.2 节）

**Priv.Kg()**
- 生成 32 字节主密钥 `msk`。
- 派生：`k_tag = HKDF(msk, info="SWPOR-V1-TAGKEY")`。
- sk = msk；无公钥。
- 注：论文的 sk = (k_enc, k_mac)，本项目用一把 AEAD 密钥 `k_tag` 同时承担"加密 + 认证"，等价于论文的 Enc-then-MAC 组合。

**Priv.St(sk, M)**
1. 按第 5 节对 M 做预处理得到 M′，切分为 {m_ij}（n 块 × s 扇区）。
2. 生成随机 32 字节 `file_id`，以及每文件随机密钥：`k_prf`、`k_alpha`（各 32 字节）；若启用第 5 节的置乱或加密，再生成 `k_perm`、`k_fenc`。
3. 派生 α_j = f_{k_alpha}(j)，0 ≤ j < s（论文 1.1 节允许用 PRF 生成 α_j）。
4. 对每个 i 计算：
```
σ_i = f_{k_prf}(i) + Σ_{j=0}^{s-1} α_j · m_ij   (mod r)
```
5. 生成文件标签 t（格式见 4.3）：明文头作为 AEAD 附加数据，`k_prf ‖ k_alpha ‖ [k_perm ‖ k_fenc]` 作为 AEAD 明文。
6. 输出 M* = ({m_ij}, {σ_i}) 交给服务端，t 由客户端保存并可同时交给服务端。

**Priv.V(sk, t)**
1. 用 `k_tag` 解密并验证 t。失败则输出 0（错误码 `SWPOR_E_TAG_AUTH`）。
2. 从 t 恢复 n、s、k_prf、k_alpha，派生 α_j。
3. 按 3.5 生成 Q 并发送。
4. 解析响应 (μ_0, …, μ_{s-1}, σ)：每个都必须是规范编码的 Z_r 元素（32 字节大端且 < r），否则输出 0（`SWPOR_E_PARSE`）。
5. 检查：
```
σ  ==  Σ_{(i,ν_i)∈Q} ν_i · f_{k_prf}(i)  +  Σ_{j=0}^{s-1} α_j · μ_j   (mod r)
```
   相等则输出 1，否则输出 0。比较必须用常数时间比较。

**Priv.P(t, M*)**（服务端）
1. 解析 Q，检查：l 个下标互不相同、都在 [0, n)、ν_i ∈ B。不合法则返回错误。
2. 计算：
```
μ_j = Σ_{(i,ν_i)∈Q} ν_i · m_ij   (mod r)，0 ≤ j < s
σ   = Σ_{(i,ν_i)∈Q} ν_i · σ_i    (mod r)
```
3. 返回 (μ_0, …, μ_{s-1}, σ)。

### 4.2 Pub：公开验证方案（论文 3.3 节，非对称配对版本）

**Pub.Kg()**
- 随机选 x ∈ Z_r \ {0}，计算 v = g2^x ∈ G2。
- 生成 Ed25519 密钥对 (spk, ssk)。
- sk = (x, ssk)；pk = (v, spk)。

**Pub.St(sk, M)**
1. 按第 5 节预处理得到 {m_ij}。
2. 随机生成 32 字节 `file_id`（即论文中的 name）和 32 字节 `u_seed`；按 3.4 派生 u_0, …, u_{s-1} ∈ G1。
3. 对每个 i 计算：
```
σ_i = ( H(file_id ‖ i) · Π_{j=0}^{s-1} u_j^{m_ij} )^x   ∈ G1
```
   实现提示：括号内部是 s+1 个点的多标量乘，应调用 blst 的 MSM（Pippenger），不要逐个做标量乘再相加。
4. 文件标签 t = 明文头 ‖ u_seed ‖ Ed25519_Sign(ssk, 明文头 ‖ u_seed)。

**Pub.V(pk, t)**
1. 用 spk 验证 t 的签名，失败输出 0。
2. 从 t 恢复 file_id、n、s、u_seed，派生 u_j。
3. 生成 Q（默认种子挑战）。
4. 解析响应：μ_j 为规范 Z_r 元素；σ 为 48 字节压缩 G1 点，**必须通过曲线检查和子群检查**，且不是无穷远点。任一失败输出 0。
5. 检查：
```
e(σ, g2)  ==  e( Π_{(i,ν_i)∈Q} H(file_id ‖ i)^{ν_i} · Π_{j=0}^{s-1} u_j^{μ_j} ,  v )
```
   实现提示：右侧第一个参数是 l+s 个点的 MSM；配对等式用"e(σ, −g2) · e(X, v) == 1"的形式，一次 Miller 循环对、一次最终幂。

**Pub.P(pk, t, M*)**
1. 同 4.1 校验 Q。
2. 计算 μ_j（同 Priv），以及 σ = Π_{(i,ν_i)∈Q} σ_i^{ν_i}（l 个点的 MSM）。
3. 返回 (μ_0, …, μ_{s-1}, σ)。

### 4.3 文件标签（file tag）格式

所有整数大端。

**明文头（两方案共用，共 72 字节）**

| 偏移 | 长度 | 字段 |
|---|---|---|
| 0 | 4 | magic = `"SWPT"` |
| 4 | 1 | version = 1 |
| 5 | 1 | scheme：1 = Priv，2 = Pub |
| 6 | 2 | flags：bit0 = 启用 RS，bit1 = 启用置乱，bit2 = 启用文件加密 |
| 8 | 32 | file_id |
| 40 | 8 | n（块数） |
| 48 | 2 | s（每块扇区数） |
| 50 | 2 | RS 参数 k |
| 52 | 2 | RS 参数 m |
| 54 | 2 | 保留，置 0 |
| 56 | 8 | L（原始文件长度） |
| 64 | 8 | 创建时间（Unix 秒） |

**Priv 方案的标签尾部**
- 12 字节 GCM nonce ‖ 密文（64 字节，若启用置乱/加密则为 128 字节） ‖ 16 字节 GCM 认证标签。
- AEAD 附加数据 = 72 字节明文头。

**Pub 方案的标签尾部**
- 32 字节 u_seed ‖ 64 字节 Ed25519 签名（签名对象 = 明文头 ‖ u_seed）。

---

## 5. 文件预处理流水线（纠删码层）

论文要求纠删码在**对抗性擦除**下仍能恢复（论文 1.1 节与附录 A）。全文件级 RS 编码的复杂度是 O(n²)，不可行；因此 v1 采用"条带 RS + 秘密置乱"的工程折中：

```
M ──[可选] AES-256-CTR(k_fenc) ──► 切成 BLOCK_BYTES 大小的数据块
  ──► 每 k 个数据块为一个条带，用 RS(k, m) 生成 m 个校验块（ISA-L，系统码）
  ──► [可选] 用 k_perm 对全部 n 个块做秘密伪随机置换
  ──► M′（n 块）
```

- 默认 k = m = 64（ρ = 1/2）。最后一个条带不足 k 块时用全零块补齐（补齐的块也参与存储与审计）。
- 置换：用 k_perm 驱动的 Fisher–Yates 洗牌，随机源为 HMAC-SHA-256(k_perm, "SWPOR-PERM-V1" ‖ ctr)，拒绝采样取下标。
- **恢复**：读取全部块 → 逆置换 → 每个条带用任意 k 个完好块解码 → 拼接 → 解密 → 按 L 截断。验证块是否"完好"的方法：对单块做一次只含该块的挑战（l=1）或直接重算其 σ_i（Priv 方案下客户端有密钥）。

**安全性说明（必须写入测试报告和论文的"局限性"部分）：**
- 条带 RS 只在**单个条带内**抵抗对抗性擦除。若服务端知道哪些块属于同一条带，就可以集中删除一个条带中超过 m 块而让文件不可恢复，同时只让很少的审计失败。
- 秘密置乱 + 文件加密是为了让服务端无法识别条带结构（思路与论文附录 A.2 相同）。但这依赖于密钥保密，因此**只提供私有可恢复性**；Pub 方案在启用置乱时失去公开可恢复性。
- 对此折中的严格安全性分析尚未完成，登记为 **OPEN-1**。这本身也是一个可以写进论文的研究点。

---

## 6. 存储格式（服务端磁盘布局）

服务端为每个文件保存三份文件，存放在 `<data_dir>/<file_id 的十六进制>/` 下：

| 文件 | 内容 |
|---|---|
| `blocks.dat` | 8 字节文件头（magic `"SWPB"` + version + 3 字节保留）后紧接 n × BLOCK_BYTES 字节的 M′ |
| `sigma.dat` | 8 字节文件头（magic `"SWPS"` + version + scheme + 2 字节保留）后紧接 n 个 σ_i（Priv：每个 32 字节；Pub：每个 48 字节压缩 G1 点） |
| `tag.bin` | 文件标签 t（服务端不能解密 Priv 方案的秘密部分，只读取明文头） |

- 证明生成时按需随机读取 l 个块，不得把整个文件读进内存（文件可能是 GB 级）。
- 本地模式下，客户端用同样的布局写入一个本地目录，模拟服务端。

---

## 7. 密钥文件格式

| 文件 | 内容 | 权限 |
|---|---|---|
| `priv.key` | magic `"SWSK"` ‖ version ‖ scheme=1 ‖ msk(32) | 0600 |
| `pub.sk` | magic `"SWSK"` ‖ version ‖ scheme=2 ‖ x(32, 大端) ‖ ed25519_sk(32) | 0600 |
| `pub.pk` | magic `"SWPK"` ‖ version ‖ scheme=2 ‖ v(96, 压缩 G2) ‖ ed25519_pk(32) | 0644 |

- 写秘密密钥文件时用 `swpor_file_create_private`（见 2.1）：创建时就只有当前用户可读写，不覆盖已有文件，除非用户显式传 `--force`。
- 内存中的秘密数据用完后用 `OPENSSL_cleanse` 清零。

---

## 8. 网络协议（M3 起）

### 8.1 传输
- v1：TCP，单连接单请求-响应序列；服务端默认端口 7878。
- M5：在 TCP 上加 TLS 1.3（OpenSSL）。
- 注：PoR 的安全性不依赖信道保密，但产品形态需要对服务端身份进行认证，所以 TLS 是必需的后续工作。

### 8.2 帧格式
```
| length: u32 (不含本字段) | type: u8 | payload: length-1 字节 |
```
- 单帧上限 16 MiB；大文件上传分多帧（STORE_CHUNK）。
- 未知 type、超长帧、解析失败一律返回 ERROR 并关闭连接。

### 8.3 消息类型

| type | 名称 | 方向 | payload |
|---|---|---|---|
| 0x01 | HELLO | C→S | proto_version u16 |
| 0x02 | HELLO_OK | S→C | proto_version u16，server_caps u32 |
| 0x10 | STORE_BEGIN | C→S | tag_len u32 ‖ tag ‖ n u64 ‖ block_bytes u32 ‖ sigma_bytes u8 |
| 0x11 | STORE_BLOCKS | C→S | start_index u64 ‖ count u32 ‖ 块数据 |
| 0x12 | STORE_SIGMAS | C→S | start_index u64 ‖ count u32 ‖ σ 数据 |
| 0x13 | STORE_END | C→S | （空） |
| 0x14 | STORE_OK | S→C | file_id(32) |
| 0x20 | CHALLENGE | C→S | file_id(32) ‖ mode u8（0=显式，1=种子） ‖ l u32 ‖ [显式：l × (index u64 ‖ ν 16B)] 或 [种子：seed 32B] |
| 0x21 | PROOF | S→C | s u16 ‖ s × μ_j(32B) ‖ σ（32B 或 48B） |
| 0x30 | GET_TAG | C→S | file_id(32) |
| 0x31 | TAG | S→C | tag_len u32 ‖ tag |
| 0x32 | GET_BLOCKS | C→S | file_id(32) ‖ start u64 ‖ count u32 |
| 0x33 | BLOCKS | S→C | start u64 ‖ count u32 ‖ 块数据 |
| 0x40 | DELETE | C→S | file_id(32) |
| 0x41 | OK | S→C | （空） |
| 0x7F | ERROR | S→C | code u16 ‖ msg_len u16 ‖ msg（UTF-8） |

- 服务端对 CHALLENGE 的 l 设上限（默认 4096），防止资源耗尽。

### 8.4 服务端并发模型：固定大小线程池
- 主线程负责 `accept()`，把新连接放入**有界**任务队列；队列满时直接返回 ERROR（code = BUSY）并关闭连接，不无限排队。
- 工作线程数默认等于 CPU 核数（`--threads` 可配置）。每个工作线程用阻塞 I/O 处理一个连接上的全部请求，直到连接关闭。
- 每个连接设置读写超时（默认 30 秒，`SO_RCVTIMEO` / `SO_SNDTIMEO`；注意 Windows 上这两个选项的参数是毫秒数 DWORD，POSIX 上是 `struct timeval`，由平台层屏蔽），防止慢速连接长期占用线程。
- 线程、锁一律通过 `src/platform/` 的接口使用（见 2.1）。
- 选择理由：证明生成是 CPU 密集（Pub 方案的 MSM）加上随机读盘，并发连接数不高（几十到几百），线程池足够，而且代码简单、可移植（macOS 与 Linux 一致）。epoll/kqueue 适合上万个空闲长连接的场景，本项目用不到。
- 文件级并发控制：同一 file_id 的 STORE 与 DELETE 互斥；CHALLENGE、GET_BLOCKS 可以并发读。用每文件一个读写锁实现。

---

## 9. 软件组成与命令行

### 9.1 组件

| 组件 | 角色 | 说明 |
|---|---|---|
| `libswpor` | 核心库 | 第 3～7 节的全部算法与格式；**不含任何网络或 CLI 代码** |
| `porctl` | 数据所有者客户端 | 密钥生成、预处理、打标签、上传、审计、检索 |
| `pord` | 存储服务端 | 存储 M* 与 t，响应挑战与检索 |
| `porta` | 第三方审计者（M4） | 只持有 pk 和 t，按计划定期审计 Pub 方案文件，记录审计日志 |
| `porbench` | 基准测试工具（M4） | 输出 CSV，供测试报告和论文作图 |

### 9.2 `porctl` 子命令

```
porctl keygen   --scheme priv|pub  --out <dir>
porctl store    --key <keyfile> --in <file> [--s 128] [--rs 64:64] [--no-rs] [--perm] [--encrypt]
                (--local <dir> | --server <host:port>)
                → 输出 file_id 和本地保存的 tag 路径
porctl audit    --key <keyfile> --tag <tagfile> [--l 128] [--seed-mode]
                (--local <dir> | --server <host:port>)
                → 输出 PASS / FAIL、耗时、响应大小
porctl retrieve --key <keyfile> --tag <tagfile> --out <file>  (--local <dir> | --server <host:port>)
porctl info     --tag <tagfile>
porctl tamper   --local <dir> --file-id <hex> --mode flip|zero|delete --ratio <0..1> [--seed N]
                （仅用于测试与演示：在本地存储中按比例篡改块）
```

- 退出码：0 = 成功/PASS；1 = 审计 FAIL；2 = 参数错误；3 = I/O 错误；4 = 网络错误；5 = 密码学/格式错误。
- 所有子命令支持 `--json`，输出机器可读结果，供测试脚本使用。

### 9.3 `pord`
```
pord --listen 0.0.0.0:7878 --data-dir <dir> [--max-l 4096] [--threads N] [--log <file>]
```

### 9.4 执行轨迹（trace）事件流
为了让可视化界面、测试脚本和基准工具都能观察算法的执行过程，`libswpor` 提供一个可选的事件回调：

```c
typedef void (*swpor_trace_fn)(const swpor_event_t *ev, void *user);
void swpor_set_trace(swpor_ctx_t *ctx, swpor_trace_fn fn, void *user);
```

- 未设置回调时没有任何开销（只是一次空指针判断）。
- `porctl` 与 `pord` 增加 `--trace <file|->` 选项，把事件以 **NDJSON**（每行一个 JSON 对象）写出。
- 事件类型（v1）：

| type | 触发时机 | 主要字段 |
|---|---|---|
| `file_split` | 完成分块 | n, s, L, block_bytes |
| `ec_stripe` | 完成一个 RS 条带 | stripe, k, m |
| `tag_block` | 每生成一个 σ_i（大文件时按每 N 块采样一次） | i |
| `tag_done` | 打标签结束 | n, elapsed_ms |
| `challenge` | 生成挑战 | l, mode, indices（前 64 个） |
| `prove_done` | 服务端生成证明 | l, s, elapsed_ms, proof_bytes |
| `verify` | 验证结束 | result（PASS/FAIL）, elapsed_ms |
| `tamper` | `porctl tamper` 篡改块 | indices, mode |

- **任何事件都不得包含秘密数据**（msk、k_prf、α_j、x 等）；也不输出完整的块内容或 σ_i 值。

### 9.5 可视化界面（M-UI，选做）
- 定位：课程答辩与软著截图用的**教学演示**，不是核心产品；核心产品仍是 CLI（`porctl` / `pord` / `porta`）。
- 技术路线：**Web 前端（HTML + TypeScript）**，两种模式：
  1. **教学模式**：用很小的玩具参数（如 n = 8、s = 4、p 为 16 bit 素数）在前端用 JS BigInt 重新实现 Priv 方案，逐步动画展示：扇区矩阵 → α_j 与 σ_i → 挑战选中的行与 ν_i → 按列聚合得到 μ_j → 验证等式两边 → PASS/FAIL；可以点击任意格子篡改数据，再次审计看检测结果。教学模式**仅用于演示，与 C 实现无关**，界面上要明确标注"玩具参数，不安全"。
  2. **实况模式**：前端读取 `porctl --trace` 输出的 NDJSON 事件，展示真实文件的审计过程与耗时。
- 桌面封装（可选）：同一套 Web 前端可以用基于系统 WebView 的桌面框架打包成跨平台桌面应用，后端以子进程方式调用 `porctl`，不直接链接 `libswpor`。具体框架在 M-UI 开始前决定。

---

## 10. 测试计划（与《测试报告》一一对应）

### 10.1 正确性

| 编号 | 内容 | 里程碑 |
|---|---|---|
| T-01 | 域运算、扇区编码的往返测试（字节→Z_r→字节） | M0 |
| T-02 | PRF 确定性；不同 k、不同 i 输出不同 | M0 |
| T-03 | 差分测试：Python 参考实现（`tests/ref/priv_ref.py`，用 Python 大整数）与 C 实现对同一输入的 σ_i、μ、σ 逐字节一致 | M0/M1 |
| T-04 | 诚实服务端：随机文件 × 多组 (n, s, l) 参数，审计 100% 通过 | M1 |
| T-05 | 篡改单个扇区后，挑战命中该块时审计必须失败 | M1 |
| T-06 | 篡改 σ_i 后，挑战命中该块时审计必须失败 | M1 |
| T-07 | 伪造响应：随机 μ/σ、非规范编码（≥ r）、长度错误，均必须被拒绝 | M1 |
| T-08 | 篡改文件标签任一字节，Priv 解密失败 / Pub 验签失败 | M1 |
| T-09 | 边界情况：L = 0、L = 1、L 恰为 BLOCK_BYTES 整数倍、n = 1、l > n | M2 |
| T-10 | 检索：无损坏时恢复文件与原文件逐字节相同 | M2 |
| T-11 | 每个条带删除 ≤ m 块后仍能恢复 | M2 |
| T-12 | 某条带删除 > m 块时，恢复报告失败而不是输出错误数据 | M2 |
| T-13 | 启用 `--perm --encrypt` 后的往返恢复 | M2 |
| T-14 | CLI 退出码与 `--json` 输出格式 | M2 |
| T-15 | 网络往返：本地模式与远程模式的审计结果一致 | M3 |
| T-16 | 协议健壮性：畸形帧、超长帧、未知 type、半关闭连接，服务端不崩溃 | M3 |
| T-17 | 并发：N 个客户端同时审计，结果全部正确 | M3 |
| T-18 | 服务端重启后数据仍可审计 | M3 |
| T-19 | Pub 方案：重复 T-04～T-08 | M4 |
| T-20 | Pub 方案：σ 为非子群点、无穷远点、非法压缩编码时必须拒绝 | M4 |
| T-21 | `porta` 只用 pk 和 t 就能完成审计 | M4 |
| T-25 | 跨平台互通：在一个平台上 `store`，在另一个平台上 `audit` / `retrieve`（至少覆盖 macOS 客户端 ↔ Linux 服务端，以及 Windows 客户端 ↔ Linux 服务端）；同一输入与同一确定性测试随机源下，三个平台生成的标签文件逐字节相同 | M3 |
| T-26 | 非 ASCII 路径（中文文件名、带空格的路径）在三个平台上都能正常存储与恢复 | M2 |

### 10.2 篡改检测率实验
| 编号 | 内容 |
|---|---|
| T-22 | 以比例 x ∈ {0.1%, 0.5%, 1%, 5%, 10%} 随机损坏块，每组运行 ≥ 1000 次审计，统计检测率，与理论值 1 − C(n−d, l)/C(n, l)（d = 损坏块数）对比作图 |

### 10.3 性能基准
| 编号 | 内容 |
|---|---|
| T-23 | 扫描参数：文件大小 {1 MB, 16 MB, 256 MB, 1 GB} × s {1, 16, 64, 128, 256} × l {64, 128, 460}，分别测：预处理时间、打标签吞吐（MB/s）、证明生成时间、验证时间、挑战大小、响应大小、存储开销 |
| T-24 | 方案对比：Priv vs Pub vs Simple-MAC 基线（vs RSA，若做了 M5） |

- 每个数据点至少重复 10 次，报告中位数与四分位数。
- 每次基准运行时记录：CPU 型号、核数、内存、OS、编译器版本、编译选项、git commit 哈希。结果保存为 `bench/results/<日期>_<commit>.csv`。

### 10.4 工程质量
- 所有单元测试在 `-fsanitize=address,undefined` 下运行无报错。
- 对 `PROOF` 解析、`CHALLENGE` 解析、文件标签解析分别做 libFuzzer 模糊测试（M3 起），每个目标至少运行 1 小时无崩溃。
- valgrind memcheck 无泄漏（M2 起）。

---

## 11. 安全注意事项清单

1. 所有从网络或磁盘读入的域元素都必须做规范性检查（< r），所有群元素都必须做曲线检查与子群检查。
2. 验证方的最终等式比较使用常数时间比较。
3. 秘密数据（msk、k_prf、k_alpha、x、α_j）用完立即清零；不得出现在日志、错误消息或 `--json` 输出中。
4. 随机数只能来自 `RAND_bytes`；测试用的确定性随机数必须通过编译期开关 `SWPOR_TESTING` 才能启用，发布构建中不存在该代码路径。
5. 服务端必须校验 Q 中下标不重复、在范围内；不重复这一条很重要：论文的提取论证依赖下标互不相同。
6. 服务端的输入长度、l 上限、帧大小都要有上限，防止资源耗尽。
7. 论文附录 B 说明：若去掉挑战系数 ν_i（即令 B = {1}），存在实际攻击。**禁止**提供 ν_i = 1 的"优化"选项。

---

## 12. 论文勘误（实现时注意，不要照抄）

- 3.2 节 Priv.P 与 3.3 节 Pub.P 末尾的"Send to the prover in response"应为"发送给验证方（verifier）"。
- 6.1 节 PubRSA.P 中"For each j, 1 ≤ s ≤ j"应为"1 ≤ j ≤ s"。
- 6.1 节小标题写作"private verification scheme PubRSA"，实为公开验证方案。

---

## 13. 待定问题（OPEN）

| 编号 | 问题 | 状态 |
|---|---|---|
| OPEN-1 | 条带 RS + 秘密置乱 的安全性严格分析；能否找到更好的、线性时间且抵抗对抗性擦除的编码方案 | 研究问题 |
| ~~OPEN-2~~ | 服务端并发模型 | **已决定**：固定大小线程池（8.4） |
| OPEN-3 | 私有方案使用 p = 2^127 − 1 的快速变体是否值得做；与 255 bit 域的性能差距 | M4 后评估 |
| OPEN-4 | Pub 方案的批量审计（多个文件/多个用户的配对批量验证） | 研究方向，可作为论文创新点 |
| ~~OPEN-5~~ | 构建系统 | **已决定**：CMake（2.1） |
| OPEN-6 | M-UI 桌面封装框架的选择 | M-UI 开始前决定 |

---

## 14. 变更记录

| 日期 | 版本 | 变更 | 作者 |
|---|---|---|---|
| 2026-11-05 | v0.1 | 初稿 | |
| 2026-11-05 | v0.2 | 确定 CMake 与线程池（关闭 OPEN-2、OPEN-5）；新增 2.1 平台要求、8.4 并发模型、9.4 trace 事件流、9.5 可视化界面与 M-UI 里程碑；新增 OPEN-6 | |
| 2026-11-05 | v0.3 | 新增 Windows 支持（Tier 2）；2.1 节改为三级平台支持、vcpkg、平台抽象层与发布流程；新增 T-25、T-26 | |
| 2026-11-05 | v0.4 | Windows 只做客户端，`pord` 不在 Windows 上构建（新增 CMake 选项 `SWPOR_BUILD_SERVER`） | |
