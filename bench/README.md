# bench — 基准测试（M4）

- `results/`：`porbench` 输出的 CSV，命名为 `<日期>_<commit>.csv`，**提交到仓库**，作为测试报告和论文数据的来源。
- `summarize.py`：按参数分组输出中位数与四分位数（Markdown 表格），只读 CSV，不硬编码任何数字。
- `plot/`：作图脚本（尚未编写；需要先决定作图依赖，见 AGENTS.md"引入新依赖前先问用户"）。

正式数据在 Linux x86_64 上用 `release` 预设构建后测量，每个数据点至少重复 10 次（SPEC 10.3）：

```bash
cmake --preset release && cmake --build --preset release
B=build/release/apps
OUT=bench/results/$(date +%Y%m%d)_$(git rev-parse --short HEAD).csv
# T-23：参数扫描（1 GB 的组耗时较长，可分批运行，结果追加到同一个 CSV）
$B/porbench sweep --scheme priv,pub --sizes 1M,16M,256M,1G --s 1,16,64,128,256 --l 64,128,460 --reps 10 --out $OUT
# T-24：方案对比
$B/porbench sweep --scheme priv,pub,mac --sizes 16M --s 128 --l 128 --reps 10 --out $OUT
# T-22：篡改检测率（与理论值 1 − C(n−d, l)/C(n, l) 一起输出）
$B/porbench detect --n 10000 --l 128 --ratios 0.001,0.005,0.01,0.05,0.1 --trials 1000 \
    --out bench/results/$(date +%Y%m%d)_$(git rev-parse --short HEAD)_detect.csv
python3 bench/summarize.py $OUT
```

说明：`porbench` 在进程内调用库函数并把数据写到 `--dir`（默认 `bench/tmp/`，已在 .gitignore 中），
不经过网络，因此 `prove_ms` 包含读盘时间但不含网络往返。`tag_ms` = 预处理 + 打标签 + 写盘的总时间减去单独测得的预处理时间。
