# bench — 基准测试（M4）

- `results/`：`porbench` 输出的 CSV，命名为 `<日期>_<commit>.csv`，**提交到仓库**，作为测试报告和论文数据的来源。
- `plot/`：作图脚本，只从 CSV 读数据，不硬编码任何数字。

正式数据在 Linux x86_64 上用 `release` 预设构建后测量，每个数据点至少重复 10 次（SPEC 10.3）。
