#!/usr/bin/env python3
"""
汇总 porbench 输出的 CSV（SPEC 10.3：报告中位数与四分位数）。只用 Python 标准库。

用法：python3 bench/summarize.py bench/results/<日期>_<commit>.csv [--metric prove_ms ...]

按 (scheme, size_bytes, s, l) 分组，对每个指标输出 中位数 [Q1, Q3]，格式为 Markdown 表格。
所有数字都直接来自 CSV，不做任何修改。
"""

import argparse
import csv
import statistics
import sys
from collections import OrderedDict

DEFAULT_METRICS = ["preprocess_ms", "tag_ms", "tag_mb_s", "prove_ms", "verify_ms",
                   "challenge_bytes", "proof_bytes", "storage_overhead"]


def quartiles(xs):
    xs = sorted(xs)
    if len(xs) == 1:
        return xs[0], xs[0], xs[0]
    q = statistics.quantiles(xs, n=4, method="inclusive")
    return q[0], statistics.median(xs), q[2]


def fmt(v):
    return f"{v:.4g}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--metric", action="append")
    args = ap.parse_args()
    metrics = args.metric or DEFAULT_METRICS

    groups = OrderedDict()
    env = set()
    with open(args.csv, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if "prove_ms" not in row:
                sys.exit("this does not look like 'porbench run/sweep' output")
            key = (row["scheme"], int(row["size_bytes"]), int(row["s"]), int(row["l"]))
            groups.setdefault(key, []).append(row)
            env.add((row["commit"], row["cpu"], row["os"], row["compiler"], row["build_type"]))

    for e in sorted(env):
        print(f"- commit `{e[0]}`, CPU {e[1]}, {e[2]}, {e[3]}, {e[4]}")
    print()
    print("| scheme | size | s | l | reps | " + " | ".join(metrics) + " |")
    print("|---|---|---|---|---|" + "---|" * len(metrics))
    for (scheme, size, s, l), rows in groups.items():
        cells = []
        for m in metrics:
            vals = [float(r[m]) for r in rows]
            q1, med, q3 = quartiles(vals)
            cells.append(f"{fmt(med)} [{fmt(q1)}, {fmt(q3)}]")
        print(f"| {scheme} | {size} | {s} | {l} | {len(rows)} | " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
