#!/usr/bin/env python
"""Finalize the bench_100 report: accuracy table, confusion matrix, branch
and first-stage stats from evaluation/bench_100/{TYPE}/records.jsonl.

Usage: python evaluation/bench_100/finalize_report.py [--markdown out.md]
"""

import argparse
import collections
import glob
import json
import os
import statistics

BENCH = os.path.dirname(os.path.abspath(__file__))
TYPES = json.load(open(os.path.join(os.path.dirname(os.path.dirname(BENCH)),
                                    "config", "rag_devices.json")))["IoT"]


def load_records():
    data = {}
    for t in TYPES:
        p = os.path.join(BENCH, t, "records.jsonl")
        if not os.path.exists(p):
            continue
        last = {}
        for line in open(p):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if r.get("ip") and r.get("predicted_type"):
                last[str(r["ip"])] = r
        if last:
            data[t] = list(last.values())
    return data


def report(data):
    lines = []
    tot_n = tot_ok = 0
    conf = collections.Counter()
    elapsed_all = []
    win = collections.Counter()
    for t in TYPES:
        recs = data.get(t, [])
        done = [r for r in recs if r.get("predicted_type")]
        committed = [r for r in done if r["predicted_type"] != "UNKNOWN"]
        unk = len(done) - len(committed)
        ok = [r for r in committed if r["predicted_type"] == t]
        for r in committed:
            conf[(t, r["predicted_type"])] += 1
            if r.get("winning_llm"):
                win[r["winning_llm"]] += 1
            if isinstance(r.get("elapsed_sec"), (int, float)):
                elapsed_all.append(r["elapsed_sec"])
        tot_n += len(committed)
        tot_ok += len(ok)
        el = [r["elapsed_sec"] for r in committed
              if isinstance(r.get("elapsed_sec"), (int, float))]
        med = statistics.median(el) if el else None
        acc = f"{100*len(ok)/max(1,len(committed)):.0f}%"
        unk_note = f" (+{unk} UNKNOWN)" if unk else ""
        med_s = f"{med:.0f}s" if med is not None else "-"
        lines.append(f"| {t} | {len(ok)}/{len(committed)}{unk_note} | {acc} | {med_s} |")
    lines.append(f"| **TOTAL** | **{tot_ok}/{tot_n}** | "
                 f"**{100*tot_ok/max(1,tot_n):.1f}%** | "
                 f"{statistics.median(elapsed_all):.0f}s |" if elapsed_all else
                 "| **TOTAL** | - | - | - |")

    out = ["## 最终效果表", "",
           "| 类型 | 判对/完成 | 准确率 | 决策耗时中位/IP |",
           "|---|---|---|---|"] + lines + ["",
           f"- 判决获胜方分布: {dict(win)}",
           f"- 决策耗时中位: {statistics.median(elapsed_all):.0f}s"
           if elapsed_all else "", "",
           "## 混淆矩阵（行=真值, 列=Top 预测）", ""]
    for t in TYPES:
        recs = data.get(t, [])
        if not recs:
            continue
        c = collections.Counter(r["predicted_type"] for r in recs)
        top = ", ".join(f"{k}×{v}" for k, v in c.most_common(4))
        out.append(f"- **{t}** → {top}")
    return "\n".join(out)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--markdown", default=None)
    a = p.parse_args()
    data = load_records()
    txt = report(data)
    print(txt)
    if a.markdown:
        open(a.markdown, "w").write(txt + "\n")
        print(f"\nwritten -> {a.markdown}")
