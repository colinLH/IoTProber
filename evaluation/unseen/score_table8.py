#!/usr/bin/env python3
"""Table 8 (unseen devices: VPN / Media Server) canonical scorer.

Recomputes every Table 8 cell from the RAW released prediction artifacts
(no derived CSVs needed) with EXPLICIT conventions:

  type   : accuracy = P(pred_type == device); F1 = 2*acc/(1+acc)
           (binary positive-class F1 — every test IP is of the unseen type,
           so precision is 1 by construction; see split_and_evaluate.py,
           whose loader functions this script imports)
  vendor : top-1 / top-3 accuracy over the vendor-labeled subset
           (evaluation/unseen/vendor/dataset/test_<dev>_label.csv), reported
           under BOTH conventions:
             fuzzy  case/punctuation-insensitive (split_and_evaluate canonical)
             exact  case-sensitive byte equality

Verified findings (scorer v1.1.0) — which convention reproduces the paper:
  * IoTProber vendor cells reproduce under EXACT match only:
      VPN 3572/3933 = 0.9082 (fuzzy would give 0.9090; the 3 flipped IPs are
      case-only variants: SonicWall/SonicWALL ×2, TP-Link/TP-LINK),
      MEDIA_SERVER 8932/9525 = 0.9377 (fuzzy 0.9378; one Asus/ASUS flip).
  * B2 (ClaudeOpus) vendor cells reproduce under FUZZY match only
      (exact drops them to 0.6272/0.9602 and 0.8411/0.8986).
    => the paper's Table 8 mixes two vendor-scoring passes.
  * B2 type cells reproduce exactly (its released type_analysis.csv contains
    0.7979/0.6638 and 0.1586/0.0861).
  * B1 (Mahmood) cells are NOT reproducible from the released
    predict_{dev}.json: they give type 0.7802/0.6397 (MS) and 0.7668/0.6217
    (VPN), vendor 0.5630/0.9415 (MS) and 0.5645/0.9321 (VPN) under every
    convention tested. The printed B1 values (0.8234/0.7512, 0.3421/0.2156,
    0.5123/0.8456, 0.6234/0.8912) admit no integer solution at the released
    denominators (7804/12050/3933/9525), so they come from a different B1
    prediction matrix that was not preserved.

Inputs (HuggingFace ``IoTProber/raw_dataset``, prefix ``evaluation/unseen``):
  predict/IoTProber/predict_{dev}.json
  predict/baseline/Mahmood/predict_{dev}.json            (B1)
  predict/baseline/ClaudeOpus/all_result_type_{dev}.csv   (B2)
  predict/baseline/llama3raw/all_result_type_{dev}.csv

Usage
  python score_table8.py                  # recompute + compare with paper cells
  python score_table8.py --json out.json
"""
import argparse
import json
import os
import platform
import sys

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from split_and_evaluate import (  # noqa: E402
    METHODS,
    load_predictions_csv,
    load_predictions_json,
    load_vendor_labels,
    compute_vendor_metrics,
)

SCORER_VERSION = "1.1.0"

# Paper (CCS'26 submission) Table 8 cells, format IoTProber / B1 / B2
# (source: evaluation/unseen/table4.tex).
PAPER_CELLS = {
    "MEDIA_SERVER": {
        "type_f1": ("0.9980", "0.8234", "0.7979"),
        "type_accuracy": ("0.9961", "0.7512", "0.6638"),
        "vendor_top1": ("0.9377", "0.5123", "0.6299"),
        "vendor_top3": ("1.0000", "0.8456", "0.9654"),
    },
    "VPN": {
        "type_f1": ("0.9963", "0.3421", "0.1586"),
        "type_accuracy": ("0.9926", "0.2156", "0.0861"),
        "vendor_top1": ("0.9082", "0.6234", "0.8596"),
        "vendor_top3": ("1.0000", "0.8912", "0.9186"),
    },
}

DEVICE_TYPES = ["VPN", "MEDIA_SERVER"]
PAPER_METHOD_ORDER = ["IoTProber", "Mahmood", "ClaudeOpus"]  # M / B1 / B2


def type_metrics(type_df, dev):
    n = len(type_df)
    acc = (type_df["pred_type"].astype(str) == dev).sum() / n
    f1 = 2 * acc / (1 + acc) if acc > 0 else 0.0
    return round(f1, 4), round(acc, 4)


def vendor_metrics_exact(vendor_df, ip2vendor):
    """Case-sensitive byte-equality top-1/top-3 over the labeled subset."""
    df = vendor_df[vendor_df["ip"].isin(ip2vendor)].copy()
    if df.empty:
        return 0.0, 0.0
    true = df["ip"].map(ip2vendor).astype(str)
    tops = [df[c].astype(str) for c in ("pred_top1", "pred_top2", "pred_top3")]
    n = len(df)
    top1 = (true == tops[0]).sum() / n
    top3 = ((true == tops[0]) | (true == tops[1]) | (true == tops[2])).sum() / n
    return round(top1, 4), round(top3, 4)


def main():
    base = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="write machine-readable record here")
    args = ap.parse_args()

    record = {
        "scorer_version": SCORER_VERSION,
        "python": platform.python_version(),
        "pandas": pd.__version__,
        "conventions": {
            "type": "F1 = 2*acc/(1+acc), acc = P(pred_type == device)",
            "vendor_fuzzy": "split_and_evaluate.normalize_vendor on both sides",
            "vendor_exact": "case-sensitive byte equality",
        },
        "rows": [],
    }

    header = (f"{'device':<14}{'method':<12}{'type F1':>9}{'type acc':>10}"
              f"{'v top1 fz':>10}{'v top1 ex':>10}{'v top3 fz':>10}{'v top3 ex':>10}")
    lines = [header, "-" * len(header)]
    for dev in DEVICE_TYPES:
        ip2v = load_vendor_labels(dev)
        for m in ["IoTProber", "Mahmood", "ClaudeOpus", "llama3raw"]:
            cfg = METHODS[m]
            path = cfg["path"](dev)
            if not os.path.exists(path):
                lines.append(f"{dev:<14}{m:<12}MISSING {path}")
                continue
            if cfg["kind"] == "json":
                type_df, vendor_df = load_predictions_json(dev, path)
            else:
                type_df, vendor_df = load_predictions_csv(dev, path)
            f1, acc = type_metrics(type_df, dev)
            t1f, t3f = compute_vendor_metrics(vendor_df, ip2v)
            t1e, t3e = vendor_metrics_exact(vendor_df, ip2v)
            row = {"device": dev, "method": m, "type_f1": f1, "type_accuracy": acc,
                   "vendor_top1_fuzzy": t1f, "vendor_top1_exact": t1e,
                   "vendor_top3_fuzzy": t3f, "vendor_top3_exact": t3e,
                   "n": len(type_df)}
            record["rows"].append(row)
            lines.append(f"{dev:<14}{m:<12}{f1:>9}{acc:>10}"
                         f"{t1f:>10}{t1e:>10}{t3f:>10}{t3e:>10}")
        lines.append("")

    lines.append("Paper Table 8 cells (IoTProber / B1 / B2) vs recomputed "
                 "(vendor: fz=comparison under fuzzy, ex=under exact):")
    for dev, metrics in PAPER_CELLS.items():
        got = {r["method"]: r for r in record["rows"] if r["device"] == dev}
        for metric, cells in metrics.items():
            for i, m in enumerate(PAPER_METHOD_ORDER):
                want = cells[i]
                r = got.get(m)
                if r is None:
                    continue
                key = metric
                if metric.startswith("vendor"):
                    key = metric  # handled below with both conventions
                have = r.get(key if key in r else metric)
                if metric.startswith("vendor"):
                    fz = r[metric + "_fuzzy"] if metric + "_fuzzy" in r else r.get(metric)
                    ex = r[metric + "_exact"]
                    mark = ("OK(exact)" if f"{ex:.4f}" == want else
                            "OK(fuzzy)" if fz is not None and f"{fz:.4f}" == want else
                            f"DIFFERS (paper {want}; ex {ex}, fz {fz})")
                    lines.append(f"  {dev:<14}{metric:<14}{m:<11}{mark}")
                else:
                    mark = "OK" if have is not None and f"{have:.4f}" == want else \
                           f"DIFFERS (paper {want}, recomputed {have})"
                    lines.append(f"  {dev:<14}{metric:<14}{m:<11}{mark}")

    report = "\n".join(lines)
    print(report)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(record, fh, indent=1)
        print(f"\nrecord -> {args.json}")


if __name__ == "__main__":
    main()
