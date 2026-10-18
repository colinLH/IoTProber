#!/usr/bin/env python
"""Score a fresh IoTProber run against the values reported in the paper.

Reads only the per-device decision records written by
``agent/agent.py --decision`` (``$IOTPROBER_PREDICTION_DIR/{DEV}_type_prediction.json``
and ``{DEV}_vendor_prediction.json``) and the test fingerprints the run consumed
(``$IOTPROBER_VALIDATION_DIR/test_{DEV}_1.csv``). Every test IP counts: an IP
without a committed decision is scored as ``UNKNOWN`` (wrong), so incomplete
runs cannot inflate a metric by shrinking its denominator.

Tolerance per metric = max(1 percentage point, 95% binomial half-width
1.96*sqrt(p(1-p)/n)) at the paper value p and the number n of samples that
enter the metric in this run.

Usage:
  python evaluation/check_results.py --suite known    # Tables 2, 3, 7 (full-pipeline rows)
  python evaluation/check_results.py --suite unseen   # Table 8
"""

import argparse
import json
import math
import os
import re
import sys

import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from path_config import (  # noqa: E402
    EVALUATION_DIR, LABEL_DATA_DIR, PREDICTION_DIR, RAG_DEVICES_FILE, VALIDATION_DIR,
)

KNOWN = json.load(open(RAG_DEVICES_FILE))["IoT"]
UNSEEN = ["MEDIA_SERVER", "VPN"]

# Paper, Table 2 (IoTProber column): per-type (precision, recall).
TABLE2 = {
    "ROUTER": (0.9834, 0.9804), "SCADA": (0.9647, 0.9820), "PRINTER": (0.9763, 0.9905),
    "CAMERA": (0.9898, 0.9773), "MEDICAL": (0.9271, 0.9799),
    "BUILDING_AUTOMATION": (0.9275, 0.9843), "POWER_METER": (0.8962, 0.9709),
    "NVR": (0.9292, 0.9763), "NAS": (0.9872, 0.9741), "ALARM": (1.0000, 0.7514),
    "CONTROLLER": (0.9750, 1.0000),
}
TABLE2_AGG = {"macro_precision": 0.9597, "macro_recall": 0.9607,
              "macro_f1": 0.9582, "overall_accuracy": 0.9778}
# Paper, Table 3 (M1): per-type (identification rate, Top-3 accuracy).
TABLE3 = {
    "MEDICAL": (0.9930, 0.9349), "NAS": (0.9980, 0.9312), "NVR": (0.9677, 0.9618),
    "POWER_METER": (0.9643, 0.9401), "ROUTER": (0.9885, 0.9347), "PRINTER": (0.9736, 0.9268),
    "SCADA": (0.9760, 0.9355), "CAMERA": (0.9802, 0.9288),
    "BUILDING_AUTOMATION": (0.9885, 0.9257), "ALARM": (0.9944, 0.8531),
    "CONTROLLER": (1.0000, 1.0000),
}
TABLE3_AGG = {"avg_identification_rate": 0.9840, "avg_top3_accuracy": 0.9339}
# Paper, Table 8 (IoTProber): type F1 / accuracy, vendor Top-1 / Top-3.
TABLE8 = {
    "MEDIA_SERVER": {"type_f1": 0.9980, "type_accuracy": 0.9961,
                     "vendor_top1": 0.9377, "vendor_top3": 1.0000},
    "VPN": {"type_f1": 0.9963, "type_accuracy": 0.9926,
            "vendor_top1": 0.9082, "vendor_top3": 1.0000},
}


def tolerance(p, n):
    return max(0.01, 1.96 * math.sqrt(p * (1 - p) / n)) if n else None


def norm_type(name):
    return re.sub(r"[\s\-]+", "_", str(name or "UNKNOWN").strip().upper()) or "UNKNOWN"


def norm_vendor(name):
    s = re.sub(r"[^a-z0-9]", "", str(name or "").lower())
    return s if s and s not in ("unknown", "none", "nan") else "unknown"


def load_records(pred_dir, dev, kind):
    path = os.path.join(pred_dir, f"{dev}_{kind}_prediction.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        return {str(r["ip"]): r for r in json.load(handle) if r.get("ip")}


def test_ips(test_dir, dev):
    path = os.path.join(test_dir, f"test_{dev}_1.csv")
    return pd.read_csv(path, usecols=["ip"], dtype=str, low_memory=False)["ip"].str.strip().drop_duplicates().tolist()


def vendor_labels(dev, ips):
    path = os.path.join(EVALUATION_DIR, "validation", "vendor_testset", f"test_{dev}_1_label.csv")
    if not os.path.exists(path):
        path = os.path.join(EVALUATION_DIR, "unseen", "vendor", "dataset", f"test_{dev}_label.csv")
    if not os.path.exists(path):
        path = os.path.join(LABEL_DATA_DIR, f"label_{dev}.csv")
    frame = pd.read_csv(path, dtype=str).drop_duplicates("ip")
    frame = frame[frame["ip"].isin(set(ips))]
    return dict(zip(frame["ip"], frame["vendor"]))


def vendor_candidates(record):
    for key in ("top3_vendors", "vendor_top3", "top3_vendor"):
        if isinstance(record.get(key), list):
            return [norm_vendor(v) for v in record[key]][:3], True
    return [norm_vendor(record.get("predicted_vendor"))], False


def unseen_aware(type_rec, vendor_rec):
    """Final labels for unseen evaluation: the first-stage label wins once its
    novelty probability exceeds 0.5 (the gate used by IoTDecisionGraph)."""
    unseen = ((type_rec.get("first_stage") or {}).get("unseen") or {})
    dtype = type_rec.get("predicted_device_type") or "UNKNOWN"
    if float(unseen.get("new_type_probability") or 0) > 0.5 and unseen.get("predicted_type") not in (None, "", "none"):
        dtype = unseen["predicted_type"]
    vendor = dict(vendor_rec)
    if float(unseen.get("new_vendor_probability") or 0) > 0.5 and unseen.get("predicted_vendor") not in (None, "", "none"):
        vendor["predicted_vendor"] = unseen["predicted_vendor"]
    return norm_type(dtype), vendor


def collect(pred_dir, test_dir, devices, unseen=False):
    rows = []
    for dev in devices:
        types, vendors = load_records(pred_dir, dev, "type"), load_records(pred_dir, dev, "vendor")
        for ip in test_ips(test_dir, dev):
            t, v = types.get(ip, {}), vendors.get(ip, {})
            if unseen:
                pred, v = unseen_aware(t, v)
            else:
                pred = norm_type(t.get("predicted_device_type"))
            rows.append({"ip": ip, "true": dev, "pred": pred, "decided": ip in types,
                         "vendor_rec": v})
    return pd.DataFrame(rows)


def vendor_scores(frame, dev):
    sub = frame[frame["true"] == dev]
    labels = vendor_labels(dev, sub["ip"].tolist())
    sub = sub[sub["ip"].isin(labels)]
    n = len(sub)
    if not n:
        return n, None, None, None, False
    identified = top1 = top3 = 0
    has_list = True
    for ip, rec in zip(sub["ip"], sub["vendor_rec"]):
        cands, listed = vendor_candidates(rec)
        has_list &= listed
        truth = norm_vendor(labels[ip])
        identified += cands[0] != "unknown"
        known_truth = truth != "unknown"
        top1 += known_truth and cands[0] == truth
        top3 += known_truth and truth in cands
    return n, identified / n, top1 / n, (top3 / n if has_list else None), has_list


def check(rows, name, measured, target, n):
    tol = tolerance(target, n)
    if not n:
        measured, status = None, "N/A"
    elif measured is None:
        status = "N/A"
    else:
        status = "PASS" if abs(measured - target) <= tol else "FAIL"
    rows.append({"metric": name, "paper": target, "measured": measured, "n": n,
                 "tolerance": None if tol is None else round(tol, 4), "status": status})


def known_suite(frame):
    out = []
    labels = KNOWN
    p, r, f1, support = precision_recall_fscore_support(
        frame["true"], frame["pred"], labels=labels, average=None, zero_division=0)
    for i, dev in enumerate(labels):
        check(out, f"T2 {dev} precision", float(p[i]), TABLE2[dev][0], int(support[i]))
        check(out, f"T2 {dev} recall", float(r[i]), TABLE2[dev][1], int(support[i]))
    n = len(frame)
    check(out, "T2 macro precision", float(p.mean()), TABLE2_AGG["macro_precision"], n)
    check(out, "T2 macro recall", float(r.mean()), TABLE2_AGG["macro_recall"], n)
    check(out, "T2 macro F1", float(f1.mean()), TABLE2_AGG["macro_f1"], n)
    check(out, "T2 overall accuracy", float((frame["true"] == frame["pred"]).mean()),
          TABLE2_AGG["overall_accuracy"], n)

    ident, top3 = [], []
    for dev in labels:
        nv, idr, top1, t3, _ = vendor_scores(frame, dev)
        check(out, f"T3 {dev} identification rate", idr, TABLE3[dev][0], nv)
        check(out, f"T3 {dev} Top-3 accuracy", t3, TABLE3[dev][1], nv)
        out.append({"metric": f"T3 {dev} Top-1 accuracy (lower bound of Top-3)", "paper": None,
                    "measured": top1, "n": nv, "tolerance": None, "status": "INFO"})
        ident.append(idr)
        top3.append(t3)
    avg = lambda values: None if any(v is None for v in values) else sum(values) / len(values)
    check(out, "T3 average identification rate", avg(ident), TABLE3_AGG["avg_identification_rate"], len(frame))
    check(out, "T3 average Top-3 accuracy", avg(top3), TABLE3_AGG["avg_top3_accuracy"], len(frame))
    return out


def unseen_suite(frame):
    out = []
    for dev in UNSEEN:
        sub = frame[frame["true"] == dev]
        n = len(sub)
        if not n:
            continue
        acc = float((sub["pred"] == dev).mean())
        check(out, f"T8 {dev} type accuracy", acc, TABLE8[dev]["type_accuracy"], n)
        check(out, f"T8 {dev} type F1", 2 * acc / (1 + acc), TABLE8[dev]["type_f1"], n)
        nv, _, top1, top3, _ = vendor_scores(frame, dev)
        check(out, f"T8 {dev} vendor Top-1 accuracy", top1, TABLE8[dev]["vendor_top1"], nv)
        check(out, f"T8 {dev} vendor Top-3 accuracy", top3, TABLE8[dev]["vendor_top3"], nv)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--suite", choices=["known", "unseen"], required=True)
    parser.add_argument("--pred-dir", default=PREDICTION_DIR)
    parser.add_argument("--test-dir", default=VALIDATION_DIR)
    parser.add_argument("--devices", nargs="+", default=None,
                        help="Restrict to these device types (partial / pilot runs)")
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    devices = args.devices or (KNOWN if args.suite == "known" else UNSEEN)
    frame = collect(args.pred_dir, args.test_dir, devices, unseen=args.suite == "unseen")
    rows = known_suite(frame) if args.suite == "known" else unseen_suite(frame)
    if args.devices:
        # aggregates over all 11 types are meaningless for a partial run
        rows = [r for r in rows
                if any(f" {d} " in f"{r['metric']} " for d in args.devices)]
    coverage = {
        dev: {"test_ips": int((frame["true"] == dev).sum()),
              "decided": int(frame.loc[frame["true"] == dev, "decided"].sum())}
        for dev in devices
    }
    report = {"suite": args.suite, "pred_dir": args.pred_dir, "test_dir": args.test_dir,
              "coverage": coverage, "checks": rows,
              "summary": {s: sum(r["status"] == s for r in rows) for s in ("PASS", "FAIL", "N/A")}}
    output = args.output or os.path.join(EVALUATION_DIR, f"reproduction_report_{args.suite}.json")
    with open(output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)

    print(f"{'metric':58} {'paper':>8} {'measured':>9} {'tol':>7} {'n':>7}  status")
    for r in rows:
        fmt = lambda v: "-" if v is None else f"{v:.4f}"
        print(f"{r['metric']:58} {fmt(r['paper']):>8} {fmt(r['measured']):>9} "
              f"{fmt(r['tolerance']):>7} {r['n'] or 0:>7}  {r['status']}")
    print("coverage:", json.dumps(coverage))
    print("summary:", report["summary"], "->", output)


if __name__ == "__main__":
    main()
