#!/usr/bin/env python3
"""
Evaluate type prediction metrics for each method under evaluation/validation/type/predict/.

Metrics per device type:
  - Precision, Recall, F1-score

Aggregate metrics:
  - Macro average Precision, Macro average Recall, Macro F1-score
  - Overall Accuracy

Methods evaluated:
  - ClaudeOpus
  - IoTProber
  - Mahmood
  - shodan

Usage:
  python evaluate_type.py
"""

import os
import csv
import glob
import json
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support, accuracy_score

# ── Config ─────────────────────────────────────────────────────────────────────
PRED_DIR = os.path.dirname(os.path.abspath(__file__))

METHODS = ["ClaudeOpus", "IoTProber", "Mahmood", "shodan"]

DEVICE_TYPES = [
    "Camera", "Printer", "Scada", "Router", "NAS",
    "NVR", "Power_meter", "Building_Automation", "Medical",
    "Alarm", "Controller",
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def load_predictions(method):
    """
    Load all type_{dev}.csv files for a given method.

    Returns a DataFrame with columns: ip, true_type, predicted_type
    - ClaudeOpus CSVs have all three columns.
    - IoTProber / Mahmood CSVs have ip, predicted_type; true_type is inferred
      from the filename (e.g. type_Camera.csv -> Camera).
    - shodan directory may be empty.
    """
    method_dir = os.path.join(PRED_DIR, method)
    frames = []

    for csv_path in sorted(glob.glob(os.path.join(method_dir, "type_*.csv"))):
        dev = os.path.basename(csv_path).replace("type_", "").replace(".csv", "")
        df = pd.read_csv(csv_path, dtype=str)

        if "true_type" in df.columns:
            df["true_type"] = df["true_type"].str.strip()
        else:
            df["true_type"] = dev

        df["predicted_type"] = df["predicted_type"].str.strip()
        frames.append(df[["ip", "true_type", "predicted_type"]])

    if not frames:
        return None

    return pd.concat(frames, ignore_index=True)


def compute_metrics(df, labels):
    """
    Compute per-type precision, recall, F1, and overall accuracy.

    Uses sklearn's precision_recall_fscore_support with average=None for per-type
    scores, then computes macro averages manually.
    """
    y_true = df["true_type"].values
    y_pred = df["predicted_type"].values

    # Per-type metrics (only for labels that actually appear)
    p, r, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average=None, zero_division=0
    )

    per_type = {}
    for i, label in enumerate(labels):
        per_type[label] = {
            "precision": p[i],
            "recall": r[i],
            "f1": f1[i],
            "support": int(support[i]),
        }

    # Macro averages (over all device types in the label list)
    macro_p = p.mean()
    macro_r = r.mean()
    macro_f1 = f1.mean()

    # Overall accuracy
    overall_acc = accuracy_score(y_true, y_pred)

    return per_type, macro_p, macro_r, macro_f1, overall_acc, len(y_true)


def print_results(method, per_type, macro_p, macro_r, macro_f1, overall_acc, total):
    """Print formatted metrics table for a method."""
    print(f"\n{'=' * 80}")
    print(f"  Method: {method}  (total samples: {total})")
    print(f"{'=' * 80}")
    print(f"  {'Device Type':<25} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"  {'-' * 25} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 10}")
    for dev in DEVICE_TYPES:
        if dev in per_type:
            m = per_type[dev]
            print(f"  {dev:<25} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1']:>10.4f} {m['support']:>10}")
        else:
            print(f"  {dev:<25} {'N/A':>10} {'N/A':>10} {'N/A':>10} {'N/A':>10}")

    print(f"  {'-' * 25} {'-' * 10} {'-' * 10} {'-' * 10} {'-' * 10}")
    print(f"  {'Macro Average':<25} {macro_p:>10.4f} {macro_r:>10.4f} {macro_f1:>10.4f} {total:>10}")
    print(f"  {'Overall Accuracy':<25} {'':>10} {'':>10} {overall_acc:>10.4f} {total:>10}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    all_results = {}

    for method in METHODS:
        df = load_predictions(method)
        if df is None or len(df) == 0:
            print(f"\n[SKIP] {method}: no prediction files found")
            all_results[method] = None
            continue

        # Collect all labels present in the data (union of true and predicted)
        present_labels = sorted(
            set(df["true_type"].unique()) | set(df["predicted_type"].unique())
        )
        # Use the full DEVICE_TYPES list as labels so every type is reported,
        # even if absent in a particular method's output
        eval_labels = DEVICE_TYPES[:]

        per_type, macro_p, macro_r, macro_f1, overall_acc, total = compute_metrics(
            df, eval_labels
        )

        print_results(method, per_type, macro_p, macro_r, macro_f1, overall_acc, total)

        all_results[method] = {
            "total_samples": total,
            "per_type": per_type,
            "macro_precision": macro_p,
            "macro_recall": macro_r,
            "macro_f1": macro_f1,
            "overall_accuracy": overall_acc,
        }

    # ── Save JSON summary ────────────────────────────────────────────────────
    out_json = os.path.join(PRED_DIR, "type_metrics.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"\nMetrics saved to: {out_json}")


if __name__ == "__main__":
    main()
