#!/usr/bin/env python3
"""Table 10 (in-class concept drift) canonical scorer.

Reproduces every number of paper Table 10 from the released prediction
CSVs (HuggingFace dataset ``IoTProber/raw_dataset``, path prefix
``evaluation/drift/CADE``) under EXPLICIT label-matching rules, so the
matching strategy is no longer notebook folklore.

Inputs (all columns: ip,vendor,label,label_pred,correct)
  Stage 2 (SVM on 2026-04-06 test):   SVM_test/predict/*.csv
  Stage 3 IoTProber (after retrain):  SVM_validation/performance/IoTProber/predict/*.csv
  Stage 3 CADE (after retrain):       SVM_validation/performance/CADE/predict/*.csv
  Drift detection:                    SVM_validation/{IoTProber,CADE}/{detected,correct}_ips.csv

Matching rules (--match)
  exact        byte equality of label vs label_pred. This is what the original
               trainer/scorer (evaluation/drift/CADE/svm.py, run_test) used for
               the STAGE-2 row of the paper.
  normalized   casefold + strip every non [a-z0-9] character of the whole label
               ("NVR-Merit Lilin" == "NVR-Merit LILIN" == "NVR-Merit Li-Lin").
  original     THE RULE THAT PRODUCED THE PAPER'S STAGE-3 ROWS, recovered
               verbatim from svm.py::normalize_label (initial commit 25f6a47):
               split the label on the FIRST '-', lowercase the device-type part
               as-is, strip non [a-z0-9] from the vendor part only, then apply
               the vendor alias {"electroind": "electroindustries"}. This rule
               agrees with the shipped ``correct`` column of the Stage-3 CSVs on
               7,239/7,239 rows for both methods.

Verified findings (scorer v1.1.0, sklearn-free, deterministic):
  Stage 2  exact      0.4937 / 0.7403 / 0.6892   == paper row exactly
  Stage 2  original   0.5180 / 0.8633 / 0.8341   (what Stage 2 is under the
                                                   same rule as Stage 3)
  Stage 3 IoTProber
           exact      0.5270 / 0.7047 / 0.6709
           original   0.5509 / 0.8711 / 0.8483   == paper row exactly (6141/7239)
  Stage 3 CADE
           exact      0.5191 / 0.7050 / 0.6654
           original   0.5430 / 0.8649 / 0.8402   == paper row exactly (6082/7239)

  Therefore the paper's Stage2 -> Stage3 accuracy gain mixes two rules
  (Stage 2 byte-equality, Stage 3 the fuzzy ``original`` rule). Under ONE
  consistent rule the deltas are:
      exact      0.6892 -> 0.6709   (-1.83 pp, IoTProber)
      original   0.8341 -> 0.8483   (+1.42 pp, IoTProber)  <- matches the
                                                             reviewer's ~1.42 pp
      original   0.8341 -> 0.8402   (+0.61 pp, CADE)
  The 15.91 pp headline (0.6892 -> 0.8483) must not be quoted as a
  retraining gain. The drift-detection correctness figures
  (IoTProber 773/814 = 94.96%, CADE 767/1112 = 68.97%) compare detected IPs
  against ground-truth drift IPs and are rule-independent; they stand.

Usage
  python score_table10.py                     # all rules + detection stage
  python score_table10.py --match original    # the paper's Stage-3 rule
  python score_table10.py --json out.json     # machine-readable record
"""
import argparse
import glob
import hashlib
import json
import os
import platform
import re
import sys

import pandas as pd

SCORER_VERSION = "1.1.0"

# Recovered verbatim from svm.py (initial commit 25f6a47).
VENDOR_ALIASES = {
    "electroind": "electroindustries",
}


def _normalize_vendor(v):
    return re.sub(r"[^a-z0-9]", "", v.lower())


def normalize(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(label).lower())


def original_rule(label: str) -> str:
    parts = str(label).split("-", 1)
    if len(parts) != 2:
        return str(label).lower()
    dt, vendor = parts
    nv = _normalize_vendor(vendor)
    nv = VENDOR_ALIASES.get(nv, nv)
    return dt.lower() + "-" + nv


STAGES = {
    "stage2_svm": "SVM_test/predict",
    "stage3_iotprober": "SVM_validation/performance/IoTProber/predict",
    "stage3_cade": "SVM_validation/performance/CADE/predict",
}


def load_stage(data_root: str, sub: str):
    files = sorted(glob.glob(os.path.join(data_root, sub, "*.csv")))
    if not files:
        sys.exit(f"no prediction CSVs under {os.path.join(data_root, sub)}")
    labels, preds = [], []
    for path in files:
        df = pd.read_csv(path, dtype=str)
        labels += df["label"].tolist()
        preds += df["label_pred"].tolist()
    return labels, preds, files


def detection_stage(data_root: str, method: str):
    base = os.path.join(data_root, "SVM_validation", method)
    n_det = len(pd.read_csv(os.path.join(base, "detected_ips.csv")))
    n_cor = len(pd.read_csv(os.path.join(base, "correct_ips.csv")))
    return n_cor, n_det


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def score(labels, preds, rule: str):
    f = {"exact": str, "normalized": normalize, "original": original_rule}[rule]
    y = [f(x) for x in labels]
    p = [f(x) for x in preds]
    n = len(y)
    acc = sum(a == b for a, b in zip(y, p)) / n
    classes = sorted(set(y) | set(p))
    f1s, support = [], []
    for c in classes:
        tp = sum(1 for a, b in zip(y, p) if a == c and b == c)
        fp = sum(1 for a, b in zip(y, p) if a != c and b == c)
        fn = sum(1 for a, b in zip(y, p) if a == c and b != c)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
        support.append(tp + fn)
    macro = sum(f1s) / len(f1s)
    weighted = sum(s * f for s, f in zip(support, f1s)) / sum(support)
    return {"n": n, "correct": sum(a == b for a, b in zip(y, p)),
            "accuracy": round(acc, 4), "macro_f1": round(macro, 4),
            "weighted_f1": round(weighted, 4)}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data-root",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "CADE"),
                    help="directory containing SVM_test/, SVM_validation/ "
                         "(default: <script dir>/CADE)")
    ap.add_argument("--match", choices=["exact", "normalized", "original", "all"],
                    default="all")
    ap.add_argument("--json", help="write a machine-readable record here")
    args = ap.parse_args()

    rules = ["exact", "normalized", "original"] if args.match == "all" else [args.match]
    record = {
        "scorer_version": SCORER_VERSION,
        "matching_rules": {
            "exact": "byte equality on label/label_pred (paper Stage-2 rule)",
            "normalized": "casefold + strip non [a-z0-9] from the whole label",
            "original": "svm.py::normalize_label (commit 25f6a47): split on first '-', "
                        "lowercase type part, strip non [a-z0-9] from vendor part only, "
                        "alias " + json.dumps(VENDOR_ALIASES)
                        + " (paper Stage-3 rule; == shipped 'correct' column 7239/7239)",
        },
        "python": platform.python_version(),
        "pandas": pd.__version__,
        "inputs": {},
        "stages": {},
        "detection": {},
    }

    stage_data = {}
    for stage, sub in STAGES.items():
        labels, preds, files = load_stage(args.data_root, sub)
        stage_data[stage] = (labels, preds)
        record["inputs"][stage] = {
            "glob": sub,
            "files": [os.path.relpath(f, args.data_root) for f in files],
            "sha256": {os.path.relpath(f, args.data_root): sha256(f) for f in files},
        }

    header = f"{'stage':<20}{'rule':<12}{'correct':>9}{'macroF1':>9}{'wF1':>8}{'acc':>8}"
    lines = [header, "-" * len(header)]
    for stage in STAGES:
        labels, preds = stage_data[stage]
        record["stages"][stage] = {}
        for rule in rules:
            m = score(labels, preds, rule)
            record["stages"][stage][rule] = m
            lines.append(f"{stage:<20}{rule:<12}{m['correct']:>7}/{m['n']}"
                         f"{m['macro_f1']:>9}{m['weighted_f1']:>8}{m['accuracy']:>8}")
    if len(rules) > 1:
        lines.append("")
        for stage in ("stage3_iotprober", "stage3_cade"):
            for rule in rules:
                a0 = record["stages"]["stage2_svm"][rule]["accuracy"]
                a1 = record["stages"][stage][rule]["accuracy"]
                lines.append(f"{stage:<20}{rule + ' delta':<16}"
                             f"{'':>9}{'':>9}{'':>8}{a1 - a0:>+8.4f}")

    lines.append("")
    for method in ("IoTProber", "CADE"):
        n_cor, n_det = detection_stage(args.data_root, method)
        record["detection"][method] = {"correct": n_cor, "detected": n_det,
                                       "correctness": round(n_cor / n_det, 4)}
        lines.append(f"drift-detection correctness {method}: "
                     f"{n_cor}/{n_det} = {n_cor / n_det:.2%}")

    report = "\n".join(lines)
    print(report)
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(record, fh, indent=1)
        print(f"\nrecord -> {args.json}")


if __name__ == "__main__":
    main()
