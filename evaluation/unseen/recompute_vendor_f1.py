#!/usr/bin/env python
"""
Recompute vendor-novelty F1 under the rule "a correct vendor prediction counts
as correct" (user request 2026-09-20).

Original rule (release gate):  predicted_new := vendor_score > threshold, where
vendor_score is the token confidence of an *unlisted* vendor — a pseudo-vendor
sample whose true vendor is still in the inference-time known list scores 0 by
construction, so F1 ≈ 0.

New rule: the model "detects" the (new) vendor when it outputs the sample's
ground-truth vendor, i.e. decision := vendor_exact.
  positive class (new vendor)  = pseudo-vendor samples
  negative class (known vendor) = known samples
  TP = pseudo & exact   FN = pseudo & !exact
  TN = known  & exact   FP = known  & !exact
     (a known sample whose vendor the model fails to reproduce would be emitted
      as an unlisted/unknown vendor → flagged new → false positive)
Threshold-free (the decision is the label match itself).
"""

import json
import os
import sys

import numpy as np

REPO = "/home/nfs/iotprober"
sys.path.insert(0, os.path.join(REPO, "evaluation", "unseen", "llama3"))
sys.path.insert(0, REPO)

import rerun_calibration_retrieval as rc  # noqa: E402

WORK = "/dev/shm/calib_v4"

raw_eval_ds = rc.ft.load_sft_dataset(rc.VALIDATION_FILE)
(sel, tgs, vgs, k1, k2, pv, ms, vp) = rc.selected_indices(raw_eval_ds, 200)

P = {}
for i in range(8):
    P.update({int(k): v for k, v in json.load(open(f"{WORK}/predictions_{i}.json")).items()})
P = {i: v for i, v in P.items() if "error" not in v}
fps = {int(k): v for k, v in json.load(open(f"{WORK}/fingerprints.json")).items()}

folds = [
    ("MEDIA_SERVER_calibration__VPN_test",
     k2[:vgs] + pv[:vgs], k2[vgs:] + pv[vgs:]),
    ("VPN_calibration__MEDIA_SERVER_test",
     k2[vgs:] + pv[vgs:], k2[:vgs] + pv[:vgs]),
]

print(f"{'fold':40} {'rule':16} {'P':>6} {'R':>6} {'F1':>6} {'acc':>6}")
for name, vcal, vtest in folds:
    vt = [i for i in vtest if i in P]
    for rule in ("original", "correct-vendor"):
        if rule == "original":
            score = np.array([P[i]["vendor_score"] for i in vt])
            is_new = np.array([P[i]["is_new_vendor"] for i in vt], bool)
            dec = score > 0.5
        else:
            dec = np.array([P[i]["vendor_exact"] for i in vt], bool)
            is_new = np.array([P[i]["is_new_vendor"] for i in vt], bool)
        # Confusion matrix. For the correct-vendor rule the usual convention
        # (FP = dec & !is_new) would count a *correct* prediction on a known
        # sample as a false positive — meaningless. Under this rule the model
        # "flags" a sample as new whenever it fails to reproduce the sample's
        # ground-truth vendor (the emitted name is unlisted/unknown), so:
        #   new-vendor samples  : exact -> TP,  !exact -> FN
        #   known-vendor samples: !exact -> FP, exact  -> TN
        if rule == "original":
            TP = sum(1 for d, n in zip(dec, is_new) if d and n)
            FP = sum(1 for d, n in zip(dec, is_new) if d and not n)
            FN = sum(1 for d, n in zip(dec, is_new) if not d and n)
            TN = sum(1 for d, n in zip(dec, is_new) if not d and not n)
        else:
            TP = sum(1 for d, n in zip(dec, is_new) if d and n)
            FN = sum(1 for d, n in zip(dec, is_new) if not d and n)
            FP = sum(1 for d, n in zip(dec, is_new) if not d and not n)
            TN = sum(1 for d, n in zip(dec, is_new) if d and not n)
        prec = TP / (TP + FP) if TP + FP else 0.0
        rec = TP / (TP + FN) if TP + FN else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        acc = (TP + TN) / len(vt)
        print(f"{name[:40]:40} {rule:16} {prec:6.3f} {rec:6.3f} {f1:6.3f} {acc:6.3f}")

# headline numbers per group
print()
for g, sel_idx in (("pseudo-vendor (new)", pv), ("known", k2)):
    idx = [i for i in sel_idx if i in P]
    ex = float(np.mean([P[i]["vendor_exact"] for i in idx]))
    print(f"{g:22} n={len(idx):4} vendor_exact(直接判对率) = {ex:.3f}")
