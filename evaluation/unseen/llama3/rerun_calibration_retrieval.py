#!/usr/bin/env python
"""
Production-faithful calibration & verification: real test fingerprints through
the actual detect_unseen inference chain.

* fingerprints come from the REAL raw sources — dataset_MEDIA_SERVER.csv /
  dataset_VPN.csv for unseen types, ipraw_{TYPE}.csv (from the HF tar) for
  known/pseudo-vendor samples — keyed by each validation row's metadata.ip
* prompts are built by the production builder
  build_unseen_type_vendor_classification_prompt() (exactly what
  UnseenDeviceDetector._build_aligned_prompt emits for the adapter path)
* generation + scoring run through the production methods
  _generate_classification() + _parse_response() +
  _classification_novelty_result() on a real UnseenDeviceDetector

The adapter production prompt contains NO retrieval evidence, so no vector DB /
LLM keys are needed. Long fingerprints that would exceed the summarizer budget
are locally truncated (DeepSeek summary API offline); the count is reported.

Modes:
  --prep                    build <work>/fingerprints.json (skipped if present)
  --rank R --world_size 8   per-rank generation
  --merge                   folds + thresholds + gates + metadata write

Example (8x H800):
  for i in 0..7: CUDA_VISIBLE_DEVICES=$i python rerun_calibration_retrieval.py \
      --rank $i --world_size 8 --ckpt_dir <adapter> --work /dev/shm/calib_v3 &
  python rerun_calibration_retrieval.py --merge --ckpt_dir <adapter> --work /dev/shm/calib_v3
"""

import argparse
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone

REPO = "/home/nfs/iotprober"
LLAMA3_DIR = os.path.join(REPO, "evaluation", "unseen", "llama3")
ORIG_FT = os.path.join(LLAMA3_DIR, "log", "original_run", "fine-tune.py")
CKPT_DIR = os.path.join(LLAMA3_DIR, "results", "checkpoint-14576")
DATASET_DIR = os.path.join(LLAMA3_DIR, "dataset")
VALIDATION_FILE = os.path.join(DATASET_DIR, "validation_sft.jsonl")
METADATA_SRC = os.path.join(DATASET_DIR, "known_vendors.json")
UNSEEN_DS_DIR = os.path.join(REPO, "evaluation", "unseen", "dataset")
IPRAW_DIR = "/dev/shm/ipraw"
WORK = "/dev/shm/calib_v3"

sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "agent"))

spec = importlib.util.spec_from_file_location("finetune_original", ORIG_FT)
ft = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ft)

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from util import (  # noqa: E402
    build_fingerprint_info_text,
    build_unseen_type_vendor_classification_prompt,
)
from unseen import UnseenDeviceDetector  # noqa: E402


def selected_indices(raw_eval_ds, samples_per_group):
    """Same selection as fine-tune.py (rng seed 42) for comparability."""
    groups = {"known": [], "MEDIA_SERVER": [], "VPN": [], "pseudo_vendor": []}
    for index, row in enumerate(raw_eval_ds):
        target = ft._parse_target(row["output"])
        origin = (row.get("metadata") or {}).get("split_origin")
        if origin == "known_validation":
            groups["known"].append(index)
        elif origin == "pseudo_unseen_vendor_validation":
            groups["pseudo_vendor"].append(index)
        elif target["device_type"] in ("MEDIA_SERVER", "VPN"):
            groups[target["device_type"]].append(index)
    type_group_size = min(samples_per_group, len(groups["known"]) // 2,
                          len(groups["MEDIA_SERVER"]), len(groups["VPN"]))
    vendor_group_size = min(samples_per_group, len(groups["known"]) // 2,
                            len(groups["pseudo_vendor"]) // 2)
    if type_group_size < 1 or vendor_group_size < 1:
        raise ValueError("insufficient calibration groups")
    rng = np.random.default_rng(42)
    k1 = rng.choice(groups["known"], size=type_group_size * 2, replace=False).tolist()
    k2 = rng.choice(groups["known"], size=vendor_group_size * 2, replace=False).tolist()
    pv = rng.choice(groups["pseudo_vendor"], size=vendor_group_size * 2, replace=False).tolist()
    ms = rng.choice(groups["MEDIA_SERVER"], size=type_group_size, replace=False).tolist()
    vp = rng.choice(groups["VPN"], size=type_group_size, replace=False).tolist()
    return (sorted(set(k1 + k2 + pv + ms + vp)), type_group_size, vendor_group_size,
            k1, k2, pv, ms, vp)


def run_prep(samples_per_group):
    os.makedirs(WORK, exist_ok=True)
    out_path = os.path.join(WORK, "fingerprints.json")
    if os.path.exists(out_path):
        print(f"{out_path} already exists — reuse it (delete to rebuild)")
        return
    raw_eval_ds = ft.load_sft_dataset(VALIDATION_FILE)
    sel, *_ = selected_indices(raw_eval_ds, samples_per_group)
    print(f"selected {len(sel)} validation indices")

    need_unseen = {"MEDIA_SERVER": set(), "VPN": set()}
    need_known = {}
    rows_by_idx = {}
    for idx in sel:
        row = raw_eval_ds[idx]
        target = ft._parse_target(row["output"])
        ip = (row.get("metadata") or {}).get("ip")
        if not ip:
            continue
        rows_by_idx[idx] = {"ip": ip, "type": target["device_type"],
                            "vendor": target.get("device_vendor", ""),
                            "is_new_type": target["device_type"] in ("MEDIA_SERVER", "VPN"),
                            "is_new_vendor": bool((row.get("metadata") or {}).get("is_new_vendor"))}
        if target["device_type"] in need_unseen:
            need_unseen[target["device_type"]].add(ip)
        else:
            need_known.setdefault(target["device_type"], set()).add(ip)

    fp_by_ip = {}

    def load_ips(csv_path, ips):
        df = pd.read_csv(csv_path, low_memory=False)
        sub = df[df["ip"].isin(ips)]
        return {r["ip"]: {k: (None if pd.isna(v) else v) for k, v in r.items()}
                for _, r in sub.iterrows()}

    for dev, ips in need_unseen.items():
        path = os.path.join(UNSEEN_DS_DIR, f"dataset_{dev}.csv")
        got = load_ips(path, ips)
        print(f"{dev}: {len(got)}/{len(ips)} fingerprints from {path}")
        fp_by_ip.update(got)
    for dev, ips in need_known.items():
        path = os.path.join(IPRAW_DIR, f"ipraw_{dev}.csv")
        got = load_ips(path, ips)
        print(f"{dev}: {len(got)}/{len(ips)} fingerprints from {path}")
        fp_by_ip.update(got)

    out, missing = {}, 0
    for idx, info in rows_by_idx.items():
        fp = fp_by_ip.get(info["ip"])
        if fp is None:
            missing += 1
            continue
        out[idx] = {"fp": fp, "gt": info}
    print(f"fingerprints resolved: {len(out)}, missing: {missing}")
    json.dump({str(k): v for k, v in out.items()}, open(out_path, "w"))
    print(f"wrote {out_path}")


def run_rank(rank, world_size, max_len, ckpt_dir):
    os.makedirs(WORK, exist_ok=True)
    fps = {int(k): v for k, v in json.load(open(os.path.join(WORK, "fingerprints.json"))).items()}
    sel = sorted(fps)
    my = sel[rank::world_size]
    print(f"[rank {rank}] {len(my)}/{len(sel)} samples", flush=True)

    detector = UnseenDeviceDetector(adapter_path=ckpt_dir, gpu=0, load_in_4bit=True,
                                    max_input_tokens=max_len)
    budget = int(detector.classification_metadata.get("fingerprint_token_budget", 25454))
    truncated = 0
    preds = {}
    for i, idx in enumerate(my):
        fp, gt = fps[idx]["fp"], fps[idx]["gt"]
        fp_text = build_fingerprint_info_text(fp) or "(no fingerprint info available)"
        n_tok = len(detector.tokenizer(fp_text).input_ids or [])
        if n_tok > budget - 512:
            ids = detector.tokenizer(fp_text, truncation=True, max_length=budget - 512).input_ids
            fp_text = detector.tokenizer.decode(ids, skip_special_tokens=True)
            truncated += 1
        prompt = build_unseen_type_vendor_classification_prompt(
            fp_text, detector.rag_devices, detector.known_vendors_by_type)
        try:
            text, conf = detector._generate_classification(prompt)
            parsed = detector._parse_response(text)
            nov = detector._classification_novelty_result(parsed, conf)
            preds[idx] = {
                "type_score": float(nov["new_type_probability"]),
                "vendor_score": float(nov["new_vendor_probability"]),
                "is_new_type": gt["is_new_type"],
                "is_new_vendor": gt["is_new_vendor"],
                "type_exact": str(nov["classified_type"]).strip().upper() == gt["type"].strip().upper(),
                "vendor_exact": str(nov["classified_vendor"]).strip().upper() == gt["vendor"].strip().upper(),
                "classified_type": nov["classified_type"],
                "classified_vendor": nov["classified_vendor"],
            }
        except Exception as exc:
            preds[idx] = {"error": str(exc)[:200]}
        if (i + 1) % 25 == 0:
            print(f"[rank {rank}] {i+1}/{len(my)} (truncated {truncated})", flush=True)

    out = os.path.join(WORK, f"predictions_{rank}.json")
    json.dump({str(k): v for k, v in preds.items()}, open(out, "w"))
    print(f"[rank {rank}] wrote {len(preds)} -> {out} (truncated={truncated})", flush=True)


def run_merge(samples_per_group, ckpt_dir, tag=""):
    metadata = json.load(open(METADATA_SRC, encoding="utf-8"))
    raw_eval_ds = ft.load_sft_dataset(VALIDATION_FILE)
    (sel, tgs, vgs, k1, k2, pv, ms, vp) = selected_indices(raw_eval_ds, samples_per_group)
    fps = {int(k): v for k, v in json.load(open(os.path.join(WORK, "fingerprints.json"))).items()}
    predictions = {}
    for f in os.listdir(WORK):
        if f.startswith("predictions_") and f.endswith(".json"):
            predictions.update({int(k): v for k, v in json.load(open(os.path.join(WORK, f))).items()})
    P = predictions
    ok = [i for i in sel if i in P and "error" not in P.get(i, {})]
    errors = sum(1 for i in sel if "error" in P.get(i, {}))
    print(f"usable predictions: {len(ok)}/{len(sel)} (errors: {errors})")

    # per-group breakdown (the key novelty signal)
    from collections import Counter
    groups = {"MEDIA_SERVER": [], "VPN": [], "known": [], "pseudo": []}
    for i in ok:
        t = fps[i]["gt"]["type"]
        g = t if t in ("MEDIA_SERVER", "VPN") else ("pseudo" if fps[i]["gt"]["is_new_vendor"] else "known")
        groups[g].append(i)
    print("\n=== per-group verification ===")
    for g, idxs in groups.items():
        if not idxs:
            continue
        te = float(np.mean([P[i]["type_exact"] for i in idxs]))
        ve = float(np.mean([P[i]["vendor_exact"] for i in idxs]))
        types = Counter(P[i]["classified_type"] for i in idxs).most_common(3)
        print(f"{g:14} n={len(idxs):4} type_exact={te:.3f} vendor_exact={ve:.3f} top={types}")

    def avail(indices):
        return [i for i in indices if i in P and "error" not in P[i]]

    folds = [
        {"name": "MEDIA_SERVER_calibration__VPN_test",
         "type_calibration": avail(k1[:tgs] + ms), "type_test": avail(k1[tgs:] + vp),
         "vendor_calibration": avail(k2[:vgs] + pv[:vgs]),
         "vendor_test": avail(k2[vgs:] + pv[vgs:])},
        {"name": "VPN_calibration__MEDIA_SERVER_test",
         "type_calibration": avail(k1[tgs:] + vp), "type_test": avail(k1[:tgs] + ms),
         "vendor_calibration": avail(k2[vgs:] + pv[vgs:]),
         "vendor_test": avail(k2[:vgs] + pv[:vgs])},
    ]
    fold_results = []
    for fold in folds:
        tc = [(P[i]["type_score"], P[i]["is_new_type"]) for i in fold["type_calibration"]]
        vc = [(P[i]["vendor_score"], P[i]["is_new_vendor"]) for i in fold["vendor_calibration"]]
        tt = [(P[i]["type_score"], P[i]["is_new_type"]) for i in fold["type_test"]]
        vt = [(P[i]["vendor_score"], P[i]["is_new_vendor"]) for i in fold["vendor_test"]]
        t_thr, v_thr = ft._select_novelty_threshold(tc), ft._select_novelty_threshold(vc)
        fold_results.append({
            "name": fold["name"], "type_threshold": t_thr, "vendor_threshold": v_thr,
            "type_test": ft._binary_novelty_metrics(tt, t_thr),
            "vendor_test": ft._binary_novelty_metrics(vt, v_thr),
            "type_exact_accuracy": float(np.mean([P[i]["type_exact"] for i in fold["type_test"]])),
            "vendor_exact_accuracy": float(np.mean([P[i]["vendor_exact"] for i in fold["vendor_test"]])),
        })

    def avg(key):
        return float(np.mean([f[key] for f in fold_results]))

    calibration = {
        "type_confidence_threshold": avg("type_threshold"),
        "vendor_confidence_threshold": avg("vendor_threshold"),
        "confidence_calibrated": True,
        "calibration_strategy": "production_chain_real_fingerprints__type_MS_VPN_cross__vendor_pseudo_cross",
        "samples_per_group": {"type": tgs, "vendor": vgs},
        "generated_validation_samples": len(ok),
        "folds": fold_results,
        "average_test_metrics": {
            field: {m: float(np.mean([f[field][m] for f in fold_results]))
                    for m in ("precision", "recall", "f1", "accuracy")}
            for field in ("type_test", "vendor_test")
        } | {
            "type_exact_accuracy": float(np.mean([f["type_exact_accuracy"] for f in fold_results])),
            "vendor_exact_accuracy": float(np.mean([f["vendor_exact_accuracy"] for f in fold_results])),
        },
    }
    gate = ft.evaluate_release_gates(calibration, min_type_f1=0.80, min_vendor_f1=0.80,
                                     min_type_exact_accuracy=0.50, min_vendor_exact_accuracy=0.50)
    print("\nCalibration:", json.dumps({k: v for k, v in calibration.items() if k != "folds"}, indent=2, default=str))
    print("Release gate:", json.dumps(gate, indent=2, default=str))

    cfg = json.load(
        open(os.path.join(REPO, "config", "llm_config.json"), encoding="utf-8")
    )
    out = dict(metadata)
    out.update(calibration)
    out["release_gate"] = gate
    out["long_fingerprint_strategy"] = "deepseek_summary"
    out["summarizer"] = {"provider": "DEEPSEEK", "model": cfg["DEEPSEEK"]["MODEL"],
                         "prompt_version": 1,
                         "token_budget": metadata.get("fingerprint_token_budget", 25454)}
    out["calibrated_at"] = datetime.now(timezone.utc).isoformat()
    out["calibration_note"] = ("Calibrated via the production inference chain on real fingerprints "
                               "(8-GPU sharded). Long fingerprints truncated locally.")
    meta_path = os.path.join(ckpt_dir, "known_vendors.json")
    report_path = os.path.join(os.path.dirname(ckpt_dir),
                               f"release_gate_report{tag}.json")
    json.dump({"calibration": calibration, "release_gate": gate, "groups":
               {g: {"n": len(idx), "type_exact": float(np.mean([P[i]["type_exact"] for i in idx]))}
                for g, idx in groups.items() if idx}},
              open(report_path, "w"), ensure_ascii=False, indent=2, default=str)
    if os.path.exists(meta_path):
        os.replace(meta_path, meta_path + ".uncal.bak")
    json.dump(out, open(meta_path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    print(f"\nWrote {meta_path}\nWrote {report_path}")
    print(f"type threshold = {out['type_confidence_threshold']:.4f} | "
          f"vendor threshold = {out['vendor_confidence_threshold']:.4f} | "
          f"gate passed = {gate.get('passed')}")
    print("DONE", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--prep", action="store_true")
    p.add_argument("--rank", type=int, default=None)
    p.add_argument("--world_size", type=int, default=8)
    p.add_argument("--merge", action="store_true")
    p.add_argument("--samples_per_group", type=int, default=200)
    p.add_argument("--max_len", type=int, default=32768)
    p.add_argument("--ckpt_dir", type=str, default=None)
    p.add_argument("--work", type=str, default=None)
    p.add_argument("--tag", type=str, default="")
    a = p.parse_args()
    if a.ckpt_dir:
        CKPT_DIR = os.path.abspath(a.ckpt_dir)
    if a.work:
        WORK = a.work
    print(f"ckpt_dir={CKPT_DIR}\nwork={WORK}")
    if a.prep:
        run_prep(a.samples_per_group)
    elif a.merge:
        run_merge(a.samples_per_group, CKPT_DIR, a.tag)
    elif a.rank is not None:
        run_rank(a.rank, a.world_size, a.max_len, CKPT_DIR)
    else:
        raise SystemExit("specify --prep / --rank R / --merge")
