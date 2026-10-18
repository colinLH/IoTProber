"""
llama3_perspective_predict.py

Use local Llama-3.1-8B-Instruct (vLLM on GPU7) to identify the ALARM / CONTROLLER
test devices in evaluation/validation/46_features.

For each device row, ONE prompt is built whose raw fingerprint is **organised by
perspective** (as / whois / os / sw / hw / sd / body / htags / hfavicons /
certificate / dns, plus a "basic" bucket for the columns that belong to no
perspective — per perspective_info.json / perspective_name.json). The model then
emits a SINGLE combined device_type and vendor prediction that synthesises all
perspectives. Vendor is judged solely from these raw fingerprint features;
candidate device types come from all_IoT_devices.json.

Results are written under evaluation/llam3_predict/{type,vendor}/, then vendor /
type accuracies and the predicted-type distribution are computed against
platform_data/csv/label/label_{DEV}.csv and printed as tables.

Prompt style modeled on agent/decision.py (single-turn JSON answer, no RAG tools).
"""

import os
import re
import json
from collections import Counter

import pandas as pd

# ── paths ────────────────────────────────────────────────────────────────────
# This script lives in evaluation/validation/baseline/Mahmood/, so the repo
# root (where platform_data/, all_IoT_devices.json, rag_devices.json, … live)
# is four levels up. Results are written alongside the script (this folder).
BASE      = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE, "..", "..", "..", ".."))
FEAT_DIR  = os.path.join(REPO_ROOT, "evaluation", "validation", "46_features")
LABEL_DIR = os.path.join(REPO_ROOT, "platform_data", "csv", "label")
OUT_DIR   = BASE                                   # results live in Mahmood/
TYPE_DIR  = os.path.join(OUT_DIR, "type")
VEND_DIR  = os.path.join(OUT_DIR, "vendor")

# Predict CSV folders (Mahmood baseline convention), used by extract_predict_csvs()
TYPE_PRED_DIR  = os.path.join(REPO_ROOT, "evaluation", "validation", "type",   "predict", "Mahmood")
VEND_PRED_DIR  = os.path.join(REPO_ROOT, "evaluation", "validation", "vendor", "predict", "Mahmood")

MODEL_PATH   = "/home/nfs/models/Llama-3.1-8B-Instruct"
DEVS         = ["ALARM", "CONTROLLER"]
MAX_VAL      = 600      # truncate each fingerprint field value (chars)
MAX_TOKENS   = 600
TEMPERATURE  = 0.3

# output naming for this baseline round (results live in Mahmood/ alongside
# this script): type/{dev}.json, vendor/{dev}.json, metrics.json.
SUFFIX        = ""
METRICS_FILE  = "metrics.json"

# acceptable predicted type strings per device (normalized comparison). The
# CONTROLLER candidate was renamed to SMART_HOME_CONTROLLER this round, so a
# CONTROLLER device is counted correct when predicted as either name.
TYPE_TARGETS = {
    "ALARM":      ["ALARM"],
    "CONTROLLER": ["CONTROLLER", "SMART_HOME_CONTROLLER"],
}

# ── load candidate device types & perspective definitions ────────────────────
# Candidate device types come from rag_devices.json (the 11 evaluation types).
CANDIDATE_TYPES = json.load(open(os.path.join(REPO_ROOT, "rag_devices.json"), encoding="utf-8"))["IoT"]

# How each candidate type is presented to the LLM. CONTROLLER is expressed as
# "smart home controller" so the model grasps the device-class semantics; the
# emitted answer is mapped back to CONTROLLER by canonical_type() below.
TYPE_DISPLAY = {
    "CONTROLLER": "SMART_HOME_CONTROLLER (a smart home controller / home-automation hub)",
}

# Canonical (uppercase) → display-case name, matching the Mahmood predict-CSV
# convention (type_Alarm.csv uses "Alarm"; vendor_ALARM.csv uses uppercase).
TYPE_DISPLAY_CASE = {
    "NAS": "NAS", "NVR": "NVR", "POWER_METER": "Power_meter",
    "BUILDING_AUTOMATION": "Building_Automation", "MEDICAL": "Medical",
    "ROUTER": "Router", "PRINTER": "Printer", "SCADA": "Scada",
    "CAMERA": "Camera", "ALARM": "Alarm", "CONTROLLER": "Controller",
}

PERSPECTIVE_INFO = json.load(open(os.path.join(REPO_ROOT, "perspective_info.json"), encoding="utf-8"))
PERSPECTIVE_NAME = json.load(open(os.path.join(REPO_ROOT, "perspective_name.json"), encoding="utf-8"))

# weight>0 leaf perspectives (skip composite http/hpart/overall whose weight==0)
ORDER = ["as", "whois", "os", "sw", "hw", "sd", "body", "htags", "hfavicons", "certificate", "dns"]
LEAF_PERSPECTIVES = [
    p for p in ORDER
    if PERSPECTIVE_INFO.get(p, {}).get("weight", 0) > 0
]


def build_perspective_columns(csv_columns):
    """Map each perspective -> list of CSV columns actually present. Derive `basic`."""
    used = set()
    persp_cols = {}
    for p in LEAF_PERSPECTIVES:
        cols = [c for c in PERSPECTIVE_INFO[p]["cols"] if c in csv_columns]
        persp_cols[p] = cols
        used.update(cols)
    # basic = real feature columns present in the CSV but not covered by any perspective
    basic_cols = [c for c in csv_columns if c != "ip" and c not in used]
    persp_cols["basic"] = basic_cols
    return persp_cols


# ── prompt construction (modeled on agent/decision.py) ───────────────────────
SYSTEM_PROMPT = """\
You are an expert IoT network device classifier with deep knowledge of network
traffic fingerprinting. Your mission is to identify the **device type** and
**manufacturer/vendor** of an unknown IoT device.

The device's raw network fingerprint is organised into several **perspectives**
(e.g. hardware, software, services, HTTP, certificates, ASN, WHOIS, DNS, …).
Weigh the evidence across ALL perspectives together, then give ONE consolidated
answer. The "basic" perspective bundles miscellaneous leftover fields.

## Candidate Device Types
{candidates}

**HARD CONSTRAINT**: `device_type` MUST be exactly ONE of the candidate types listed
above. Outputting any other device type is forbidden.

## How to Reason (chain-of-thought)
1. Hardware & Software — examine the hw-* and sw-* vendors/products for the
   manufacturer identity and product clues.
2. Network services — open ports / service-distribution point to a device class.
3. TLS / certificates — cert subjects/issuers often carry vendor/organisation names.
4. HTTP — bodies / tags / favicons reveal the web interface type.
5. ASN / WHOIS / DNS / basic — context that can corroborate or contradict.
6. Synthesise ALL perspectives into a single device type and a single vendor.

## Required Output
Output a single JSON block and nothing else after it:
```json
{{
  "analysis":            "<short reasoning synthesising the perspectives>",
  "device_type":         "<ONE candidate type, or UNKNOWN>",
  "device_type_reason":  "<concise key evidence for the device type>",
  "vendor":              "<manufacturer name, or Unknown>",
  "vendor_reason":       "<concise key evidence for the vendor>",
  "confidence":          0.0
}}
```
""".format(candidates=" | ".join(TYPE_DISPLAY.get(t, t) for t in CANDIDATE_TYPES))


def fmt_fields(row, cols):
    """Compact JSON of the non-null fields among *cols* (truncated)."""
    display = {}
    for c in cols:
        v = row.get(c)
        if v is None:
            continue
        s = str(v)
        if s.strip().lower() in ("", "nan", "none"):
            continue
        if len(s) > MAX_VAL:
            s = s[:MAX_VAL] + "…"
        display[c] = s
    return display


def build_user_prompt(ip, perspective_columns, row):
    """One prompt per device: fingerprint grouped & labelled by perspective."""
    all_perspectives = LEAF_PERSPECTIVES + ["basic"]
    sections = []
    for p in all_perspectives:
        cols = perspective_columns[p]
        prompt_info = PERSPECTIVE_INFO.get(p, {}).get(
            "prompt_info", "Miscellaneous / leftover raw fingerprint fields"
        )
        fields = fmt_fields(row, cols)
        body = (
            json.dumps(fields, ensure_ascii=False, indent=2)
            if fields
            else "(no observable fields for this perspective)"
        )
        sections.append(f"### perspective: {p}\n# {prompt_info}\n{body}")
    fp = "\n\n".join(sections)
    return (
        f"Identify the device with IP {ip}. Its raw network fingerprint, "
        f"organised by perspective, is:\n\n{fp}\n\n"
        f"Synthesise ALL perspectives and output your final JSON classification."
    )


# ── JSON extraction (replicated from agent/decision.py::_extract_json) ────────
def extract_json(text):
    m = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            pass
    for match in re.finditer(r"\{[^{}]*\"device_type\"[^{}]*\}", text, re.DOTALL):
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            continue
    start, end = text.rfind("{"), text.rfind("}") + 1
    if 0 <= start < end:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    return {}


# ── vendor matching (normalized) ─────────────────────────────────────────────
def norm_type(s):
    s = str(s).upper().strip()
    s = re.sub(r"[\s\-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s


def type_match(pred, dev):
    """A predicted type is correct if it matches any acceptable target for *dev*."""
    targets = TYPE_TARGETS.get(dev, [dev])
    npred = norm_type(pred)
    return npred in {norm_type(t) for t in targets}


def canonical_type(pred):
    """Map the model-emitted type back to a canonical candidate name.

    CONTROLLER is shown to the LLM as 'SMART_HOME_CONTROLLER (smart home ...)', so
    the model often returns 'SMART_HOME_CONTROLLER' / 'smart home controller'. Those
    are mapped back to the canonical candidate 'CONTROLLER' for storage/metrics.
    """
    n = norm_type(pred)
    canon = {norm_type(c): c for c in CANDIDATE_TYPES}
    if n in canon:
        return canon[n]
    if n == "SMART_HOME_CONTROLLER" or "HOME_CONTROLLER" in n:
        return "CONTROLLER"
    return str(pred).upper().strip() or "UNKNOWN"


def norm_vendor(s):
    s = str(s).lower().strip()
    s = re.sub(r"[^a-z0-9 ]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def vendor_match(pred, true):
    a, b = norm_vendor(pred), norm_vendor(true)
    if not a or not b:
        return False
    if a == b:
        return True
    return (a in b) or (b in a)  # tolerate Schneider <-> Schneider Electric


def extract_predict_csvs(results):
    """Write per-device prediction CSVs into the Mahmood predict folders.

      type/predict/Mahmood/type_{Dev}.csv     columns: ip, predicted_type
      vendor/predict/Mahmood/vendor_{DEV}.csv columns: ip, vendor1, vendor2, vendor3

    Filenames and columns match the existing files in those folders (e.g.
    type_Camera.csv, vendor_CAMERA.csv). The model predicts a single vendor, so
    only vendor1 is filled.
    """
    import csv as _csv
    os.makedirs(TYPE_PRED_DIR, exist_ok=True)
    os.makedirs(VEND_PRED_DIR, exist_ok=True)
    for dev in DEVS:
        recs = results[dev]
        dev_disp = TYPE_DISPLAY_CASE.get(dev, dev.title())
        # ── type CSV ──
        type_path = os.path.join(TYPE_PRED_DIR, f"type_{dev_disp}.csv")
        with open(type_path, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["ip", "predicted_type"])
            for r in recs:
                pt = TYPE_DISPLAY_CASE.get(r["predicted_device_type"], r["predicted_device_type"])
                w.writerow([r["ip"], pt])
        # ── vendor CSV ──
        vend_path = os.path.join(VEND_PRED_DIR, f"vendor_{dev}.csv")
        with open(vend_path, "w", newline="", encoding="utf-8") as fh:
            w = _csv.writer(fh)
            w.writerow(["ip", "vendor1", "vendor2", "vendor3"])
            for r in recs:
                v = str(r["predicted_vendor"]).strip()
                if v.lower() in ("", "unknown", "none", "nan"):
                    v = ""
                w.writerow([r["ip"], v, "", ""])
        print(f"  [predict-csv] {os.path.basename(type_path)}  +  {os.path.basename(vend_path)}")


# ── main ─────────────────────────────────────────────────────────────────────
def main():
    os.makedirs(TYPE_DIR, exist_ok=True)
    os.makedirs(VEND_DIR, exist_ok=True)

    from vllm import LLM, SamplingParams

    all_messages = []   # list[list[{"role","content"}]]
    meta = []           # parallel list of (dev, ip, true_vendor)

    perspective_columns = None
    for dev in DEVS:
        df = pd.read_csv(os.path.join(FEAT_DIR, f"test_{dev}_1.csv"), low_memory=False)
        df.columns = df.columns.str.replace("﻿", "", regex=True).str.strip()
        if perspective_columns is None:
            perspective_columns = build_perspective_columns(list(df.columns))

        lab = pd.read_csv(os.path.join(LABEL_DIR, f"label_{dev}.csv"))
        lab["ip"] = lab["ip"].astype(str)
        label_map = dict(zip(lab["ip"], lab["vendor"]))

        df["ip"] = df["ip"].astype(str)
        for _, row in df.iterrows():
            ip = row["ip"]
            user = build_user_prompt(ip, perspective_columns, row.to_dict())
            all_messages.append(
                [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ]
            )
            meta.append((dev, ip, label_map.get(ip, "Unknown")))

    print(f"[prompt] {len(all_messages)} prompts (one combined prompt per device)")
    print(f"[perspectives] leaf={LEAF_PERSPECTIVES} + basic")

    llm = LLM(
        model=MODEL_PATH,
        dtype="bfloat16",
        gpu_memory_utilization=0.55,
        max_model_len=8192,
        tensor_parallel_size=1,
    )
    sampling = SamplingParams(temperature=TEMPERATURE, max_tokens=MAX_TOKENS)
    outputs = llm.chat(all_messages, sampling)

    # parse + bucket per device
    results = {dev: [] for dev in DEVS}
    fail = 0
    for (dev, ip, true_vendor), out in zip(meta, outputs):
        text = out.outputs[0].text
        parsed = extract_json(text)
        if not parsed:
            fail += 1
        dev_type = canonical_type(parsed.get("device_type", "UNKNOWN"))
        vendor = str(parsed.get("vendor", "Unknown")).strip() or "Unknown"
        if vendor.lower() == "unknown":
            vendor = "Unknown"
        results[dev].append({
            "ip": ip,
            "true_device_type": dev,
            "true_vendor": true_vendor,
            "predicted_device_type": dev_type,
            "device_type_reason": parsed.get("device_type_reason", ""),
            "predicted_vendor": vendor,
            "vendor_reason": parsed.get("vendor_reason", ""),
            "analysis": parsed.get("analysis", ""),
            "confidence": float(parsed.get("confidence", 0.0) or 0.0),
        })
    print(f"[parse] {fail}/{len(outputs)} responses failed JSON extraction")

    # save
    for dev in DEVS:
        recs = results[dev]
        type_recs = [
            {k: r[k] for k in (
                "ip", "true_device_type", "predicted_device_type",
                "device_type_reason", "confidence")}
            for r in recs
        ]
        vend_recs = [
            {k: r[k] for k in (
                "ip", "true_device_type", "true_vendor",
                "predicted_vendor", "vendor_reason", "confidence")}
            for r in recs
        ]
        with open(os.path.join(TYPE_DIR, f"{dev}{SUFFIX}.json"), "w", encoding="utf-8") as fh:
            json.dump(type_recs, fh, ensure_ascii=False, indent=2)
        with open(os.path.join(VEND_DIR, f"{dev}{SUFFIX}.json"), "w", encoding="utf-8") as fh:
            json.dump(vend_recs, fh, ensure_ascii=False, indent=2)
    print(f"[save] wrote type/{{ALARM,CONTROLLER}}{SUFFIX}.json and vendor/ "
          f"(4 files) under {OUT_DIR}")

    # metrics
    metrics = {}
    for dev in DEVS:
        recs = results[dev]
        n = len(recs)
        v_correct = sum(1 for r in recs if vendor_match(r["predicted_vendor"], r["true_vendor"]))
        t_correct = sum(1 for r in recs if type_match(r["predicted_device_type"], dev))
        type_dist = Counter(r["predicted_device_type"] for r in recs)
        metrics[dev] = {
            "n": n,
            "vendor_correct": v_correct,
            "vendor_accuracy": round(v_correct / n, 4) if n else 0.0,
            "type_correct": t_correct,
            "type_accuracy": round(t_correct / n, 4) if n else 0.0,
            "type_distribution": dict(type_dist),
        }
    with open(os.path.join(OUT_DIR, METRICS_FILE), "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, ensure_ascii=False, indent=2)

    # ── extract type/vendor prediction CSVs into predict/Mahmood ──
    print("\n[extract] writing prediction CSVs into predict/Mahmood ...")
    extract_predict_csvs(results)

    # ── tables ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("TABLE 1 — Vendor & Device-Type Accuracy (combined, per device)")
    print("=" * 64)
    print(f"{'Device':<14}{'N':>5}{'Vendor Acc':>14}{'Type Acc':>12}")
    print("-" * 64)
    for dev in DEVS:
        m = metrics[dev]
        print(f"{dev:<14}{m['n']:>5}"
              f"{m['vendor_accuracy'] * 100:>13.1f}%"
              f"{m['type_accuracy'] * 100:>11.1f}%")
    print("-" * 64)

    print("\n" + "=" * 64)
    print("TABLE 2 — Predicted Device-Type Distribution (per device)")
    print("=" * 64)
    for dev in DEVS:
        dist = metrics[dev]["type_distribution"]
        items = ", ".join(f"{k}:{v}" for k, v in sorted(dist.items(), key=lambda x: -x[1]))
        print(f"  {dev:<14} {items}")

    print("\n=== DONE ===")


if __name__ == "__main__":
    main()
