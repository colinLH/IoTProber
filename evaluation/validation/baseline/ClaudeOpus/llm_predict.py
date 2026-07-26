#!/usr/bin/env python3
"""
LLM-based device type and Top-3 vendor identification using Claude Opus (CLAUDEBaseline).

Pipeline:
  For each device type in TYPES:
    1. Read IP fingerprints from evaluation/validation/46_features/test_{TYPE}_1.csv
    2. Build concise fingerprint text per IP
    3. Call chat_with_llm("CLAUDEBaseline", ...) to get device type + Top-3 vendors
    4. Save predict_{dev}.json  (format: [{ip, type, top3_vendor}, ...])

Resume support: if predict_{dev}.json already exists, processed IPs are skipped.
"""

import os
import sys
import json
import time
import csv
import pandas as pd

# ── Path setup ─────────────────────────────────────────────────────────────────
PREDICT_DIR  = os.path.dirname(os.path.abspath(__file__))
BASE_DIR     = os.path.abspath(os.path.join(PREDICT_DIR, "..", "..", "..", ".."))
FEAT_DIR     = os.path.join(BASE_DIR, "evaluation", "validation", "46_features")
LOG_DIR      = os.path.join(BASE_DIR, "evaluation", "logs")
LABEL_DIR    = os.path.join(BASE_DIR, "platform_data", "csv", "label")
TYPE_PRED_DIR = os.path.join(BASE_DIR, "evaluation", "validation", "type", "predict", "ClaudeOpus")
VENDOR_PRED_DIR = os.path.join(BASE_DIR, "evaluation", "validation", "vendor", "predict", "ClaudeOpus")
os.makedirs(LOG_DIR, exist_ok=True)
sys.path.insert(0, BASE_DIR)

from llm import LLM

# ── Config ─────────────────────────────────────────────────────────────────────
LLM_KEY = "CLAUDEBaseline"

TYPES = [
    "Camera", "Printer", "Scada", "Router", "NAS",
    "NVR", "Power_meter", "Building_Automation", "Medical",
    "Alarm", "Controller",
]

FEAT_FILE = {
    "Camera":              "test_CAMERA_1.csv",
    "Printer":             "test_PRINTER_1.csv",
    "Scada":               "test_SCADA_1.csv",
    "Router":              "test_ROUTER_1.csv",
    "NAS":                 "test_NAS_1.csv",
    "NVR":                 "test_NVR_1.csv",
    "Power_meter":         "test_POWER_METER_1.csv",
    "Building_Automation": "test_BUILDING_AUTOMATION_1.csv",
    "Medical":             "test_MEDICAL_1.csv",
    "Alarm":               "test_ALARM_1.csv",
    "Controller":          "test_CONTROLLER_1.csv",
}

# LLM type label → display format used in predict_{dev}.json
TYPE_NORM = {
    "CAMERA":              "Camera",
    "PRINTER":             "Printer",
    "SCADA":               "Scada",
    "ROUTER":              "Router",
    "NAS":                 "NAS",
    "NVR":                 "NVR",
    "POWER_METER":         "Power_meter",
    "BUILDING_AUTOMATION": "Building_Automation",
    "MEDICAL":             "Medical",
    "ALARM":               "Alarm",
    "CONTROLLER":          "Controller",
    "UNKNOWN":             "UNKNOWN",
}

ALL_DEVICE_TYPES = list(TYPE_NORM.keys())

SAVE_INTERVAL = 20   # save checkpoint every N processed IPs
REQUEST_DELAY = 0.5  # seconds between API calls

# Claude Opus pricing (per 1M tokens, USD)
INPUT_PRICE_PER_M = 15.0
OUTPUT_PRICE_PER_M = 75.0

# Global token tracking
total_input_tokens = 0
total_output_tokens = 0
total_api_calls = 0

# ── Prompts ────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = f"""You are an expert in IoT device fingerprinting, classification, and vendor identification.
Given a device fingerprint derived from network scanning data, you must:
1. Identify the **device type** — choose exactly one label from the candidates below.
2. Identify the **vendor** (manufacturer / software brand) — return up to 3 candidates.

**Device type candidates**: {', '.join(ALL_DEVICE_TYPES)}
- Use "UNKNOWN" only if you cannot determine the type.

**Vendor identification rules**:
- Return 1–3 vendors clearly supported by the evidence.
- If no vendor can be determined, return [{{"vendor": "unknown"}}].
- Do NOT pad to 3 vendors if fewer are clearly supported by the evidence.

Respond ONLY in valid JSON with this exact structure:
{{
  "device_type": "<TYPE or UNKNOWN>",
  "vendor_top3": [
    {{"vendor": "<name>"}},
    ...
  ]
}}
Write all text in English."""


def build_fingerprint_text(fp: dict) -> str:
    """Select key fields from a 46-feature row and format for the LLM prompt."""
    fields = [
        ("Service Distribution",     "service-distribution"),
        ("Software Vendors",         "sw-vendors"),
        ("Software Products",        "sw-products"),
        ("Software Versions",        "sw-versions"),
        ("Software Info",            "sw-info"),
        ("Hardware Vendors",         "hw-vendors"),
        ("Hardware Products",        "hw-products"),
        ("Hardware Info",            "hw-info"),
        ("OS Vendor",                "os-vendor"),
        ("OS Product",               "os-product"),
        ("OS Version",               "os-version"),
        ("TLS Certificate Subjects", "cert-subjects"),
        ("TLS Certificate Issuers",  "cert-issuers"),
        ("TLS Certificate Info",     "cert-info"),
        ("TLS Versions",             "tls-versions"),
        ("HTTP Tags",                "http-tags"),
        ("HTTP Favicon Hashes",      "http-favicon-hashes"),
        ("DNS Reverse",              "dns-reverse"),
        ("AS Name",                  "as-name"),
        ("WHOIS Organization",       "whois-organization-name"),
        ("Country",                  "loc-country"),
    ]
    lines = []
    for label, key in fields:
        val = (fp.get(key) or "").strip()
        if val:
            if len(val) > 500:
                val = val[:500] + "...[truncated]"
            lines.append(f"- {label}: {val}")
    return "\n".join(lines) if lines else "(No fingerprint data available)"


def build_user_prompt(ip: str, fp_text: str) -> str:
    return (
        f"Analyze the following IoT device fingerprint and identify its type and vendor.\n\n"
        f"**Device IP**: {ip}\n\n"
        f"**Device Fingerprint**:\n{fp_text}\n\n"
        f"Return your analysis as JSON."
    )


def normalise_type(raw: str) -> str:
    """Map LLM-returned type string to canonical display format."""
    key = raw.upper().strip().replace(" ", "_")
    return TYPE_NORM.get(key, raw)


def extract_vendor_list(vendor_top3) -> list:
    """Convert vendor_top3 (list of {vendor}) to plain name list (top 3)."""
    names = []
    if isinstance(vendor_top3, list):
        for v in vendor_top3:
            if isinstance(v, dict):
                name = v.get("vendor", "unknown")
                if name.lower() != "unknown":
                    names.append(name)
    if not names:
        names = ["unknown"]
    return names[:3]


# ── Main ───────────────────────────────────────────────────────────────────────

print("Initializing LLM client...")
llm_client = LLM()

for dev in TYPES:
    feat_path = os.path.join(FEAT_DIR, FEAT_FILE[dev])
    out_path  = os.path.join(PREDICT_DIR, f"predict_{dev}.json")

    if not os.path.exists(feat_path):
        print(f"[SKIP] {feat_path} not found")
        continue

    # ── Load feature CSV ───────────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"Processing [{dev}]  ←  {FEAT_FILE[dev]}")
    print("=" * 60)

    rows = []
    with open(feat_path, encoding="utf-8-sig", errors="replace") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    print(f"  Loaded {len(rows)} rows")

    # ── Resume: load existing results ─────────────────────────────────────────
    existing: dict[str, dict] = {}
    if os.path.exists(out_path):
        try:
            with open(out_path, encoding="utf-8") as f:
                for entry in json.load(f):
                    if "type" in entry:
                        existing[entry["ip"]] = entry
            print(f"  Resuming: {len(existing)} IPs already done")
        except Exception as exc:
            print(f"  [WARN] Could not load existing results: {exc}")

    results: list[dict] = list(existing.values())

    # ── Inference loop ─────────────────────────────────────────────────────────
    total   = len(rows)
    new_cnt = 0

    for idx, row in enumerate(rows, 1):
        ip = str(row.get("ip", "")).strip()
        if not ip:
            continue

        if ip in existing:
            print(f"  [{idx}/{total}] Cached  {ip}")
            continue

        fp_text  = build_fingerprint_text(row)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": build_user_prompt(ip, fp_text)},
        ]

        try:
            response, usage = llm_client.chat_with_llm(LLM_KEY, messages, whether_json=True, return_usage=True)

            total_input_tokens += usage["prompt_tokens"]
            total_output_tokens += usage["completion_tokens"]
            total_api_calls += 1

            pred_type = normalise_type(response.get("device_type", "UNKNOWN"))
            vendors   = extract_vendor_list(response.get("vendor_top3", []))

            entry = {
                "ip":          ip,
                "type":        pred_type,
                "top3_vendor": vendors,
            }
            print(f"  [{idx}/{total}] OK     {ip}  type={pred_type}  vendors={vendors}")

        except Exception as exc:
            entry = {
                "ip":          ip,
                "type":        "UNKNOWN",
                "top3_vendor": ["unknown"],
            }
            print(f"  [{idx}/{total}] ERROR  {ip}  {exc}")

        results.append(entry)
        existing[ip] = entry
        new_cnt += 1

        # Periodic checkpoint
        if new_cnt % SAVE_INTERVAL == 0:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"  >> Checkpoint saved ({len(results)}/{total})")

        time.sleep(REQUEST_DELAY)

    # ── Final save ─────────────────────────────────────────────────────────────
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    n_ok  = sum(1 for e in results if e["type"] != "UNKNOWN")
    print(f"\n  [{dev}] Done.  Total={len(results)}  Identified={n_ok}  Saved → {out_path}")

# ── Extract type and vendor CSVs ──────────────────────────────────────────────
def extract_csvs(dev_list):
    """Extract type_{dev}.csv and vendor_{dev}.csv from predict_{dev}.json"""
    for dev in dev_list:
        src = os.path.join(PREDICT_DIR, f"predict_{dev}.json")
        if not os.path.exists(src):
            print(f"  [SKIP] {src} not found")
            continue
        with open(src, "r", encoding="utf-8") as f:
            records = json.load(f)

        # Type CSV
        type_path = os.path.join(TYPE_PRED_DIR, f"type_{dev}.csv")
        with open(type_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "true_type", "predicted_type"])
            for rec in records:
                writer.writerow([rec["ip"], dev, rec["type"]])
        print(f"  Saved type_{dev}.csv  ({len(records)} records)")

        # Vendor CSV
        vendor_path = os.path.join(VENDOR_PRED_DIR, f"vendor_{dev.upper()}.csv")
        with open(vendor_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "vendor1", "vendor2", "vendor3"])
            for rec in records:
                vendors = rec.get("top3_vendor", ["unknown"])
                while len(vendors) < 3:
                    vendors.append("")
                writer.writerow([rec["ip"]] + vendors[:3])
        print(f"  Saved vendor_{dev.upper()}.csv  ({len(records)} records)")


def calculate_accuracy(dev_list):
    """Calculate type (top-1) and vendor (top-1, top-3) accuracy"""
    results = {}
    for dev in dev_list:
        dev_key = dev.upper()
        # Type accuracy
        type_path = os.path.join(TYPE_PRED_DIR, f"type_{dev}.csv")
        type_df = pd.read_csv(type_path, dtype=str)
        type_df["true_type"] = type_df["true_type"].str.strip()
        type_df["predicted_type"] = type_df["predicted_type"].str.strip()
        total_t = len(type_df)
        correct_t1 = (type_df["true_type"] == type_df["predicted_type"]).sum()

        # Vendor accuracy
        vendor_path = os.path.join(VENDOR_PRED_DIR, f"vendor_{dev_key}.csv")
        vendor_pred = pd.read_csv(vendor_path, dtype=str)
        gt_path = os.path.join(LABEL_DIR, f"label_{dev_key}.csv")
        gt_df = pd.read_csv(gt_path, dtype=str)
        gt_df["vendor"] = gt_df["vendor"].str.strip()

        merged = vendor_pred.merge(gt_df, on="ip", how="inner", suffixes=("_pred", "_gt"))
        total_v = len(merged)
        if total_v == 0:
            results[dev] = {"type_top1": 0, "vendor_top1": 0, "vendor_top3": 0, "type_total": total_t, "vendor_total": 0}
            continue

        merged["vendor1"] = merged["vendor1"].fillna("").str.strip()
        merged["vendor2"] = merged["vendor2"].fillna("").str.strip()
        merged["vendor3"] = merged["vendor3"].fillna("").str.strip()
        merged["vendor"] = merged["vendor"].str.strip()

        correct_v1 = (merged["vendor1"].str.lower() == merged["vendor"].str.lower()).sum()

        def in_top3(row):
            gt = row["vendor"].lower()
            for col in ["vendor1", "vendor2", "vendor3"]:
                if row[col] and row[col].lower() == gt:
                    return True
            return False

        correct_v3 = merged.apply(in_top3, axis=1).sum()

        results[dev] = {
            "type_top1": correct_t1,
            "type_total": total_t,
            "vendor_top1": correct_v1,
            "vendor_top3": correct_v3,
            "vendor_total": total_v,
        }
    return results


# ── Extract CSVs ──────────────────────────────────────────────────────────────
processed_devs = [d for d in TYPES if os.path.exists(os.path.join(PREDICT_DIR, f"predict_{d}.json"))]
print(f"\n{'='*60}")
print("Extracting type and vendor CSVs...")
print("="*60)
extract_csvs(processed_devs)

# ── Calculate accuracy ────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("Calculating accuracy...")
print("="*60)
acc = calculate_accuracy(processed_devs)

# ── Calculate cost ────────────────────────────────────────────────────────────
total_tokens = total_input_tokens + total_output_tokens
input_cost = total_input_tokens / 1_000_000 * INPUT_PRICE_PER_M
output_cost = total_output_tokens / 1_000_000 * OUTPUT_PRICE_PER_M
total_cost = input_cost + output_cost

# ── Print results ─────────────────────────────────────────────────────────────
print(f"\n{'='*60}")
print("Claude Opus (CLAUDEBaseline) Prediction Results")
print("="*60)
print(f"\nAPI Calls: {total_api_calls}")
print(f"Input Tokens:  {total_input_tokens:,}")
print(f"Output Tokens: {total_output_tokens:,}")
print(f"Total Tokens:  {total_tokens:,}")
print(f"Input Cost:  ${input_cost:.4f}")
print(f"Output Cost: ${output_cost:.4f}")
print(f"Total Cost:  ${total_cost:.4f}")

print(f"\n{'='*60}")
print("Accuracy Summary")
print("="*60)
for dev in processed_devs:
    a = acc[dev]
    t1 = a["type_top1"] / a["type_total"] * 100 if a["type_total"] > 0 else 0
    v1 = a["vendor_top1"] / a["vendor_total"] * 100 if a["vendor_total"] > 0 else 0
    v3 = a["vendor_top3"] / a["vendor_total"] * 100 if a["vendor_total"] > 0 else 0
    print(f"\n  [{dev}]")
    print(f"    Type  Top-1: {a['type_top1']}/{a['type_total']} = {t1:.2f}%")
    print(f"    Vendor Top-1: {a['vendor_top1']}/{a['vendor_total']} = {v1:.2f}%")
    print(f"    Vendor Top-3: {a['vendor_top3']}/{a['vendor_total']} = {v3:.2f}%")

# ── Save log ──────────────────────────────────────────────────────────────────
log_path = os.path.join(LOG_DIR, "claude_opus_predict.log")
with open(log_path, "w", encoding="utf-8") as f:
    f.write(f"{'='*60}\n")
    f.write(f"Claude Opus (CLAUDEBaseline) Prediction Results\n")
    f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write(f"{'='*60}\n\n")
    f.write(f"API Calls: {total_api_calls}\n")
    f.write(f"Input Tokens:  {total_input_tokens:,}\n")
    f.write(f"Output Tokens: {total_output_tokens:,}\n")
    f.write(f"Total Tokens:  {total_tokens:,}\n")
    f.write(f"Input Cost:  ${input_cost:.4f}\n")
    f.write(f"Output Cost: ${output_cost:.4f}\n")
    f.write(f"Total Cost:  ${total_cost:.4f}\n\n")
    f.write(f"{'='*60}\n")
    f.write(f"Accuracy Summary\n")
    f.write(f"{'='*60}\n")
    for dev in processed_devs:
        a = acc[dev]
        t1 = a["type_top1"] / a["type_total"] * 100 if a["type_total"] > 0 else 0
        v1 = a["vendor_top1"] / a["vendor_total"] * 100 if a["vendor_total"] > 0 else 0
        v3 = a["vendor_top3"] / a["vendor_total"] * 100 if a["vendor_total"] > 0 else 0
        f.write(f"\n  [{dev}]\n")
        f.write(f"    Type  Top-1: {a['type_top1']}/{a['type_total']} = {t1:.2f}%\n")
        f.write(f"    Vendor Top-1: {a['vendor_top1']}/{a['vendor_total']} = {v1:.2f}%\n")
        f.write(f"    Vendor Top-3: {a['vendor_top3']}/{a['vendor_total']} = {v3:.2f}%\n")
    f.write(f"\n{'='*60}\n")
print(f"\nLog saved to: {log_path}")

print("\nAll device types processed.")
