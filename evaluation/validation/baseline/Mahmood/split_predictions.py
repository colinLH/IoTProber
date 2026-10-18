#!/usr/bin/env python3
"""
Split Mahmood baseline prediction JSONs into type and vendor CSVs.

Source:
  evaluation/validation/baseline/Mahmood/type/{DEV}.json     -> type_{dev}.csv
  evaluation/validation/baseline/Mahmood/vendor/{DEV}.json   -> vendor_{DEV}.csv

Targets:
  evaluation/validation/type/predict/Mahmood/type_{dev}.csv
  evaluation/validation/vendor/predict/Mahmood/vendor_{DEV}.csv

Formats match existing files in the target directories:
  type CSV:   ip,predicted_type
  vendor CSV: ip,vendor1,vendor2,vendor3
"""

import os
import json
import csv

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
MAHMOOD_DIR = os.path.join(BASE_DIR, "evaluation", "validation", "baseline", "Mahmood")
TYPE_OUT = os.path.join(BASE_DIR, "evaluation", "validation", "type", "predict", "Mahmood")
VENDOR_OUT = os.path.join(BASE_DIR, "evaluation", "validation", "vendor", "predict", "Mahmood")

os.makedirs(TYPE_OUT, exist_ok=True)
os.makedirs(VENDOR_OUT, exist_ok=True)

TYPE_NORM = {
    "CAMERA": "Camera",
    "PRINTER": "Printer",
    "SCADA": "Scada",
    "ROUTER": "Router",
    "NAS": "NAS",
    "NVR": "NVR",
    "POWER_METER": "Power_meter",
    "BUILDING_AUTOMATION": "Building_Automation",
    "MEDICAL": "Medical",
    "ALARM": "Alarm",
    "CONTROLLER": "Controller",
    "SMART_HOME_CONTROLLER": "Controller",
    "UNKNOWN": "UNKNOWN",
}

def normalise_type(raw):
    key = raw.upper().strip().replace(" ", "_")
    return TYPE_NORM.get(key, raw)

for subdir, out_dir, kind in [("type", TYPE_OUT, "type"), ("vendor", VENDOR_OUT, "vendor")]:
    src_dir = os.path.join(MAHMOOD_DIR, subdir)
    if not os.path.isdir(src_dir):
        print(f"[SKIP] {src_dir} not found")
        continue

    for fname in sorted(os.listdir(src_dir)):
        if not fname.endswith(".json"):
            continue

        dev_upper = fname.replace(".json", "")
        dev_display = normalise_type(dev_upper)

        with open(os.path.join(src_dir, fname), encoding="utf-8") as f:
            records = json.load(f)

        if kind == "type":
            out_path = os.path.join(out_dir, f"type_{dev_display}.csv")
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "predicted_type"])
                for rec in records:
                    pred = normalise_type(rec.get("predicted_device_type", "UNKNOWN"))
                    writer.writerow([rec["ip"], pred])
            print(f"  Saved {out_path}  ({len(records)} records)")

        elif kind == "vendor":
            out_path = os.path.join(out_dir, f"vendor_{dev_upper}.csv")
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "vendor1", "vendor2", "vendor3"])
                for rec in records:
                    v = rec.get("predicted_vendor", "Unknown")
                    if not v or v.lower() == "unknown":
                        writer.writerow([rec["ip"], "Unknown", "", ""])
                    else:
                        writer.writerow([rec["ip"], v, "", ""])
            print(f"  Saved {out_path}  ({len(records)} records)")

print("Done.")
