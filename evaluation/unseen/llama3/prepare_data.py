"""
Data preparation for LLaMA-3.1-8B *unseen-device-detection* fine-tuning.

Aligns the fine-tuning target with what `agent/unseen.py` expects the adapter to
produce at inference time: for each labeled device fingerprint we emit an
instruction-tuning triple whose `output` is the unseen-detection JSON with TWO
independent probabilities and per-field "none" labels:

    {
      "new_type_probability":   <float>,   # >0.5 ⟺ new device *type*
      "new_vendor_probability": <float>,   # >0.5 ⟺ new device *vendor*
      "is_unseen": <bool>,                 # either probability > 0.5
      "predicted_type":   "<type or 'none'>",
      "predicted_vendor": "<vendor or 'none'>",
      "confidence": <float>
    }

Ground-truth logic
------------------
- new type   : device type ∈ new_devices.json  (i.e. NOT in rag_devices.json)
- new vendor : by default follows the new-type verdict; a per-row `is_new_vendor`
               column (0/1) in the label CSV overrides it when present.
- Known (RAG) devices become NEGATIVE samples (both probabilities ≈ 0.05, labels
  "none"), unseen devices become POSITIVE samples — so the model learns BOTH
  classes rather than a vendor-only mapping.

Usage:
    python prepare_data.py
Output:
    dataset/unseen_sft.jsonl   (one {"instruction","input","output"} per line)
"""
import os
import sys
import json

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
from util import load_all_dev_labels, load_new_dev_labels  # noqa: E402

BASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
IPRAW_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "all")
LABEL_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "label")
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
OUTPUT_JSONL = os.path.join(OUTPUT_DIR, "unseen_sft.jsonl")

# Positive/negative probability anchors (mirror unseen.generate_training_sample)
_P_NEW, _P_KNOWN = 0.92, 0.05
_NONE = "none"

_SYSTEM = (
    "You are an expert IoT network device classifier specializing in "
    "unseen device detection. Always respond with valid JSON as instructed."
)

# Columns excluded from the prompt body (identifiers / labels)
_EXCLUDE = {"ip", "vendor", "device_type", "is_new_vendor"}


def _build_prompt(metadata: str, known_types, unseen_types) -> str:
    """Compact unseen-detection prompt built from a labeled fingerprint.
    Mirrors the schema of agent/unseen.py's inference prompt so the fine-tuned
    adapter sees a consistent instruction at train and inference time."""
    return f"""Determine whether the following IoT device is a NEW device *type* and/or a NEW *vendor*, based on its network fingerprint.

## Known Device Types (RAG)
{', '.join(known_types)}

## Unseen Candidate Types
{', '.join(unseen_types)}

## Device Fingerprint
{metadata}

## Task
Estimate two INDEPENDENT probabilities:
- new_type_probability: how likely the device is a NEW type not in the Known Device Types.
- new_vendor_probability: how likely the device is from a NEW vendor.
If information is insufficient to decide, keep the probability BELOW 0.5.
If new_type_probability > 0.5 output the new type, else predicted_type = "none".
If new_vendor_probability > 0.5 output the new vendor, else predicted_vendor = "none".

Respond with ONLY a JSON block:
```json
{{
    "new_type_probability": <float 0.0-1.0>,
    "new_vendor_probability": <float 0.0-1.0>,
    "is_unseen": <bool>,
    "predicted_type": "<type or 'none'>",
    "predicted_vendor": "<vendor or 'none'>",
    "confidence": <float 0.0-1.0>
}}
```"""


def _row_to_metadata(row: pd.Series) -> str:
    parts = []
    for col, val in row.items():
        if col in _EXCLUDE or val is None:
            continue
        val = str(val)
        if val and val not in ("nan", ""):
            parts.append(f"{col}: {val}")
    return "\n".join(parts)


def _make_sample(metadata, known_types, unseen_types,
                 gt_type, gt_vendor, is_new_type, is_new_vendor):
    new_type_prob = _P_NEW if is_new_type else _P_KNOWN
    new_vendor_prob = _P_NEW if is_new_vendor else _P_KNOWN
    target = {
        "new_type_probability": new_type_prob,
        "new_vendor_probability": new_vendor_prob,
        "is_unseen": bool(is_new_type or is_new_vendor),
        "predicted_type": gt_type if is_new_type else _NONE,
        "predicted_vendor": gt_vendor if is_new_vendor else _NONE,
        "confidence": 0.85,
    }
    return {
        "instruction": _SYSTEM,
        "input": _build_prompt(metadata, known_types, unseen_types),
        "output": "```json\n" + json.dumps(target, ensure_ascii=False, indent=2) + "\n```",
    }


def prepare_data():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    known_types = load_all_dev_labels() or []
    unseen_types = load_new_dev_labels() or []
    train_types = known_types  # only known RAG devices in training set
    if not train_types:
        print("No device labels found!")
        return

    total = 0
    with open(OUTPUT_JSONL, "w", encoding="utf-8") as out:
        for dev in train_types:
            is_new_type = dev in unseen_types
            label_path = os.path.join(LABEL_DIR, f"label_{dev}.csv")
            ipraw_path = os.path.join(IPRAW_DIR, f"ipraw_{dev}.csv")
            if not os.path.exists(ipraw_path):
                print(f"[SKIP] ipraw_{dev}.csv not found.")
                continue

            ipraw_df = pd.read_csv(ipraw_path, dtype=str, low_memory=False)

            # Merge vendor (+ optional is_new_vendor) label when available
            if os.path.exists(label_path):
                label_df = pd.read_csv(label_path, dtype=str)
                label_cols = ["ip", "vendor"]
                if "is_new_vendor" in label_df.columns:
                    label_cols.append("is_new_vendor")
                merged = ipraw_df.merge(label_df[label_cols], on="ip", how="left")
            else:
                merged = ipraw_df
                merged["vendor"] = "Unknown"

            merged["vendor"] = merged["vendor"].fillna("Unknown")

            for _, row in merged.iterrows():
                vendor = str(row.get("vendor", "Unknown")).strip() or "Unknown"
                # Per-row override, else default: new vendor iff new type
                if "is_new_vendor" in merged.columns and pd.notna(row.get("is_new_vendor")):
                    is_new_vendor = str(row["is_new_vendor"]).strip() in ("1", "true", "True")
                else:
                    is_new_vendor = is_new_type
                metadata = _row_to_metadata(row)
                if not metadata:
                    continue
                sample = _make_sample(
                    metadata, known_types, unseen_types,
                    gt_type=dev, gt_vendor=vendor,
                    is_new_type=is_new_type, is_new_vendor=is_new_vendor,
                )
                out.write(json.dumps(sample, ensure_ascii=False) + "\n")
                total += 1

            print(f"  {dev}: processed (is_new_type={is_new_type})")

    print(f"\nData preparation complete! Total SFT samples: {total}")
    print(f"Saved to {OUTPUT_JSONL}")


if __name__ == "__main__":
    prepare_data()
