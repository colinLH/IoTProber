"""Prepare supervised type/vendor classification data for LLaMA-3.1-8B.

Only IPs present in ``platform_data/csv/rag/ipraw_<TYPE>.csv`` are used. The
device type is the ``<TYPE>`` suffix and the vendor is joined by IP from
``platform_data/csv/label/label_<TYPE>.csv``. The target contains only the two
ground-truth labels:

    {"device_type": "...", "device_vendor": "..."}

Confidence is deliberately not included because there is no confidence label.
Inference derives field confidence from generated-token probabilities.

The per-perspective info columns in ``util.UNSEEN_INFO_COLS`` form the input
    fingerprint. Fingerprints beyond the 32768-token full-sequence budget are
    summarized by the shared DeepSeek helper used at inference; hard token
    truncation is the final fallback.

Outputs under ``evaluation/unseen/llama3/dataset``:
    finetune_data_<TYPE>.csv  filtered labeled source rows
    unseen_sft_<TYPE>.jsonl   per-type SFT shards
    unseen_sft.jsonl          known + pseudo-new-type + pseudo-new-vendor samples
    validation_sft.jsonl      known holdout + OOD calibration samples
    known_vendors.json        RAG type/vendor contract copied into the adapter
"""
import os
import sys
import glob
import json
import argparse

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
from util import (  # noqa: E402
    load_all_dev_labels,
    UNSEEN_INFO_COLS,
    CLASSIFIER_SYSTEM,
    CLASSIFICATION_CONTRACT_VERSION,
    build_fingerprint_info_text,
    build_unseen_type_vendor_classification_prompt,
    DeepSeekFingerprintSummarizer,
    normalize_unseen_vendor,
)

BASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
IPRAW_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "rag")
ALL_IPRAW_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "all")
LABEL_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "label")
LLAMA_MODEL_PATH = os.path.join(BASE_PATH, "Meta-Llama-3.1-8B-Instruct")
LLM_CFG_PATH = os.path.join(BASE_PATH, "llm_config.json")

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
COMBINED_JSONL = os.path.join(OUTPUT_DIR, "unseen_sft.jsonl")
VALIDATION_JSONL = os.path.join(OUTPUT_DIR, "validation_sft.jsonl")
METADATA_FILENAME = "known_vendors.json"
CACHE_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data_summary_cache",
)
CACHE_PATH = os.path.join(CACHE_DIR, "summary_cache.jsonl")
ANSWER_BUDGET = 96        # room for the two-label assistant JSON answer
# Training and inference use the same 32K context and DeepSeek summary contract.
DEFAULT_MAX_LEN = 32768
DEFAULT_VALIDATION_FRACTION = 0.05
DEFAULT_OOD_VALIDATION_PER_TYPE = 500
DEFAULT_PSEUDO_UNSEEN_FRACTION = 0.25
DEFAULT_PSEUDO_UNSEEN_VENDOR_FRACTION = 0.25
DEFAULT_PSEUDO_VENDOR_VALIDATION_FRACTION = 0.25
RANDOM_SEED = 42
OOD_VALIDATION_TYPES = ("MEDIA_SERVER", "VPN")
_INVALID_LABELS = {"", "unknown", "none", "nan", "null"}


def _vendor_key(value):
    return normalize_unseen_vendor(value)


def _make_sample(user_prompt, gt_type, gt_vendor, metadata=None):
    target = {"device_type": gt_type, "device_vendor": gt_vendor}
    sample = {
        "instruction": CLASSIFIER_SYSTEM,
        "input": user_prompt,
        "output": json.dumps(target, ensure_ascii=False, separators=(",", ":")),
    }
    if metadata:
        sample["metadata"] = metadata
    return sample


def _strip_bom_columns(df):
    df.columns = [str(c).lstrip("﻿").strip() for c in df.columns]
    return df


def _device_type_from_path(path):
    name = os.path.basename(path)
    return name[len("ipraw_"):-len(".csv")]


def _load_labeled_frame(device_type, ipraw_path, limit=None):
    """Load one type, join labels, and drop rows without a usable vendor."""
    label_path = os.path.join(LABEL_DIR, f"label_{device_type}.csv")
    if not os.path.exists(label_path):
        raise FileNotFoundError(f"Missing label file: {label_path}")

    ipraw_df = _strip_bom_columns(
        pd.read_csv(
            ipraw_path,
            dtype=str,
            low_memory=False,
            nrows=limit,
        )
    )
    label_df = _strip_bom_columns(
        pd.read_csv(label_path, dtype=str, low_memory=False)
    )
    required_ipraw = {"ip"}
    required_labels = {"ip", "vendor"}
    if not required_ipraw.issubset(ipraw_df.columns):
        raise ValueError(f"{ipraw_path} must contain column 'ip'")
    if not required_labels.issubset(label_df.columns):
        raise ValueError(f"{label_path} must contain columns 'ip' and 'vendor'")
    if label_df["ip"].duplicated().any():
        duplicates = int(label_df["ip"].duplicated(keep=False).sum())
        raise ValueError(f"{label_path} contains {duplicates} duplicate IP rows")

    keep_cols = ["ip"] + [
        col for col in UNSEEN_INFO_COLS if col in ipraw_df.columns
    ]
    df = ipraw_df[keep_cols].merge(
        label_df[["ip", "vendor"]],
        on="ip",
        how="left",
        validate="many_to_one",
    )
    invalid_vendor = (
        df["vendor"].isna()
        | df["vendor"].fillna("").astype(str).str.strip().str.lower().isin(
            _INVALID_LABELS
        )
    )
    input_rows = len(df)
    dropped_vendor_rows = int(invalid_vendor.sum())
    df = df.loc[~invalid_vendor].copy()
    if df.empty:
        raise ValueError(f"{device_type}: no rows have a valid vendor label")

    df["device_type"] = device_type
    df["device_vendor"] = df["vendor"].astype(str).str.strip()
    return (
        df.drop(columns=["vendor"]).reset_index(drop=True),
        {
            "input_rows": input_rows,
            "dropped_invalid_vendor_rows": dropped_vendor_rows,
            "valid_rows": len(df),
        },
    )


def _load_known_vendors_by_type(known_types):
    """Collect a separate canonical vendor registry for each RAG type."""
    vendors_by_type = {}
    for device_type in known_types:
        label_path = os.path.join(LABEL_DIR, f"label_{device_type}.csv")
        if not os.path.exists(label_path):
            raise FileNotFoundError(f"Missing RAG vendor label file: {label_path}")
        label_df = _strip_bom_columns(
            pd.read_csv(label_path, usecols=["vendor"], dtype=str)
        )
        vendors = {
            value
            for value in label_df["vendor"].fillna("").astype(str).str.strip()
            if value.casefold() not in _INVALID_LABELS
        }
        canonical = {}
        for vendor in sorted(vendors, key=str.casefold):
            canonical.setdefault(normalize_unseen_vendor(vendor), vendor)
        vendors_by_type[device_type] = sorted(
            canonical.values(),
            key=str.casefold,
        )
    return vendors_by_type


def _write_samples(
    df,
    out,
    summarizer,
    known_types,
    known_vendors_by_type,
    split_origin,
    known_vendor_keys_by_type,
    pseudo_new_vendor=False,
):
    """Write samples in bounded chunks and return write/truncation counts."""
    info_cols = [col for col in UNSEEN_INFO_COLS if col in df.columns]
    written = 0
    truncated = 0
    chunk_size = 512
    for start in range(0, len(df), chunk_size):
        chunk = df.iloc[start:start + chunk_size]
        records = chunk[info_cols].fillna("").astype(str).to_dict("records")
        fingerprints = [build_fingerprint_info_text(record) for record in records]
        fitted_fingerprints = summarizer.fit_many(fingerprints)
        for offset, (fingerprint_text, was_summarized) in enumerate(
            fitted_fingerprints
        ):
            if not fingerprint_text:
                continue
            row = chunk.iloc[offset]
            target_vendor_key = _vendor_key(row["device_vendor"])
            prompt_known_vendors = known_vendors_by_type
            if pseudo_new_vendor:
                prompt_known_vendors = dict(known_vendors_by_type)
                prompt_known_vendors[row["device_type"]] = [
                    vendor
                    for vendor in known_vendors_by_type.get(
                        row["device_type"], []
                    )
                    if _vendor_key(vendor) != target_vendor_key
                ]
            prompt = build_unseen_type_vendor_classification_prompt(
                fingerprint_text, known_types, prompt_known_vendors
            )
            sample = _make_sample(
                prompt,
                row["device_type"],
                row["device_vendor"],
                metadata={
                    "ip": row["ip"],
                    "split_origin": split_origin,
                    "is_new_type": row["device_type"] not in known_types,
                    "is_new_vendor": (
                        pseudo_new_vendor
                        or row["device_type"] not in known_types
                        or target_vendor_key
                        not in known_vendor_keys_by_type.get(
                            row["device_type"], set()
                        )
                    ),
                },
            )
            out.write(json.dumps(sample, ensure_ascii=False) + "\n")
            written += 1
            truncated += int(was_summarized)
        out.flush()
    return written, truncated


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════
def prepare_data(
    max_len=DEFAULT_MAX_LEN,
    max_workers=32,
    devices=None,
    limit=None,
    keep_existing=False,
    output_dir=OUTPUT_DIR,
    validation_fraction=DEFAULT_VALIDATION_FRACTION,
    ood_validation_per_type=DEFAULT_OOD_VALIDATION_PER_TYPE,
    pseudo_unseen_fraction=DEFAULT_PSEUDO_UNSEEN_FRACTION,
    pseudo_unseen_vendor_fraction=DEFAULT_PSEUDO_UNSEEN_VENDOR_FRACTION,
    pseudo_vendor_validation_fraction=(
        DEFAULT_PSEUDO_VENDOR_VALIDATION_FRACTION
    ),
):
    os.makedirs(output_dir, exist_ok=True)
    combined_jsonl = os.path.join(output_dir, "unseen_sft.jsonl")
    validation_jsonl = os.path.join(output_dir, "validation_sft.jsonl")
    metadata_path = os.path.join(output_dir, METADATA_FILENAME)
    os.makedirs(CACHE_DIR, exist_ok=True)

    if not 0 <= validation_fraction < 1:
        raise ValueError("--validation_fraction must be in [0, 1)")
    if not 0 <= pseudo_unseen_fraction <= 1:
        raise ValueError("--pseudo_unseen_fraction must be in [0, 1]")
    if not 0 <= pseudo_unseen_vendor_fraction <= 1:
        raise ValueError(
            "--pseudo_unseen_vendor_fraction must be in [0, 1]"
        )
    if not 0 <= pseudo_vendor_validation_fraction <= 1:
        raise ValueError(
            "--pseudo_vendor_validation_fraction must be in [0, 1]"
        )

    known_types = load_all_dev_labels() or []
    source_paths = {
        _device_type_from_path(path): path
        for path in sorted(glob.glob(os.path.join(IPRAW_DIR, "ipraw_*.csv")))
    }
    if not known_types:
        raise RuntimeError("rag_devices.json contains no RAG device types")
    missing_sources = [name for name in known_types if name not in source_paths]
    if missing_sources:
        raise FileNotFoundError(
            "Missing RAG source files: " + ", ".join(missing_sources)
        )
    non_rag_sources = sorted(set(source_paths) - set(known_types))
    if non_rag_sources:
        raise ValueError(
            "RAG training directory contains non-RAG types: "
            + ", ".join(non_rag_sources)
        )

    train_types = list(known_types)
    if devices:
        requested = set(devices)
        unavailable = sorted(requested - set(source_paths))
        if unavailable:
            raise ValueError(
                "Requested RAG types are unavailable: "
                + ", ".join(unavailable)
            )
        train_types = [name for name in train_types if name in requested]

    known_vendors_by_type = _load_known_vendors_by_type(known_types)
    known_vendor_keys_by_type = {
        device_type: {
            _vendor_key(vendor) for vendor in vendors
        }
        for device_type, vendors in known_vendors_by_type.items()
    }

    if not keep_existing:
        patterns = (
            "finetune_data_*.csv",
            "unseen_sft_*.jsonl",
            "unseen_sft.jsonl",
            "validation_sft.jsonl",
        )
        for pattern in patterns:
            for path in glob.glob(os.path.join(output_dir, pattern)):
                os.remove(path)

    print("Loading Llama-3.1 tokenizer ...")
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(LLAMA_MODEL_PATH)
    empty_prompt = build_unseen_type_vendor_classification_prompt(
        "", known_types, known_vendors_by_type
    )
    prompt_overhead = len(tokenizer.apply_chat_template(
        [
            {"role": "system", "content": CLASSIFIER_SYSTEM},
            {"role": "user", "content": empty_prompt},
        ],
        tokenize=True,
        add_generation_prompt=True,
    ))
    fingerprint_budget = max_len - prompt_overhead - ANSWER_BUDGET
    if fingerprint_budget < 512:
        raise RuntimeError(
            f"Fingerprint budget {fingerprint_budget} is too small"
        )
    summarizer = DeepSeekFingerprintSummarizer(
        LLM_CFG_PATH,
        CACHE_PATH,
        fingerprint_budget,
        tokenizer,
        max_workers=max_workers,
    )

    total_train = 0
    total_validation = 0
    total_summarized = 0
    training_vendors = set()
    per_type_stats = {}
    shard_paths = []
    validation_tmp = validation_jsonl + ".tmp"

    with open(validation_tmp, "w", encoding="utf-8") as validation_out:
        for type_index, device_type in enumerate(train_types):
            frame, load_stats = _load_labeled_frame(
                device_type,
                source_paths[device_type],
                limit=limit,
            )
            validation_rows = 0
            if validation_fraction > 0 and len(frame) > 1:
                validation_rows = min(
                    len(frame) - 1,
                    max(1, round(len(frame) * validation_fraction)),
                )
            if validation_rows:
                validation_frame = frame.sample(
                    n=validation_rows,
                    random_state=RANDOM_SEED + type_index,
                )
                train_frame = frame.drop(validation_frame.index).reset_index(
                    drop=True
                )
                validation_frame = validation_frame.reset_index(drop=True)
            else:
                train_frame = frame
                validation_frame = frame.iloc[0:0]

            training_vendors.update(train_frame["device_vendor"].tolist())
            train_frame.to_csv(
                os.path.join(
                    output_dir,
                    f"finetune_data_{device_type}.csv",
                ),
                index=False,
            )
            shard_path = os.path.join(
                output_dir,
                f"unseen_sft_{device_type}.jsonl",
            )
            shard_paths.append(shard_path)
            with open(shard_path, "w", encoding="utf-8") as shard_out:
                train_written, train_summarized = _write_samples(
                    train_frame,
                    shard_out,
                    summarizer,
                    known_types,
                    known_vendors_by_type,
                    "known_train",
                    known_vendor_keys_by_type,
                )
                pseudo_rows = 0
                pseudo_summarized = 0
                pseudo_vendor_rows = 0
                pseudo_vendor_summarized = 0
                if pseudo_unseen_fraction > 0 and len(train_frame):
                    pseudo_rows = min(
                        len(train_frame),
                        max(1, round(
                            len(train_frame) * pseudo_unseen_fraction
                        )),
                    )
                    pseudo_frame = train_frame.sample(
                        n=pseudo_rows,
                        random_state=RANDOM_SEED + 1000 + type_index,
                    ).reset_index(drop=True)
                    pseudo_known_types = [
                        name
                        for name in known_types
                        if name != device_type
                    ]
                    pseudo_rows, pseudo_summarized = _write_samples(
                        pseudo_frame,
                        shard_out,
                        summarizer,
                        pseudo_known_types,
                        known_vendors_by_type,
                        "pseudo_unseen_type_train",
                        known_vendor_keys_by_type,
                    )
                    del pseudo_frame
                if pseudo_unseen_vendor_fraction > 0 and len(train_frame):
                    pseudo_vendor_rows = min(
                        len(train_frame),
                        max(1, round(
                            len(train_frame)
                            * pseudo_unseen_vendor_fraction
                        )),
                    )
                    pseudo_vendor_frame = train_frame.sample(
                        n=pseudo_vendor_rows,
                        random_state=RANDOM_SEED + 2000 + type_index,
                    ).reset_index(drop=True)
                    (
                        pseudo_vendor_rows,
                        pseudo_vendor_summarized,
                    ) = _write_samples(
                        pseudo_vendor_frame,
                        shard_out,
                        summarizer,
                        known_types,
                        known_vendors_by_type,
                        "pseudo_unseen_vendor_train",
                        known_vendor_keys_by_type,
                        pseudo_new_vendor=True,
                    )
                    del pseudo_vendor_frame
            validation_written, validation_summarized = _write_samples(
                validation_frame,
                validation_out,
                summarizer,
                known_types,
                known_vendors_by_type,
                "known_validation",
                known_vendor_keys_by_type,
            )
            pseudo_vendor_validation_rows = 0
            pseudo_vendor_validation_summarized = 0
            if (
                pseudo_vendor_validation_fraction > 0
                and len(validation_frame)
            ):
                pseudo_vendor_validation_rows = min(
                    len(validation_frame),
                    max(1, round(
                        len(validation_frame)
                        * pseudo_vendor_validation_fraction
                    )),
                )
                pseudo_vendor_validation_frame = validation_frame.sample(
                    n=pseudo_vendor_validation_rows,
                    random_state=RANDOM_SEED + 3000 + type_index,
                ).reset_index(drop=True)
                (
                    pseudo_vendor_validation_rows,
                    pseudo_vendor_validation_summarized,
                ) = _write_samples(
                    pseudo_vendor_validation_frame,
                    validation_out,
                    summarizer,
                    known_types,
                    known_vendors_by_type,
                    "pseudo_unseen_vendor_validation",
                    known_vendor_keys_by_type,
                    pseudo_new_vendor=True,
                )
                del pseudo_vendor_validation_frame
            total_train += (
                train_written + pseudo_rows + pseudo_vendor_rows
            )
            total_validation += (
                validation_written + pseudo_vendor_validation_rows
            )
            total_summarized += (
                train_summarized
                + pseudo_summarized
                + pseudo_vendor_summarized
                + validation_summarized
                + pseudo_vendor_validation_summarized
            )
            per_type_stats[device_type] = {
                **load_stats,
                "training_rows": train_written,
                "pseudo_unseen_training_rows": pseudo_rows,
                "pseudo_unseen_vendor_training_rows": pseudo_vendor_rows,
                "known_validation_rows": validation_written,
                "pseudo_unseen_vendor_validation_rows": (
                    pseudo_vendor_validation_rows
                ),
                "summarized_rows": (
                    train_summarized
                    + pseudo_summarized
                    + pseudo_vendor_summarized
                    + validation_summarized
                    + pseudo_vendor_validation_summarized
                ),
            }
            del frame, train_frame, validation_frame

        ood_types = []
        ood_limit = ood_validation_per_type
        if limit is not None:
            ood_limit = min(ood_limit, limit)
        for device_type in OOD_VALIDATION_TYPES:
            path = os.path.join(
                ALL_IPRAW_DIR,
                f"ipraw_{device_type}.csv",
            )
            label_path = os.path.join(
                LABEL_DIR,
                f"label_{device_type}.csv",
            )
            if not os.path.exists(path) or not os.path.exists(label_path):
                continue
            frame, load_stats = _load_labeled_frame(
                device_type,
                path,
                limit=ood_limit,
            )
            written, summarized = _write_samples(
                frame,
                validation_out,
                summarizer,
                known_types,
                known_vendors_by_type,
                "ood_validation",
                known_vendor_keys_by_type,
            )
            ood_types.append(device_type)
            total_validation += written
            total_summarized += summarized
            per_type_stats[f"validation:{device_type}"] = {
                **load_stats,
                "ood_validation_rows": written,
                "summarized_rows": summarized,
            }
            del frame
    os.replace(validation_tmp, validation_jsonl)

    with open(combined_jsonl + ".tmp", "w", encoding="utf-8") as out:
        for shard_path in shard_paths:
            with open(shard_path, "r", encoding="utf-8") as shard:
                for line in shard:
                    out.write(line)
    os.replace(combined_jsonl + ".tmp", combined_jsonl)

    metadata = {
        "contract_version": CLASSIFICATION_CONTRACT_VERSION,
        "rag_device_types": known_types,
        "known_vendors_by_type": known_vendors_by_type,
        "training_vendors": sorted(training_vendors, key=str.casefold),
        "training_device_types": train_types,
        "ood_validation_types": ood_types,
        "known_vendor_source": (
            "platform_data/csv/label/label_<RAG_TYPE>.csv"
        ),
        "source_directory": os.path.relpath(IPRAW_DIR, BASE_PATH),
        "max_input_tokens": max_len,
        "answer_budget": ANSWER_BUDGET,
        "fingerprint_token_budget": fingerprint_budget,
        "long_fingerprint_strategy": "deepseek_summary",
        "summarizer": summarizer.contract,
        "training_sample_count": total_train,
        "pseudo_unseen_fraction": pseudo_unseen_fraction,
        "pseudo_unseen_vendor_fraction": pseudo_unseen_vendor_fraction,
        "pseudo_vendor_validation_fraction": (
            pseudo_vendor_validation_fraction
        ),
        "validation_sample_count": total_validation,
        "summarized_sample_count": total_summarized,
        "type_confidence_threshold": 0.5,
        "vendor_confidence_threshold": 0.5,
        "confidence_calibrated": False,
        "per_type_stats": per_type_stats,
    }
    with open(metadata_path + ".tmp", "w", encoding="utf-8") as out:
        json.dump(metadata, out, ensure_ascii=False, indent=2)
        out.write("\n")
        out.flush()
        os.fsync(out.fileno())
    os.replace(metadata_path + ".tmp", metadata_path)

    print(
        f"Prepared {total_train} train and {total_validation} validation "
        f"samples; DeepSeek-fitted {total_summarized} fingerprints."
    )
    print(
        f"DeepSeek calls={summarizer.n_calls}, "
        f"cache_hits={summarizer.n_cache_hits}, "
        f"hard_truncates={summarizer.n_hard_truncates}, "
        f"errors={summarizer.n_errors}"
    )


def _parse_args():
    p = argparse.ArgumentParser(
        description="Prepare RAG-IP type/vendor classification SFT data."
    )
    p.add_argument("--max_len", type=int, default=DEFAULT_MAX_LEN,
                   help=f"Full-sequence token budget (default {DEFAULT_MAX_LEN}). "
                        "Rows whose prompt exceeds this are LLM-summarized.")
    p.add_argument("--max_workers", type=int, default=32,
                   help="Concurrent summarization workers (default 32).")
    p.add_argument("--devices", type=str, default=None,
                   help="Comma-separated types available in platform_data/csv/rag.")
    p.add_argument("--limit", type=int, default=None,
                   help="Row limit per device (smoke test).")
    p.add_argument("--keep_existing", action="store_true",
                   help="Do not delete existing dataset outputs.")
    p.add_argument("--output_dir", type=str, default=OUTPUT_DIR,
                   help=f"Output directory (default {OUTPUT_DIR}).")
    p.add_argument(
        "--validation_fraction",
        type=float,
        default=DEFAULT_VALIDATION_FRACTION,
        help="Known-type validation fraction (default 0.05).",
    )
    p.add_argument(
        "--ood_validation_per_type",
        type=int,
        default=DEFAULT_OOD_VALIDATION_PER_TYPE,
        help="Maximum OOD validation rows per available type (default 500).",
    )
    p.add_argument(
        "--pseudo_unseen_fraction",
        type=float,
        default=DEFAULT_PSEUDO_UNSEEN_FRACTION,
        help="Extra pseudo-unseen training fraction per RAG type (default 0.25).",
    )
    p.add_argument(
        "--pseudo_unseen_vendor_fraction",
        type=float,
        default=DEFAULT_PSEUDO_UNSEEN_VENDOR_FRACTION,
        help="Extra pseudo-unseen vendor fraction per RAG type (default 0.25).",
    )
    p.add_argument(
        "--pseudo_vendor_validation_fraction",
        type=float,
        default=DEFAULT_PSEUDO_VENDOR_VALIDATION_FRACTION,
        help="Known-type pseudo-new-vendor validation fraction (default 0.25).",
    )
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    prepare_data(
        max_len=args.max_len,
        max_workers=args.max_workers,
        devices=args.devices.split(",") if args.devices else None,
        limit=args.limit,
        keep_existing=args.keep_existing,
        output_dir=args.output_dir,
        validation_fraction=args.validation_fraction,
        ood_validation_per_type=args.ood_validation_per_type,
        pseudo_unseen_fraction=args.pseudo_unseen_fraction,
        pseudo_unseen_vendor_fraction=args.pseudo_unseen_vendor_fraction,
        pseudo_vendor_validation_fraction=(
            args.pseudo_vendor_validation_fraction
        ),
    )
