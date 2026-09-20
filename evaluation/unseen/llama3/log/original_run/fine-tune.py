"""QLoRA fine-tuning for supervised IoT device type/vendor classification.

The adapter learns only the two labels available in the source data:

    {"device_type": "...", "device_vendor": "..."}

There is no synthetic seen/unseen or confidence target. At inference,
``agent/unseen.py`` derives confidence from generated-token probabilities and
decides novelty by comparing the predicted labels with the RAG type/vendor
contract saved alongside the adapter.

- H100-oriented bf16 4-bit NF4 QLoRA (r=8, attention projections only).
- Dynamic micro-batches: at most 32768 padded tokens and 2 samples.
- Four micro-batches are gradient-accumulated per optimizer step.
- FlashAttention 2 is preferred, with PyTorch SDPA fallback.
- Gradient checkpointing enabled
- Preparation, training, and inference share a 32768-token input budget.
- Only assistant label JSON tokens are supervised.
- Every original sample is retained; temperature-balanced replay is appended.
- Open-set thresholds use MEDIA_SERVER/VPN two-fold calibration and testing.

Input data: dataset/unseen_sft.jsonl produced by prepare_data.py, one JSON object
per line with keys {"instruction", "input", "output"}.
"""
import os
import sys
import glob
import json
import math
import re
import importlib.util
from dataclasses import dataclass
from collections import Counter, defaultdict
from typing import Any, Dict, List

import numpy as np
import torch
from torch.utils.data import DataLoader, Sampler
from datasets import concatenate_datasets, load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    PreTrainedTokenizerBase,
)

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."),
)
from util import (  # noqa: E402
    field_generation_confidences,
    match_known_unseen_type,
    match_known_unseen_vendor,
    normalize_unseen_label,
    normalize_unseen_vendor,
)

# ──────────────────────────── Paths ────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# MODEL_ID = os.path.join(SCRIPT_DIR, "..", "..", "..", "Meta-Llama-3.1-8B-Instruct")
MODEL_ID = "/home/nfs/models/Llama-3.1-8B-Instruct"
DATASET_DIR = os.path.join(SCRIPT_DIR, "dataset")
DATA_FILE = os.path.join(DATASET_DIR, "unseen_sft.jsonl")
VALIDATION_FILE = os.path.join(DATASET_DIR, "validation_sft.jsonl")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "results")
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
METADATA_FILENAME = "known_vendors.json"

MAX_LEN = 32768
TRAIN_EPOCHS = 1.0
TARGET_FIELDS = {"device_type", "device_vendor"}
FT_NUM_PROC = int(os.environ.get("FT_NUM_PROC", "32"))  # tokenization 并行进程数(改自 lambda 以支持缓存指纹+并行)


def resolve_h100_attention_backend():
    """Prefer FlashAttention 2 on H100, otherwise use PyTorch SDPA."""
    if importlib.util.find_spec("flash_attn") is not None:
        return "flash_attention_2"
    return "sdpa"


def build_temperature_replay_dataset(
    raw_dataset,
    replay_fraction=0.5,
    type_temperature=0.0,
    vendor_temperature=0.5,
    max_repeats=5,
    seed=42,
):
    """Keep every sample once, then append temperature-balanced replay."""
    if replay_fraction <= 0 or not len(raw_dataset):
        return raw_dataset, {
            "base_samples": len(raw_dataset),
            "replay_samples": 0,
        }
    if not 0 <= type_temperature <= 1:
        raise ValueError("type_temperature must be in [0, 1]")
    if not 0 <= vendor_temperature <= 1:
        raise ValueError("vendor_temperature must be in [0, 1]")
    if max_repeats < 1:
        raise ValueError("max_repeats must be >= 1")

    targets = [_parse_target(row["output"]) for row in raw_dataset]
    type_counts = Counter(target["device_type"] for target in targets)
    vendor_counts = Counter(
        (target["device_type"], target["device_vendor"])
        for target in targets
    )
    indices_by_type = defaultdict(list)
    for index, target in enumerate(targets):
        indices_by_type[target["device_type"]].append(index)

    replay_target = round(len(raw_dataset) * replay_fraction)
    type_names = sorted(type_counts)
    type_weights = np.array(
        [type_counts[name] ** type_temperature for name in type_names],
        dtype=np.float64,
    )
    type_weights /= type_weights.sum()
    rng = np.random.default_rng(seed)
    allocation = rng.multinomial(replay_target, type_weights)
    replay_indices = []
    replay_by_type = {}

    for type_name, requested in zip(type_names, allocation):
        candidates = indices_by_type[type_name]
        requested = min(requested, len(candidates) * max_repeats)
        if requested <= 0:
            continue
        candidate_weights = np.array(
            [
                vendor_counts[
                    (type_name, targets[index]["device_vendor"])
                ] ** (vendor_temperature - 1)
                for index in candidates
            ],
            dtype=np.float64,
        )
        candidate_weights /= candidate_weights.sum()
        repeats = Counter()
        selected = []
        attempts = 0
        while len(selected) < requested and attempts < 20:
            remaining = requested - len(selected)
            draws = rng.choice(
                candidates,
                size=max(remaining * 2, 64),
                replace=True,
                p=candidate_weights,
            )
            for index in draws:
                index = int(index)
                if repeats[index] >= max_repeats:
                    continue
                repeats[index] += 1
                selected.append(index)
                if len(selected) == requested:
                    break
            attempts += 1
        replay_indices.extend(selected)
        replay_by_type[type_name] = len(selected)

    replay = raw_dataset.select(replay_indices)
    combined = concatenate_datasets([raw_dataset, replay]).shuffle(seed=seed)
    return combined, {
        "base_samples": len(raw_dataset),
        "replay_samples": len(replay_indices),
        "replay_fraction": replay_fraction,
        "type_temperature": type_temperature,
        "vendor_temperature": vendor_temperature,
        "max_repeats": max_repeats,
        "replay_by_type": replay_by_type,
    }


# ──────────────────────────── Data helpers ────────────────────────────
def _parse_target(text: str) -> Dict[str, str]:
    """Parse and validate one two-label SFT target."""
    text = str(text).strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    target = json.loads(text.strip())
    if set(target) != TARGET_FIELDS:
        raise ValueError(
            f"SFT target fields must be {sorted(TARGET_FIELDS)}, got {sorted(target)}"
        )
    for field in TARGET_FIELDS:
        if not isinstance(target[field], str) or not target[field].strip():
            raise ValueError(f"SFT target field {field!r} must be a non-empty string")
    return target


def load_sft_dataset(data_file=None):
    """Load and validate type/vendor SFT JSONL produced by prepare_data.py."""
    data_file = data_file or DATA_FILE
    if not os.path.exists(data_file):
        # Backward-compat: allow sharded jsonl files unseen_sft_*.jsonl
        shards = sorted(glob.glob(os.path.join(DATASET_DIR, "unseen_sft*.jsonl")))
        if not shards:
            raise FileNotFoundError(
                f"No unseen SFT data found. Run prepare_data.py to create {data_file}."
            )
        ds = load_dataset("json", data_files=shards, split="train")
    else:
        ds = load_dataset("json", data_files=data_file, split="train")
    for index, row in enumerate(ds):
        try:
            _parse_target(row["output"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError(f"Invalid SFT target at row {index}: {exc}") from exc
    print(f"  Total training samples: {len(ds)}")
    return ds


def format_and_tokenize(examples, tokenizer, max_length=MAX_LEN):
    """
    Build a Llama-3.1 chat sequence and supervise only the assistant's
    device_type/device_vendor JSON. Standard causal cross-entropy therefore
    directly trains the two label strings; confidence has no training target.
    """
    all_input_ids, all_attn, all_labels = [], [], []
    batch_size = len(examples["output"])

    for i in range(batch_size):
        system = examples["instruction"][i]
        user = examples["input"][i]
        answer = examples["output"][i]

        # Prompt portion (system + user) via chat template, generation prompt on.
        prompt_ids = tokenizer.apply_chat_template(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tokenize=True,
            add_generation_prompt=True,
        )
        # Answer portion (assistant content) + eos
        answer_ids = tokenizer(answer, add_special_tokens=False)["input_ids"]
        answer_ids = answer_ids + [tokenizer.eos_token_id]

        # prepare_data.py pre-compresses long fingerprints. Keep the complete label
        # target and right-truncate only the prompt as a final safety net.
        prompt_budget = max_length - len(answer_ids)
        if prompt_budget < 1:
            prompt_budget = max(1, max_length // 8)
        if len(prompt_ids) > prompt_budget:
            prompt_ids = prompt_ids[:prompt_budget]

        input_ids = prompt_ids + answer_ids
        # Supervise only the answer tokens
        labels = [-100] * len(prompt_ids) + answer_ids
        attn = [1] * len(input_ids)

        all_input_ids.append(input_ids)
        all_attn.append(attn)
        all_labels.append(labels)

    return {
        "input_ids": all_input_ids,
        "attention_mask": all_attn,
        "labels": all_labels,
        "length": [len(input_ids) for input_ids in all_input_ids],
    }


def preprocess_logits_for_metrics(logits, labels):
    if isinstance(logits, tuple):
        logits = logits[0]
    return logits.argmax(dim=-1)


def compute_label_metrics(eval_prediction):
    predictions, labels = eval_prediction
    predictions = predictions[:, :-1]
    labels = labels[:, 1:]
    mask = labels != -100
    correct = (predictions == labels) & mask
    token_total = int(mask.sum())
    token_accuracy = (
        float(correct.sum() / token_total) if token_total else 0.0
    )
    sequence_matches = []
    for predicted_row, label_row, row_mask in zip(
        predictions, labels, mask
    ):
        if not row_mask.any():
            continue
        sequence_matches.append(
            bool(np.array_equal(
                predicted_row[row_mask],
                label_row[row_mask],
            ))
        )
    return {
        "label_token_accuracy": token_accuracy,
        "label_exact_match": (
            float(np.mean(sequence_matches)) if sequence_matches else 0.0
        ),
    }


def _parse_generated_labels(text):
    match = re.search(r"\{[^{}]*\"device_type\"[^{}]*\}", text, re.DOTALL)
    if match is None:
        return {}
    try:
        return json.loads(match.group())
    except json.JSONDecodeError:
        return {}


@torch.inference_mode()
def _generate_labels_with_confidence(
    model,
    tokenizer,
    instruction,
    prompt,
    max_length,
):
    input_text = tokenizer.apply_chat_template(
        [
            {"role": "system", "content": instruction},
            {"role": "user", "content": prompt},
        ],
        tokenize=False,
        add_generation_prompt=True,
    )
    inputs = tokenizer(
        input_text,
        return_tensors="pt",
        truncation=True,
        max_length=max_length,
    ).to(model.device)
    outputs = model.generate(
        **inputs,
        max_new_tokens=256,
        do_sample=False,
        repetition_penalty=1.05,
        pad_token_id=tokenizer.pad_token_id,
        return_dict_in_generate=True,
        output_scores=True,
    )
    generated_ids = outputs.sequences[
        0, inputs["input_ids"].shape[-1]:
    ].tolist()
    text = tokenizer.decode(
        generated_ids,
        skip_special_tokens=True,
        clean_up_tokenization_spaces=False,
    )
    token_log_probs = [
        float(torch.log_softmax(score[0].float(), dim=-1)[token_id].item())
        for score, token_id in zip(outputs.scores, generated_ids)
    ]
    return (
        _parse_generated_labels(text),
        field_generation_confidences(
            tokenizer,
            text,
            generated_ids,
            token_log_probs,
        ),
    )


def _binary_novelty_metrics(samples, threshold):
    true_positive = false_positive = true_negative = false_negative = 0
    for score, is_new in samples:
        predicted_new = score > threshold
        if predicted_new and is_new:
            true_positive += 1
        elif predicted_new:
            false_positive += 1
        elif is_new:
            false_negative += 1
        else:
            true_negative += 1
    precision = (
        true_positive / (true_positive + false_positive)
        if true_positive + false_positive else 0.0
    )
    recall = (
        true_positive / (true_positive + false_negative)
        if true_positive + false_negative else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )
    total = len(samples)
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": (
            (true_positive + true_negative) / total if total else 0.0
        ),
        "tp": true_positive,
        "fp": false_positive,
        "tn": true_negative,
        "fn": false_negative,
    }


def _select_novelty_threshold(samples):
    if not samples:
        return 0.5
    candidates = []
    for step in range(5, 96):
        threshold = step / 100
        metrics = _binary_novelty_metrics(samples, threshold)
        candidates.append((
            metrics["f1"],
            metrics["accuracy"],
            -abs(threshold - 0.5),
            threshold,
        ))
    return max(candidates)[-1]


def cross_validate_open_set_thresholds(
    model,
    tokenizer,
    raw_eval_dataset,
    known_types,
    known_vendors_by_type,
    max_length,
    samples_per_group,
):
    groups = {
        "known": [],
        "MEDIA_SERVER": [],
        "VPN": [],
        "pseudo_vendor": [],
    }
    for index, row in enumerate(raw_eval_dataset):
        target = _parse_target(row["output"])
        origin = (row.get("metadata") or {}).get("split_origin")
        if origin == "known_validation":
            groups["known"].append(index)
        elif origin == "pseudo_unseen_vendor_validation":
            groups["pseudo_vendor"].append(index)
        elif target["device_type"] in ("MEDIA_SERVER", "VPN"):
            groups[target["device_type"]].append(index)

    type_group_size = min(
        samples_per_group,
        len(groups["known"]) // 2,
        len(groups["MEDIA_SERVER"]),
        len(groups["VPN"]),
    )
    vendor_group_size = min(
        samples_per_group,
        len(groups["known"]) // 2,
        len(groups["pseudo_vendor"]) // 2,
    )
    if type_group_size < 1:
        raise ValueError(
            "Cross-validation requires known, MEDIA_SERVER, and VPN samples"
        )
    if vendor_group_size < 1:
        raise ValueError(
            "Vendor calibration requires known and pseudo-new-vendor samples"
        )
    rng = np.random.default_rng(42)
    known_type_indices = rng.choice(
        groups["known"],
        size=type_group_size * 2,
        replace=False,
    ).tolist()
    known_vendor_indices = rng.choice(
        groups["known"],
        size=vendor_group_size * 2,
        replace=False,
    ).tolist()
    pseudo_vendor_indices = rng.choice(
        groups["pseudo_vendor"],
        size=vendor_group_size * 2,
        replace=False,
    ).tolist()
    media_indices = rng.choice(
        groups["MEDIA_SERVER"],
        size=type_group_size,
        replace=False,
    ).tolist()
    vpn_indices = rng.choice(
        groups["VPN"],
        size=type_group_size,
        replace=False,
    ).tolist()
    selected_indices = sorted(set(
        known_type_indices
        + known_vendor_indices
        + pseudo_vendor_indices
        + media_indices
        + vpn_indices
    ))

    predictions = {}
    for index in selected_indices:
        row = raw_eval_dataset[index]
        target = _parse_target(row["output"])
        predicted, confidence = _generate_labels_with_confidence(
            model,
            tokenizer,
            row["instruction"],
            row["input"],
            max_length,
        )
        metadata = row.get("metadata") or {}
        matched_type = match_known_unseen_type(
            predicted.get("device_type"),
            known_types,
        )
        matched_vendor = match_known_unseen_vendor(
            predicted.get("device_vendor"),
            matched_type,
            known_vendors_by_type,
        )
        predictions[index] = {
            "type_score": (
                float(confidence.get("device_type", 0.0))
                if matched_type is None else 0.0
            ),
            "vendor_score": (
                float(confidence.get("device_vendor", 0.0))
                if matched_vendor is None else 0.0
            ),
            "is_new_type": bool(metadata.get("is_new_type")),
            "is_new_vendor": bool(metadata.get("is_new_vendor")),
            "type_exact": (
                normalize_unseen_label(predicted.get("device_type"))
                == normalize_unseen_label(target["device_type"])
            ),
            "vendor_exact": (
                normalize_unseen_vendor(predicted.get("device_vendor"))
                == normalize_unseen_vendor(target["device_vendor"])
            ),
        }

    folds = [
        {
            "name": "MEDIA_SERVER_calibration__VPN_test",
            "type_calibration": (
                known_type_indices[:type_group_size] + media_indices
            ),
            "type_test": (
                known_type_indices[type_group_size:] + vpn_indices
            ),
            "vendor_calibration": (
                known_vendor_indices[:vendor_group_size]
                + pseudo_vendor_indices[:vendor_group_size]
            ),
            "vendor_test": (
                known_vendor_indices[vendor_group_size:]
                + pseudo_vendor_indices[vendor_group_size:]
            ),
        },
        {
            "name": "VPN_calibration__MEDIA_SERVER_test",
            "type_calibration": (
                known_type_indices[type_group_size:] + vpn_indices
            ),
            "type_test": (
                known_type_indices[:type_group_size] + media_indices
            ),
            "vendor_calibration": (
                known_vendor_indices[vendor_group_size:]
                + pseudo_vendor_indices[vendor_group_size:]
            ),
            "vendor_test": (
                known_vendor_indices[:vendor_group_size]
                + pseudo_vendor_indices[:vendor_group_size]
            ),
        },
    ]
    fold_results = []
    for fold in folds:
        type_calibration = [
            (
                predictions[index]["type_score"],
                predictions[index]["is_new_type"],
            )
            for index in fold["type_calibration"]
        ]
        vendor_calibration = [
            (
                predictions[index]["vendor_score"],
                predictions[index]["is_new_vendor"],
            )
            for index in fold["vendor_calibration"]
        ]
        type_threshold = _select_novelty_threshold(type_calibration)
        vendor_threshold = _select_novelty_threshold(vendor_calibration)
        type_test = [
            (
                predictions[index]["type_score"],
                predictions[index]["is_new_type"],
            )
            for index in fold["type_test"]
        ]
        vendor_test = [
            (
                predictions[index]["vendor_score"],
                predictions[index]["is_new_vendor"],
            )
            for index in fold["vendor_test"]
        ]
        fold_results.append({
            "name": fold["name"],
            "type_threshold": type_threshold,
            "vendor_threshold": vendor_threshold,
            "type_test": _binary_novelty_metrics(
                type_test, type_threshold
            ),
            "vendor_test": _binary_novelty_metrics(
                vendor_test, vendor_threshold
            ),
            "type_exact_accuracy": float(np.mean([
                predictions[index]["type_exact"]
                for index in fold["type_test"]
            ])),
            "vendor_exact_accuracy": float(np.mean([
                predictions[index]["vendor_exact"]
                for index in fold["vendor_test"]
            ])),
        })

    averaged_type_threshold = float(np.mean([
        fold["type_threshold"] for fold in fold_results
    ]))
    averaged_vendor_threshold = float(np.mean([
        fold["vendor_threshold"] for fold in fold_results
    ]))
    average_test_metrics = {}
    for field in ("type_test", "vendor_test"):
        average_test_metrics[field] = {
            metric: float(np.mean([
                fold[field][metric] for fold in fold_results
            ]))
            for metric in ("precision", "recall", "f1", "accuracy")
        }
    average_test_metrics["type_exact_accuracy"] = float(np.mean([
        fold["type_exact_accuracy"] for fold in fold_results
    ]))
    average_test_metrics["vendor_exact_accuracy"] = float(np.mean([
        fold["vendor_exact_accuracy"] for fold in fold_results
    ]))
    return {
        "type_confidence_threshold": averaged_type_threshold,
        "vendor_confidence_threshold": averaged_vendor_threshold,
        "confidence_calibrated": True,
        "calibration_strategy": (
            "type_MEDIA_SERVER_VPN_cross__vendor_pseudo_cross"
        ),
        "samples_per_group": {
            "type": type_group_size,
            "vendor": vendor_group_size,
        },
        "generated_validation_samples": len(selected_indices),
        "pseudo_new_vendor_examples": len(groups["pseudo_vendor"]),
        "folds": fold_results,
        "average_test_metrics": average_test_metrics,
    }


def evaluate_release_gates(
    calibration,
    min_type_f1,
    min_vendor_f1,
    min_type_exact_accuracy,
    min_vendor_exact_accuracy,
):
    metrics = calibration["average_test_metrics"]
    checks = {
        "type_novelty_f1": {
            "actual": metrics["type_test"]["f1"],
            "minimum": min_type_f1,
        },
        "vendor_novelty_f1": {
            "actual": metrics["vendor_test"]["f1"],
            "minimum": min_vendor_f1,
        },
        "type_exact_accuracy": {
            "actual": metrics["type_exact_accuracy"],
            "minimum": min_type_exact_accuracy,
        },
        "vendor_exact_accuracy": {
            "actual": metrics["vendor_exact_accuracy"],
            "minimum": min_vendor_exact_accuracy,
        },
    }
    for check in checks.values():
        check["passed"] = check["actual"] >= check["minimum"]
    return {
        "passed": all(check["passed"] for check in checks.values()),
        "checks": checks,
    }


# ──────────────────────────── Collator ────────────────────────────
@dataclass
class CausalPaddingCollator:
    """Pad input_ids / attention_mask / labels to the longest sequence in the batch."""
    tokenizer: PreTrainedTokenizerBase

    def __call__(self, features: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        max_len = max(len(f["input_ids"]) for f in features)
        input_ids, attn, labels = [], [], []
        for f in features:
            pad = max_len - len(f["input_ids"])
            input_ids.append(f["input_ids"] + [self.tokenizer.pad_token_id] * pad)
            attn.append(f["attention_mask"] + [0] * pad)
            labels.append(f["labels"] + [-100] * pad)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attn, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
        }


class TokenBudgetBatchSampler(Sampler):
    """Length-bucketed batches bounded by padded tokens and sample count."""

    def __init__(
        self,
        lengths,
        max_tokens,
        max_samples,
        rank=0,
        world_size=1,
        seed=42,
        drop_last=True,
    ):
        self.lengths = [int(length) for length in lengths]
        self.max_tokens = int(max_tokens)
        self.max_samples = int(max_samples)
        self.rank = int(rank)
        self.world_size = int(world_size)
        self.seed = int(seed)
        self.drop_last = bool(drop_last)
        self.epoch = 0
        if self.max_tokens < 1 or self.max_samples < 1:
            raise ValueError("Dynamic batch limits must be positive")
        self._rank_batches = self._build_rank_batches()

    def _build_global_batches(self):
        ordered = sorted(
            range(len(self.lengths)),
            key=self.lengths.__getitem__,
        )
        batches = []
        current = []
        current_max = 0
        for index in ordered:
            length = self.lengths[index]
            candidate_max = max(current_max, length)
            candidate_count = len(current) + 1
            padded_tokens = candidate_max * candidate_count
            if current and (
                candidate_count > self.max_samples
                or padded_tokens > self.max_tokens
            ):
                batches.append(current)
                current = []
                current_max = 0
            current.append(index)
            current_max = max(current_max, length)
        if current:
            batches.append(current)
        rng = np.random.default_rng(self.seed + self.epoch)
        rng.shuffle(batches)
        return batches

    def _build_rank_batches(self):
        batches = self._build_global_batches()
        if self.world_size > 1:
            remainder = len(batches) % self.world_size
            if remainder:
                if self.drop_last:
                    batches = batches[:-remainder]
                else:
                    batches.extend(batches[:self.world_size - remainder])
            batches = batches[self.rank::self.world_size]
        return batches

    def set_epoch(self, epoch):
        self.epoch = int(epoch)
        self._rank_batches = self._build_rank_batches()

    def __iter__(self):
        return iter(self._rank_batches)

    def __len__(self):
        return len(self._rank_batches)

    @property
    def stats(self):
        sample_counts = [len(batch) for batch in self._rank_batches]
        padded_tokens = [
            max(self.lengths[index] for index in batch) * len(batch)
            for batch in self._rank_batches
        ]
        return {
            "micro_batches": len(self._rank_batches),
            "single_sample_batches": sum(count == 1 for count in sample_counts),
            "multi_sample_batches": sum(count > 1 for count in sample_counts),
            "max_padded_tokens": max(padded_tokens, default=0),
            "mean_padded_tokens": (
                float(np.mean(padded_tokens)) if padded_tokens else 0.0
            ),
        }


class DynamicTokenBatchTrainer(Trainer):
    def __init__(
        self,
        *args,
        max_tokens_per_batch,
        max_samples_per_batch,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.max_tokens_per_batch = max_tokens_per_batch
        self.max_samples_per_batch = max_samples_per_batch
        self.token_batch_sampler = None
        # 自定义变长 batch sampler: 关闭 accelerate 的 even_batches 填充(它要求固定batch_size)
        if getattr(self, "accelerator", None) is not None:
            self.accelerator.even_batches = False

    def get_train_dataloader(self):
        if self.train_dataset is None:
            raise ValueError("Trainer requires a train_dataset")
        lengths = self.train_dataset["length"]
        self.token_batch_sampler = TokenBudgetBatchSampler(
            lengths,
            max_tokens=self.max_tokens_per_batch,
            max_samples=self.max_samples_per_batch,
            # Accelerate shards the prepared batch sampler across DDP ranks.
            rank=0,
            world_size=1,
            seed=self.args.data_seed or self.args.seed,
            drop_last=self.args.dataloader_drop_last,
        )
        dataloader = DataLoader(
            self.train_dataset,
            batch_sampler=self.token_batch_sampler,
            collate_fn=self.data_collator,
            num_workers=self.args.dataloader_num_workers,
            pin_memory=self.args.dataloader_pin_memory,
            persistent_workers=(
                self.args.dataloader_persistent_workers
                and self.args.dataloader_num_workers > 0
            ),
        )
        self.accelerator.even_batches = False
        return self.accelerator.prepare(dataloader)


# ──────────────────────────── Distributed helpers ────────────────────────────
def _is_distributed() -> bool:
    """True when launched under torchrun / accelerate (WORLD_SIZE > 1)."""
    return int(os.environ.get("WORLD_SIZE", "1")) > 1


def _local_rank() -> int:
    return int(os.environ.get("LOCAL_RANK", "0"))


def _parse_args():
    import argparse

    p = argparse.ArgumentParser(
        description="QLoRA fine-tune Llama-3.1-8B-Instruct for type/vendor classification"
    )
    # ── Parallel training switch (DEFAULT OFF) ──
    # Enable multi-GPU DDP. Must be launched with:
    #   torchrun --nproc_per_node=<N> fine-tune.py --parallel
    p.add_argument(
        "--parallel",
        action="store_true",
        help="Enable multi-GPU DDP training (launch via torchrun --nproc_per_node=N). "
        "Default OFF.",
    )
    p.add_argument(
        "--max_len",
        type=int,
        default=MAX_LEN,
        help=f"Max sequence length in tokens (default {MAX_LEN}); keep it aligned "
             "with prepare_data.py and agent/unseen.py.",
    )
    p.add_argument(
        "--max_train_samples",
        type=int,
        default=None,
        help="Limit #training samples (smoke test).",
    )
    p.add_argument(
        "--output_dir",
        type=str,
        default=None,
        help=f"Output dir (default {OUTPUT_DIR}).",
    )
    p.add_argument(
        "--data_file",
        type=str,
        default=None,
        help=f"SFT JSONL (default {DATA_FILE}).",
    )
    p.add_argument(
        "--validation_file",
        type=str,
        default=None,
        help=f"Validation JSONL (default {VALIDATION_FILE}).",
    )
    p.add_argument(
        "--open_set_samples_per_group",
        type=int,
        default=200,
        help="Known/MEDIA_SERVER/VPN samples per cross-validation group.",
    )
    p.add_argument("--replay_fraction", type=float, default=0.5)
    p.add_argument("--type_temperature", type=float, default=0.0)
    p.add_argument("--vendor_temperature", type=float, default=0.5)
    p.add_argument("--max_replays_per_sample", type=int, default=5)
    p.add_argument("--learning_rate", type=float, default=5e-5)
    p.add_argument("--max_tokens_per_batch", type=int, default=32768)
    p.add_argument("--max_samples_per_batch", type=int, default=2)
    p.add_argument("--gradient_accumulation_steps", type=int, default=4)
    p.add_argument("--min_type_novelty_f1", type=float, default=0.80)
    p.add_argument("--min_vendor_novelty_f1", type=float, default=0.80)
    p.add_argument("--min_type_exact_accuracy", type=float, default=0.50)
    p.add_argument("--min_vendor_exact_accuracy", type=float, default=0.50)
    return p.parse_args()


# ──────────────────────────── Main ────────────────────────────
def run_training(args=None):
    """
    Run QLoRA fine-tuning of Llama-3.1-8B-Instruct for unseen-device detection.

    Single-GPU (default, switch OFF):
        python fine-tune.py
    Multi-GPU DDP (switch ON, one model replica per GPU, gradients synced):
        torchrun --nproc_per_node=<N> fine-tune.py --parallel

    Args:
        args: argparse.Namespace. If None, parsed from sys.argv.
              `parallel=True` selects the multi-GPU DDP path (each process pins
              its model to LOCAL_RANK).
    """
    if args is None:
        args = _parse_args()

    distributed = _is_distributed()
    local_rank = _local_rank()
    world_size = int(os.environ.get("WORLD_SIZE", "1"))
    is_main = (not distributed) or (local_rank == 0)

    if distributed:
        torch.cuda.set_device(local_rank)
        if is_main:
            print(f"[DDP] world_size={world_size}: one replica per GPU, "
                  f"gradients AllReduce-synced. Effective batch = {1 * 8 * world_size}.")

    if args.parallel and not distributed:
        print("WARNING: --parallel set but not launched under torchrun; "
              "running single-GPU (device_map='auto').")

    # ── Tokenizer ──
    if is_main:
        print("Loading tokenizer …")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    tokenizer.truncation_side = "right"
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # ── Dataset ──
    if is_main:
        print("Loading dataset …")
    data_file = args.data_file or DATA_FILE
    metadata_file = os.path.join(
        os.path.dirname(os.path.abspath(data_file)), METADATA_FILENAME
    )
    if not os.path.exists(metadata_file):
        raise FileNotFoundError(
            f"Missing classification metadata {metadata_file}; run prepare_data.py first."
        )
    raw_ds = load_sft_dataset(data_file)
    validation_file = args.validation_file or VALIDATION_FILE
    if not os.path.exists(validation_file):
        raise FileNotFoundError(
            f"Missing validation data {validation_file}; run prepare_data.py first."
        )
    raw_eval_ds = load_sft_dataset(validation_file)
    if args.max_train_samples is not None:  # smoke test
        raw_ds = raw_ds.select(range(min(args.max_train_samples, len(raw_ds))))
        if is_main:
            print(f"  [SMOKE TEST] using only {len(raw_ds)} samples")
    raw_ds, replay_stats = build_temperature_replay_dataset(
        raw_ds,
        replay_fraction=args.replay_fraction,
        type_temperature=args.type_temperature,
        vendor_temperature=args.vendor_temperature,
        max_repeats=args.max_replays_per_sample,
    )
    if is_main:
        print(f"  Temperature replay: {replay_stats}")
    all_cols = raw_ds.column_names
    max_len = getattr(args, "max_len", None) or MAX_LEN
    dataset = raw_ds.map(
        format_and_tokenize,
        fn_kwargs={"tokenizer": tokenizer, "max_length": max_len},
        batched=True,
        batch_size=256,
        num_proc=FT_NUM_PROC,
        remove_columns=all_cols,
        desc=f"Formatting + tokenizing (rank {local_rank})",
    )
    if is_main:
        print(f"  Tokenized dataset: {len(dataset)} samples")
    eval_dataset = raw_eval_ds.map(
        format_and_tokenize,
        fn_kwargs={"tokenizer": tokenizer, "max_length": max_len},
        batched=True,
        batch_size=256,
        num_proc=FT_NUM_PROC,
        remove_columns=raw_eval_ds.column_names,
        desc=f"Formatting + tokenizing validation (rank {local_rank})",
    )

    # ── QLoRA 4-bit quantization ──
    if is_main:
        print("Loading model with 4-bit quantization …")
    attention_backend = resolve_h100_attention_backend()
    if is_main:
        print(f"  H100 attention backend: {attention_backend}")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
    )
    # DDP: pin the WHOLE model to this process's GPU (device_map="auto" would
    # shard one model across all GPUs and break data-parallel gradient sync).
    device_map = {"": local_rank} if distributed else "auto"
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        quantization_config=bnb_config,
        device_map=device_map,
        torch_dtype=torch.bfloat16,
        attn_implementation=attention_backend,
    )
    model.config.use_cache = False  # required with gradient checkpointing
    model = prepare_model_for_kbit_training(model)

    # ── LoRA adapters ──
    lora_config = LoraConfig(
        r=8,
        lora_alpha=8,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        lora_dropout=0.10,
        bias="none",
        task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora_config)
    # Ensure inputs require grad so backprop reaches the frozen k-bit base
    # under gradient checkpointing.
    model.enable_input_require_grads()
    if is_main:
        model.print_trainable_parameters()

    # ── Training arguments ──
    output_dir = args.output_dir or OUTPUT_DIR
    training_args = TrainingArguments(
        output_dir=output_dir,
        num_train_epochs=TRAIN_EPOCHS,
        # This is the maximum sample count; the custom batch sampler may emit 1.
        per_device_train_batch_size=args.max_samples_per_batch,
        per_device_eval_batch_size=1,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        learning_rate=args.learning_rate,
        bf16=True,
        fp16=False,
        tf32=True,
        logging_dir=LOG_DIR,
        logging_steps=10,
        save_strategy="steps",
        save_steps=5000,
        save_total_limit=1,
        eval_strategy="epoch",
        optim="paged_adamw_8bit",
        report_to="none",
        group_by_length=False,
        include_tokens_per_second=True,
        # DDP: keep gradient sync correct for attention-projection LoRA. If a
        # "Expected to have finished reduction" error appears, flip to True.
        ddp_find_unused_parameters=False if distributed else None,
        dataloader_drop_last=True,
    )

    # ── Trainer ──
    trainer = DynamicTokenBatchTrainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        eval_dataset=eval_dataset,
        data_collator=CausalPaddingCollator(tokenizer=tokenizer),
        compute_metrics=compute_label_metrics,
        preprocess_logits_for_metrics=preprocess_logits_for_metrics,
        max_tokens_per_batch=args.max_tokens_per_batch,
        max_samples_per_batch=args.max_samples_per_batch,
    )
    micro_batches_per_rank = len(trainer.get_train_dataloader())
    token_batch_stats = trainer.token_batch_sampler.stats
    optimizer_steps_per_epoch = math.ceil(
        micro_batches_per_rank
        / training_args.gradient_accumulation_steps
    )
    training_plan = {
        "epochs": TRAIN_EPOCHS,
        "world_size": world_size,
        "dataset_samples": len(dataset),
        "micro_batches_per_rank_per_epoch": micro_batches_per_rank,
        "gradient_accumulation_steps": (
            training_args.gradient_accumulation_steps
        ),
        "micro_batch_samples": {
            "min": 1,
            "max": args.max_samples_per_batch,
        },
        "max_tokens_per_micro_batch": args.max_tokens_per_batch,
        "max_tokens_per_optimizer_step": (
            args.max_tokens_per_batch
            * training_args.gradient_accumulation_steps
            * world_size
        ),
        "optimizer_steps_per_epoch": optimizer_steps_per_epoch,
        "estimated_total_optimizer_steps": math.ceil(
            optimizer_steps_per_epoch * TRAIN_EPOCHS
        ),
        "length_bucketed": True,
        "token_batch_stats": token_batch_stats,
        "attention_backend": attention_backend,
        "compute_dtype": "bfloat16",
    }
    if is_main:
        print(f"Training plan: {training_plan}")

    if is_main:
        print("Starting training …")
    trainer.train()

    # ── Save final LoRA adapter + tokenizer (rank 0 only) ──
    if is_main:
        with open(metadata_file, "r", encoding="utf-8") as file:
            metadata = json.load(file)
        metadata["temperature_replay"] = replay_stats
        metadata["training_plan"] = training_plan
        metadata["lora_training_config"] = {
            "r": 8,
            "alpha": 8,
            "dropout": 0.10,
            "target_modules": [
                "q_proj", "k_proj", "v_proj", "o_proj"
            ],
            "learning_rate": args.learning_rate,
            "attention_backend": attention_backend,
            "compute_dtype": "bfloat16",
            "max_tokens_per_batch": args.max_tokens_per_batch,
            "max_samples_per_batch": args.max_samples_per_batch,
            "gradient_accumulation_steps": (
                args.gradient_accumulation_steps
            ),
        }
        if args.open_set_samples_per_group <= 0:
            raise ValueError(
                "open_set_samples_per_group must be positive for release gating"
            )
        old_use_cache = trainer.model.config.use_cache
        trainer.model.config.use_cache = True
        trainer.model.eval()
        try:
            calibration = cross_validate_open_set_thresholds(
                trainer.model,
                tokenizer,
                raw_eval_ds,
                metadata["rag_device_types"],
                metadata["known_vendors_by_type"],
                max_len,
                args.open_set_samples_per_group,
            )
        finally:
            trainer.model.config.use_cache = old_use_cache
        metadata.update(calibration)
        release_gate = evaluate_release_gates(
            calibration,
            min_type_f1=args.min_type_novelty_f1,
            min_vendor_f1=args.min_vendor_novelty_f1,
            min_type_exact_accuracy=args.min_type_exact_accuracy,
            min_vendor_exact_accuracy=args.min_vendor_exact_accuracy,
        )
        metadata["release_gate"] = release_gate
        report_path = os.path.join(output_dir, "release_gate_report.json")
        with open(report_path, "w", encoding="utf-8") as file:
            json.dump(
                {
                    "calibration": calibration,
                    "release_gate": release_gate,
                },
                file,
                ensure_ascii=False,
                indent=2,
            )
            file.write("\n")
        print(f"Confidence calibration: {calibration}")
        print(f"Release gate: {release_gate}")
        if not release_gate["passed"]:
            raise RuntimeError(
                f"Release gate failed; see {report_path}"
            )

        save_path = os.path.join(output_dir, "final_model")
        trainer.save_model(save_path)
        tokenizer.save_pretrained(save_path)
        with open(
            os.path.join(save_path, METADATA_FILENAME),
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(metadata, file, ensure_ascii=False, indent=2)
            file.write("\n")
        print(f"Training complete. Adapter saved to {save_path}")
        print("Use it with: UnseenDeviceDetector(adapter_path=..., load_in_4bit=True)")


# Back-compat alias.
main = run_training


if __name__ == "__main__":
    run_training()
