"""
Data preparation for LLaMA-3.1-8B *unseen-device-detection* fine-tuning (Method B).

Train/inference prompt alignment ("Method B")
--------------------------------------------
Uses util.build_unseen_detection_prompt — the SAME prompt builder that
agent/unseen.py uses for the fine-tuned-adapter inference path — so the adapter
sees a byte-identical instruction at train and inference time. (The base-model
zero-shot path in agent/unseen.py keeps its richer prompt.)

Feature selection (info columns only)
-------------------------------------
Only the per-perspective "info" columns (util.UNSEEN_INFO_COLS) are placed in the
fingerprint. Raw vendor/product/version sub-columns are dropped (e.g.
hw-vendors/hw-products/hw-versions excluded, only hw-info kept; http-bodys /
http-tags / http-part-info excluded, only http-info kept).

Length control — enlarged window + GLM-5.2 compression of outliers
-------------------------------------------------------------------
MAX_LEN (default 32768; analyzed from the empirical full-IP-row distribution)
replaces the old hard 2048 cut. The full chat prompt (system + user + answer) is
sized with the Llama-3.1 tokenizer; rows that still exceed MAX_LEN have their
fingerprint compressed with GLM-5.2 (llm_config.json -> BIGMODEL, reasoning_effort
= max) into a per-perspective keyword summary that fits the remaining budget,
preserving the "col: value" structure. LLM calls run concurrently (--max_workers)
and the reasoning model is handled with a generous max_tokens (retried once if it
returns empty content). A hard token-truncate is the final safety net, and
fine-tune.py right-truncates any residual overflow.

Caching / resume safety
-----------------------
Every summary is appended immediately (thread-safe) to
    data_summary_cache/summary_cache.jsonl   (key = sha256 of model + original
fingerprint text, so switching summarizers never reuses stale summaries). SFT data
is written per-device as
    dataset/unseen_sft_<DEV>.jsonl          (flushed per sample)
so a quota exhaustion or kill NEVER loses paid-for work: completed devices stay
intact, the partial device is rewritten on resume, and all LLM calls hit the
cache. A combined dataset/unseen_sft.jsonl is produced at the end.

Usage:
    python prepare_data.py [--max_len 32768] [--max_workers 32]
                            [--devices NAS,ROUTER,...] [--limit N] [--keep_existing]
Outputs (evaluation/unseen/llama3/dataset/):
    finetune_data_<DEV>.csv        filtered source (ip + info cols + vendor[ + is_new_vendor])
    unseen_sft_<DEV>.jsonl         per-device SFT shard (resumable)
    unseen_sft.jsonl               combined SFT file (what fine-tune.py consumes)
    ../data_summary_cache/summary_cache.jsonl   GLM-5.2 summary cache (resume-safe,
                                               model-keyed; shared across runs)
"""
import os
import sys
import glob
import json
import time
import hashlib
import logging
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
from util import (  # noqa: E402
    load_all_dev_labels,
    load_new_dev_labels,
    UNSEEN_INFO_COLS,
    UNSEEN_SYSTEM,
    build_fingerprint_info_text,
    build_unseen_detection_prompt,
)

BASE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..")
IPRAW_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "all")
LABEL_DIR = os.path.join(BASE_PATH, "platform_data", "csv", "label")
LLAMA_MODEL_PATH = os.path.join(BASE_PATH, "Meta-Llama-3.1-8B-Instruct")
LLM_CFG_PATH = os.path.join(BASE_PATH, "llm_config.json")

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
COMBINED_JSONL = os.path.join(OUTPUT_DIR, "unseen_sft.jsonl")
# Summary cache lives in its OWN directory (persists across runs/smokes; entries are
# keyed by model+fingerprint so it is safe to share between smokes and the full run).
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data_summary_cache")
CACHE_PATH = os.path.join(CACHE_DIR, "summary_cache.jsonl")

ANSWER_BUDGET = 220       # tokens reserved for the assistant JSON answer (safety)
CHAR_PER_TOKEN = 3.0      # conservative pre-filter ratio (Llama-3 on this content)
# Chosen from the empirical full-distribution analysis (see analyze_len): at 32768,
# 98.4% of rows fit unchanged and only 6,913 (1.6%) need GLM summarization,
# while staying fine-tune-feasible on a 32GB V100 (8B 4-bit QLoRA, ~13GB) and within
# Llama-3.1-8B-Instruct's native 128k context.
DEFAULT_MAX_LEN = 32768

# Summarization LLM: GLM-5.2 via BIGMODEL (llm_config.json), reasoning cranked to max.
LLM_PROVIDER = "BIGMODEL"
LLM_REASONING_EFFORT = "max"

_P_NEW, _P_KNOWN = 0.92, 0.05
_NONE = "none"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "prepare_data.log"),
    filemode="a",
)
log = logging.getLogger("prepare_data")


# ═════════════════════════════════════════════════════════════════════════════
# Fingerprint summarizer — GLM-5.2 (cached, concurrent, resume-safe)
# ═════════════════════════════════════════════════════════════════════════════
class FingerprintSummarizer:
    """Compress over-long fingerprints with an LLM (default GLM-5.2 via BIGMODEL,
    reasoning_effort=max), caching every call and running concurrently."""

    def __init__(self, cfg_path, cache_path, fp_token_budget, tokenizer, max_workers=32,
                 provider=LLM_PROVIDER, reasoning_effort=LLM_REASONING_EFFORT):
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)[provider]
        self.provider = provider
        self.model = cfg["MODEL"]
        self.reasoning_effort = reasoning_effort
        self._cfg = cfg
        self.cache_path = cache_path
        self.cache = self._load_cache()
        self.fp_budget = fp_token_budget
        self.budget_chars = int(fp_token_budget * CHAR_PER_TOKEN)
        self.tokenizer = tokenizer
        self.max_workers = max_workers
        self._client = None
        self._disabled = False
        self._lock = threading.Lock()
        self.n_calls = 0
        self.n_cache_hits = 0
        self.n_hard_trunc = 0
        self.n_errors = 0

    # ── cache ──
    def _load_cache(self):
        cache = {}
        if os.path.exists(self.cache_path):
            with open(self.cache_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        cache[obj["key"]] = obj["summary"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        log.info(f"Loaded {len(cache)} cached summaries ({self.provider}/{self.model})")
        return cache

    def _append_cache(self, key, summary):
        # caller holds self._lock
        with open(self.cache_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"key": key, "summary": summary}, ensure_ascii=False) + "\n")
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass

    # ── client (lazy, thread-safe) ──
    def _get_client(self):
        with self._lock:
            if self._client is None:
                from openai import OpenAI
                # OpenAI-compatible proxies (e.g. micuapi.ai) require the /v1 path;
                # the official DeepSeek API accepts it too, so always normalise.
                base = self._cfg["BASE_URL"].rstrip("/")
                if not base.endswith("/v1"):
                    base = base + "/v1"
                self._client = OpenAI(api_key=self._cfg["API_KEY"], base_url=base)
        return self._client

    @staticmethod
    def _strip_fences(text):
        text = (text or "").strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[-1] if "\n" in text else text
            if text.endswith("```"):
                text = text.rsplit("```", 1)[0]
        return text.strip()

    def _llm_summarize(self, fingerprint_text):
        """Return a compressed fingerprint, or None on failure / when disabled.

        GLM-5.2 runs with reasoning_effort=max: it produces a chain-of-thought and
        then the answer in `content`. With a small max_tokens the reasoning can eat
        the budget and content comes back EMPTY, so we retry once with a larger
        budget. max_tokens caps the final answer `content`; reasoning is generated
        regardless and is the wall-time bottleneck.
        """
        if self._disabled:
            return None
        prompt = (
            "You compress IoT device fingerprints for a classifier. Summarize the "
            "fingerprint below into a keyword summary.\n"
            "Rules:\n"
            "- Keep the SAME `col: value` line format and ONLY these field labels, in "
            "this order: as-info, whois-info, os-info, sw-info, hw-info, "
            "service-distribution, http-info, cert-info, dns-reverse. Drop any field "
            "with no useful content.\n"
            "- For each field keep ONLY the most discriminative keywords: "
            "vendor / product / version names, domains, certificate CN/O/issuer, OUI "
            "prefixes, model strings, service:port tokens. Remove boilerplate, "
            "repeated tokens, and generic words.\n"
            "- Output the summary ONLY (no prose, no code fence).\n"
            f"- Be concise; the result MUST fit under {self.fp_budget} tokens.\n\n"
            f"Fingerprint:\n{fingerprint_text}"
        )
        # The summary is a concise keyword list, so cap content tightly to keep each
        # call fast; fp_budget is the upper bound. Retry with a larger budget only if
        # content comes back empty.
        max_tokens = min(max(self.fp_budget, 1024), 4096)
        client = self._get_client()
        for attempt in range(2):
            try:
                kwargs = dict(
                    model=self.model,
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=max_tokens,
                )
                if self.reasoning_effort:
                    kwargs["reasoning_effort"] = self.reasoning_effort
                resp = client.chat.completions.create(**kwargs)
                content = self._strip_fences(resp.choices[0].message.content)
                if content:
                    return content
                # Empty content: reasoning exhausted the budget → enlarge and retry once.
                if attempt == 0:
                    max_tokens = min(max(self.fp_budget, 1024), 8192)
                    continue
                return None
            except Exception as exc:  # noqa: BLE001
                with self._lock:
                    self.n_errors += 1
                low = repr(exc).lower()
                log.warning(f"{self.provider} summarize failed: {repr(exc)[:200]}")
                if any(s in low for s in ("402", "quota", "insufficient", "balance", "401", "authentication")):
                    with self._lock:
                        self._disabled = True
                    log.error(f"{self.provider} DISABLED (quota/auth). Over-long rows "
                              f"will be hard-truncated for the rest of this run.")
                    return None
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None
        return None

    def _hard_truncate(self, text):
        ids = self.tokenizer(text, add_special_tokens=False).input_ids[: self.fp_budget]
        self.n_hard_trunc += 1
        return self.tokenizer.decode(ids, skip_special_tokens=True)

    # ── worker: compress a single text (cache-aware) ──
    def _compress_one(self, text):
        """Return (summary_or_None, from_cache). None summary => hard-truncate needed."""
        # Key includes the model so switching summarizers never reuses stale summaries.
        key = hashlib.sha256(f"{self.provider}/{self.model}\x00{text}".encode("utf-8")).hexdigest()
        with self._lock:
            if key in self.cache:
                self.n_cache_hits += 1
                return self.cache[key], True
        summary = self._llm_summarize(text)
        if summary:
            with self._lock:
                # Re-check: another worker may have cached the same key concurrently.
                if key not in self.cache:
                    self.cache[key] = summary
                    self._append_cache(key, summary)
                    self.n_calls += 1
                else:
                    summary = self.cache[key]
            return summary, False
        return None, False

    def compress_over_budget(self, texts):
        """Given a list of over-budget fingerprint texts, return {index: fitted_text}.

        Runs LLM calls concurrently; cache hits are instant. Entries that
        the LLM could not compress are left absent (the caller hard-truncates them).
        """
        out = {}
        if not texts:
            return out
        workers = max(1, self.max_workers)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self._compress_one, t): i for i, t in enumerate(texts)}
            done = 0
            for fut in as_completed(futures):
                i = futures[fut]
                try:
                    summary, _ = fut.result()
                except Exception as exc:  # noqa: BLE001
                    log.warning(f"compress worker error: {repr(exc)[:160]}")
                    summary = None
                if summary is not None:
                    # verify fit; hard-truncate the summary if the LLM overshot
                    if len(self.tokenizer(summary, add_special_tokens=False).input_ids) > self.fp_budget:
                        summary = self._hard_truncate(summary)
                    out[i] = summary
                done += 1
                if done % 200 == 0:
                    log.info(f"  compress progress {done}/{len(texts)} "
                             f"(calls={self.n_calls} cache={self.n_cache_hits} "
                             f"hard={self.n_hard_trunc} err={self.n_errors})")
        return out


# ═════════════════════════════════════════════════════════════════════════════
# Sample construction
# ═════════════════════════════════════════════════════════════════════════════
def _make_target(gt_type, gt_vendor, is_new_type, is_new_vendor):
    return {
        "new_type_probability": _P_NEW if is_new_type else _P_KNOWN,
        "new_vendor_probability": _P_NEW if is_new_vendor else _P_KNOWN,
        "is_unseen": bool(is_new_type or is_new_vendor),
        "predicted_type": gt_type if is_new_type else _NONE,
        "predicted_vendor": gt_vendor if is_new_vendor else _NONE,
        "confidence": 0.85,
    }


def _make_sample(user_prompt, gt_type, gt_vendor, is_new_type, is_new_vendor):
    target = _make_target(gt_type, gt_vendor, is_new_type, is_new_vendor)
    return {
        "instruction": UNSEEN_SYSTEM,
        "input": user_prompt,
        "output": "```json\n" + json.dumps(target, ensure_ascii=False, indent=2) + "\n```",
    }


def _strip_bom_columns(df):
    df.columns = [str(c).lstrip("﻿").strip() for c in df.columns]
    return df


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════
def prepare_data(max_len=DEFAULT_MAX_LEN, max_workers=32, devices=None, limit=None,
                 keep_existing=False, output_dir=OUTPUT_DIR):
    os.makedirs(output_dir, exist_ok=True)
    combined_jsonl = os.path.join(output_dir, "unseen_sft.jsonl")
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_path = CACHE_PATH  # fixed cache location, independent of --output_dir

    known_types = load_all_dev_labels() or []
    unseen_types = load_new_dev_labels() or []
    train_types = known_types
    if devices:
        train_types = [d for d in train_types if d in set(devices)]
    if not train_types:
        print("No device labels found / selected!")
        return

    # ── Delete old outputs (keep the summary cache for resume safety) ──
    if not keep_existing:
        for pattern in ("finetune_data_*.csv", "unseen_sft_*.jsonl", "unseen_sft.jsonl"):
            for path in glob.glob(os.path.join(output_dir, pattern)):
                try:
                    os.remove(path)
                    print(f"  [del] {os.path.basename(path)}")
                except OSError:
                    pass

    # ── Tokenizer + fixed prompt overhead ──
    print("Loading Llama-3.1 tokenizer …")
    from transformers import AutoTokenizer
    tokenizer = AutoTokenizer.from_pretrained(LLAMA_MODEL_PATH)

    empty_user = build_unseen_detection_prompt("", known_types, unseen_types)
    overhead = len(tokenizer.apply_chat_template(
        [{"role": "system", "content": UNSEEN_SYSTEM},
         {"role": "user", "content": empty_user}],
        tokenize=True, add_generation_prompt=True,
    ))
    # fingerprint must leave room for prompt overhead + assistant JSON answer
    fp_budget = max_len - overhead - ANSWER_BUDGET
    print(f"  MAX_LEN={max_len}  prompt_overhead={overhead} tok  answer_budget="
          f"{ANSWER_BUDGET} tok  -> fingerprint_budget={fp_budget} tok "
          f"(budget_chars={int(fp_budget * CHAR_PER_TOKEN)})")
    if fp_budget < 512:
        raise RuntimeError(f"Fingerprint token budget too small ({fp_budget}); raise --max_len.")

    summarizer = FingerprintSummarizer(LLM_CFG_PATH, cache_path, fp_budget, tokenizer, max_workers)

    total = 0
    shard_paths = []
    t_start = time.time()

    for dev in train_types:
        is_new_type = dev in unseen_types
        ipraw_path = os.path.join(IPRAW_DIR, f"ipraw_{dev}.csv")
        label_path = os.path.join(LABEL_DIR, f"label_{dev}.csv")
        if not os.path.exists(ipraw_path):
            print(f"[SKIP] {ipraw_path} not found.")
            continue

        print(f"\n=== {dev} (is_new_type={is_new_type}) ===")
        t_dev = time.time()
        ipraw_df = pd.read_csv(ipraw_path, dtype=str, low_memory=False)
        _strip_bom_columns(ipraw_df)
        if limit:
            ipraw_df = ipraw_df.head(limit)

        keep_cols = ["ip"] + [c for c in UNSEEN_INFO_COLS if c in ipraw_df.columns]
        df = ipraw_df[keep_cols].copy()

        if os.path.exists(label_path):
            label_df = pd.read_csv(label_path, dtype=str)
            _strip_bom_columns(label_df)
            label_cols = ["ip", "vendor"]
            if "is_new_vendor" in label_df.columns:
                label_cols.append("is_new_vendor")
            df = df.merge(label_df[label_cols], on="ip", how="left")
        else:
            df["vendor"] = "Unknown"
        df["vendor"] = df["vendor"].fillna("Unknown")
        if "is_new_vendor" not in df.columns:
            df["is_new_vendor"] = ""
        df = df.reset_index(drop=True)  # positional alignment: row i == texts[i]

        dev_csv = os.path.join(output_dir, f"finetune_data_{dev}.csv")
        df.to_csv(dev_csv, index=False)

        # Build fingerprint texts per row
        info_cols = [c for c in UNSEEN_INFO_COLS if c in df.columns]
        records = df[info_cols].fillna("").astype(str).to_dict("records")
        texts = [build_fingerprint_info_text(r) for r in records]

        # Identify over-budget rows (batched tokenization, char pre-filter)
        over_idx = []
        over_texts = []
        chk = 512
        for i in range(0, len(texts), chk):
            chunk = texts[i:i + chk]
            enc = tokenizer(chunk, add_special_tokens=False).input_ids
            for j, ids in enumerate(enc):
                idx = i + j
                if not texts[idx]:
                    continue
                if len(ids) > fp_budget or len(texts[idx]) > summarizer.budget_chars:
                    over_idx.append(idx)
                    over_texts.append(texts[idx])

        print(f"  {dev}: {len(df)} rows, {len(over_idx)} over-budget "
              f"({100*len(over_idx)/max(len(df),1):.1f}%) -> {summarizer.provider}")
        comp = summarizer.compress_over_budget(over_texts)
        comp_by_idx = {over_idx[k]: v for k, v in comp.items()}

        shard_path = os.path.join(output_dir, f"unseen_sft_{dev}.jsonl")
        shard_paths.append(shard_path)
        over_idx_set = set(over_idx)  # precomputed once (avoids O(n²) rebuild in the loop)
        row_records = df.to_dict("records")
        n_written = 0
        with open(shard_path, "w", encoding="utf-8") as out:
            for i in range(len(row_records)):
                fp_text = texts[i]
                if not fp_text:
                    continue
                if i in comp_by_idx:
                    fp_text = comp_by_idx[i]
                elif i in over_idx_set:
                    # LLM did not return a summary (error/disabled) -> hard-truncate
                    fp_text = summarizer._hard_truncate(fp_text)
                user_prompt = build_unseen_detection_prompt(fp_text, known_types, unseen_types)
                row = row_records[i]
                vendor = str(row.get("vendor", "Unknown")).strip() or "Unknown"
                inv = row.get("is_new_vendor", "")
                if isinstance(inv, str) and inv.strip() and inv.strip().lower() not in ("nan", "none"):
                    is_new_vendor = str(inv).strip() in ("1", "true", "True")
                else:
                    is_new_vendor = is_new_type
                sample = _make_sample(user_prompt, dev, vendor, is_new_type, is_new_vendor)
                out.write(json.dumps(sample, ensure_ascii=False) + "\n")
                out.flush()
                n_written += 1
                total += 1

        print(f"  {dev}: wrote {n_written}/{len(df)} -> {os.path.basename(shard_path)} "
              f"({time.time()-t_dev:.0f}s) | summ={summarizer.n_calls} "
              f"cache={summarizer.n_cache_hits} hard={summarizer.n_hard_trunc} "
              f"err={summarizer.n_errors}"
              + (f" [{summarizer.provider} DISABLED]" if summarizer._disabled else ""))

    # ── Combine shards ──
    print("\nCombining shards -> unseen_sft.jsonl …")
    with open(combined_jsonl, "w", encoding="utf-8") as out:
        for sp in shard_paths:
            if not os.path.exists(sp):
                continue
            with open(sp, "r", encoding="utf-8") as fh:
                for line in fh:
                    out.write(line)

    print("\n==========================================================")
    print(f"Data preparation complete! Total SFT samples: {total}")
    print(f"{summarizer.provider}/{summarizer.model} (reasoning_effort={summarizer.reasoning_effort}) "
          f"calls: {summarizer.n_calls} | cache hits: {summarizer.n_cache_hits} | "
          f"hard-truncates: {summarizer.n_hard_trunc} | errors: {summarizer.n_errors}"
          + (f" | [{summarizer.provider} WAS DISABLED]" if summarizer._disabled else ""))
    print(f"MAX_LEN={max_len}  Combined file: {combined_jsonl}")
    print(f"Total time: {time.time()-t_start:.0f}s")
    print("==========================================================")


def _parse_args():
    p = argparse.ArgumentParser(description="Prepare unseen-detection SFT data (Method B).")
    p.add_argument("--max_len", type=int, default=DEFAULT_MAX_LEN,
                   help=f"Full-sequence token budget (default {DEFAULT_MAX_LEN}). "
                        "Rows whose prompt exceeds this are GLM-summarized.")
    p.add_argument("--max_workers", type=int, default=32,
                   help="Concurrent GLM summarization workers (default 32).")
    p.add_argument("--devices", type=str, default=None,
                   help="Comma-separated device types to process (default: all RAG types).")
    p.add_argument("--limit", type=int, default=None,
                   help="Row limit per device (smoke test).")
    p.add_argument("--keep_existing", action="store_true",
                   help="Do not delete existing dataset outputs.")
    p.add_argument("--output_dir", type=str, default=OUTPUT_DIR,
                   help=f"Output directory (default {OUTPUT_DIR}).")
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
    )
