"""
QLoRA fine-tuning of Meta-Llama-3.1-8B-Instruct for UNSEEN DEVICE DETECTION.

Aligned with `agent/unseen.py`: the adapter is trained to emit the unseen-detection
JSON with TWO independent probabilities and per-field "none" labels
(new_type_probability / new_vendor_probability / predicted_type / predicted_vendor),
NOT a vendor-only string.

- 4-bit NF4 quantization + LoRA (r=8, all-linear)   → the "LoRA 4-bit quantized
  LLaMA-3.1-8B" configuration referenced by the design.
- Microbatch 1 × gradient-accumulation 8 → effective batch size 8
- Gradient checkpointing enabled
- Right-truncation at 2048 tokens (prompt is long: perspective comparison)
- Targeted loss masking: only the assistant JSON answer tokens are supervised.

Input data: dataset/unseen_sft.jsonl produced by prepare_data.py, one JSON object
per line with keys {"instruction", "input", "output"}.
"""
import os
import glob
from dataclasses import dataclass
from typing import Any, Dict, List

import torch
from datasets import load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
    PreTrainedTokenizerBase,
)

# ──────────────────────────── Paths ────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_ID = os.path.join(SCRIPT_DIR, "..", "..", "..", "Meta-Llama-3.1-8B-Instruct")
DATASET_DIR = os.path.join(SCRIPT_DIR, "dataset")
DATA_FILE = os.path.join(DATASET_DIR, "unseen_sft.jsonl")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "results")
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")

MAX_LEN = 2048


# ──────────────────────────── Data helpers ────────────────────────────
def load_sft_dataset(data_file=None):
    """Load the unseen-detection SFT JSONL produced by prepare_data.py."""
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
    print(f"  Total training samples: {len(ds)}")
    return ds


def format_and_tokenize(examples, tokenizer, max_length=MAX_LEN):
    """
    Build a Llama-3.1 chat sequence (system + user + assistant JSON) and mask the
    loss to the ASSISTANT answer only, so the model learns to produce the
    unseen-detection JSON rather than copying the prompt.
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

        # Guarantee the ANSWER tokens are always supervised. The unseen-detection
        # prompts are very long (the perspective comparison dump routinely exceeds
        # 2k tokens, up to ~75k), so a plain RIGHT-truncation `(prompt+answer)[:N]`
        # would slice the answer JSON away entirely → every label becomes -100 and
        # the model receives ZERO supervision. Instead, when the prompt is too long,
        # LEFT-truncate the prompt (keep its tail, which carries the task
        # instructions and the JSON schema the model must reproduce) and append the
        # FULL answer unchanged.
        prompt_budget = max_length - len(answer_ids)
        if prompt_budget < 1:
            prompt_budget = max(1, max_length // 8)
        if len(prompt_ids) > prompt_budget:
            prompt_ids = prompt_ids[-prompt_budget:]

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


# ──────────────────────────── Distributed helpers ────────────────────────────
def _is_distributed() -> bool:
    """True when launched under torchrun / accelerate (WORLD_SIZE > 1)."""
    return int(os.environ.get("WORLD_SIZE", "1")) > 1


def _local_rank() -> int:
    return int(os.environ.get("LOCAL_RANK", "0"))


def _parse_args():
    import argparse

    p = argparse.ArgumentParser(
        description="QLoRA fine-tune Llama-3.1-8B-Instruct for unseen-device detection"
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
    p.add_argument("--epochs", type=float, default=3.0)
    p.add_argument(
        "--max_len",
        type=int,
        default=MAX_LEN,
        help=f"Max sequence length in tokens (default {MAX_LEN}). With the "
        "left-truncation fix the answer is always kept; a larger max_len keeps "
        "more of the device evidence.",
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
    raw_ds = load_sft_dataset(args.data_file)
    if args.max_train_samples is not None:  # smoke test
        raw_ds = raw_ds.select(range(min(args.max_train_samples, len(raw_ds))))
        if is_main:
            print(f"  [SMOKE TEST] using only {len(raw_ds)} samples")
    all_cols = raw_ds.column_names
    max_len = getattr(args, "max_len", None) or MAX_LEN
    dataset = raw_ds.map(
        lambda ex: format_and_tokenize(ex, tokenizer, max_length=max_len),
        batched=True,
        batch_size=256,
        remove_columns=all_cols,
        desc=f"Formatting + tokenizing (rank {local_rank})",
    )
    if is_main:
        print(f"  Tokenized dataset: {len(dataset)} samples")

    # ── QLoRA 4-bit quantization ──
    if is_main:
        print("Loading model with 4-bit quantization …")
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_compute_dtype=torch.float16,
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
        torch_dtype=torch.float16,
    )
    model.config.use_cache = False  # required with gradient checkpointing
    model = prepare_model_for_kbit_training(model)

    # ── LoRA adapters ──
    lora_config = LoraConfig(
        r=8,
        lora_alpha=16,
        target_modules="all-linear",
        lora_dropout=0.05,
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
        num_train_epochs=args.epochs,
        per_device_train_batch_size=1,
        gradient_accumulation_steps=8,          # effective batch = 8 × world_size
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        learning_rate=2e-4,
        fp16=True,                              # V100 (sm_70) has no bf16
        logging_dir=LOG_DIR,
        logging_steps=10,
        save_strategy="epoch",
        optim="paged_adamw_8bit",
        report_to="none",
        # DDP: keep gradient sync correct for all-linear LoRA. If a
        # "Expected to have finished reduction" error appears, flip to True.
        ddp_find_unused_parameters=False if distributed else None,
        dataloader_drop_last=True,
    )

    # ── Trainer ──
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        data_collator=CausalPaddingCollator(tokenizer=tokenizer),
    )

    if is_main:
        print("Starting training …")
    trainer.train()

    # ── Save final LoRA adapter + tokenizer (rank 0 only) ──
    if is_main:
        save_path = os.path.join(output_dir, "final_model")
        trainer.save_model(save_path)
        tokenizer.save_pretrained(save_path)
        print(f"Training complete. Adapter saved to {save_path}")
        print("Use it with: UnseenDeviceDetector(adapter_path=..., load_in_4bit=True)")


# Back-compat alias.
main = run_training


if __name__ == "__main__":
    run_training()
