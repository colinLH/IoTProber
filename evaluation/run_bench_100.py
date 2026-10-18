#!/usr/bin/env python
"""
Per-type 100-sample pipeline benchmark over the validation set.

Samples 100 validation IPs per device type (seed 42, deduped), runs the
complete IdentificationAgent flow for each type, and records per-IP verdicts
for the improvement analysis. Designed to run as several OS processes, one
per GPU, each pulling types from a shared work queue (a plain text file with
an flock-protected pop).

Usage (worker):
  CUDA_VISIBLE_DEVICES=$G HF_HOME=/dev/shm/ft_v2/hf \
    python evaluation/run_bench_100.py --worker $G

Sampling only:
  python evaluation/run_bench_100.py --sample
"""

import argparse
import fcntl
import json
import os
import shutil
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "agent"))
sys.path.insert(0, REPO)

TYPES = json.load(open(os.path.join(REPO, "config", "rag_devices.json")))["IoT"]
VALID = os.path.join(REPO, "evaluation", "validation")
QDB = os.path.join(REPO, "agent", "query_db")
PRED = os.path.join(REPO, "evaluation", "predict")
BENCH = os.path.join(REPO, "evaluation", "bench_100")
ADAPTER = os.path.join(REPO, "evaluation/unseen/llama3/results_v2/final_model")
DRIFT = os.path.join(REPO, "drift_data/autoencoder_drift")
QUEUE = "/tmp/bench_queue.txt"
N_PER_TYPE = 100
SEED = 42


def sample_all():
    import pandas as pd
    for t in TYPES:
        src = os.path.join(VALID, f"test_{t}_1.csv")
        dst = os.path.join(BENCH, f"sample_{t}_100.csv")
        if os.path.exists(dst):
            print(f"[sample] {t}: exists")
            continue
        df = pd.read_csv(src, low_memory=False).drop_duplicates(subset=["ip"])
        n = min(N_PER_TYPE, len(df))
        s = df.sample(n=n, random_state=SEED)
        s.to_csv(dst, index=False)
        print(f"[sample] {t}: {n}/{len(df)} -> {dst}")


def pop_type():
    """Atomically pop the next type from the shared queue file."""
    fd = os.open(QUEUE, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        content = os.read(fd, 65536).decode()
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        if not lines:
            return None
        nxt, rest = lines[0], lines[1:]
        os.pwrite(fd, "\n".join(rest).encode(), 0)
        os.ftruncate(fd, len("\n".join(rest)))
        return nxt
    finally:
        os.close(fd)


def swap_test_csv(t):
    path = os.path.join(VALID, f"test_{t}_1.csv")
    backup = path + ".bench_bak"
    if os.path.exists(path) and not os.path.exists(backup):
        shutil.copy2(path, backup)
    shutil.copy2(os.path.join(BENCH, f"sample_{t}_100.csv"), path)


def restore_test_csv(t):
    path = os.path.join(VALID, f"test_{t}_1.csv")
    backup = path + ".bench_bak"
    if os.path.exists(backup):
        shutil.move(backup, path)


def done_ips(t):
    """IPs that already have a decision verdict recorded for this type."""
    p = os.path.join(BENCH, t, "records.jsonl")
    if not os.path.exists(p):
        return set()
    out = set()
    with open(p) as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            # only a committed verdict counts as done; empty rows AND
            # UNKNOWN rows are retried (UNKNOWN is how the branches answer
            # when their evidence chain was rate-limited mid-run)
            if rec.get("ip") and rec.get("predicted_type") not in (None, "", "UNKNOWN"):
                out.add(str(rec["ip"]))
    return out


def append_record(t, rec):
    os.makedirs(os.path.join(BENCH, t), exist_ok=True)
    with open(os.path.join(BENCH, t, "records.jsonl"), "a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        fh.flush()


def run_type(t):
    from agent import IdentificationAgent
    swap_test_csv(t)
    try:
        agent = IdentificationAgent(llm="DEEPSEEK", gpu=0)
        already = done_ips(t)
        # retrieval: quick_resume skips IPs whose caches are complete
        agent.run_retrieval(whether_decompose=True, whether_local=True,
                            whether_community=True, whether_reasoning=True,
                            devices=[t], top_k=5, quick_resume=True)
        # decision for the whole sample (this call was missing in the first
        # launch — workers "completed" after retrieval alone)
        agent.run_decision(devices=[t], whether_local=True, whether_community=True,
                           whether_reasoning=True, top_k=5, enable_first_stage=True,
                           unseen_adapter_path=ADAPTER, unseen_load_in_4bit=True,
                           drift_model_dir=DRIFT, gpu=0, quick_resume=True)
        import pandas as pd
        sample_ips = set(pd.read_csv(
            os.path.join(BENCH, f"sample_{t}_100.csv"),
            usecols=["ip"], low_memory=False)["ip"].astype(str))
        tp_all = {str(r["ip"]): r for r in json.load(
            open(os.path.join(PRED, f"{t}_type_prediction.json")))}
        vp_all = {str(r["ip"]): r for r in json.load(
            open(os.path.join(PRED, f"{t}_vendor_prediction.json")))}
        fresh = [ip for ip in sample_ips
                 if ip in tp_all and ip not in already]
        for ip in fresh:
            tp, vp = tp_all[ip], vp_all.get(ip, {})
            append_record(t, {
                "ip": ip,
                "true_type": t,
                "predicted_type": tp.get("predicted_device_type"),
                "confidence": tp.get("confidence"),
                "winning_llm": tp.get("winning_llm"),
                "gemini_type": tp.get("gemini_device_type"),
                "claude_type": tp.get("claude_device_type"),
                "predicted_vendor": vp.get("predicted_vendor"),
                "first_stage": tp.get("first_stage"),
                "elapsed_sec": tp.get("elapsed_sec"),
                "ts": time.strftime("%H:%M:%S"),
            })
        # retry IPs whose decision came back empty or UNKNOWN (API hiccups /
        # rate-limited evidence). They still carry pipeline_version, so
        # quick_resume would wrongly skip them — rerun that subset.
        empties = [ip for ip in fresh
                   if tp_all[ip].get("predicted_device_type") in (None, "", "UNKNOWN")]
        if empties:
            print(f"[{t}] retrying {len(empties)} empty-verdict IPs", flush=True)
            import pandas as pd
            sample = pd.read_csv(os.path.join(BENCH, f"sample_{t}_100.csv"),
                                 low_memory=False)
            sub = sample[sample["ip"].astype(str).isin(empties)]
            sub.to_csv(os.path.join(VALID, f"test_{t}_1.csv"), index=False)
            try:
                agent.run_decision(devices=[t], whether_local=True,
                                   whether_community=True, whether_reasoning=True,
                                   top_k=5, enable_first_stage=True,
                                   unseen_adapter_path=ADAPTER,
                                   unseen_load_in_4bit=True,
                                   drift_model_dir=DRIFT, gpu=0)
                tp2 = {str(r["ip"]): r for r in json.load(
                    open(os.path.join(PRED, f"{t}_type_prediction.json")))}
                for ip in empties:
                    r = tp2.get(ip, {})
                    if r.get("predicted_device_type"):
                        append_record(t, {
                            "ip": ip, "true_type": t, "retry": True,
                            "predicted_type": r["predicted_device_type"],
                            "confidence": r.get("confidence"),
                            "winning_llm": r.get("winning_llm"),
                            "gemini_type": r.get("gemini_device_type"),
                            "claude_type": r.get("claude_device_type"),
                            "elapsed_sec": r.get("elapsed_sec"),
                            "ts": time.strftime("%H:%M:%S"),
                        })
            except Exception as exc:  # noqa: BLE001
                print(f"[{t}] retry pass failed: {str(exc)[:120]}", flush=True)
            finally:
                swap_test_csv(t)
        n = len(done_ips(t))
        print(f"[{t}] type pass complete — {n} IPs recorded", flush=True)
    finally:
        restore_test_csv(t)


def summarize():
    import collections
    tot = collections.Counter()
    for t in TYPES:
        p = os.path.join(BENCH, t, "records.jsonl")
        if not os.path.exists(p):
            continue
        last = {}
        for l in open(p):
            try:
                r = json.loads(l)
            except ValueError:
                continue
            last[str(r.get("ip"))] = r   # later records (retries) win
        recs = list(last.values())
        done = [r for r in recs if r.get("predicted_type")]
        ok = [r for r in done if r["predicted_type"] == t]
        tot["n"] += len(done); tot["ok"] += len(ok)
        print(f"{t:22} {len(ok):3}/{len(done):3}  "
              f"({100*len(ok)/max(1,len(done)):.0f}%)")
    if tot["n"]:
        print(f"{'TOTAL':22} {tot['ok']:3}/{tot['n']:3}  "
              f"({100*tot['ok']/tot['n']:.1f}%)")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--sample", action="store_true")
    p.add_argument("--worker", type=int, default=None)
    p.add_argument("--types", nargs="*", default=None)
    p.add_argument("--summary", action="store_true")
    a = p.parse_args()
    os.makedirs(BENCH, exist_ok=True)
    if a.sample:
        sample_all()
    elif a.summary:
        summarize()
    elif a.types:
        for t in a.types:
            run_type(t)
    elif a.worker is not None:
        while True:
            t = pop_type()
            if t is None:
                print("queue empty, worker exiting", flush=True)
                break
            print(f"worker {a.worker} picked {t}", flush=True)
            try:
                run_type(t)
            except Exception as exc:  # noqa: BLE001
                print(f"[{t}] FAILED: {type(exc).__name__}: {str(exc)[:160]}",
                      flush=True)
                restore_test_csv(t)
    else:
        p.error("need --sample | --worker N | --types ... | --summary")
