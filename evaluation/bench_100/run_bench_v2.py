#!/usr/bin/env python
"""bench v2 重跑: 只重跑"未判对"的 IP, 吃全部已落地的改进。

改进清单 (相对 9-26 基线):
  - D4 指纹截断 (util.truncate_fingerprint_for_llm)
  - D6 弃权回退 adapter 判决 (agent._maybe_adapter_fallback)
  - 特征端口硬信号进 prompt (agent._port_signals)
  - 类型串空白规范化 (decision.normalize_decision)
  - KB 去重: 跨类型重复 IP 不再作为 local 近邻 (retrieval._ambiguous_kb_ips)
  - PM/CONTROLLER/ALARM 社区层重建 (10-18 晨, 簇摘要已再生)

用法 (worker, 每卡一个):
  CUDA_VISIBLE_DEVICES=1 HF_HOME=/dev/shm/ft_v2/hf \
    python evaluation/bench_100/run_bench_v2.py --worker 1
"""

import argparse
import fcntl
import json
import os
import shutil
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "agent"))
sys.path.insert(0, REPO)

TYPES = json.load(open(os.path.join(REPO, "config", "rag_devices.json")))["IoT"]
VALID = os.path.join(REPO, "evaluation", "validation")
PRED = os.path.join(REPO, "evaluation", "predict")
BENCH = os.path.join(REPO, "evaluation", "bench_100")
ADAPTER = os.path.join(REPO, "evaluation/unseen/llama3/results_v2/final_model")
DRIFT = os.path.join(REPO, "drift_data/autoencoder_drift")
QUEUE = "/tmp/bench_v2_queue.txt"


def append_record(t, rec):
    os.makedirs(os.path.join(BENCH, t), exist_ok=True)
    with open(os.path.join(BENCH, t, "records.jsonl"), "a") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        fh.flush()


def pop_type():
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


def load_predictions(t):
    """predict JSON 兼容 list/dict 两种形态, 统一为 (type_map, vendor_map)。

    注意文件名 `POWER_METER_type_prediction.json` 按 '_' 切分会切进类型名
    内部 (POWER|METER), 必须按前后缀判别, 不能用 split 取段。
    """
    maps = {}
    for kind, suffix in (("type", "_type_prediction.json"),
                         ("vendor", "_vendor_prediction.json")):
        p = os.path.join(PRED, f"{t}{suffix}")
        try:
            data = json.load(open(p))
        except (OSError, ValueError):
            continue
        if isinstance(data, list):
            maps[kind] = {str(r.get("ip")): r for r in data if isinstance(r, dict)}
        else:
            maps[kind] = {str(k): v for k, v in data.items()}
    return maps.get("type"), maps.get("vendor")


def targets_for(t):
    """sample 中"最后一条记录判错/弃权/无记录"的 IP → 待重跑子集。"""
    import pandas as pd
    sample = pd.read_csv(os.path.join(BENCH, f"sample_{t}_100.csv"), low_memory=False)
    last = {}
    p = os.path.join(BENCH, t, "records.jsonl")
    if os.path.exists(p):
        for l in open(p):
            try:
                r = json.loads(l)
            except ValueError:
                continue
            last[str(r.get("ip"))] = r
    todo = [ip for ip in sample["ip"].astype(str)
            if last.get(ip, {}).get("predicted_type") != t]
    return sample[sample["ip"].astype(str).isin(todo)], todo


def run_type(t, limit=None):
    from agent import IdentificationAgent
    sub, todo = targets_for(t)
    if limit:
        todo = todo[:limit]
        sub = sub[sub["ip"].astype(str).isin(todo)]
    if not todo:
        print(f"[{t}] 无待重跑 IP", flush=True)
        return
    print(f"[{t}] 待重跑 {len(todo)} IP", flush=True)

    path = os.path.join(VALID, f"test_{t}_1.csv")
    bak = path + ".bench_bak"
    if os.path.exists(path) and not os.path.exists(bak):
        shutil.copy2(path, bak)
    sub.to_csv(path, index=False)
    try:
        agent = IdentificationAgent(llm="DEEPSEEK", gpu=0)
        agent.run_retrieval(whether_decompose=True, whether_local=True,
                            whether_community=True, whether_reasoning=True,
                            devices=[t], top_k=5, quick_resume=True)
        agent.run_decision(devices=[t], whether_local=True, whether_community=True,
                           whether_reasoning=True, top_k=5, enable_first_stage=True,
                           unseen_adapter_path=ADAPTER, unseen_load_in_4bit=True,
                           drift_model_dir=DRIFT, gpu=0)
        tp_all, vp_all = load_predictions(t)
        tp_all, vp_all = tp_all or {}, vp_all or {}
        n = ok = fb = 0
        for ip in todo:
            r = tp_all.get(ip) or {}
            pred = r.get("predicted_device_type")
            if not pred:
                continue
            n += 1
            ok += (pred == t)
            used_fb = r.get("decision_source") == "adapter_fallback"
            fb += used_fb
            vp = vp_all.get(ip) or {}
            append_record(t, {
                "ip": ip, "true_type": t,
                "predicted_type": pred,
                "confidence": r.get("final_confidence", r.get("confidence")),
                "winning_llm": r.get("winning_llm"),
                "gemini_type": r.get("gemini_device_type"),
                "claude_type": r.get("claude_device_type"),
                "predicted_vendor": vp.get("predicted_vendor"),
                "decision_source": r.get("decision_source"),
                "adapter_fallback": r.get("adapter_fallback"),
                "first_stage": r.get("first_stage"),
                "elapsed_sec": r.get("elapsed_sec"),
                "pipeline_version": "v2_improved",
                "ts": time.strftime("%m-%d %H:%M:%S"),
            })
        print(f"[{t}] v2 完成: 判决 {n}/{len(todo)}, 对 {ok}, adapter回退 {fb}",
              flush=True)
    finally:
        if os.path.exists(bak):
            shutil.move(bak, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--worker", type=int, default=None)
    ap.add_argument("--types", nargs="*", default=None,
                    help="直接指定类型 (冒烟用), 忽略队列")
    ap.add_argument("--limit", type=int, default=None)
    args = ap.parse_args()

    if args.types:
        for t in args.types:
            run_type(t, limit=args.limit)
        return

    while True:
        t = pop_type()
        if t is None:
            print("[worker] 队列空, 退出", flush=True)
            return
        try:
            run_type(t)
        except Exception as exc:  # noqa: BLE001 — 单类型失败不拖垮 worker
            print(f"[{t}] FAILED: {exc}", flush=True)


if __name__ == "__main__":
    main()
