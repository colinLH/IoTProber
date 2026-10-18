#!/usr/bin/env python
"""证据落盘重跑：验证 MEDICAL→EasyIO 是否为社区检索错引。

取 bench_100 MEDICAL 里被判为 BUILDING_AUTOMATION/EasyIO 的误判 IP,
只重跑这几个 IP 的决策, 并把 retrieval 证据 (local/community/reasoning)
完整落盘到 /tmp/evdump/<ip>.json 供离线分析。
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "agent"))
sys.path.insert(0, REPO)

BENCH = os.path.join(REPO, "evaluation", "bench_100")
VALID = os.path.join(REPO, "evaluation", "validation")
DUMP = "/tmp/evdump"
os.makedirs(DUMP, exist_ok=True)

TARGET_IPS = ["3.71.188.253", "13.39.163.24", "16.112.58.170", "13.56.11.122"]


def main():
    import pandas as pd

    # 1) 构造 4-IP 子集并换入 test csv (bench 同款机制)
    src = os.path.join(BENCH, "sample_MEDICAL_100.csv")
    bak = os.path.join(VALID, "test_MEDICAL_1.csv.bench_bak")
    tst = os.path.join(VALID, "test_MEDICAL_1.csv")
    if os.path.exists(tst) and not os.path.exists(bak):
        import shutil
        shutil.copy2(tst, bak)
    df = pd.read_csv(src, low_memory=False)
    sub = df[df["ip"].astype(str).isin(TARGET_IPS)]
    sub.to_csv(tst, index=False)
    print(f"[dump] {len(sub)} IPs swapped into test_MEDICAL_1.csv")

    # 2) patch RetrievalToolRuntime.run 落盘证据
    import decision

    _orig_run = decision.RetrievalToolRuntime.run

    def dumping_run(self, ip):
        combined = _orig_run(self, ip)
        try:
            with open(os.path.join(DUMP, f"{ip}.json"), "w") as fh:
                json.dump(combined, fh, ensure_ascii=False, default=str)
        except Exception as exc:  # noqa: BLE001
            print(f"[dump] write failed {ip}: {exc}")
        return combined

    decision.RetrievalToolRuntime.run = dumping_run

    # ── token 用量计量: 拦截 ChatOpenAI.invoke(决策分支) 与 LLM.chat_with_llm(检索漏斗) ──
    USAGE = {
        "decision_prompt": 0, "decision_completion": 0, "decision_cache_read": 0,
        "decision_calls": 0, "funnel_prompt": 0, "funnel_completion": 0,
        "funnel_calls": 0,
    }

    from langchain_openai import ChatOpenAI as _CO
    _orig_invoke = _CO.invoke

    def _counting_invoke(self, input, *a, **kw):
        r = _orig_invoke(self, input, *a, **kw)
        try:
            um = getattr(r, "usage_metadata", None) or {}
            USAGE["decision_prompt"] += int(um.get("input_tokens") or 0)
            USAGE["decision_completion"] += int(um.get("output_tokens") or 0)
            det = um.get("input_token_details") or {}
            USAGE["decision_cache_read"] += int(det.get("cache_read") or 0)
            USAGE["decision_calls"] += 1
        except Exception:  # noqa: BLE001
            pass
        return r

    _CO.invoke = _counting_invoke

    import llm as _llm_mod
    _orig_chat = _llm_mod.LLM.chat_with_llm

    def _counting_chat(self, llm_name, messages, *a, **kw):
        kw["return_usage"] = True
        res = _orig_chat(self, llm_name, messages, *a, **kw)
        try:
            result, usage = res
        except (TypeError, ValueError):
            return res
        if usage:
            USAGE["funnel_prompt"] += int(usage.get("prompt_tokens") or 0)
            USAGE["funnel_completion"] += int(usage.get("completion_tokens") or 0)
            USAGE["funnel_calls"] += 1
        return result

    _llm_mod.LLM.chat_with_llm = _counting_chat

    # 3) 跑决策 (强模型 deepseek 双分支)
    from agent import IdentificationAgent

    agent = IdentificationAgent(llm="DEEPSEEK", gpu=0)
    try:
        agent.run_decision(
            devices=["MEDICAL"], whether_local=True, whether_community=True,
            whether_reasoning=True, top_k=5, enable_first_stage=True,
            unseen_adapter_path=os.path.join(
                REPO, "evaluation/unseen/llama3/results_v2/final_model"),
            unseen_load_in_4bit=True,
            drift_model_dir=os.path.join(REPO, "drift_data/autoencoder_drift"),
            gpu=0,
        )
    finally:
        # 4) 还原 test csv
        if os.path.exists(bak):
            import shutil
            shutil.move(bak, tst)
        print("[dump] test_MEDICAL_1.csv restored")

    print("[usage]", json.dumps(USAGE))
    with open(os.path.join(DUMP, "usage.json"), "w") as fh:
        json.dump(USAGE, fh, indent=2)

    preds = json.load(open(os.path.join(
        REPO, "evaluation", "predict", "MEDICAL_type_prediction.json")))
    if isinstance(preds, list):
        preds = {str(r.get("ip")): r for r in preds if isinstance(r, dict)}
    for ip in TARGET_IPS:
        r = preds.get(ip) or {}
        print(f"{ip}: pred={r.get('predicted_device_type')} "
              f"vendor={r.get('predicted_vendor')} "
              f"conf={r.get('confidence')}")


if __name__ == "__main__":
    main()
