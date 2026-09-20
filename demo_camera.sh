#!/bin/bash
# IoTProber CAMERA minimal demo
# Prereqs: see README-demo notes. Uses conda env `iotprober`.
set -e
cd "$(dirname "$0")"
PY=/root/anaconda3/envs/iotprober/bin/python
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-3}

echo "== [1/3] Build local vector store (CAMERA) from embedding CSV =="
$PY agent/agent.py --vector --device CAMERA --gpu -1

echo "== [2/3] Local retrieval for 6 CAMERA test IPs =="
$PY agent/agent.py --local --device CAMERA --llm DEEPSEEK --gpu 0 --top_k 5

echo "== [3/3] First-stage unseen detection (local LLaMA-3.1-8B + LoRA checkpoints/checkpoint-10000) =="
$PY - <<'EOF'
import sys, os, json, glob
sys.path.insert(0, 'agent'); sys.path.insert(0, '.')
from unseen import UnseenDeviceDetector

# load cached local retrieval results written by step [2/3]
qdb = os.path.join('agent', 'query_db', 'local')
files = sorted(glob.glob(os.path.join(qdb, 'CAMERA_local*.json')))
entries = []
for fp in files:
    data = json.load(open(fp))
    if isinstance(data, dict) and 'similar_devices' in data:
        entries.append(data)
    elif isinstance(data, list):
        entries.extend(d for d in data if isinstance(d, dict) and 'similar_devices' in d)
print(f"loaded {len(entries)} cached local-retrieval entries")

import json as J
persp_cfg = J.load(open('perspective_info.json'))
# perspective_info.json: {name: {cols, weight, prompt_info}} or nested — normalize
def get_pw(cfg):
    out = {}
    for k, v in cfg.items():
        if isinstance(v, dict) and 'weight' in v:
            out[k] = float(v['weight'])
    return out
pw = get_pw(persp_cfg)
if not pw:  # nested form {"IoT": {...}} or {"perspectives": ...}
    for _k, _v in persp_cfg.items():
        if isinstance(_v, dict):
            pw.update(get_pw(_v))
KEY = ["certificate", "hfavicons", "hw", "sw", "os"]

det = UnseenDeviceDetector(
    adapter_path='checkpoints/checkpoint-10000',
    gpu=0, load_in_4bit=True)
for lr in entries:
    fp = lr.get('query_fingerprint', {})
    sims = lr.get('similar_devices', [])
    top = sims[0] if sims else {}
    top_sim = float(top.get('similarity_score', 0.0))
    fmd = []
    for p, w in pw.items():
        fmd.append({
            "feature_name": p, "importance_score": w,
            "feature_matching_score": top_sim,
            "weighted_feature_score": w * top_sim,
            "value_similarities": [
                {"cluster_id": 0, "similarity": top_sim, "weight": w,
                 "analysis_preview": ""} for _ in range(3)
            ],
        })
    pmr = {
        "cluster_key": f"local:{top.get('device_type', '')}",
        "cluster_info": {"device_type": top.get("device_type", "")},
        "path_matching_score": top_sim,
        "important_features": [{"feature_name": p} for p in KEY if p in pw],
        "feature_matching_details": fmd,
    }
    reasoning_result = {
        "query_fingerprint": fp,
        "path_matching_results": [pmr],
        "summary": ("Synthesized from local vector retrieval "
                    "(LLM reasoning-path retrieval unavailable: API keys offline)."),
    }
    res = det.detect_unseen(
        reasoning_result=reasoning_result, local_result=lr, community_result=None,
        web_search_results=None, allow_web_search=False)
    print(f"IP {fp.get('ip')}: is_unseen={res.get('is_unseen')} "
          f"type={res.get('predicted_type')} vendor={res.get('predicted_vendor')} "
          f"p_type={res.get('new_type_probability')} p_vendor={res.get('new_vendor_probability')} "
          f"confidence={res.get('confidence')}")
EOF
echo "== demo done =="
