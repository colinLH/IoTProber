#!/usr/bin/env python
"""Regenerate missing overall cluster summaries (ALARM / CONTROLLER).

The upstream artifacts were never generated for these two types, so community
retrieval returns `cluster_report_missing` for every cluster (197×/type in the
bench). This script groups each type's overall-pca clusters, feeds the member
fingerprints' key fields to an LLM, and writes {dev}_cluster_summaries.json in
the same schema the retrieval layer reads (see NVR_cluster_summaries.json).

Usage: python graph/regen_overall_summaries.py [--devices ALARM CONTROLLER]
"""

import argparse
import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pandas as pd  # noqa: E402

from llm import LLM  # noqa: E402
from path_config import LOCAL_DATA_DIR, LOCAL_OVERALL_COMMUNITY_DIR  # noqa: E402

OVERALL = LOCAL_OVERALL_COMMUNITY_DIR
RAW = LOCAL_DATA_DIR

# fingerprint fields per summary aspect (mirrors the original summary rubric)
FIELDS = {
    "hardware": ["hw-vendors", "hw-products"],
    "software": ["sw-vendors", "sw-products", "sw-versions"],
    "os": ["os-vendor", "os-product", "os-version"],
    "ssh": [],  # no ssh column in the 46-feature corpus
    "services": ["service-distribution"],
    "http_titles": ["http-tags"],
    "certificates": ["cert-subjects", "cert-issuers"],
    "favicons": ["http-favicon-hashes"],
}
EXTRA = ["as-name", "as-country_code", "dns-reverse", "whois-network-name",
         "http-bodys"]


def shorten(s, n=220):
    s = str(s) if s is not None else ""
    return s[:n]


def summarize_cluster(llm, dev, cid, members, use_llm=True, llm_name="GLM"):
    aspects = {}
    for aspect, cols in FIELDS.items():
        vals = []
        for c in cols:
            vs = members[c].dropna().astype(str).str.strip()
            vs = vs[vs != ""]
            if len(vs):
                vals.append(f"{c}: " + "; ".join(vs.unique()[:6]))
        if not vals and not cols:
            vs = members["http-info"].dropna().astype(str).str.strip()
            vs = vs[vs != ""]
            vals = [f"http-info: " + "; ".join(vs.unique()[:4])]
        aspects[aspect] = " | ".join(vals) if vals else "no signal"
    ctx = []
    for aspect, text in aspects.items():
        ctx.append(f"[{aspect}] {text[:400]}")
    for c in EXTRA:
        vs = members[c].dropna().astype(str).str.strip()
        vs = vs[vs != "Unknown"].dropna()
        if len(vs):
            ctx.append(f"[{c}] " + "; ".join(vs.unique()[:4])[:200])
    prompt = (
        f"设备类型 {dev} 的社区 #{cid}（{len(members)} 台设备）的共性指纹证据如下：\n"
        + "\n".join(ctx)
        + "\n\n请输出 JSON：{\"common_patterns\": {"
        + ", ".join(f'"{k}": "一句话"' for k in FIELDS)
        + "}, \"distribution_characteristics\": \"一句话\", "
        "\"notable_similarities\": \"一句话\", \"cluster_summary\": \"两句话\"}。"
        "所有值用中文，只输出 JSON。"
    )
    if use_llm:
        try:
            extra = {"whether_json": True, "thinking": "disabled"} if llm_name == "DEEPSEEK" else {}
            r = llm.chat_with_llm(llm_name, [{"role": "user", "content": prompt}], **extra)
            if isinstance(r, dict) and "common_patterns" in r:
                return r
        except Exception as exc:  # noqa: BLE001
            print(f"  cluster {cid} LLM 失败: {str(exc)[:80]}", flush=True)
    return {
        "common_patterns": {k: shorten(v, 160) for k, v in aspects.items()},
        "distribution_characteristics": "（降级：基于字段频次的机器摘要）",
        "notable_similarities": "（降级）",
        "cluster_summary": "；".join(
            f"{k}: {shorten(v, 80)}" for k, v in list(aspects.items())[:3]),
    }


def regen(dev, llm, use_llm=True, llm_name="GLM"):
    pca = os.path.join(OVERALL, f"ipraw_{dev}_embedding_overall_pca.csv")
    raw = os.path.join(RAW, f"ipraw_{dev}.csv")
    df = pd.read_csv(pca, usecols=["ip", "cluster"], low_memory=False)
    fp = pd.read_csv(raw, low_memory=False)
    m = df.merge(fp, on="ip", how="left")
    out = []
    for cid, grp in m[m["cluster"] != -1].groupby("cluster"):
        if len(grp) < 2:
            continue
        print(f"[{dev}] cluster {cid}: {len(grp)} 台", flush=True)
        out.append({
            "cluster_id": int(cid),
            "device_count": int(len(grp)),
            "analysis": summarize_cluster(llm, dev, int(cid), grp, use_llm, llm_name),
        })
    path = os.path.join(OVERALL, f"{dev}_cluster_summaries.json")
    json.dump(out, open(path, "w"), ensure_ascii=False, indent=2)
    print(f"[{dev}] 写出 {len(out)} 个社区摘要 -> {path}", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--devices", nargs="*", default=["ALARM", "CONTROLLER"])
    p.add_argument("--no-llm", action="store_true", help="直接用字段频次机器摘要(通道不可用时)")
    p.add_argument("--llm", default="GLM", choices=["GLM", "CLAUDE", "DEEPSEEK", "GEMINI", "OPENAI"],
                   help="config/llm_config*.json 中用于生成社区摘要的 LLM 条目")
    a = p.parse_args()
    llm = None if a.no_llm else LLM()
    for d in a.devices:
        regen(d, llm, use_llm=not a.no_llm, llm_name=a.llm)
