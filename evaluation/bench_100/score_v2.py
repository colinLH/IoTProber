#!/usr/bin/env python
"""bench v2 终局评分: 全量口径 + 客观清洁口径。

清洁口径: 用 title/hw-products 级产品硬证据把每个样本分桶 —
  ok                指纹含本类型决定性产品、无他类产品 → 可判、标签可信
  label_contradicted 含他类决定性产品、无本类产品 → 标签错
  ambiguous          双侧产品并存 (多租户云主机/蜜罐) → 物理不可判
  no_hard_evidence   无任何硬产品 → 只进全量口径
全量口径照原始标签算 (与 v1 基线可比); 清洁口径只算 ok 桶。
"""
import json
import os
import re
import sys

import pandas as pd

BENCH = os.path.dirname(os.path.abspath(__file__))

PROD = {
    "NAS": (r"synology|qnap|readynas|asustor|terastation|mycloud|freenas|truenas|unraid",
            r"jetdirect|mirth|easyio|onvif|dlms|bacnet|fortimanager|fortiswitch|routerlogin|main_login"),
    "NVR": (r"\bnvr\b|video recorder|surveillance station|hibird|dss enterprise|lorex",
            r"jetdirect|mirth|easyio|dlms|routerlogin|main_login"),
    "POWER_METER": (r"\bdlms\b|\bcosem\b|gaugetech|electroind|\bshelly\b|powerlogic|conzerv|\biem\d+",
                    r"easyio|sedona|mirth|dicom|jetdirect|onvif|fortimanager|main_login"),
    "BUILDING_AUTOMATION": (r"easyio|sedona|niagara|tridium|\bbacnet\b|distech|wattstopper|\bjace\d",
                            r"mirth|dicom|jetdirect|papercut|onvif|\bdlms\b|fortimanager|main_login|usg\d"),
    "MEDICAL": (r"mirth|dicom|\bhl7\b|ge.healthcare|cerner|draeger|mindray|steris",
                r"easyio|sedona|niagara|bacnet|jetdirect|papercut|onvif|main_login|routerlogin"),
    "ROUTER": (r"routerlogin|main_login|asus login|netgear|mikrotik|routeros|openwrt|fortigate|fortiswitch|fortimanager|usg\d|edgerouter|\bunifi\b",
               r"jetdirect|mirth|easyio|onvif|\bdlms\b|dicom"),
    "PRINTER": (r"jetdirect|papercut|laserjet|workcentre|pagewide|web access|epson|brother|kyocera|\bcanon\b",
                r"mirth|easyio|dlms|dicom|fortimanager|routerlogin|main_login"),
    "SCADA": (r"modbus|\bnode-red\b|grafana|opc-?ua?|ignition|wincc|\bscada\b|dnp3",
              r"jetdirect|mirth|easyio|dlms|dicom|routerlogin"),
    "CAMERA": (r"onvif|axis communications|hanwha|vivotek|reolink|ip camera|webcam|hikvision|dahua",
               r"jetdirect|mirth|easyio|dlms|dicom|papercut"),
    "ALARM": (r"burglar|intrusion|alarm panel|solution \d+|\bdmp\b|vista panel|power series|prosys",
              r"jetdirect|mirth|easyio|dlms|dicom|routerlogin|onvif"),
    "CONTROLLER": (r"\bbacnet\b|niagara|tridium|\bjace\d|schneider|m340|click plc|knx|easyio",
                   r"jetdirect|mirth|dicom|dlms|routerlogin|onvif|papercut"),
}


def bucket_for(t, row):
    own_re, other_re = PROD[t]
    text = (str(row.get("http-tags") or "") + " " + str(row.get("hw-products") or ""))[:30000].lower()
    own = bool(re.search(own_re, text))
    other = bool(re.search(other_re, text))
    if own and other:
        return "ambiguous"
    if other:
        return "label_contradicted"
    if own:
        return "ok"
    return "no_hard_evidence"


def last_records(t):
    last = {}
    p = os.path.join(BENCH, t, "records.jsonl")
    if os.path.exists(p):
        for l in open(p):
            try:
                r = json.loads(l)
            except ValueError:
                continue
            last[str(r.get("ip"))] = r
    return last


def main():
    types = json.load(open(os.path.join(BENCH, "..", "..", "config", "rag_devices.json")))["IoT"]
    audit = json.load(open(os.path.join(BENCH, "label_audit.json"))) if os.path.exists(
        os.path.join(BENCH, "label_audit.json")) else {}

    print(f"{'类型':<22}{'全量':>10}{'清洁(ok)':>10}{'ok占比':>8}{'v2回退':>7}")
    tot = clean_tot = clean_ok = ok_cnt = 0
    for t in types:
        df = pd.read_csv(os.path.join(BENCH, f"sample_{t}_100.csv"), low_memory=False)
        last = last_records(t)
        n = ok = clean_n = clean_ok_n = amb = contra = noev = 0
        for _, row in df.iterrows():
            ip = str(row["ip"])
            r = last.get(ip)
            if not r or not r.get("predicted_type"):
                continue
            n += 1
            hit = r["predicted_type"] == t
            ok += hit
            b = bucket_for(t, row)
            audit[f"{t}/{ip}"] = {"bucket": b, "was_wrong": not hit}
            if b == "ok":
                clean_n += 1
                clean_ok_n += hit
            elif b == "ambiguous":
                amb += 1
            elif b == "label_contradicted":
                contra += 1
            else:
                noev += 1
        tot += ok
        clean_tot += clean_n
        clean_ok += clean_ok_n
        ok_cnt += n
        pct = f"{ok}/{n}"
        cpct = f"{clean_ok_n}/{clean_n}" if clean_n else "-"
        share = f"{clean_n/(n or 1):.0%}"
        print(f"{t:<22}{pct:>10}{cpct:>10}{share:>8}", end="")
        fb = sum(1 for r in last.values() if r.get("decision_source") == "adapter_fallback")
        print(f"{fb:>7}")
        # 桶明细
        print(f"{'':<22}桶: ok={clean_n} amb={amb} contra={contra} noev={noev}")
    print(f"\n全量口径: {tot}/{ok_cnt} = {tot/max(ok_cnt,1):.1%}")
    print(f"清洁口径(仅ok桶): {clean_ok}/{clean_tot} = {clean_ok/max(clean_tot,1):.1%}")
    json.dump(audit, open(os.path.join(BENCH, "label_audit.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
