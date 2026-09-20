#!/usr/bin/env python
"""
IoTProber demo web UI — local visualization of the 11-device-type showcase.

Serves demo/{TYPE}/cases.json + selection_summary.json and an optional live
classify endpoint that runs the v2 adapter on a posted fingerprint.

Run in the SAME env the cases were generated with, so the live endpoint
reproduces the stored confidences:

  cd /home/nfs/iotprober/demo && /root/anaconda3/envs/elastic_slm/bin/python app.py
  # http://localhost:5001        (the iotprober env also runs the static page,
  #  but its torch/transformers give slightly different numerics)

Endpoints:
  GET  /              static UI
  GET  /api/demo      cases + summary + drift threshold
  POST /api/classify  {"<fingerprint column>": "<value>", ...} -> classification
"""

import json
import os
import re
import sys
import threading

# Pin to ONE GPU *before* torch is ever imported. With 4-bit loading,
# unseen.py passes device_map="auto", which would otherwise shard the 8B model
# across every visible card (~27 GB total on this 8-GPU box) — wasteful and
# unfriendly to other tenants. Override with DEMO_GPU=<n>.
os.environ.setdefault("CUDA_VISIBLE_DEVICES", os.environ.get("DEMO_GPU", "0"))

from flask import Flask, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(BASE)
sys.path.insert(0, REPO)                 # util / unseen live at repo root
sys.path.insert(0, os.path.join(REPO, "agent"))

ADAPTER_DIR = os.path.join(REPO, "evaluation/unseen/llama3/results_v2/final_model")
DRIFT_DIR = os.path.join(REPO, "drift_data/autoencoder_drift")

TYPES = json.load(open(os.path.join(REPO, "rag_devices.json")))["IoT"]
INFO_COLS = ("as-info", "whois-info", "os-info", "sw-info", "hw-info",
             "service-distribution", "http-info", "cert-info", "dns-reverse")

app = Flask(__name__, static_folder="static", static_url_path="/static")

_detector = None
_det_lock = threading.Lock()     # Werkzeug dev server is threaded; guard the load


def get_detector():
    global _detector
    with _det_lock:
        if _detector is None:
            from unseen import UnseenDeviceDetector
            _detector = UnseenDeviceDetector(adapter_path=ADAPTER_DIR, gpu=0, load_in_4bit=True)
    return _detector


def drift_threshold():
    """τ from the trained PACA artifacts (never hard-coded in the UI)."""
    try:
        import joblib
        import drift as _drift          # registers _comma_tokenizer for unpickling
        art = joblib.load(os.path.join(DRIFT_DIR, "paca_artifacts.pkl"))
        return float(art["threshold"])
    except Exception:
        return None


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/demo")
def api_demo():
    types, failures = {}, []
    for t in TYPES:
        p = os.path.join(BASE, t, "cases.json")
        if not os.path.exists(p):
            continue
        try:
            types[t] = json.load(open(p))
        except Exception as exc:                      # one bad file must not 500 the page
            failures.append(f"{t}: {type(exc).__name__}")
    summary = {}
    sp = os.path.join(BASE, "selection_summary.json")
    if os.path.exists(sp):
        try:
            summary = json.load(open(sp))
        except Exception as exc:
            failures.append(f"selection_summary: {type(exc).__name__}")
    return jsonify({"types": types, "summary": summary,
                    "drift_threshold": drift_threshold(), "load_failures": failures})


@app.post("/api/classify")
def api_classify():
    fp = request.get_json(silent=True)
    if not isinstance(fp, dict) or not fp:
        return jsonify({"error": "expected a JSON object of column -> value "
                                 "(e.g. {\"hw-info\": \"...\", \"cert-info\": \"...\"})"}), 400
    if not any(fp.get(c) for c in INFO_COLS):
        return jsonify({"error": "no usable fingerprint: expected at least one of "
                        + ", ".join(INFO_COLS)}), 400
    try:
        from util import build_fingerprint_info_text
        det = get_detector()
        # production path: handles the token budget + summarizer contract itself
        qfp = {k: v for k, v in fp.items() if k != "ip"}
        prompt, _ = det._build_aligned_prompt(qfp)
        text, conf = det._generate_classification(prompt)
        nov = det._classification_novelty_result(det._parse_response(text), conf)
        return jsonify({
            "classified_type": nov["classified_type"],
            "classified_vendor": nov["classified_vendor"],
            "type_confidence": round(float(nov["type_confidence"]), 4),
            "vendor_confidence": round(float(nov["vendor_confidence"]), 4),
            "new_type_probability": round(float(nov["new_type_probability"]), 4),
            "new_vendor_probability": round(float(nov["new_vendor_probability"]), 4),
            "is_unseen": bool(nov["is_unseen"]),
        })
    except Exception as exc:  # noqa: BLE001
        app.logger.exception("classify failed")
        msg = re.sub(r"/[\w./-]{12,}", "<path>", str(exc))[:160]   # no host paths in the response
        return jsonify({"error": f"{type(exc).__name__}: {msg}"}), 500


if __name__ == "__main__":
    print("IoTProber demo UI -> http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
