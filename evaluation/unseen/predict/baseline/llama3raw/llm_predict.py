#!/usr/bin/env python3
"""
Raw (non-fine-tuned) Llama-3.1-8B-Instruct device type/vendor identification
for MEDIA_SERVER and VPN unseen test sets.

Same protocol as the ClaudeOpus baseline (predict/baseline/ClaudeOpus/llm_predict.py):
1. Filter test IPs from ipraw files using label files (known IPs only)
2. Build device fingerprint text for each IP
3. Call the local base Llama-3.1-8B-Instruct via vLLM to identify device
   type + vendor (Top-3)
4. Save:
   - all_result_method1_{dev}.csv   (ip, true_type, pred_type, true_vendor,
                                     vendor_top1, vendor_top2, vendor_top3)
   - llm_result_{dev}.json          (full LLM output per IP)
   - llm_result_typeonly_{dev}.json + typeonly_result_{dev}.csv
                                     (Unknown-vendor IPs, type-only prompt)
   - all_result_type_{dev}.csv      (merged, input for type/vendor evaluation)
"""

import argparse
import os
import sys
import json
import re
import pandas as pd

# ── Path setup ────────────────────────────────────────────────────────
PREDICT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(PREDICT_DIR)))))
IPRAW_DIR      = os.path.join(BASE_DIR, 'platform_data', 'csv', 'all')
LABEL_DIR      = os.path.join(BASE_DIR, 'platform_data', 'csv', 'label', 'known')
FULL_LABEL_DIR = os.path.join(BASE_DIR, 'platform_data', 'csv', 'label')

LLAMA_MODEL_PATH = '/home/nfs/models/Llama-3.1-8B-Instruct'

DEVICE_TYPES = ['MEDIA_SERVER', 'VPN']

# ── CLI args ───────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description='Raw Llama-3.1-8B device type/vendor identification')
parser.add_argument('--devices', type=str, default=','.join(DEVICE_TYPES),
                    help='Comma-separated device types to process')
parser.add_argument('--type-only', action='store_true',
                    help='Skip known-vendor (type+vendor) inference; only run type-only loop '
                         'for Unknown-vendor IPs, then merge into all_result_type_{dev}.csv')
parser.add_argument('--max-model-len', type=int, default=16384)
parser.add_argument('--max-tokens', type=int, default=1024)
parser.add_argument('--gpu-mem', type=float, default=0.90)
args = parser.parse_args()

DEVICE_TYPES = [d.strip() for d in args.devices.split(',') if d.strip()]

# Known device type candidates (for LLM context)
ALL_DEVICE_TYPES = [
    'CAMERA', 'PRINTER', 'SCADA', 'NAS', 'ROUTER', 'NVR', "POWER_METER",
    'MEDIA_SERVER', 'VPN', 'BUILDING_AUTOMATION', 'MEDICAL', 'UNKNOWN'
]

# ── Helpers ────────────────────────────────────────────────────────────

def safe_str(val):
    if pd.isna(val) or val is None:
        return ''
    return str(val).strip()


def get_field(fp, field):
    return safe_str(fp.get(field, ''))


def build_fingerprint_text(fp):
    """Extract key fingerprint fields into concise text for LLM prompt."""
    fields = [
        ('Service Distribution',      'service-distribution'),
        ('Software Vendors',          'sw-vendors'),
        ('Software Products',         'sw-products'),
        ('Software Versions',         'sw-versions'),
        ('Software Info',             'sw-info'),
        ('Hardware Vendors',          'hw-vendors'),
        ('Hardware Products',         'hw-products'),
        ('Hardware Info',             'hw-info'),
        ('OS Vendor',                 'os-vendor'),
        ('OS Product',                'os-product'),
        ('OS Version',                'os-version'),
        ('TLS Certificate Subjects',  'cert-subjects'),
        ('TLS Certificate Issuers',   'cert-issuers'),
        ('TLS Certificate Info',      'cert-info'),
        ('TLS Versions',              'tls-versions'),
        ('HTTP Tags',                 'http-tags'),
        ('HTTP Favicon Hashes',       'http-favicon-hashes'),
        ('DNS Reverse',               'dns-reverse'),
        ('AS Name',                   'as-name'),
        ('WHOIS Organization',        'whois-organization-name'),
        ('Country',                   'loc-country'),
    ]
    lines = []
    for label, key in fields:
        val = get_field(fp, key)
        if val:
            if len(val) > 500:
                val = val[:500] + '...[truncated]'
            lines.append(f'- {label}: {val}')
    return '\n'.join(lines) if lines else '(No fingerprint data available)'


# ── Prompts (identical to the ClaudeOpus baseline) ────────────────────

SYSTEM_PROMPT = f"""You are an expert in IoT device fingerprinting, classification, and vendor identification.
Given a device fingerprint (network scan data), you must:
1. Identify the **device type** (exactly one label).
2. Identify the **vendor** (manufacturer/software brand), returning up to 3 high-confidence candidates.

**Device type candidates**: {', '.join(ALL_DEVICE_TYPES)}
- Use "UNKNOWN" for device type only if you cannot determine it with any confidence.

**Vendor identification rules**:
- Return a list of 1–3 vendors that you have high confidence in. Do NOT pad to 3 if only 1–2 are clearly supported by evidence.
- If you cannot identify any vendor with reasonable confidence, return ["unknown"].
- Each vendor entry should include a confidence score (0.0–1.0).

**Confidence thresholds**:
- High: ≥ 0.65 → include in vendor list
- Low:  < 0.65 → mark vendor as "unknown" OR omit that candidate

**Ambiguous keywords**: If the fingerprint contains technical terms, product names, or identifiers that you do not recognize or are uncertain about, list them in "ambiguous_keywords".

Respond ONLY in valid JSON with this exact structure:
{{
  "device_type": "<TYPE or UNKNOWN>",
  "type_confidence": <0.0–1.0>,
  "type_reason": "<concise explanation for device type assignment>",
  "vendor_top3": [
    {{"vendor": "<name>", "confidence": <0.0–1.0>}},
    ...
  ],
  "vendor_reason": "<concise explanation for vendor identification>",
  "ambiguous_keywords": ["<keyword1>", ...]
}}

If vendor confidence is below threshold for ALL candidates, set vendor_top3 to [{{"vendor": "unknown", "confidence": 0.0}}].
Write all text in English."""


SYSTEM_PROMPT_TYPE_ONLY = f"""You are an expert in IoT device fingerprinting and classification.
Given a device fingerprint (network scan data), identify the **device type** (exactly one label).

**Device type candidates**: {', '.join(ALL_DEVICE_TYPES)}
- Use "UNKNOWN" only if you cannot determine the type with any confidence.

**Ambiguous keywords**: If the fingerprint contains technical terms or identifiers that you do not recognize, list them in "ambiguous_keywords".

Respond ONLY in valid JSON with this exact structure:
{{
  "device_type": "<TYPE or UNKNOWN>",
  "type_confidence": <0.0–1.0>,
  "type_reason": "<concise explanation>",
  "ambiguous_keywords": ["<keyword1>", ...]
}}
Write all text in English."""


def build_user_prompt(ip, fp_text):
    return f"""Analyze the following IoT device fingerprint and identify its type and vendor.

**Device IP**: {ip}

**Device Fingerprint**:
{fp_text}

Return your analysis as JSON."""


def build_user_prompt_type_only(ip, fp_text):
    return f"""Analyze the following IoT device fingerprint and identify its device type.

**Device IP**: {ip}

**Device Fingerprint**:
{fp_text}

Return your analysis as JSON."""


# ── LLM output parsing ─────────────────────────────────────────────────

def _to_float(val, default=0.0):
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def parse_llm_json(text):
    """Extract the first JSON object from raw LLM output; None on failure."""
    if not text:
        return None
    start = text.find('{')
    if start == -1:
        return None
    # Walk to the matching closing brace (handles nested braces in strings poorly,
    # but Llama JSON output is well-formed in practice).
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == '\\':
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                cand = text[start:i + 1]
                try:
                    return json.loads(cand)
                except json.JSONDecodeError:
                    # Retry after removing trailing commas
                    try:
                        return json.loads(re.sub(r',\s*([}\]])', r'\1', cand))
                    except json.JSONDecodeError:
                        return None
    return None


def parse_response(text):
    """Normalise one raw LLM output into the response dict the pipeline expects."""
    data = parse_llm_json(text)
    if data is None:
        data = {}

    device_type = safe_str(data.get('device_type')).upper()
    if not device_type:
        # Fallback: look for the first "device_type": "..." occurrence
        m = re.search(r'"device_type"\s*:\s*"([^"]+)"', text or '')
        device_type = m.group(1).strip().upper() if m else 'UNKNOWN'

    raw_v3 = data.get('vendor_top3', [])
    if not isinstance(raw_v3, list):
        raw_v3 = []
    vendors = []
    for v in raw_v3:
        if isinstance(v, dict):
            name = safe_str(v.get('vendor'))
            if name:
                vendors.append({'vendor': name, 'confidence': _to_float(v.get('confidence'))})
        elif isinstance(v, str) and v.strip():
            vendors.append({'vendor': v.strip(), 'confidence': 0.0})

    ambiguous = data.get('ambiguous_keywords', [])
    if not isinstance(ambiguous, list):
        ambiguous = [str(ambiguous)]

    return {
        'device_type':       device_type,
        'type_confidence':   _to_float(data.get('type_confidence')),
        'type_reason':       safe_str(data.get('type_reason')),
        'vendor_top3':       vendors,
        'vendor_reason':     safe_str(data.get('vendor_reason')),
        'ambiguous_keywords': ambiguous,
    }


def normalise_vendors(response):
    """Filter vendor_top3 to high-confidence entries (>= 0.65), as in the baseline."""
    raw_v3 = response.get('vendor_top3', [])
    if isinstance(raw_v3, list):
        high_conf = [
            v for v in raw_v3
            if isinstance(v, dict) and float(v.get('confidence', 0)) >= 0.65
        ]
    else:
        high_conf = []
    if not high_conf:
        high_conf = [{'vendor': 'unknown', 'confidence': 0.0}]
    return high_conf


# ── Load data ─────────────────────────────────────────────────────────

print('Loading label and fingerprint data...')

label_dfs         = {}   # dev -> DataFrame(ip, vendor)
ipraw_dfs         = {}   # dev -> DataFrame(all columns, filtered to known-vendor IPs)
unknown_ipraw_dfs = {}   # dev -> DataFrame(all columns, filtered to Unknown-vendor IPs)

for dev in DEVICE_TYPES:
    label_path      = os.path.join(LABEL_DIR,      f'label_nonempty_{dev}.csv')
    full_label_path = os.path.join(FULL_LABEL_DIR, f'label_{dev}.csv')
    ipraw_path      = os.path.join(IPRAW_DIR,      f'ipraw_{dev}.csv')

    df_label = pd.read_csv(label_path)
    df_ipraw = pd.read_csv(ipraw_path, low_memory=False)
    df_ipraw.columns = [str(c).lstrip('﻿').strip() for c in df_ipraw.columns]

    known_ips = set(df_label['ip'].astype(str))
    df_test   = df_ipraw[df_ipraw['ip'].astype(str).isin(known_ips)].copy()

    df_full  = pd.read_csv(full_label_path)
    unk_ips  = set(df_full[df_full['vendor'].str.upper() == 'UNKNOWN']['ip'].astype(str))
    df_unk_test = df_ipraw[df_ipraw['ip'].astype(str).isin(unk_ips)].copy()

    label_dfs[dev]         = df_label
    ipraw_dfs[dev]         = df_test
    unknown_ipraw_dfs[dev] = df_unk_test

    print(f'  [{dev}] Known-vendor IPs: {len(known_ips)} | Matched in ipraw: {len(df_test)}')
    print(f'  [{dev}] Unknown-vendor IPs: {len(unk_ips)} | Matched in ipraw: {len(df_unk_test)}')


# ── Initialize vLLM engine ────────────────────────────────────────────

print(f'\nInitializing Llama-3.1-8B-Instruct (raw) from {LLAMA_MODEL_PATH} ...')
from vllm import LLM, SamplingParams

llm = LLM(
    model=LLAMA_MODEL_PATH,
    max_model_len=args.max_model_len,
    gpu_memory_utilization=args.gpu_mem,
    enable_prefix_caching=True,
)
sampling_params = SamplingParams(temperature=0.0, max_tokens=args.max_tokens)


def run_batch(df, system_prompt, user_prompt_builder):
    """Run batch chat inference over all rows; returns ip -> parsed response."""
    conversations = []
    ips = []
    for _, row in df.iterrows():
        ip = str(row['ip'])
        fp_text = build_fingerprint_text(row.to_dict())
        conversations.append([
            {'role': 'system', 'content': system_prompt},
            {'role': 'user',   'content': user_prompt_builder(ip, fp_text)},
        ])
        ips.append(ip)

    print(f'  Running vLLM batch inference on {len(conversations)} prompts ...')
    outputs = llm.chat(conversations, sampling_params)

    parsed = {}
    n_bad = 0
    for ip, out in zip(ips, outputs):
        text = out.outputs[0].text
        response = parse_response(text)
        if response['device_type'] in ('', 'UNKNOWN') and not response['type_reason']:
            n_bad += 1
        parsed[ip] = response
    if n_bad:
        print(f'  Warning: {n_bad}/{len(ips)} outputs could not be parsed to JSON')
    return parsed


# ── Main inference loop ───────────────────────────────────────────────

if args.type_only:
    print('\n[--type-only] Skipping known-vendor inference loop.')

for dev in DEVICE_TYPES if not args.type_only else []:
    print(f'\n{"=" * 60}')
    print(f'Processing [{dev}]')
    print('=' * 60)

    df_label = label_dfs[dev]
    df_test  = ipraw_dfs[dev]

    # Build ip→vendor ground truth map
    true_vendor_map = dict(zip(df_label['ip'].astype(str), df_label['vendor']))

    # Output paths
    csv_path  = os.path.join(PREDICT_DIR, f'all_result_method1_{dev}.csv')
    json_path = os.path.join(PREDICT_DIR, f'llm_result_{dev}.json')

    # Resume support: load existing JSON results
    existing = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                old_data = json.load(f)
            for entry in old_data:
                if 'device_type' in entry:
                    existing[entry['ip']] = entry
            print(f'  Loaded {len(existing)} cached results (resume mode)')
        except Exception:
            pass

    # Batch inference only for IPs not yet cached
    todo = df_test[~df_test['ip'].astype(str).isin(existing)]
    parsed = run_batch(todo, SYSTEM_PROMPT, build_user_prompt) if len(todo) else {}

    results_json = []   # full LLM output per IP
    results_csv  = []   # flattened for CSV

    total = len(df_test)
    for idx, (_, row) in enumerate(df_test.iterrows(), 1):
        ip       = str(row['ip'])
        true_v   = true_vendor_map.get(ip, 'unknown')
        true_t   = dev

        if ip in existing:
            entry = existing[ip]
        elif ip in parsed:
            response = parsed[ip]
            high_conf = normalise_vendors(response)
            entry = {
                'ip':                ip,
                'true_type':         true_t,
                'true_vendor':       true_v,
                'device_type':       response.get('device_type', 'UNKNOWN'),
                'type_confidence':   response.get('type_confidence', 0.0),
                'type_reason':       response.get('type_reason', ''),
                'vendor_top3':       high_conf,
                'vendor_reason':     response.get('vendor_reason', ''),
                'ambiguous_keywords': response.get('ambiguous_keywords', []),
            }
        else:
            entry = {
                'ip':                ip,
                'true_type':         true_t,
                'true_vendor':       true_v,
                'device_type':       'UNKNOWN',
                'type_confidence':   0.0,
                'type_reason':       'LLM error: no output',
                'vendor_top3':       [{'vendor': 'unknown', 'confidence': 0.0}],
                'vendor_reason':     'LLM error: no output',
                'ambiguous_keywords': [],
            }

        results_json.append(entry)
        v3 = entry.get('vendor_top3', [])
        results_csv.append({
            'ip':          ip,
            'true_type':   true_t,
            'pred_type':   entry.get('device_type', 'unknown'),
            'true_vendor': true_v,
            'vendor_top1': v3[0]['vendor'] if len(v3) > 0 else 'unknown',
            'vendor_top2': v3[1]['vendor'] if len(v3) > 1 else '',
            'vendor_top3': v3[2]['vendor'] if len(v3) > 2 else '',
            'type_confidence':  entry.get('type_confidence', 0.0),
            'vendor_top1_conf': v3[0].get('confidence', 0.0) if len(v3) > 0 else 0.0,
        })
        if idx % 1000 == 0:
            print(f'  [{idx}/{total}] stitched')

    # Final save
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(results_json, f, ensure_ascii=False, indent=2)
    pd.DataFrame(results_csv).to_csv(csv_path, index=False)

    n_total       = len(results_csv)
    n_type_ok     = sum(1 for r in results_csv if r['pred_type'] == r['true_type'])
    n_vendor_unk  = sum(1 for r in results_csv if r['vendor_top1'] == 'unknown')
    n_vendor_ok   = sum(
        1 for r in results_csv
        if r['vendor_top1'] == r['true_vendor']
    )
    print(f'\n  [{dev}] Done. Total={n_total} | '
          f'Type Acc={n_type_ok/n_total:.2%} | '
          f'Vendor Top-1 Acc={n_vendor_ok/n_total:.2%} | '
          f'Vendor Unknown={n_vendor_unk}')
    print(f'  Saved CSV  → {csv_path}')
    print(f'  Saved JSON → {json_path}')

# ── Type-only inference for Unknown-vendor IPs ────────────────────────

for dev in DEVICE_TYPES:
    print(f'\n{"=" * 60}')
    print(f'Processing type-only [{dev}] (Unknown-vendor IPs)')
    print('=' * 60)

    df_unk_test = unknown_ipraw_dfs[dev]

    json_path_to = os.path.join(PREDICT_DIR, f'llm_result_typeonly_{dev}.json')
    csv_path_to  = os.path.join(PREDICT_DIR, f'typeonly_result_{dev}.csv')

    # Resume support
    existing_to = {}
    if os.path.exists(json_path_to):
        try:
            with open(json_path_to, 'r', encoding='utf-8') as f:
                old_data = json.load(f)
            for entry in old_data:
                if 'device_type' in entry:
                    existing_to[entry['ip']] = entry
            print(f'  Loaded {len(existing_to)} cached results (resume mode)')
        except Exception:
            pass

    todo = df_unk_test[~df_unk_test['ip'].astype(str).isin(existing_to)]
    parsed = run_batch(todo, SYSTEM_PROMPT_TYPE_ONLY, build_user_prompt_type_only) if len(todo) else {}

    results_json_to = []
    results_csv_to  = []

    total = len(df_unk_test)
    for idx, (_, row) in enumerate(df_unk_test.iterrows(), 1):
        ip     = str(row['ip'])
        true_t = dev

        if ip in existing_to:
            entry = existing_to[ip]
        elif ip in parsed:
            response = parsed[ip]
            entry = {
                'ip':                ip,
                'true_type':         true_t,
                'true_vendor':       'Unknown',
                'device_type':       response.get('device_type', 'UNKNOWN'),
                'type_confidence':   response.get('type_confidence', 0.0),
                'type_reason':       response.get('type_reason', ''),
                'ambiguous_keywords': response.get('ambiguous_keywords', []),
                'type_only':         True,
            }
        else:
            entry = {
                'ip':                ip,
                'true_type':         true_t,
                'true_vendor':       'Unknown',
                'device_type':       'UNKNOWN',
                'type_confidence':   0.0,
                'type_reason':       'LLM error: no output',
                'ambiguous_keywords': [],
                'type_only':         True,
            }

        results_json_to.append(entry)
        results_csv_to.append({
            'ip':               ip,
            'true_type':        true_t,
            'pred_type':        entry.get('device_type', 'UNKNOWN'),
            'true_vendor':      'Unknown',
            'vendor_top1':      '',
            'vendor_top2':      '',
            'vendor_top3':      '',
            'type_confidence':  entry.get('type_confidence', 0.0),
            'vendor_top1_conf': '',
        })
        if idx % 1000 == 0:
            print(f'  [{idx}/{total}] stitched')

    # Final save
    with open(json_path_to, 'w', encoding='utf-8') as f:
        json.dump(results_json_to, f, ensure_ascii=False, indent=2)
    pd.DataFrame(results_csv_to).to_csv(csv_path_to, index=False)

    n_total = len(results_csv_to)
    if n_total > 0:
        n_type_ok = sum(1 for r in results_csv_to if r['pred_type'] == r['true_type'])
        print(f'\n  [{dev}] Type-only done. Total={n_total} | Type Acc={n_type_ok/n_total:.2%}')
    else:
        print(f'\n  [{dev}] No Unknown-vendor IPs to process.')
    print(f'  Saved JSON → {json_path_to}')
    print(f'  Saved CSV  → {csv_path_to}')

# ── Merge type results ─────────────────────────────────────────────────

print('\nMerging type+vendor and type-only results...')

for dev in DEVICE_TYPES:
    method1_path  = os.path.join(PREDICT_DIR, f'all_result_method1_{dev}.csv')
    typeonly_path = os.path.join(PREDICT_DIR, f'typeonly_result_{dev}.csv')
    merged_path   = os.path.join(PREDICT_DIR, f'all_result_type_{dev}.csv')

    df_method1  = pd.read_csv(method1_path)  if os.path.exists(method1_path)  else pd.DataFrame()
    df_typeonly = pd.read_csv(typeonly_path) if os.path.exists(typeonly_path) else pd.DataFrame()

    df_merged = pd.concat([df_method1, df_typeonly], ignore_index=True)
    df_merged.to_csv(merged_path, index=False)
    print(f'  [{dev}] Merged {len(df_method1)} known-vendor + {len(df_typeonly)} type-only = {len(df_merged)} total')
    print(f'  Saved → {merged_path}')

print('\nAll done!')
