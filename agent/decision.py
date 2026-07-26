"""
agent/decision.py

IoT Device Type Decision Agent.
Uses LangChain to build two independent classification agents (Gemini + Claude),
each equipped with a single unified multi-level retrieval tool. Joint voting by
confidence score determines the final device type and vendor prediction.

First-stage gate (per Figure 1 "First-stage Results"):
  1. Unseen detection (fine-tuned LLaMA)   → new_type_probability, new_vendor_probability + labels.
  2. If BOTH probabilities < 0.5, run in-class concept-drift detection (PACA AutoEncoder)
     → probability / verdict of in-class concept drift for the queried device.
  3. Regardless of the first-stage outcome, joint voting (Gemini + Claude) produces the
     final device type + vendor with reasoning.
"""

import os
import sys
import json
import re
import logging
import time
from threading import RLock
from typing import Any, Dict, List, Optional

import pandas as pd

# ── project root on path ──────────────────────────────────────────────────────
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from langchain_core.tools import tool
from langchain_classic.agents import AgentExecutor, create_openai_tools_agent
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import SystemMessage, HumanMessage

from util import load_all_dev_labels, convert_json_from_str

# ── logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    filename=os.path.join(os.path.dirname(os.path.abspath(__file__)), "decision.log"),
    filemode="a",
)

# ── path constants ────────────────────────────────────────────────────────────
_BASE      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LOCAL_RAW = os.path.join(_BASE, "platform_data", "csv", "local", "1")
_VAL_PATH  = os.path.join(_BASE, "evaluation", "validation")
_QDB_PATH  = os.path.join(_BASE, "agent", "query_db")
_RES_PATH  = os.path.join(_BASE, "evaluation", "predict")
_CFG_PATH  = os.path.join(_BASE, "llm_config.json")

# ── module-level state shared with @tool closures ─────────────────────────────
_dev_labels: List[str] = []


# ═════════════════════════════════════════════════════════════════════════════
# §1  Multi-Level Retrieval Tool (three retrieval levels unified as ONE tool)
# ═════════════════════════════════════════════════════════════════════════════
#
# Per the framework's control plane ("Multi-Level Retrieval [As a Tool]"), the three
# retrieval algorithms implemented by agent/retrieval.py::MultiLevelRetrieval —
# local-entity, community, and reasoning-path — are exposed to the Decision Agent as
# a SINGLE tool (`multi_level_retrieval`). One call returns all three retrieval levels
# for the query device, so the agent invokes retrieval once rather than orchestrating
# three separate tools.

def _lookup_qdb(sub: str, ip: str) -> Dict:
    """
    Search query_db/{sub}/{DEV}_{sub}.json for an entry whose
    query_fingerprint.ip matches *ip*.  Returns the raw entry on hit.
    """
    db_dir = os.path.join(_QDB_PATH, sub)
    for dev in _dev_labels:
        fp = os.path.join(db_dir, f"{dev}_{sub}.json")
        if not os.path.exists(fp):
            continue
        with open(fp, "r", encoding="utf-8") as fh:
            entries = json.load(fh)
        for entry in entries:
            if str(entry.get("query_fingerprint", {}).get("ip", "")) == str(ip):
                return {"status": "found", "candidate_dev": dev, "entry": entry}
    return {"status": "not_found", "ip": ip}


def _lookup_result(sub: str, ip: str) -> Optional[Dict]:
    """
    Return the full retrieval-result record (local / community / reasoning) for *ip*
    from query_db/{sub}/, or None if not found. Used to feed the unseen detector
    with the same structured retrieval outputs it consumes at inference time.
    """
    hit = _lookup_qdb(sub, ip)
    return hit["entry"] if hit.get("status") == "found" else None


# ── Level 1: Local entity retrieval section ───────────────────────────────────

def _local_section(ip: str) -> Dict:
    """
    Local embedding-based retrieval: top-k most similar known IoT devices to the
    query device, by comparing multi-perspective network fingerprint embeddings
    stored in the vector database. Returns device_type + cosine similarity scores.
    """
    hit = _lookup_qdb("local", ip)
    if hit["status"] == "not_found":
        return {"status": "not_found"}

    entry = hit["entry"]
    return {
        "status": "found",
        "candidate_dev": hit["candidate_dev"],
        "top_k": entry.get("top_k", 5),
        "similar_devices": entry.get("similar_devices", []),
    }


# ── Level 2: Community / cluster-level retrieval section ───────────────────────

def _community_section(ip: str) -> Dict:
    """
    Community / cluster-level retrieval: which device behaviour clusters the query
    device belongs to (based on the similar IPs from local retrieval). Returns
    matched cluster common-pattern reports and per-cluster similarity scores.
    """
    hit = _lookup_qdb("community", ip)
    if hit["status"] == "not_found":
        return {"status": "not_found"}

    entry = hit["entry"]
    matched = entry.get("matched_clusters", [])
    trimmed = []
    for c in matched[:5]:
        report = c.get("report", {})
        if isinstance(report, dict):
            raw_patterns = report.get("common_patterns", {})
            patterns = (
                {k: str(v)[:300] for k, v in list(raw_patterns.items())[:8]}
                if isinstance(raw_patterns, dict)
                else str(raw_patterns)[:500]
            )
        else:
            patterns = str(report)[:500]

        trimmed.append(
            {
                "device_type":       c.get("device_type"),
                "cluster_id":        c.get("cluster_id"),
                "similarity_score":  c.get("similarity_score"),
                "common_patterns":   patterns,
                "matched_features":  c.get("matched_features", [])[:3],
                "unmatched_features": c.get("unmatched_features", [])[:3],
            }
        )

    return {
        "status":         "found",
        "total_clusters": entry.get("total_clusters", len(matched)),
        "matched_clusters": trimmed,
    }


# ── Level 3: Reasoning-path retrieval section ─────────────────────────────────

def _reasoning_section(ip: str) -> Dict:
    """
    Reasoning path retrieval: the key discriminative features that place the query
    device into a particular cluster, via Shannon entropy-based feature importance.
    Returns path matching scores and weighted per-feature similarity breakdowns.
    """
    hit = _lookup_qdb("reasoning", ip)
    if hit["status"] == "not_found":
        return {"status": "not_found"}

    entry = hit["entry"]
    path_results = entry.get("path_matching_results", [])
    trimmed = []
    for pr in path_results[:3]:
        ci = pr.get("cluster_info", {})
        details = sorted(
            pr.get("feature_matching_details", []),
            key=lambda x: x.get("importance_score", 0),
            reverse=True,
        )[:4]
        trimmed.append(
            {
                "cluster_key":        pr.get("cluster_key"),
                "device_type":        ci.get("device_type"),
                "path_matching_score": pr.get("path_matching_score"),
                "important_features": pr.get("important_features", [])[:5],
                "top_feature_scores": [
                    {
                        "feature":        fd.get("feature_name"),
                        "importance":     fd.get("importance_score"),
                        "matching_score": fd.get("feature_matching_score"),
                    }
                    for fd in details
                ],
            }
        )

    summary = entry.get("summary") or {}
    top_cluster = summary.get("top_cluster") or {}
    return {
        "status":               "found",
        "path_matching_results": trimmed,
        "top_cluster_key":      top_cluster.get("cluster_key"),
    }


@tool
def multi_level_retrieval(ip: str) -> str:
    """
    Multi-Level Retrieval — the single unified RAG tool for the Decision Agent.
    In one call it runs all THREE retrieval levels for the query device and returns
    their combined evidence:

      1. local_entity_retrieval    – top-k most similar known devices (vector similarity)
      2. community_retrieval       – cluster-level behavioural common-pattern reports
      3. reasoning_path_retrieval  – key discriminative features (Shannon-entropy importance)

    Call this tool ONCE per device; it returns all three retrieval levels together,
    so there is no need to invoke separate retrieval tools.

    Args:
        ip: IP address of the query device.
    """
    combined = {
        "ip": ip,
        "local_entity_retrieval":   _local_section(ip),
        "community_retrieval":      _community_section(ip),
        "reasoning_path_retrieval": _reasoning_section(ip),
    }
    return json.dumps(combined, ensure_ascii=False, indent=2)


_TOOLS = [multi_level_retrieval]


# ═════════════════════════════════════════════════════════════════════════════
# §1b  Configurable Retrieval Tool Runtime (for the LangGraph decision branches)
# ═════════════════════════════════════════════════════════════════════════════
#
# The LangGraph decision LLM nodes call ONE unified retrieval tool. Which of the
# three retrieval algorithms it actually runs is controlled by the CLI flags
# (--local / --community / --reasoning); when none are supplied the default is
# "all". The runtime lazily runs the live MultiLevelRetrieval algorithms for the
# enabled levels (skipping any already cached in query_db), then returns the same
# trimmed evidence sections consumed by the legacy tool.

class RetrievalToolRuntime:
    """
    可配置的检索工具运行时: 按 (--local / --community / --reasoning) 选择要运行的检索算法, 默认全部.
    Configurable retrieval runtime shared by the LangGraph decision branches.
    """

    def __init__(
        self,
        whether_local: bool = True,
        whether_community: bool = True,
        whether_reasoning: bool = True,
        top_k: int = 5,
        llm_type: str = "CLAUDE",
        retrieval_agent: Any = None,
    ):
        # 若三者都未开启, 默认运行全部 / default to all when nothing is enabled
        if not (whether_local or whether_community or whether_reasoning):
            whether_local = whether_community = whether_reasoning = True
        self.whether_local = whether_local
        self.whether_community = whether_community
        self.whether_reasoning = whether_reasoning
        self.top_k = top_k
        self.llm_type = llm_type
        self.retrieval_agent = retrieval_agent
        self._context: Dict[str, Dict[str, Any]] = {}
        self._lock = RLock()

    # ── per-IP context (device label + fingerprint) ──
    def register(self, ip: str, device_name: str, fingerprint: Dict[str, Any]) -> None:
        with self._lock:
            self._context[str(ip)] = {
                "device_name": device_name,
                "fingerprint": fingerprint,
            }
            global _dev_labels
            if device_name and device_name not in _dev_labels:
                _dev_labels = list(_dev_labels) + [device_name]

    def _ensure_retrieved(self, ip: str, ctx: Dict[str, Any]) -> None:
        """Run the enabled retrieval algorithms for levels not yet cached in query_db."""
        if self.retrieval_agent is None:
            return
        device_name = ctx["device_name"]
        fingerprint = ctx["fingerprint"]
        existing_local, existing_community, existing_reasoning = (
            self.retrieval_agent.load_retrieval_result_by_type(ip, device_name)
        )
        need_local = self.whether_local and existing_local is None
        need_community = self.whether_community and existing_community is None
        need_reasoning = self.whether_reasoning and existing_reasoning is None
        if not (need_local or need_community or need_reasoning):
            return
        # community / reasoning cascade requires local + community to exist
        run_local = need_local
        run_community = need_community or (need_reasoning and existing_community is None)
        with self._lock:
            self.retrieval_agent.run_retrieval_algorithm(
                test_fingerprint=fingerprint,
                top_k=self.top_k,
                whether_local=run_local,
                whether_community=run_community,
                whether_reasoning=need_reasoning,
                local_result=existing_local,
                community_result=existing_community,
                llm_type=self.llm_type,
                device_name=device_name,
            )
            self.retrieval_agent.clear_history()

    def ensure(self, ip: str) -> None:
        """Public helper: run enabled retrieval algorithms for *ip* if not cached."""
        ctx = self._context.get(str(ip))
        if ctx is not None:
            self._ensure_retrieved(str(ip), ctx)

    def run(self, ip: str) -> Dict[str, Any]:
        ip = str(ip)
        ctx = self._context.get(ip)
        if ctx is not None:
            try:
                self._ensure_retrieved(ip, ctx)
            except Exception as exc:  # pragma: no cover - live retrieval is best-effort
                logging.warning("Live retrieval failed for %s: %s", ip, exc)

        combined: Dict[str, Any] = {"ip": ip, "levels_run": []}
        if self.whether_local:
            combined["local_entity_retrieval"] = _local_section(ip)
            combined["levels_run"].append("local")
        if self.whether_community:
            combined["community_retrieval"] = _community_section(ip)
            combined["levels_run"].append("community")
        if self.whether_reasoning:
            combined["reasoning_path_retrieval"] = _reasoning_section(ip)
            combined["levels_run"].append("reasoning")
        return combined


# module-level runtime consulted by the configurable tool closure
_retrieval_runtime: Optional[RetrievalToolRuntime] = None


def set_retrieval_runtime(runtime: Optional[RetrievalToolRuntime]) -> None:
    """Register the runtime that the configurable retrieval tool should use."""
    global _retrieval_runtime
    _retrieval_runtime = runtime


@tool
def configurable_multi_level_retrieval(ip: str) -> str:
    """
    Multi-Level Retrieval — the single unified RAG tool for the Decision Agent.
    It runs the enabled retrieval algorithms (local-entity, community, and/or
    reasoning-path, selected via the --local/--community/--reasoning flags,
    defaulting to all) for the query device and returns their combined evidence.

    You MUST call this tool exactly once, before any analysis, and base your
    reasoning on its result.

    Args:
        ip: IP address of the query device.
    """
    runtime = _retrieval_runtime
    if runtime is not None:
        combined = runtime.run(ip)
    else:
        combined = {
            "ip": ip,
            "local_entity_retrieval": _local_section(ip),
            "community_retrieval": _community_section(ip),
            "reasoning_path_retrieval": _reasoning_section(ip),
        }
    return json.dumps(combined, ensure_ascii=False, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
# §1c  Shared helpers for the LangGraph decision branches
# ═════════════════════════════════════════════════════════════════════════════

def extract_decision_json(text: str) -> Dict[str, Any]:
    """Module-level wrapper around the robust JSON extractor."""
    return DecisionAgent._extract_json(text)


def normalize_decision(parsed: Dict[str, Any], llm_name: str, raw_output: str) -> Dict[str, Any]:
    """Normalise a parsed LLM answer into the canonical classification dict."""
    parsed = dict(parsed or {})
    parsed.setdefault("device_type", "UNKNOWN")
    parsed.setdefault("device_type_reason", "")
    parsed.setdefault("vendor", "Unknown")
    parsed.setdefault("vendor_reason", "")
    parsed["confidence"] = float(parsed.get("confidence", 0.0))
    parsed["device_type"] = str(parsed["device_type"]).upper().strip()
    parsed["vendor"] = str(parsed.get("vendor", "Unknown"))
    parsed["device_type_reason"] = str(parsed.get("device_type_reason", ""))
    parsed["vendor_reason"] = str(parsed.get("vendor_reason", ""))
    parsed["llm"] = llm_name
    parsed["full_response"] = raw_output
    return parsed


def joint_vote(gemini: Dict[str, Any], claude: Dict[str, Any]) -> Dict[str, Any]:
    """Module-level wrapper around the DecisionAgent joint-voting strategy."""
    return DecisionAgent._joint_vote(gemini, claude)


# ═════════════════════════════════════════════════════════════════════════════
# §2  Prompt Templates
# ═════════════════════════════════════════════════════════════════════════════

_AGENT_SYSTEM = """\
You are an expert IoT network device classifier with deep knowledge of network
traffic fingerprinting. Your mission is to identify the **device type** and
**manufacturer/vendor** of an unknown IoT device.

## Candidate Device Types
CAMERA | NVR | ROUTER | NAS | PRINTER | MEDICAL | SCADA | BUILDING_AUTOMATION | POWER_METER

## Your Workflow
You have access to ONE unified multi-level retrieval tool that returns the
enabled retrieval levels in a single call:
  multi_level_retrieval(ip) → {
     local_entity_retrieval:    top-k similar known devices,
     community_retrieval:       cluster-level behavioural patterns,
     reasoning_path_retrieval:  discriminative feature importance
  }

You MUST call the multi_level_retrieval tool EXACTLY ONCE, as your very first
action, before producing any analysis. Do NOT emit your final JSON answer until
you have received the tool result. After the tool returns, reason step by step
through the Chain-of-Thought framework below, then emit your final JSON answer.

## Chain-of-Thought Reasoning Framework

**[Step 1] Hardware & Software Fingerprint**
Analyse hw-vendors, hw-products, sw-vendors, sw-products, sw-versions.
What manufacturer/product identifiers are present?

**[Step 2] Network Service Profile**
Examine service-distribution (open ports). Characteristic patterns:
  - NVR / Camera → RTSP-554, HTTP-8000, ONVIF
  - Router       → Telnet-23, SSH-22, HTTP-80/443
  - Printer      → IPP-631, JetDirect-9100, LPD-515
  - NAS          → SMB-445, NFS-2049, FTP-21
  - SCADA        → Modbus-502, DNP3-20000, BACnet-47808
  - Medical      → HL7/DICOM, HTTP-8080
  - Power Meter  → DLMS/COSEM, IEC 61850

**[Step 3] TLS / Certificate Evidence**
Analyse cert-subjects, cert-issuers, tls-versions.
Self-signed vs CA-signed? Subject organisation name?

**[Step 4] HTTP Behavioural Signature**
Analyse http-bodys (HTML content), http-tags (title/meta), http-favicon-hashes.
What type of web interface does this suggest?

**[Step 5] ASN & Location Context**
Examine as-name, as-country_code, whois-network-name.
Consumer ISP → likely endpoint device; Cloud ASN → possible scanner/honeypot.

**[Step 6] Local Retrieval Evidence**
Review top-k similar devices. Dominant device type? Similarity scores?
(>0.85 = very strong, 0.70–0.85 = moderate, <0.70 = weak)

**[Step 7] Community Cluster Evidence**
Review matched clusters: similarity scores, common patterns, matched/unmatched
features. Do they corroborate the fingerprint analysis?

**[Step 8] Reasoning Path Evidence**
Review path matching scores and feature importance. Which features are most
discriminative and do they align with the query device?

**[Step 9] Synthesis & Confidence**
Weigh all evidence. Assign confidence:
  0.90–1.00 – overwhelming, consistent evidence across all sources
  0.75–0.89 – strong evidence with minor gaps
  0.60–0.74 – moderate evidence, some conflicting signals
  0.40–0.59 – weak evidence, notable uncertainty
  0.00–0.39 – very uncertain, mostly noise

## Required Final Output
After your chain-of-thought, output a **single JSON block** (no trailing text):
```json
{
  "step1_hardware":      "<analysis>",
  "step2_services":      "<analysis>",
  "step3_certs":         "<analysis>",
  "step4_http":          "<analysis>",
  "step5_asn":           "<analysis>",
  "step6_local":         "<analysis>",
  "step7_community":     "<analysis>",
  "step8_reasoning":     "<analysis>",
  "step9_synthesis":     "<analysis>",
  "device_type":         "<ONE type from the candidate list>",
  "device_type_reason":  "<Concise explanation of the key evidence that led to this device type decision>",
  "vendor":              "<manufacturer name or 'Unknown'>",
  "vendor_reason":       "<Concise explanation of the key evidence that identified this specific vendor>",
  "confidence":          0.0
}
```
"""

_AGENT_HUMAN = """\
Classify the IoT device with IP address: {ip}

Raw network fingerprint (excluding null fields):
```json
{fingerprint}
```

Call the multi_level_retrieval tool for this IP, then apply the 9-step reasoning
framework, and output your final JSON classification.
"""


# ═════════════════════════════════════════════════════════════════════════════
# §3  DecisionAgent
# ═════════════════════════════════════════════════════════════════════════════

class DecisionAgent:
    """
    LangChain-based IoT device classification agent.

    Two independent LangChain AgentExecutors (Gemini + Claude) each:
      - call the unified multi_level_retrieval tool (local + community + reasoning_path)
      - perform 9-step chain-of-thought reasoning
      - output {device_type, vendor, confidence}

    Joint voting selects the result with the higher confidence score.
    When both LLMs agree on device_type, confidence is boosted slightly.
    """

    # ── construction ─────────────────────────────────────────────────────────

    def __init__(
        self,
        enable_first_stage: bool = True,
        unseen_adapter_path: Optional[str] = None,
        unseen_load_in_4bit: bool = True,
        drift_model_dir: Optional[str] = None,
        gpu: int = -1,
    ):
        os.makedirs(_RES_PATH, exist_ok=True)

        with open(_CFG_PATH, "r") as fh:
            self.cfg = json.load(fh)

        self.dev_labels: List[str] = load_all_dev_labels() or []
        global _dev_labels
        _dev_labels = self.dev_labels

        # ── first-stage (unseen + drift) configuration ──
        # 第一阶段 (unseen + drift) 检测配置; 模型缺失时自动降级跳过, 不阻断联合投票
        self.enable_first_stage = enable_first_stage
        self._unseen_adapter_path = unseen_adapter_path
        self._unseen_load_in_4bit = unseen_load_in_4bit
        self._drift_model_dir = drift_model_dir
        self._gpu = gpu
        self._unseen_detector = None   # lazy-loaded UnseenDeviceDetector
        self._drift_detector = None    # lazy-loaded DriftDetector

        # LangChain LLM clients (both accessed via OpenAI-compatible endpoints)
        self.gemini_llm = ChatOpenAI(
            api_key=self.cfg["GEMINI"]["API_KEY"],
            base_url=self.cfg["GEMINI"]["BASE_URL"],
            model=self.cfg["GEMINI"]["MODEL"],
            temperature=0.3,
            max_tokens=4096,
        )
        self.claude_llm = ChatOpenAI(
            api_key=self.cfg["CLAUDE"]["API_KEY"],
            base_url=self.cfg["CLAUDE"]["BASE_URL"],
            model=self.cfg["CLAUDE"]["MODEL"],
            temperature=0.3,
            max_tokens=4096,
        )

        # Build independent LangChain agents for each LLM
        self._gemini_executor = self._build_agent(self.gemini_llm)
        self._claude_executor  = self._build_agent(self.claude_llm)

        logging.info(
            "DecisionAgent initialised (Gemini + Claude, first_stage=%s).",
            self.enable_first_stage,
        )

    # ── first-stage detector loaders (lazy, fail-safe) ─────────────────────────

    def _get_unseen_detector(self):
        """
        懒加载 UnseenDeviceDetector (微调后的 LLaMA-3.1-8B, LoRA 4-bit).
        Lazily load the fine-tuned-LLaMA unseen detector. Returns None on failure
        so that decision-making degrades gracefully to joint voting only.
        """
        if self._unseen_detector is not None:
            return self._unseen_detector
        try:
            from unseen import UnseenDeviceDetector
            self._unseen_detector = UnseenDeviceDetector(
                adapter_path=self._unseen_adapter_path,
                gpu=self._gpu,
                load_in_4bit=self._unseen_load_in_4bit,
            )
        except Exception as exc:
            logging.warning("Unseen detector unavailable, skipping: %s", exc)
            self._unseen_detector = None
        return self._unseen_detector

    def _get_drift_detector(self):
        """
        懒加载 DriftDetector (训练好的 PACA AutoEncoder).
        Lazily load the trained PACA drift detector. Returns None on failure.
        """
        if self._drift_detector is not None:
            return self._drift_detector
        try:
            from drift import DriftDetector, DRIFT_OUTPUT_DIR
            model_dir = self._drift_model_dir or DRIFT_OUTPUT_DIR
            self._drift_detector = DriftDetector(model_dir=model_dir)
        except Exception as exc:
            logging.warning("Drift detector unavailable, skipping: %s", exc)
            self._drift_detector = None
        return self._drift_detector

    def _run_first_stage(
        self, ip: str, fingerprint: Dict
    ) -> Optional[Dict[str, Any]]:
        """
        执行第一阶段: 先 unseen 检测, 若「新类型」与「新厂商」概率均 < 0.5, 再做 drift 检测.
        Run the first-stage gate: unseen detection first; only when BOTH the
        new-type and new-vendor probabilities are < 0.5 do we run in-class
        concept-drift detection for the queried device.

        Returns a dict summarising the first-stage outcome, or None if disabled /
        no detector is available (so downstream joint voting is unaffected).
        """
        if not self.enable_first_stage:
            return None

        summary: Dict[str, Any] = {}

        # ── 1) Unseen detection ──
        detector = self._get_unseen_detector()
        unseen_res = None
        if detector is not None:
            try:
                local_result = _lookup_result("local", ip)
                community_result = _lookup_result("community", ip)
                reasoning_result = _lookup_result("reasoning", ip)
                if reasoning_result is not None:
                    unseen_res = detector.detect_unseen(
                        reasoning_result=reasoning_result,
                        local_result=local_result,
                        community_result=community_result,
                    )
                else:
                    logging.info("No reasoning result for %s; skipping unseen.", ip)
            except Exception as exc:
                logging.warning("Unseen detection failed for %s: %s", ip, exc)

        new_type_prob = float(unseen_res.get("new_type_probability", 0.0)) if unseen_res else 0.0
        new_vendor_prob = float(unseen_res.get("new_vendor_probability", 0.0)) if unseen_res else 0.0
        summary["unseen"] = {
            "new_type_probability": new_type_prob,
            "new_vendor_probability": new_vendor_prob,
            "is_unseen": bool(unseen_res.get("is_unseen")) if unseen_res else False,
            "predicted_type": unseen_res.get("predicted_type", "none") if unseen_res else "none",
            "predicted_vendor": unseen_res.get("predicted_vendor", "none") if unseen_res else "none",
            "confidence": unseen_res.get("confidence", 0.0) if unseen_res else 0.0,
            "available": unseen_res is not None,
        }

        # ── 2) In-class concept-drift detection (only when both probs < 0.5) ──
        # 仅当「新类型」与「新厂商」概率都 < 0.5 时才判定 in-class concept drift
        run_drift = (new_type_prob < 0.5) and (new_vendor_prob < 0.5)
        summary["drift_checked"] = run_drift
        if run_drift:
            drift_det = self._get_drift_detector()
            if drift_det is not None:
                try:
                    summary["drift"] = drift_det.detect_query_device(fingerprint)
                except Exception as exc:
                    logging.warning("Drift detection failed for %s: %s", ip, exc)
                    summary["drift"] = {"error": str(exc)}
            else:
                summary["drift"] = {"available": False}

        logging.info(
            "First-stage %s: new_type=%.2f new_vendor=%.2f drift_checked=%s",
            ip, new_type_prob, new_vendor_prob, run_drift,
        )
        return summary

    # ── agent construction ────────────────────────────────────────────────────

    def _build_agent(self, llm: ChatOpenAI) -> AgentExecutor:
        """
        Wrap *llm* in a LangChain AgentExecutor with the unified multi_level_retrieval tool.
        Uses create_openai_tools_agent which supports function-calling APIs.
        """
        prompt = ChatPromptTemplate.from_messages(
            [
                ("system",  _AGENT_SYSTEM),
                ("human",   _AGENT_HUMAN),
                MessagesPlaceholder("agent_scratchpad"),
            ]
        )
        agent = create_openai_tools_agent(llm=llm, tools=_TOOLS, prompt=prompt)
        return AgentExecutor(
            agent=agent,
            tools=_TOOLS,
            verbose=False,
            max_iterations=8,
            handle_parsing_errors=True,
            return_intermediate_steps=True,
        )

    # ── fingerprint loader ────────────────────────────────────────────────────

    def _load_fingerprint(self, ip: str, dev_type: str) -> Optional[Dict]:
        """
        Load the raw fingerprint row for *ip* from
        evaluation/validation/test_{dev_type}_1.csv.
        Returns None if not found.
        """
        csv_path = os.path.join(_VAL_PATH, f"test_{dev_type}_1.csv")
        if not os.path.exists(csv_path):
            logging.warning("Test CSV not found: %s", csv_path)
            return None
        df = pd.read_csv(csv_path, low_memory=False)
        rows = df[df["ip"].astype(str) == str(ip)]
        if rows.empty:
            logging.warning("IP %s not found in %s", ip, csv_path)
            return None
        raw = rows.iloc[0].to_dict()
        return {k: (None if pd.isna(v) else v) for k, v in raw.items()}

    # ── fingerprint formatter ─────────────────────────────────────────────────

    @staticmethod
    def _fmt_fp(fp: Dict) -> str:
        """Return a compact JSON representation of the fingerprint (no nulls/IP)."""
        display = {
            k: v
            for k, v in fp.items()
            if k != "ip" and v is not None and str(v) not in ("nan", "None", "")
        }
        return json.dumps(display, indent=2, ensure_ascii=False)

    # ── single LLM agent run ──────────────────────────────────────────────────

    def _run_agent(
        self,
        executor: AgentExecutor,
        llm_name: str,
        ip: str,
        fingerprint: Dict,
    ) -> Dict:
        """
        Invoke the LangChain AgentExecutor for one LLM.
        The agent calls the unified multi_level_retrieval tool, then emits a JSON answer.
        Returns a normalised classification dict.
        """
        try:
            response = executor.invoke(
                {"ip": ip, "fingerprint": self._fmt_fp(fingerprint)}
            )
            raw_output: str = response.get("output", "")
            parsed = self._extract_json(raw_output)
            parsed.setdefault("device_type", "UNKNOWN")
            parsed.setdefault("device_type_reason", "")
            parsed.setdefault("vendor", "Unknown")
            parsed.setdefault("vendor_reason", "")
            parsed["confidence"]        = float(parsed.get("confidence", 0.0))
            parsed["device_type"]       = str(parsed["device_type"]).upper().strip()
            parsed["vendor"]            = str(parsed.get("vendor", "Unknown"))
            parsed["device_type_reason"] = str(parsed.get("device_type_reason", ""))
            parsed["vendor_reason"]      = str(parsed.get("vendor_reason", ""))
            parsed["llm"]               = llm_name
            parsed["full_response"]     = raw_output
            return parsed

        except Exception as exc:
            logging.error("%s agent error: %s", llm_name, exc, exc_info=True)
            return {
                "llm":          llm_name,
                "device_type":  "UNKNOWN",
                "vendor":       "Unknown",
                "confidence":   0.0,
                "step9_synthesis": f"Agent error: {exc}",
                "error":        str(exc),
            }

    # ── JSON extractor ────────────────────────────────────────────────────────

    @staticmethod
    def _extract_json(text: str) -> Dict:
        """
        Robustly extract the last JSON object containing 'device_type' from *text*.
        Tries (in order):
          1. ```json ... ``` fenced block
          2. Innermost { } containing "device_type"
          3. Last { ... } block in the text
        """
        # 1. fenced code block
        m = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                pass

        # 2. { ... } containing "device_type"
        for match in re.finditer(r"\{[^{}]*\"device_type\"[^{}]*\}", text, re.DOTALL):
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                continue

        # 3. last { ... } block (may be a nested object)
        start, end = text.rfind("{"), text.rfind("}") + 1
        if 0 <= start < end:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                pass

        raise ValueError(f"No valid JSON found in LLM response:\n{text[:500]}")

    # ── joint voting ──────────────────────────────────────────────────────────

    @staticmethod
    def _joint_vote(gemini: Dict, claude: Dict) -> Dict:
        """
        Select the result with the higher confidence score.
        When both LLMs agree on device_type, boost the final confidence slightly
        (average of both + 0.05, capped at 1.0).
        """
        g_conf = float(gemini.get("confidence", 0.0))
        c_conf = float(claude.get("confidence", 0.0))

        winner, loser = (gemini, claude) if g_conf >= c_conf else (claude, gemini)
        agree = winner.get("device_type") == loser.get("device_type")

        final_conf = winner["confidence"]
        if agree:
            final_conf = min(1.0, round((g_conf + c_conf) / 2 + 0.05, 4))

        return {
            "final_device_type":        winner["device_type"],
            "final_device_type_reason": winner.get("device_type_reason", ""),
            "final_vendor":             winner["vendor"],
            "final_vendor_reason":      winner.get("vendor_reason", ""),
            "final_confidence":         round(final_conf, 4),
            "winning_llm":              winner["llm"],
            "llm_agreement":            agree,
            "gemini": {
                "device_type":        gemini.get("device_type"),
                "device_type_reason": gemini.get("device_type_reason", ""),
                "vendor":             gemini.get("vendor"),
                "vendor_reason":      gemini.get("vendor_reason", ""),
                "confidence":         g_conf,
                "synthesis":          gemini.get("step9_synthesis", ""),
            },
            "claude": {
                "device_type":        claude.get("device_type"),
                "device_type_reason": claude.get("device_type_reason", ""),
                "vendor":             claude.get("vendor"),
                "vendor_reason":      claude.get("vendor_reason", ""),
                "confidence":         c_conf,
                "synthesis":          claude.get("step9_synthesis", ""),
            },
        }

    # ── public: classify one IP ───────────────────────────────────────────────

    def classify(self, ip: str, dev_type: str) -> Dict:
        """
        Classify a single device IP using Gemini + Claude joint voting.

        Args:
            ip:       IP address of the query device.
            dev_type: True device type label (used to locate test CSV).

        Returns:
            Classification result dict including predicted_device_type,
            predicted_vendor, final_confidence, per-LLM outputs, and metadata.
        """
        logging.info("classify  ip=%s  dev_type=%s", ip, dev_type)
        t0 = time.time()

        fp = self._load_fingerprint(ip, dev_type)
        if fp is None:
            return {"error": f"Fingerprint not found for ip={ip}, dev_type={dev_type}"}

        # ── First-stage gate: unseen detection → (if both probs < 0.5) drift detection ──
        # 第一阶段: 先 unseen 检测, 两概率均 < 0.5 时再做 in-class concept drift 检测
        first_stage = self._run_first_stage(ip, fp)

        # Run both LangChain agents independently (each calls all 3 tools + reasons)
        gemini_result = self._run_agent(self._gemini_executor, "GEMINI", ip, fp)
        logging.info(
            "Gemini → %s  vendor=%s  conf=%.3f",
            gemini_result["device_type"], gemini_result["vendor"],
            gemini_result["confidence"],
        )

        claude_result = self._run_agent(self._claude_executor, "CLAUDE", ip, fp)
        logging.info(
            "Claude → %s  vendor=%s  conf=%.3f",
            claude_result["device_type"], claude_result["vendor"],
            claude_result["confidence"],
        )

        voting = self._joint_vote(gemini_result, claude_result)

        result = {
            "ip":                        ip,
            "true_device_type":          dev_type,
            "predicted_device_type":     voting["final_device_type"],
            "device_type_reason":        voting["final_device_type_reason"],
            "predicted_vendor":          voting["final_vendor"],
            "vendor_reason":             voting["final_vendor_reason"],
            "final_confidence":          voting["final_confidence"],
            "winning_llm":               voting["winning_llm"],
            "llm_agreement":             voting["llm_agreement"],
            "first_stage":               first_stage,
            "gemini":                    voting["gemini"],
            "claude":                    voting["claude"],
            "elapsed_sec":               round(time.time() - t0, 2),
        }

        logging.info(
            "Decision  %s  conf=%.3f  winner=%s  agree=%s",
            voting["final_device_type"], voting["final_confidence"],
            voting["winning_llm"], voting["llm_agreement"],
        )
        return result

    # ── public: batch classify ────────────────────────────────────────────────

    def run_batch(
        self,
        dev_type: str,
        max_samples: Optional[int] = None,
        ip_list: Optional[List[str]] = None,
    ) -> List[Dict]:
        """
        Classify a batch of test devices for *dev_type*.

        Reads IPs from evaluation/validation/test_{dev_type}_1.csv unless
        *ip_list* is provided.  Results are auto-saved after processing.

        Args:
            dev_type:    Device type label (e.g. 'NVR', 'ROUTER').
            max_samples: Maximum number of IPs to process (None = all).
            ip_list:     Explicit IP list (overrides test CSV).

        Returns:
            List of per-IP classification result dicts.
        """
        logging.info("run_batch  dev_type=%s  max=%s", dev_type, max_samples)

        if ip_list is None:
            csv_path = os.path.join(_VAL_PATH, f"test_{dev_type}_1.csv")
            if not os.path.exists(csv_path):
                logging.error("Test CSV not found: %s", csv_path)
                return []
            ip_list = pd.read_csv(csv_path, low_memory=False)["ip"].astype(str).tolist()

        if max_samples:
            ip_list = ip_list[:max_samples]

        print(f"[DecisionAgent] Classifying {len(ip_list)} IPs for {dev_type} …")
        results: List[Dict] = []
        for i, ip in enumerate(ip_list, 1):
            print(f"  [{i}/{len(ip_list)}] {ip}")
            results.append(self.classify(ip, dev_type))

        self._save(dev_type, results)
        return results

    # ── public: convenience entry-point ──────────────────────────────────────

    def run(
        self,
        dev_type: Optional[str] = None,
        ip: Optional[str] = None,
        max_samples: Optional[int] = None,
    ) -> Any:
        """
        Convenience entry-point:

        - run(dev_type='NVR', ip='1.2.3.4') → classify one IP, save result.
        - run(dev_type='NVR')               → classify all IPs in test CSV.
        - run()                             → classify all available device types.
        - run(max_samples=5)                → classify first 5 IPs per type.
        """
        if dev_type and ip:
            result = self.classify(ip, dev_type)
            self._save(dev_type, [result])
            return result
        elif dev_type:
            return self.run_batch(dev_type, max_samples=max_samples)
        else:
            all_results: Dict[str, List[Dict]] = {}
            for dev in self.dev_labels:
                csv_path = os.path.join(_VAL_PATH, f"test_{dev}_1.csv")
                if os.path.exists(csv_path):
                    all_results[dev] = self.run_batch(dev, max_samples=max_samples)
            return all_results

    # ── result persistence ────────────────────────────────────────────────────

    def _save(self, dev_type: str, results: List[Dict]) -> None:
        """
        Serialise *results* into two separate JSON files:
          - {dev_type}_type_prediction.json   – device type predictions + reasoning
          - {dev_type}_vendor_prediction.json – vendor predictions + reasoning
        """
        type_records = [
            {
                "ip":                    r.get("ip"),
                "true_device_type":      r.get("true_device_type"),
                "predicted_device_type": r.get("predicted_device_type"),
                "device_type_reason":    r.get("device_type_reason", ""),
                "confidence":            r.get("final_confidence"),
                "winning_llm":           r.get("winning_llm"),
                "llm_agreement":         r.get("llm_agreement"),
                "gemini_device_type":    r.get("gemini", {}).get("device_type"),
                "gemini_reason":         r.get("gemini", {}).get("device_type_reason", ""),
                "gemini_confidence":     r.get("gemini", {}).get("confidence"),
                "claude_device_type":    r.get("claude", {}).get("device_type"),
                "claude_reason":         r.get("claude", {}).get("device_type_reason", ""),
                "claude_confidence":     r.get("claude", {}).get("confidence"),
                "first_stage":           r.get("first_stage"),
                "elapsed_sec":           r.get("elapsed_sec"),
            }
            for r in results
        ]

        vendor_records = [
            {
                "ip":                r.get("ip"),
                "true_device_type":  r.get("true_device_type"),
                "predicted_vendor":  r.get("predicted_vendor"),
                "vendor_reason":     r.get("vendor_reason", ""),
                "confidence":        r.get("final_confidence"),
                "winning_llm":       r.get("winning_llm"),
                "llm_agreement":     r.get("llm_agreement"),
                "gemini_vendor":     r.get("gemini", {}).get("vendor"),
                "gemini_reason":     r.get("gemini", {}).get("vendor_reason", ""),
                "gemini_confidence": r.get("gemini", {}).get("confidence"),
                "claude_vendor":     r.get("claude", {}).get("vendor"),
                "claude_reason":     r.get("claude", {}).get("vendor_reason", ""),
                "claude_confidence": r.get("claude", {}).get("confidence"),
                "first_stage":       r.get("first_stage"),
                "elapsed_sec":       r.get("elapsed_sec"),
            }
            for r in results
        ]

        for suffix, records in (
            ("type_prediction",   type_records),
            ("vendor_prediction", vendor_records),
        ):
            out = os.path.join(_RES_PATH, f"{dev_type}_{suffix}.json")
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(records, fh, indent=2, ensure_ascii=False)
            logging.info("Saved %d records → %s", len(records), out)
            print(f"  ✓  Saved → {out}")


# ═════════════════════════════════════════════════════════════════════════════
# §4  CLI Entry Point
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="IoT Device Decision Agent (Gemini + Claude joint voting)"
    )
    parser.add_argument("--dev",  type=str, default=None,
                        help="Device type, e.g. NVR, ROUTER (omit to run all)")
    parser.add_argument("--ip",   type=str, default=None,
                        help="Specific IP address to classify")
    parser.add_argument("--max",  type=int, default=None,
                        help="Max samples per device type")
    parser.add_argument("--no_first_stage", action="store_true", default=False,
                        help="Disable unseen + drift first-stage gate (joint voting only)")
    parser.add_argument("--unseen_adapter", type=str, default=None,
                        help="Path to fine-tuned LLaMA LoRA adapter for unseen detection")
    parser.add_argument("--drift_dir", type=str, default=None,
                        help="Directory with trained PACA drift model + artifacts")
    parser.add_argument("--gpu", type=int, default=-1,
                        help="GPU index for the unseen LLaMA model (-1 = CPU)")
    args = parser.parse_args()

    agent = DecisionAgent(
        enable_first_stage=not args.no_first_stage,
        unseen_adapter_path=args.unseen_adapter,
        drift_model_dir=args.drift_dir,
        gpu=args.gpu,
    )
    result = agent.run(dev_type=args.dev, ip=args.ip, max_samples=args.max)

    # Pretty-print a preview
    preview = result if isinstance(result, dict) else (result[:3] if result else [])
    print(json.dumps(preview, indent=2, ensure_ascii=False, default=str))
