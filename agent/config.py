"""
agent/config.py — API key shim for decomposition.py / app.py.

The original local config.py (never committed) exported API keys as module
constants. This reconstruction keeps llm_config.json as the single source of
truth so keys are never hardcoded here.
"""

import json
import os

_CFG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "llm_config.json"
)

with open(_CFG_PATH, "r", encoding="utf-8") as _f:
    _cfg = json.load(_f)

GEMINI_API_KEY = _cfg["GEMINI"]["API_KEY"]
DEEPSEEK_API_KEY = _cfg["DEEPSEEK"]["API_KEY"]
OPENAI_API_KEY = _cfg["OPENAI"]["API_KEY"]
