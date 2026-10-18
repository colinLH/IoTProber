#!/usr/bin/env python
"""Pre-warm LOCAL retrieval caches for the bench samples while the external
LLM channels are down (local retrieval is pure local-embedding cosine — no
API calls). After this, the post-restart workers quick_resume past the local
layer and spend their scarce LLM quota only on community/reasoning/decision.

Usage: CUDA_VISIBLE_DEVICES=$G python evaluation/bench_100/prewarm_local.py --worker $G
"""

import argparse
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "agent"))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))  # evaluation/, where run_bench_100.py lives

from run_bench_100 import pop_type, restore_test_csv, swap_test_csv  # noqa: E402


def run_type_local(t):
    from agent import IdentificationAgent
    swap_test_csv(t)
    try:
        agent = IdentificationAgent(llm="GLM", gpu=0)
        # decompose OFF on purpose: it needs an external LLM and falls back to
        # defaults anyway; community/reasoning are the LLM consumers we skip.
        agent.run_retrieval(whether_decompose=False, whether_local=True,
                            whether_community=False, whether_reasoning=False,
                            devices=[t], top_k=5, quick_resume=True)
        print(f"[prewarm] {t} local done", flush=True)
    finally:
        restore_test_csv(t)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--worker", type=int, default=0)
    a = p.parse_args()
    while True:
        t = pop_type()
        if t is None:
            print("queue empty, prewarm worker exiting", flush=True)
            break
        try:
            run_type_local(t)
        except Exception as exc:  # noqa: BLE001
            print(f"[prewarm] {t} FAILED: {type(exc).__name__}: {str(exc)[:150]}",
                  flush=True)
            restore_test_csv(t)
