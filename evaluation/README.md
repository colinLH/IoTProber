# IoTProber — Artifact Evaluation Guide

This guide is written for the CCS '26 artifact evaluation of
*IoTProber: Internet-Scale IoT Device Identification Based on Hierarchical Graph
Retrieval-Augmented Generation*. It is organised by badge:

| Badge | Section |
|---|---|
| Artifacts Available | [1. Permanent archive and contents](#1-artifacts-available) |
| Artifacts Evaluated (Functional) | [2. Set-up from scratch, run instructions, expected outputs and checks](#2-artifacts-evaluated) |
| Results Reproduced | [3. Paper claims, datasets, commands, expected metrics and tolerances](#3-results-reproduced) |

All commands are run from the repository root unless stated otherwise.

---

## 1. Artifacts Available

### 1.1 Permanent archive

| Item | Location |
|---|---|
| **Permanent, citable archive (code snapshot + data)** | Zenodo, DOI [10.5281/zenodo.23440077](https://doi.org/10.5281/zenodo.23440077) |
| Development repository (mirror of the archived code) | <https://github.com/IoTProber/IoTProber> |
| Dataset mirror (same files as the archive's data part) | <https://huggingface.co/datasets/IoTProber/raw_dataset> |

The Zenodo record is the version of record for evaluation. GitHub and Hugging Face are
mirrors that may move ahead of the archived version.

### 1.2 What the archive contains

| Archive path | Content | Used by | Local destination |
|---|---|---|---|
| `IoTProber/` (code) | Full source tree at the archived release: `agent/`, `graph/`, `evaluation/`, `demo/`, `config/`, `tests/` | everything | repository root |
| `platform_data/csv/rag/ipraw_{TYPE}.csv` | Knowledge-base fingerprints for 11 known types (2026-02-18 collection, Table 1 `[R]`) | graph construction, retrieval, PACA | `$IOTPROBER_CSV_DATA_DIR/rag/` |
| `platform_data/csv/rag/embedding_local/` | Per-device Qwen3 embeddings (11 perspectives × 1024 dims) | HGT, local retrieval | `$IOTPROBER_CSV_DATA_DIR/rag/embedding_local/` |
| `platform_data/csv/rag/community/` | Single-perspective (Layer 2) and comprehensive-view (Layer 3) communities, HDBSCAN models, LLM cluster reports | community / reasoning-path retrieval, Neo4j Layer 2/3 | `$IOTPROBER_CSV_DATA_DIR/rag/community/` |
| `platform_data/csv/rag/vectorDB/local_npz/` | Memory-mapped local-retrieval index (`*_emb.npy`, `*_ips.npy`) | local retrieval | `$IOTPROBER_CSV_DATA_DIR/rag/vectorDB/` |
| `platform_data/csv/all/ipraw_{MEDIA_SERVER,VPN}.csv` | Unseen-device test fingerprints (Table 1, 19,854 IPs) | Table 8 | `$IOTPROBER_CSV_DATA_DIR/all/` |
| `platform_data/csv/label/` | Vendor labels | vendor metrics | `$IOTPROBER_CSV_DATA_DIR/label/` |
| `platform_data/shodan/` | Shodan fingerprints of the Alarm/Controller IPs (2026-07-21) | Table 4 inputs (no consumer script in this release, see 3.7) | any |
| `evaluation/validation/46_features/test_{TYPE}_1.csv` | Known-type test sets (Table 1 `[T]`, 76,319 IPs) | Tables 2, 3, 7 | `evaluation/validation/46_features/` |
| `evaluation/validation/vendor_testset/test_{TYPE}_1_label.csv` | Vendor test labels (Table 1 `[V]`) | Table 3 | `evaluation/validation/vendor_testset/` |
| `evaluation/unseen/vendor/dataset/test_{MEDIA_SERVER,VPN}_label.csv` | Unseen-vendor labels (13,458 IPs) | Table 8 | same path |
| `evaluation/unseen/llama3/results_v2/final_model/` | LoRA adapter of the unseen-device detector (+ `known_vendors.json` contract) | first stage of the decision graph | same path |
| `evaluation/unseen/llama3/dataset/` | SFT data of the unseen detector | adapter re-training (optional) | same path |
| `drift_data/autoencoder_drift_v2/` | Trained PACA model, thresholds, metrics, split manifest | drift node of the decision graph | `drift_data/autoencoder_drift_v2/` |
| `evaluation/drift/CADE/` | Drift datasets (2026-02-18 train, 2026-04-06 test) and per-stage outputs | Table 10 | same path |
| `entity graph/`, `hgt_results/` | Device–feature graph export and HGT weights / embeddings | HGT re-training (optional) | `entity_graph/`, `graph/model/` |

Third-party models are **not** redistributed (their licences forbid it); download them from
the official model cards:

| Model | Source | Local path |
|---|---|---|
| Llama-3.1-8B-Instruct (gated; accept the Meta licence first) | <https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct> | `./Meta-Llama-3.1-8B-Instruct/` |
| Qwen3-Embedding-0.6B | <https://huggingface.co/Qwen/Qwen3-Embedding-0.6B> | `./qwen3_embedding_06b/` |

---

## 2. Artifacts Evaluated

Every step below has an **Expected output** and a **Check** the evaluator can apply
without trusting the authors' numbers.

### 2.0 Requirements

| Component | Minimum | Used by the authors |
|---|---|---|
| OS | Linux x86-64 (Ubuntu 20.04+); Milvus Lite / bitsandbytes do not support Windows | Ubuntu 20.04 / 22.04 |
| GPU | 1 × 16 GB (4-bit Llama adapter needs ≈ 8.7 GB; Qwen3 embedding ≈ 2 GB) | 2 × V100 32 GB (pipeline), 1 × H100 80 GB (fine-tuning) |
| RAM | 32 GB (memory-mapped local index; 64 GB recommended) | 1.5 TB |
| Disk | ≈ 300 GB for the archive data (+ 160 GB if communities are rebuilt) | NVMe |
| Software | Python 3.11, CUDA 12.x driver, Java 17 (Neo4j) | — |
| Accounts | LLM API keys (Section 2.3), optional Tavily key | — |

### 2.1 Python environment

```bash
conda create -n iotprober python=3.11 -y && conda activate iotprober
python -m pip install --upgrade pip
# Install a CUDA build of torch first if the default wheel does not match your driver:
#   https://pytorch.org/get-started/locally/
python -m pip install -r requirements.txt
python -c "import torch, transformers, peft, hdbscan, langgraph, py2neo; \
print('torch', torch.__version__, 'cuda', torch.cuda.is_available())"
```

**Expected output:** `torch 2.9.1 cuda True`. **Check:** `pip check` reports no broken requirements.

### 2.2 Data and models

1. Download the Zenodo record (Section 1.1) and unpack it. Place the files at the
   destinations listed in Section 1.2. The data root can be anywhere; tell the code where it is:

   ```bash
   export IOTPROBER_CSV_DATA_DIR=/path/to/platform_data/csv   # contains rag/ all/ label/
   ```
2. Download the two models in Section 1.2 into the repository root.
3. Verify that the data matches Table 1 of the paper:

   ```bash
   python - <<'EOF'
   import json, os, pandas as pd
   C = os.environ["IOTPROBER_CSV_DATA_DIR"]
   for t in json.load(open("config/rag_devices.json"))["IoT"]:
       r = len(pd.read_csv(f"{C}/rag/ipraw_{t}.csv", usecols=["ip"], low_memory=False))
       te = len(pd.read_csv(f"evaluation/validation/46_features/test_{t}_1.csv", usecols=["ip"], low_memory=False))
       print(f"{t:20} R={r:7}  T={te:6}")
   for t in ["MEDIA_SERVER", "VPN"]:
       print(f"{t:20} T={len(pd.read_csv(f'{C}/all/ipraw_{t}.csv', usecols=['ip'], low_memory=False)):6}")
   EOF
   ```

**Expected output** (identical to Table 1):

| Type | R | T | | Type | R | T |
|---|---|---|---|---|---|---|
| CAMERA | 130,000 | 20,000 | | MEDICAL | 5,975 | 1,493 |
| ROUTER | 92,770 | 20,000 | | POWER_METER | 3,984 | 996 |
| NAS | 74,878 | 20,000 | | ALARM | 709 | 177 |
| NVR | 17,898 | 4,474 | | CONTROLLER | 469 | 117 |
| PRINTER | 17,330 | 4,332 | | MEDIA_SERVER | – | 12,050 |
| SCADA | 11,800 | 2,950 | | VPN | – | 7,804 |
| BUILDING_AUTOMATION | 7,124 | 1,780 | | | | |

**Check:** every count matches exactly. The `vendor_testset/*_label.csv` files hold
10,982 / 17,796 / 19,444 / 4,241 / 3,755 / 915 / 701 / 998 / 1,480 labelled IPs for
CAMERA / ROUTER / NAS / NVR / PRINTER / SCADA / POWER_METER / MEDICAL / BUILDING_AUTOMATION
(Table 1 `[V]`).

### 2.3 Configuration (credentials)

All credentials live in one ignored file. Copy the template and fill it in:

```bash
cp config/llm_config.json config/llm_config.local.json
chmod 600 config/llm_config.local.json
```

| Section | Role in the pipeline | Paper setting |
|---|---|---|
| `DEEPSEEK` | query decomposition, community matching, long-fingerprint summarisation, community reports (`graph/regen_overall_summaries.py`) | DeepSeek Chat-V3.2 (V4-Pro as replacement) |
| `CLAUDE` | decision branch 1 (`agent/agent.py::IoTDecisionGraph`); cluster reports in `graph/cluster.py` | Claude-Opus-4.6-Thinking |
| `GEMINI` | decision branch 2 | Gemini-3.1-Pro (3.5-Flash as replacement) |
| `CLAUDEBaseline` | baseline B2 | Claude-Opus-4.6-Thinking |
| `TAVILY` | web search of the unseen detector (optional; the loop degrades gracefully without it) | Tavily |
| `NEO4J` | `URI`, `UPDATED_URI`, `USER`, `PASSWORD` for every Neo4j client | local Neo4j 4.4 |

No credential is hard-coded anywhere in the code base; every Neo4j client goes through
`util.load_neo4j_config()`. DeepSeek-V4 models reason by default; callers that need the
whole token budget for the answer pass `thinking="disabled"` to `LLM.chat_with_llm`.

**Check:**

```bash
python - <<'EOF'
import sys; sys.path.insert(0, ".")
from llm import LLM
for m in ["DEEPSEEK", "CLAUDE", "GEMINI"]:
    print(m, LLM().chat_with_llm(m, [{"role": "user", "content": 'Reply with JSON {"ok": true}'}], whether_json=True))
EOF
```

Expected: `{'ok': True}` for each configured backend.

### 2.4 Neo4j hierarchical graph

The hierarchical graph has three layers: Layer 1 is the Device–Feature entity graph,
Layer 2 holds the single-perspective communities, and Layer 3 the comprehensive-view
communities. It is stored in Neo4j Community 4.4. Default retrieval reads the community
files directly. Only the optional `graph_neighbor` retrieval feature and graph updates
query Neo4j, so retrieval metrics do not depend on it.

```bash
# 1. Install Java 17 and Neo4j Community 4.4 (no plugins required)
wget https://dist.neo4j.org/neo4j-community-4.4.42-unix.tar.gz && tar xzf neo4j-community-4.4.42-unix.tar.gz
export JAVA_HOME=/path/to/jdk-17 NEO4J_HOME=$PWD/neo4j-community-4.4.42
cat >> $NEO4J_HOME/conf/neo4j.conf <<'EOF'
dbms.jvm.additional=--add-opens=java.base/java.nio=ALL-UNNAMED
dbms.jvm.additional=--add-opens=java.base/sun.nio.ch=ALL-UNNAMED
dbms.jvm.additional=--add-opens=java.base/java.lang=ALL-UNNAMED
dbms.jvm.additional=--add-opens=java.base/java.util=ALL-UNNAMED
dbms.jvm.additional=--add-opens=java.base/java.lang.reflect=ALL-UNNAMED
EOF
# 2. Set the password (the same value goes into NEO4J.PASSWORD of llm_config.local.json)
$NEO4J_HOME/bin/neo4j-admin set-initial-password '<your-password>'
$NEO4J_HOME/bin/neo4j start
$NEO4J_HOME/bin/cypher-shell -u neo4j -p '<your-password>' 'RETURN 1;'

# 3. Build all three layers from the archived files (CLEARS the database first)
python graph/build_neo4j.py
#    Incremental (re)build of selected types without clearing, e.g. after a community rebuild:
python graph/build_neo4j.py --devices ALARM CONTROLLER --layers 1 2 3
```

**Expected output:** per-layer summary tables, then `Final Neo4j Statistics`. On the
archived data: about 3.6 × 10⁵ `Device` nodes (one per knowledge-base row, 362,937 rows),
about 1.6 × 10⁶ `Feature` nodes, 1,493,994 single-perspective and 175,292
comprehensive-view `Cluster` nodes.

**Check:**

```cypher
MATCH (c:Cluster {perspective:'comprehensive'}) RETURN c.device_type, count(*) ORDER BY c.device_type;
MATCH (c:Cluster) WITH c.perspective AS p, c.cluster_id AS id, count(*) AS n WHERE n > 1 RETURN count(*);  // must be 0
```

Note: after decisions, `agent/agent.py --decision` inserts the classified test devices
into the graph (incremental update, paper §4.5). Rebuild with `python graph/build_neo4j.py`
before a new evaluation if a pristine knowledge graph is required.

### 2.5 RAG data plane (communities, embeddings, index)

**Option A, archived artifacts (recommended):** nothing to run. Sections 1.2 and 2.2
already place them.

**Option B, full rebuild** (≈ 148 h for 421,759 devices; needs the `CLAUDE` key for the
cluster reports):

```bash
python graph/construction.py --all --gpu 0   # cluster → Layer 1 + export → HGT (+ overall clustering) → Layer 2/3 → vector
```

The construction log `graph/construction.log` lists each step. The **check** is that every
type has `ipraw_{TYPE}_embedding_overall_pca.csv` and `{TYPE}_cluster_summaries.json`
under `rag/community/embedding_overall/`, and that `rag/vectorDB/local_npz/` holds one
`*_emb.npy` / `*_ips.npy` pair per type.

**Cross-type duplicate IPs.** `config/local_kb_ambiguous_ips.json` lists knowledge-base
IPs that appear under more than one device type (mostly multi-tenant cloud hosts). Local
retrieval never returns them as neighbours. If the file is missing, nothing is excluded.

**Comprehensive-view communities of ALARM, CONTROLLER and POWER_METER.** In the archived
release, these three types' communities were rebuilt with a deterministic, label-free
procedure:

1. Row-wise L2 normalisation of the 13 × 256-dimensional concatenated perspective embedding.
2. PCA.
3. An HDBSCAN grid that keeps the configuration with the highest DBCV among those with
   ≥ 3 clusters and a largest cluster holding ≤ 50% of the devices.
4. Soft assignment of the noise points.

Reproduce the rebuild and its reports:

```bash
python graph/repair_overall_community.py --devices ALARM CONTROLLER POWER_METER   # CPU, ~3 min, backs up old files
python graph/regen_overall_summaries.py --devices ALARM CONTROLLER POWER_METER --llm DEEPSEEK   # 56 LLM calls, ~7e4 input tokens
python graph/build_neo4j.py --devices ALARM CONTROLLER POWER_METER --layers 3
```

**Expected output:** `rebuild_manifest_{TYPE}.json` next to the assignment files.

| Type | Devices | Selected (PCA dims, min_cluster_size, min_samples, selection) | Clusters | Soft-assigned | Largest cluster |
|---|---|---|---|---|---|
| ALARM | 709 | 16, 5, –, eom | 28 | 209 | 12.4% |
| CONTROLLER | 469 | 32, 5, –, eom | 14 | 264 | 14.1% |
| POWER_METER | 3,984 | 16, 20, 5, leaf | 14 | 2,413 | 24.7% |

**Check:** `source_ip_sha256` and `cluster_sizes` in the manifests are identical across
re-runs (fixed seed 42). Each `{TYPE}_cluster_summaries.json` has one LLM report per
cluster, and none contains the degraded marker `降级`.

### 2.6 Unit tests (no GPU, no API keys)

```bash
python -m unittest tests.test_retrieval_integrity tests.test_demo_evaluation evaluation.drift.test_drift_v2
```

**Expected output:** `Ran 15 tests … OK`. The tests cover:

- local retrieval is weighted cosine, never returns the query IP, and keeps scores in [-1, 1];
- corrupt community files are isolated;
- vendor novelty does not suppress the drift check;
- the fullflow metrics are computed correctly;
- PACA perspective weights sum to 1;
- the hashed features are deterministic;
- the IP-grouped splits never leak an IP across splits;
- the calibration-quantile thresholds are correct.

### 2.7 End-to-end pipeline on a small input

The run below performs, on three curated CAMERA cases:

- query decomposition;
- local, community and reasoning-path retrieval;
- the unseen detector (Llama-3.1-8B + LoRA, 4-bit), with the Tavily loop;
- PACA drift detection;
- the Gemini and Claude ReAct branches;
- joint voting.

All outputs go to `demo/fullflow/`.

```bash
CUDA_VISIBLE_DEVICES=0 python demo/run_fullflow_demo.py --showcase-only --types CAMERA
python demo/evaluate_fullflow.py --allow-partial
```

**Expected output:**

- The first command prints `[CAMERA] k/3 completed correct …` and then `FULLFLOW SWEEP DONE`.
- It writes `demo/fullflow/CAMERA/results.json`. Each row contains:
  - `predicted_type`, `decision_confidence`, `winning_llm`, `gemini_type`, `claude_type`, `predicted_vendor`;
  - `first_stage.unseen` (`new_type_probability`, `new_vendor_probability`, …);
  - `first_stage.drift` (`drift_score`, `threshold`, `is_drift`);
  - `retrieval_evidence` for all three retrieval levels.
- It also writes `demo/fullflow/manifest.json` with `schema_version` `2026-09-25-v3`.
- `evaluate_fullflow.py` writes `demo/fullflow/evaluation_report.json`.

**Check** (in `evaluation_report.json → by_type.CAMERA`):

- `completion_rate = 1.0`;
- `self_match_violations = 0` (no query retrieves itself);
- `score_range_violations = 0` (every similarity lies in [-1, 1]);
- `local_availability`, `community_availability` and `reasoning_availability` are all `1.0`.

The same entry point runs the whole fixed-seed validation set (40 IPs per type) when
`--showcase-only` is omitted.

### 2.8 PACA concept-drift model (optional re-training)

```bash
DRIFT_NUM_WORKERS=8 python agent/drift.py --data_dir $IOTPROBER_CSV_DATA_DIR/rag \
    --output_dir drift_data/autoencoder_drift_v2_repro --device cuda   # pass --device cpu without a GPU (slow)
```

**Expected output:** a directory containing `paca_model.pt`, `paca_artifacts.pkl`,
`clean_test_metrics.csv`, `synthetic_drift_metrics.csv` and `training_manifest.json`.

**Check:**

- In `training_manifest.json`, the split sizes are deterministic and must match exactly:
  `raw_rows = 362937`, `cleaned_rows = 326499`, and 32,475 test rows.
- In `clean_test_metrics.csv`, the `__macro__` clean false-positive rate should lie between
  0.5% and 1.5%. The thresholds are the 99th percentile of a held-out calibration split,
  so the expected value is ≈ 1%; the archived model has 0.767%.

---

## 3. Results Reproduced

### 3.1 Claims and where they are evaluated

| Claim | Paper | Data | Section |
|---|---|---|---|
| C1 Device-type identification of 11 known types | Table 2 (Macro-F1 0.9582, overall accuracy 97.78%) | `46_features/test_{TYPE}_1.csv` (76,319 IPs) | 3.3 |
| C2 Vendor identification of 11 known types | Table 3 (identification rate 98.40%, Top-3 93.39%) | `vendor_testset/*_label.csv`, `label_{ALARM,CONTROLLER}.csv` | 3.3 |
| C3 Ablation of retrieval layers and unseen detection | Table 7 | Alarm + Controller (294 IPs); NAS long-tail (300 IPs) | 3.3 / 3.6 |
| C4 Comparison with Shodan | Table 4 | Alarm 163 / Controller 77 IPs with Shodan data | 3.6 |
| C5 Unseen devices (Media Server, VPN) | Table 8 (type accuracy 99.44%, vendor Top-1 92.30%) | `all/ipraw_{MEDIA_SERVER,VPN}.csv` (19,854 IPs) | 3.4 |
| C6 In-class concept drift | Table 10 | `evaluation/drift/CADE/dataset/` | 3.5 |

### 3.2 Common protocol

1. Configure the decision models as in the paper: in `config/llm_config.local.json`, set
   `CLAUDE.MODEL` to Claude-Opus-4.6-Thinking and `GEMINI.MODEL` to Gemini-3.1-Pro. The
   paper names Gemini-3.5-Flash as the updated replacement. The decision branches send
   `temperature=0.3` and `max_tokens=$IOTPROBER_DECISION_MAX_TOKENS` (default 1024). The
   code passes no extended-thinking parameter, so the "Thinking" variant must be selected
   through the model id your endpoint exposes for it.
2. Run every experiment in its own output directories so that runs never mix:

   ```bash
   export RUN=$PWD/runs/known
   export IOTPROBER_VALIDATION_DIR=$RUN/validation IOTPROBER_QUERY_DB_DIR=$RUN/query_db IOTPROBER_PREDICTION_DIR=$RUN/predict
   ```
3. Scoring: `python evaluation/check_results.py --suite {known,unseen}`. It reads only the
   decision records of the current run (`$IOTPROBER_PREDICTION_DIR/{TYPE}_{type,vendor}_prediction.json`)
   and the test files of the run (`$IOTPROBER_VALIDATION_DIR/test_{TYPE}_1.csv`). It
   prints a `paper / measured / tolerance / n / PASS|FAIL|N/A` table, and writes
   `evaluation/reproduction_report_{suite}.json`.
4. Missing results count as errors. A test IP without a committed decision is scored as
   `UNKNOWN`, i.e. wrong. `coverage` in the report gives decided/total IPs per type.
5. **Tolerance:**
   - A measured value passes if |measured − paper| ≤ max(1 percentage point,
     1.96·√(p(1−p)/n)), where p is the paper value and n is the number of samples that
     enter the metric.
   - This rule is the 95% binomial sampling half-width, floored at 1 pp. The floor absorbs
     LLM sampling and provider-side model updates; the half-width covers small classes.
   - For per-class precision and macro averages, n is approximated by the class support and
     the total sample count respectively.
6. Cost: each test IP issues several LLM calls (decomposition, community matching, two
   ReAct decision branches with tool calls). Run a pilot on 10 IPs per type, read the
   token usage of your provider, and extrapolate before launching a full run. Option
   `--devices` of `check_results.py` scores partial runs; tolerances then widen
   automatically with the smaller n.

### 3.3 C1–C3: known device types (Tables 2, 3 and the full-pipeline rows of Table 7)

```bash
mkdir -p $IOTPROBER_VALIDATION_DIR
cp evaluation/validation/46_features/test_*_1.csv $IOTPROBER_VALIDATION_DIR/
CUDA_VISIBLE_DEVICES=0 python agent/agent.py --decompose --local --community --reasoning --decision \
    --llm DEEPSEEK --top_k 5 --gpu 0 --quick_resume \
    --unseen_adapter evaluation/unseen/llama3/results_v2/final_model --unseen_load_in_4bit \
    --drift_dir drift_data/autoencoder_drift_v2
python evaluation/check_results.py --suite known
```

`--quick_resume` makes the run restartable. A type can be run alone with `--device TYPE`.

**Expected metrics, Table 2 (IoTProber):**

| Type | n | Precision | Recall | Tolerance (P / R, pp) |
|---|---|---|---|---|
| Router | 20,000 | 0.9834 | 0.9804 | 1.0 / 1.0 |
| SCADA | 2,950 | 0.9647 | 0.9820 | 1.0 / 1.0 |
| Printer | 4,332 | 0.9763 | 0.9905 | 1.0 / 1.0 |
| Camera | 20,000 | 0.9898 | 0.9773 | 1.0 / 1.0 |
| Medical | 1,493 | 0.9271 | 0.9799 | 1.3 / 1.0 |
| Building Automation | 1,780 | 0.9275 | 0.9843 | 1.2 / 1.0 |
| Power Meter | 996 | 0.8962 | 0.9709 | 1.9 / 1.0 |
| NVR | 4,474 | 0.9292 | 0.9763 | 1.0 / 1.0 |
| NAS | 20,000 | 0.9872 | 0.9741 | 1.0 / 1.0 |
| Alarm | 177 | 1.0000 | 0.7514 | 1.0 / 6.4 |
| Controller | 117 | 0.9750 | 1.0000 | 2.8 / 1.0 |
| **Macro average** | 76,319 | **0.9597** | **0.9607** | 1.0 / 1.0 |
| **Macro-F1 / overall accuracy** | 76,319 | **0.9582** | **0.9778** | 1.0 / 1.0 |

For reference, the paper reports Macro-F1 / overall accuracy of 0.8819 / 0.9550 for
baseline B1 and 0.8850 / 0.9279 for B2.

**Expected metrics, Table 3 (IoTProber, M1):**

| Type | n `[V]` | Identification rate | Top-3 accuracy | Tolerance (pp) |
|---|---|---|---|---|
| Medical | 998 | 99.30% | 93.49% | 1.0 / 1.5 |
| NAS | 19,444 | 99.80% | 93.12% | 1.0 / 1.0 |
| NVR | 4,241 | 96.77% | 96.18% | 1.0 / 1.0 |
| Power Meter | 701 | 96.43% | 94.01% | 1.4 / 1.8 |
| Router | 17,796 | 98.85% | 93.47% | 1.0 / 1.0 |
| Printer | 3,755 | 97.36% | 92.68% | 1.0 / 1.0 |
| SCADA | 915 | 97.60% | 93.55% | 1.0 / 1.6 |
| Camera | 10,982 | 98.02% | 92.88% | 1.0 / 1.0 |
| Building Automation | 1,480 | 98.85% | 92.57% | 1.0 / 1.3 |
| Alarm | 177 | 99.44% | 85.31% | 1.1 / 5.2 |
| Controller | 117 | 100.00% | 100.00% | 1.0 / 1.0 |
| **Average** | 60,312 | **98.40%** | **93.39%** | 1.0 / 1.0 |

Metric definitions:

- Vendor names are normalised to lower-case alphanumerics before comparison.
- Identification rate is the share of labelled test IPs whose top-ranked vendor is not unknown.
- Top-3 accuracy is the share of labelled test IPs whose true vendor is among the three
  ranked vendors of the prediction record.
- The released decision agent writes one `predicted_vendor` per IP. When a record carries
  no ranked vendor list, `check_results.py` marks Top-3 as `N/A` and reports Top-1 accuracy
  (a lower bound of Top-3) as `INFO`.

**Expected metrics, Table 7 (full pipeline, Alarm + Controller, 294 IPs):**

| Metric | Value | Tolerance (pp) |
|---|---|---|
| Type macro-F1 | 0.9227 | 3.1 |
| Type overall accuracy | 0.8503 | 4.1 |
| Vendor identification rate | 99.66% | 1.0 |
| Vendor Top-3 accuracy | 90.82% | 3.3 |

All four values come from the same run as Tables 2 and 3. The ablation rows of Table 7 and
the NAS long-tail block are listed in Section 3.6.

### 3.4 C5: unseen devices (Table 8)

```bash
export RUN=$PWD/runs/unseen IOTPROBER_VALIDATION_DIR=$PWD/runs/unseen/validation \
       IOTPROBER_QUERY_DB_DIR=$PWD/runs/unseen/query_db IOTPROBER_PREDICTION_DIR=$PWD/runs/unseen/predict
mkdir -p $IOTPROBER_VALIDATION_DIR
for t in MEDIA_SERVER VPN; do cp $IOTPROBER_CSV_DATA_DIR/all/ipraw_${t}.csv $IOTPROBER_VALIDATION_DIR/test_${t}_1.csv; done
CUDA_VISIBLE_DEVICES=0 python agent/agent.py --decompose --local --community --reasoning --decision \
    --device MEDIA_SERVER VPN --llm DEEPSEEK --top_k 5 --gpu 0 --quick_resume \
    --unseen_adapter evaluation/unseen/llama3/results_v2/final_model --unseen_load_in_4bit \
    --drift_dir drift_data/autoencoder_drift_v2
python evaluation/check_results.py --suite unseen
```

**Final labels.** The first-stage unseen detector emits a type label once
`new_type_probability > 0.5`, and a vendor label once `new_vendor_probability > 0.5`.
These are the gates of `IoTDecisionGraph` (`first_stage.unseen` in each record). Below the
gates, the joint-voting decision is used.

**Type F1.** Each test set contains a single true class, so precision is 1 and
F1 = 2·acc / (1 + acc).

| Device | n (type / vendor) | Type F1 | Type accuracy | Vendor Top-1 | Vendor Top-3 | Tolerance (pp) |
|---|---|---|---|---|---|---|
| Media Server | 12,050 / 9,525 | 0.9980 | 0.9961 | 0.9377 | 1.0000 | 1.0 for all |
| VPN | 7,804 / 3,933 | 0.9963 | 0.9926 | 0.9082 | 1.0000 | 1.0 for all |

The paper also reports averages: macro-F1 0.9972, accuracy 0.9944, vendor Top-1 92.30%
(pooled over 13,458 labelled IPs) and Top-3 100.0%. Vendor Top-3 follows the same `N/A`
rule as Table 3. For reference, the paper reports type accuracy of 0.7512 / 0.2156 for B1
and 0.6638 / 0.0861 for B2 (Media Server / VPN).

### 3.5 C6: in-class concept drift (Table 10)

Protocol:

- **Stage 1:** train an SVM device-type classifier on the 2026-02-18 data (13,144 samples).
- **Stage 2:** test it on the 2026-04-06 data (7,239 samples, after cross-scenario and vendor filtering).
- **Stage 3:** detect drifted samples with IoTProber (PACA) or CADE, annotate them, and retrain.

Datasets: `evaluation/drift/CADE/dataset/{train_SVM,validation_SVM,test_SVM}`.

| Stage / method | Samples | Macro-F1 | Weighted F1 | Accuracy |
|---|---|---|---|---|
| Stage 1, 2026-02-18 (train) | 13,144 | 0.9380 | 0.9370 | 0.9367 |
| Stage 2, 2026-04-06 (test) | 7,239 | 0.4937 | 0.7403 | 0.6892 |
| Stage 3, CADE [38] | 7,239 | 0.5430 | 0.8649 | 0.8402 |
| Stage 3, IoTProber | 7,239 | 0.5509 | 0.8711 | 0.8483 |

Drift-detection correctness among detected samples: IoTProber 94.96% (773 / 814),
CADE 68.97% (767 / 1,112). Tolerance: 1 pp on F1 and accuracy; the detected and correct
counts depend on the trained models and are compared with the same 95% binomial rule.

### 3.6 Further paper tables (targets)

**Table 4, comparison with Shodan.** Values are IoTProber M / B1 / B2 / B3-rule / B3-llm; a
dash means not applicable.

| Device | Type recall (%) | Vendor identification rate (%) | Vendor Top-3 (%) |
|---|---|---|---|
| Alarm (163) | 74.23 / 34.97 / 46.63 / 71.78 / 0.00 | 99.39 / 88.34 / 81.60 / 80.37 / 96.32 | 84.66 / 75.46 / 79.75 / 70.55 / 71.17 |
| Controller (77) | 100.00 / 76.62 / 83.12 / 79.22 / 75.32 | 100.00 / 92.21 / 89.61 / 75.32 / 97.40 | 100.00 / 89.61 / 89.61 / 75.32 / 75.32 |