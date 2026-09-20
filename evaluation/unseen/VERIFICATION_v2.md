# v2 Adapter 验证报告（2026-09-20）

## 训练完成
- 2191/2191 步，7h05m，8×H800（`--max_tokens_per_batch 16384` + `expandable_segments`）
- 产物：`evaluation/unseen/llama3/results_v2/final_model/`
- 训练集 `unseen_sft_v2.jsonl`：56,491 条（MS 9,113 + VPN×2 7,378 + 重放 40,000），新类占 29%

## 核心指标（生产推理链路 · 1,587 个真实指纹 · 8 卡分片）

| 指标 | 旧 adapter (ckpt-14576) | 新 adapter (v2) | Gate 要求 | 结果 |
|---|---|---|---|---|
| MEDIA_SERVER type_exact | 0.000 | **0.845** | — | ✅ |
| VPN type_exact | 0.000 | **0.805** | — | ✅ |
| known type_exact | 0.947 | 0.934 | — | ≈（-0.013） |
| pseudo type_exact | 0.912 | 0.915 | — | ✅ |
| **type_novelty_f1** | 0.005 | **0.899** | ≥0.80 | ✅ |
| **type_exact_accuracy** | 0.471 | **0.880** | ≥0.50 | ✅ |
| vendor_novelty_f1 | 0.000 | 0.010 | ≥0.80 | ❌ |
| vendor_exact_accuracy | 0.930 | 0.933 | ≥0.50 | ✅ |

校准阈值（已写入 `results_v2/final_model/known_vendors.json`，契约 `deepseek_summary`）：
**type 0.48 / vendor 0.705**；release gate 报告：`results_v2/release_gate_report_v2.json`

## 唯一未达标项：vendor_novelty_f1 —— 属验证集设计缺陷，非模型能力问题

**根因**：pseudo-vendor 验证样本的"新厂商"是从**训练提示词**中摘除的真实已知厂商（如 Synology），
而推理判定 `_classification_novelty_result` 用元数据的**全量** `known_vendors_by_type` 匹配 →
必然命中 → `new_vendor_probability` 被强制为 0（实测 99.5% 的 pseudo 样本 score=0）。

**反证（模型其实判对了厂商）**：pseudo vendor_exact = 0.907，MEDIA_SERVER 0.835，VPN 0.950。

---

## 可优化项（按优先级）

1. **vendor novelty 判定口径**（唯一硬缺口）
   - 方案 A（改代码，推荐）：`match_known_unseen_vendor` 改为对照**当前提示词中的厂商列表**——
     与训练信号一致（训练时正是"列表里没有，但仍要答对"）；改动小、口径自洽
   - 方案 B（改数据）：构造真正未知厂商（不在任何 label 文件里）的验证集
2. **MS/VPN ↔ NAS 混淆**：31/200 MS、39/200 VPN 被判成 NAS
   - 提高新类占比（当前 29% → 40%+），或补充 NAS↔MS/VPN 的 hard-negative 样本
   - 客观因素：MS/VPN 与 NAS 的指纹形态本就相近（同为 Linux 服务型设备）
3. **known 类轻微回退**（0.947→0.934）：加大 replay（40k→60k）或降低续训 LR（5e-5→2e-5）
4. **训练工程约束（务必保留）**
   - `--max_tokens_per_batch 16384` + `PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True`
   - 训练期间**禁止**并发任何 GPU 任务（会 rank OOM → NCCL watchdog 挂死）
5. vendor 阈值（0.705）在 1 项修好前意义有限；type 阈值 0.48 可直接用

---

# PACA drift 模型（2026-09-20 训练完成）

- 8 卡 DataParallel，Epoch 100/100，best loss 25,496（final 26,403）
- 产物（`drift_data/autoencoder_drift/`）：`paca_model.pt`、`paca_artifacts.pkl`（**τ = 10.507**，
  median 3.271 + 3.5×MAD 2.067）、`drift_results.csv`（59MB）、`class_drift_summary.csv`、`drift_explanations.json`
- 参考集漂移率：53,850/361,759（14.9%）；透视归因 top：dns(z=2472)、os(z=569)、whois(z=27.5)
- 生产路径已验证：`DriftDetector(model_dir=...)` 加载 + `detect_query_device()` 实测通过

## 本次修复的两个真实 bug（建议保留）
1. **`compute_drift_scores` 内存问题**：原实现一次性构造 (n × dim) 的完整重建误差矩阵（参考集约 80GB/份，
   共需 ~240GB）→ 训练完成后进程被静默 OOM 杀死、`paca_artifacts.pkl` 从未生成。已改为**逐块累加**
   （峰值内存降到 batch 级），并新增 `--load_model` 复用已训练权重（免重训 2.5h）
2. **artifacts 反序列化路径**：以 `python agent/drift.py` 直接运行时，pickle 把自定义 tokenizer 记为
   `__main__._comma_tokenizer`，导致从生产路径（`from drift import DriftDetector`）加载失败。
   已将函数 `__module__` 重定向为 `drift` 后重新保存（备份 `.mainpickle.bak`），生产加载验证通过

## 遗留问题（明天可优化）
- **contrast 项主导且不收敛**：contrast ≈26,000 vs recon ≈8.2（约 3300×），epoch 10→100 总 loss
  26,743→26,403 基本不降，模型仅在早期（best 25,496）有轻微改善。建议对两项分别加权/归一，
  或对 contrast 加系数（如 1e-3）；否则 drift 打分（基于重建误差）区分度受限
- dns 透视 z=2472 明显异常，建议检查该透视特征归一化/是否退化


---

# 补充（2026-09-20 用户要求）

## 1. vendor F1 按"判对厂商即正确"重算 → **0.932**（原口径 0.010）

判定规则（脚本 `evaluation/unseen/recompute_vendor_f1.py`，阈值无关）：
new-vendor 样本：输出=真实厂商 → TP，否则 FN；known 样本：未复现真实厂商 → FP（其输出必然未列名→会被判新），复现 → TN

| 折 | P | R | F1 | acc |
|---|---|---|---|---|
| MEDIA_SERVER_calib__VPN_test | 0.948 | 0.920 | **0.934** | 0.935 |
| VPN_calib__MEDIA_SERVER_test | 0.934 | 0.925 | **0.930** | 0.930 |

**→ 四项 release gate 在新口径下全部通过**（type F1 0.899 / vendor F1 0.932 / type acc 0.880 / vendor acc 0.933）。
注：若采用此口径，`agent/unseen.py::_classification_novelty_result` 的 vendor 判定需同步改为"输出≠列表外即判新"的语义（当前实现对已列名厂商强制 prob=0）。

## 2. known 类回退（0.947→0.934，−1.3pp）诊断与改进方法

**分组对比（旧→新）**：CAMERA 0.945→0.951 ↑；NVR/SCADA/ALARM/CONTROLLER 持平；
NAS 0.961→0.941（含 7 例 NAS→MEDIA_SERVER 新类渗入）；ROUTER 0.940→0.934；PRINTER 0.857→0.829；
MEDICAL 0.647→0.588；POWER_METER 1.000→0.900（n=10，单例即 −10pp）。

**关键判断**：回退集中在**少样本类型**（MEDICAL n=17、POWER_METER n=10、PRINTER n=70），
且 MEDICAL/PRINTER/POWER_METER 之间的互混在旧 adapter 上就存在（非新增问题）；
真正由本次续训引入的是 **NAS→MEDIA_SERVER 7 例**（新类边界渗入）。

**改进方法（按性价比排序）**：
1. **对少样本/易混类型的 replay 过采样 2×**（MEDICAL、POWER_METER、PRINTER、NAS、ROUTER）——
   等效类别加权，训练时间几乎不变，最针对性
2. **续训 LR 5e-5 → 2e-5**：减少对已学表示的扰动（续训常规做法），与新类学习配合
3. **整体加大 replay 40k → 60-70k**（新类:重放 29:71 → 22:78）：更稳但训练时间 +~30%
4. **LoRA r=8 → 16/32**：增加容量以容纳新类而不覆盖旧类（显存/时间 +10-20%）
5. 系统兜底（非训练改进）：保留旧 adapter 做低置信度回退/集成

推荐组合：**(1)+(2)** —— 成本最低、直接针对病因。

## 3. drift 损失失衡修复（已实施并重训）

contrast 项原为 55,838 维上的**平方距离和**（≈2.6e4），recon 为按维 MSE（≈8.2），量纲差 ~3300×，
导致重建目标（drift 打分 S(x) 所依赖）几乎无梯度、100 epoch 不收敛（26,743→26,403）。

修复：`PerspectiveWeightedLoss` 中按加权维度数（52,915）归一化 contrast 距离 →
contrast ≈ 0.49 vs recon 8.2（同量级）；`--lam` 仍可调。重训已启动（8 卡，~2.5h）。
旧版产物备份于 `drift_data/autoencoder_drift_prev/`（τ=10.507）以便对比。
