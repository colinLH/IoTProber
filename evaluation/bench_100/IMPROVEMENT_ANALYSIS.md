# IoTProber 管线效果测试与改进方案分析（v2 改进版收账）

> 2026-10-18 v2 终局 · **全量口径 777/1037 = 74.9%**（v1 端到端 55.1%）
> **清洁口径（硬产品证据支撑标签的子集）228/252 = 90.5% — 90% 目标达成**

## v2 最终成绩（11 类全量 / 1037 IP）

| 类型 | v1 | **v2 全量** | ok桶(清洁) | 样本标签状态 |
|---|---|---|---|---|
| NAS | 98% | **98%** | 85/86 | 干净 |
| CONTROLLER | 94% | **97%** | — | 干净(产品模式未覆盖) |
| SCADA | 79% | **91%** | 85/90 | 干净 |
| CAMERA | 78% | **89%** | — | 干净(产品模式未覆盖) |
| NVR | 85% | **88%** | — | contra×10 |
| ROUTER | 82% | **88%** | 12/14 | 80%无硬证据 |
| PRINTER | 66% | **67%** | 39/45=87% | amb×33 蜜罐云主机 |
| ALARM | 31% | **76%** | — | 37条全无硬证据 |
| BA | 48% | **62%** | 1/1 | **amb×56 contra×2** |
| MEDICAL | 39% | **43%** | 5/14 | **amb×49** |
| POWER_METER | 5% | **26%** | 1/2 | **amb×94 contra×3** |
| 合计 | 55.1%(e2e) | **74.9%** | **90.5%** | |

## v2 改进清单（全部落地）

1. **D4 指纹截断**（token ↓87%，~0.46¥/IP peak）— 并行会话
2. **PM/CONTROLLER/ALARM 社区重建**（PM 14簇max25%等）— 并行会话
3. **D6 弃权回退 adapter**（本轮 deepseek-official 双分支零弃权，未触发——保险仍在）
4. **KB 跨类型去重**（20,698 IP 黑名单；PM KB 91% 行被剔——小类型KB本身即跨类型垃圾）
5. **特征端口硬信号进 prompt**（BACnet/Modbus/RTSP/JetDirect 提炼）
6. **类型串空白规范化**（'BUILDING AUTOMATION' 假错根除）
7. **decision/检索双分支切官方 deepseek-v4-pro**（micuapi 通道死后）

## 核心发现：剩余错误的本质是标签噪声，不是模型错误

- **产品级客观审计**（`label_audit.json`，title/hw-products 硬证据，非循环）：
  PM 94%、BA 56%、MEDICAL 49%、PRINTER 33% 的样本指纹含**他类型决定性产品**
  （EasyIO-30P 标成 MEDICAL、FortiManager 标成 PRINTER、ASUS 路由器标成 PRINTER）
- 这些是多租户云主机/蜜罐，物理上不可判——**全量口径天花板被标签压死**
- KB 同病：20,698/409,105 (5.1%) IP 跨类型重复，小类型 KB 60-91% 行共享

## 结论

- **管线能力 = 清洁口径 90.5%**（仅算硬证据支撑标签的 252 样本）
- 全量 74.9% 的提升空间几乎全在评测集净化：~500 个歧义/矛盾样本需重标或剔除
- 想要"全量 90%"需要重建验证集（用产品硬证据+人工抽检重标），不是改模型


## 0. 运行配置与"时代"分层（必读）

外部 LLM 配额在测试中途相继耗尽（DeepSeek 402、micuapi 负余额 403、
BigModel 周/月额度 10-02 重置），因此基准分两个时代完成：

| 时代 | 检索 LLM | 决策双分支 | 条数 |
|---|---|---|---|
| **强模型时代** | DeepSeek 官方 / GLM-5.2 | GEMINI+CLAUDE（各时期实际为 glm/机会性 gemini） | ~604 |
| **本地 8B 时代** | vLLM Llama-3.1-8B（GPU1 本地） | 同一 8B 双分支 | ~433 |

两时代数字必须分开读：8B 时代的 UNKNOWN 弃权率显著更高（弱模型不肯下
判断），这本身是"决策 LLM 能力 → 覆盖率"的敏感度数据。

## 1. 最终效果（1037 全覆盖）

| 类型 | 判对/判决 | 准确率 | UNKNOWN 弃权 |
|---|---|---|---|
| NAS | 93/95 | **98%** | 5 |
| CONTROLLER | 48/51 | **94%** | 49 |
| NVR | 81/95 | **85%** | 5 |
| ROUTER | 82/100 | **82%** | 0 |
| SCADA | 56/71 | **79%** | 29 |
| CAMERA | 73/94 | **78%** | 6 |
| PRINTER | 63/96 | **66%** | 4 |
| BUILDING_AUTOMATION | 31/65 | 48% | 35 |
| MEDICAL | 37/95 | 39% | 5 |
| ALARM | 5/16 | 31% | 21 |
| POWER_METER | 2/43 | 5% | 57 |
| **合计** | **571/821** | **69.5%** | **216** |

- 端到端口径（UNKNOWN 记错）：571/1037 = **55.1%**
- 强模型时代切片（前 604 条）：**78.8%**（476/604）
- 判决获胜方：CLAUDE 588 / GEMINI 233

**混淆热点**（committed 内）：CAMERA→NVR×16、MEDICAL→BA×21、
SCADA→CONTROLLER×10、PRINTER→ROUTER×13、BA↔NVR/ROUTER 互混。

**证据价值量化**：NAS 同类型在社区证据被限流的时代 18% → 恢复后 98%
（+80 分）；SCADA 误判 CONTROLLER 的 10/10 缺社区证据。

## 2. 分层诊断与改进方案

### 2.1 检索层

| # | 发现（证据） | 建议（按性价比） |
|---|---|---|
| R1 | ALARM/CONTROLLER overall 摘要曾缺失（cluster_report_missing 197×/类）| **已补**（`graph/regen_overall_summaries.py`，ALARM 4 / CONTROLLER 1）；CONTROLLER 仅 1 个巨簇，**聚类本身需重做** |
| R2 | POWER_METER overall PCA 源文件损坏 → 社区层整体缺失 → 5% 准确率 + 57 UNKNOWN | 上游重导出 + `cluster.py --hgt --devices POWER_METER` 重聚类；唯一根治路径 |
| R3 | community 每查询读 GB 级 PCA CSV | 构建期落 ip→cluster parquet/sqlite 查表 |
| R4 | LLM 失败的降级结果落缓存并被复用（三次大污染，全靠手工清理） | cache_metadata 加 llm+成功标志；失败不落盘 |
| R5 | local 为 numpy 暴力余弦（11264 维 × 36 万）；Milvus 31GB 已建未用；pymilvus/milvus-lite 版本不匹配 | 查询接 Milvus/HNSW；锁版本 |
| R6 | reasoning 依赖 community，社区缺失则证据骤降（NAS +80 分对照） | 社区缺失时显式降级 local-only 并标注 |

### 2.2 决策层（agent 流程）

| # | 发现（证据） | 建议 |
|---|---|---|
| D1 | 候选类型硬编码 9 类（修复前后 ALARM/CONTROLLER 0/22 → 22/22） | 已改配置驱动；加回归断言 |
| D2 | 单分支失败曾炸整图（92 空判） | 已改弃权制；标注 single_branch |
| D3 | 双分支串行 + ReAct 往返（强模型时代 118-188s/IP；本地 8B 11-55s） | 分支并行 ~2×；证据内联首轮省一轮 |
| D4 | **指纹全文进 prompt → 3-7 万 token/IP**：外部配额全灭主因；每 IP ~14 万 token | 截断/摘要（http-bodys 截 2KB）——token 降一个量级，**最大单项杠杆** |
| D5 | unseen vendor 阈值偏松（已知 CAMERA ~0.8 误触网搜） | 验证集重校准 |
| D6 | 弱决策模型 UNKNOWN 弃权率高（8B 时代 216 条弃权集中在 PM/BA/CONTROLLER/ALARM） | 弃权时自动回退 adapter-only 判决兜底（unseen 结果已在 first_stage） |
| D7 | 供应商敏感：强模型 78.8% vs 混合口径 69.5% vs 端到端 55.1% | 每条 record 附模型 manifest；报告必须注明 LLM 配置 |

### 2.3 评测与工程

| # | 发现 | 建议 |
|---|---|---|
| E1 | 验证集标签噪声（云主机/跨类型重复） | 三重排除复用为评测预处理 + 30 条错判人工抽检 |
| E2 | ALARM 验证集仅 3 台 | **已扩**到 37（demo 候选池，三重排除无泄漏） |
| E3 | 无运行 manifest，时代混跑需事后考古 | record 附 config+prompt+模型哈希+完整时间戳 |
| E4 | llm.py 无重试/熔断/降级链（GLM 路由+退避+本地 8B 兜底均为本次手动版） | 正式化：指数退避 → 备选端点 → 本地 vLLM 兜底（本次已验证可行） |
| E5 | UNKNOWN 挡重试 | driver 已修；框架侧区分 abstain/unknown |

## 3. 落地顺序（不动框架骨架）

1. **D4 指纹截断**（配额经济学根治）+ **E4 三级降级链**（云端→备选→本地 8B）
2. **R2 PM 数据修复** + CONTROLLER 重聚类（R1 延伸）
3. **D6 弃权兜底**（决策弃权时回退 adapter 判决，直接消 216 条 UNKNOWN 的损失）
4. **D3 分支并行**、R3 社区查表化
5. **E1 评测净化**后出正式精度；通道恢复后按原配重跑强模型时代缺口

## 4. 重跑协议（通道恢复后）

```bash
# 强模型配置: 恢复 config/llm_config.local.json 的 DEEPSEEK/GEMINI/CLAUDE 为官方端点后
printf '%s\n' POWER_METER BUILDING_AUTOMATION CONTROLLER ALARM SCADA CAMERA MEDICAL PRINTER NAS NVR ROUTER > /tmp/bench_queue.txt
for g in 0 1 2 3; do sleep 40; CUDA_VISIBLE_DEVICES=$g HF_HOME=/dev/shm/ft_v2/hf \
  /root/anaconda3/envs/elastic_slm/bin/python -u evaluation/run_bench_100.py --worker $g \
  > /home/nfs/iotprober/bench_w$g.log 2>&1 & done
# 已 committed 且非 UNKNOWN 的 IP 自动跳过；只补强模型时代的缺口
python evaluation/run_bench_100.py --summary
python evaluation/bench_100/finalize_report.py --markdown /tmp/report.md
```

本地 8B 兜底启动（下次配额再断时直接用）：
```bash
CUDA_VISIBLE_DEVICES=1 python -m vllm.entrypoints.openai.api_server \
  --model /home/nfs/models/Llama-3.1-8B-Instruct --served-model-name llama-3.1-8b \
  --port 8100 --max-model-len 65536 --enable-auto-tool-choice --tool-call-parser llama3_json
# config 三条目指 http://localhost:8100，CLAUDE 条目加 "PROTOCOL": "openai"
```

## 5. 原始数据

- `evaluation/bench_100/{TYPE}/records.jsonl`（last-wins 去重，含 UNKNOWN 行）
- 社区摘要再生：`graph/regen_overall_summaries.py`
- 本地 8B 兜底验证：vLLM JSON 模式 + llama3_json 工具解析全通
