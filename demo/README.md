# IoTProber Demo — 11 类设备识别最小展示

每类设备（`rag_devices.json` 的 11 个 RAG 类型）各 3 个**识别效果最好**的真实指纹。
候选池 40/类，用 v2 adapter 走生产推理链路
（`UnseenDeviceDetector._build_aligned_prompt → _generate_classification → _classification_novelty_result`）
打分，取「类型判对 + 类型置信度最高」的 Top-3（同类内优先厂商不重复）。

## 候选池的三重排除（2026-09-20 审计后加入）

排名前必须知道 demo 数据是从什么池子里选的：

1. **训练/验证集 IP 排除**（65,027 个）——否则展示的是记忆而非识别
2. **跨类型重复 IP 排除**（15,346 个）——同一指纹同时出现在多个类型文件里，标签自相矛盾
3. **通用云主机排除**（约 8,900 行）——按 `dns-reverse`/`as-name`/`whois` 匹配 AWS/GCP/Azure 等；
   语料中 POWER_METER 一度 85% 是 AWS EC2 主机

排除后各类型候选池正确率（40 个候选，除非注明）：

| 类型 | 正确 | | 类型 | 正确 | | 类型 | 正确 |
|---|---|---|---|---|---|---|---|
| ALARM | 40/40 | | CONTROLLER | 40/40 | | NVR | 40/40 |
| POWER_METER | 38/38 | | MEDICAL | 39/40 | | NAS | 39/40 |
| SCADA | 39/40 | | BUILDING_AUTOMATION | 38/40 | | PRINTER | 37/40 |
| CAMERA | 36/40 | | ROUTER | 34/40 | | | |

> 说明：本 demo 的「正确」= 与 ipraw 语料的目录标签一致。语料标签本身有噪声
> （跨类型重复、云主机误标），上面第 2、3 条排除就是为了尽量剔除这类样本。
> CONTROLLER 的富指纹样本不足 40，候选取自全量并在 `selection_summary.json` 中标记
> `rich_filter_bypassed`。

## 目录

```
demo/
├── {TYPE}/cases.json            # 3 例：完整指纹 + 分类结果 + novelty + drift (+CAMERA 向量近邻)
├── selection_summary.json       # 每类：池大小/排除数/正确数/最高置信度/是否触及过滤回退
├── select_demo_data.py          # 筛选脚本（--candidates / --rank R / --merge，8 卡分片）
├── demo_showcase.ipynb          # 最小展示 notebook（已执行，含图表）
├── app.py + static/index.html   # 本地可视化 Web 界面
├── screenshot_ui.py             # 可选：无头浏览器截图（用于视觉回归）
└── README.md
```

## 环境要求（重要）

| 步骤 | 环境 | 原因 |
|---|---|---|
| 查看 notebook / 打开网页 | `iotprober` | 只需 pandas/matplotlib/flask |
| **在线识别**（`/api/classify`） | **`elastic_slm`** | 与生成 cases.json 时相同的 torch/transformers 数值，结果可比 |
| **重新筛选**（`select_demo_data.py`） | **`elastic_slm`** | 该脚本 import 训练脚本，依赖 `datasets`（iotprober 环境没有） |

```bash
EL=/root/anaconda3/envs/elastic_slm/bin/python     # 推理/筛选
IO=/root/anaconda3/envs/iotprober/bin/python       # 仅网页/notebook
```

## 运行

```bash
# 1) Notebook（静态展示，无需 GPU）
cd demo && $IO -m jupyter nbconvert --to notebook --execute --inplace demo_showcase.ipynb
#    或直接阅读已执行的 demo_showcase.ipynb

# 2) Web 界面 → http://localhost:5001
cd demo && $EL app.py
#    "在线识别"按需加载 v2 adapter：实测单卡约 8.7GB 显存，首次约 1 分钟
#    与存储值的关系：分类结果一致；置信度可能差 ~1e-5（4-bit 推理的浮点非确定性）
#    默认钉在 GPU 0（unseen.py 在 4-bit 下用 device_map="auto"，若不限制会把模型
#    铺满 8 卡共约 27GB）。换卡：DEMO_GPU=3 $EL app.py

# 3) 重新筛选（仅在语料更新时需要）
#    前置条件（易被忽略）：
#      · /dev/shm/ipraw/ipraw_{TYPE}.csv  ← 11 类原始指纹，约 8.4GB，tmpfs，重启即失
#        重建：hf_hub_download('IoTProber/raw_dataset', 'platform_data/rag/ipraw_files.tar.gz',
#                              repo_type='dataset') 后 tar -xzf 到 /dev/shm/ipraw
#      · /dev/shm/demo_select             ← 中间产物（candidates.json），同样是 tmpfs
#    因此三条命令必须按顺序、在同一开机周期内完成：
cd demo
$EL select_demo_data.py --candidates                   # 建候选池（含三重排除，~5 分钟）
for i in 0 1 2 3 4 5 6 7; do                            # 8 卡分片推理，~2 分钟
  CUDA_VISIBLE_DEVICES=$i $EL select_demo_data.py --rank $i --world_size 8 &
done
wait
$EL select_demo_data.py --merge                        # 选择 + drift + CAMERA 近邻（~2 分钟）
```

## 展示内容

每个 case 含：完整 46 列指纹、adapter 分类（类型/厂商/双置信度/两个 novelty 概率）、
PACA drift 分数（τ=8.7755，取自 artifacts，非硬编码）、以及 CAMERA 的向量近邻。

```bash
python - <<'PY'
import json
c = json.load(open('demo/CAMERA/cases.json'))[0]
print(c['ip'], c['result']['classified_type'], c['result']['classified_vendor'], c['result']['type_confidence'])
PY
```
