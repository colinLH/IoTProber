# evaluation

评估与测试数据目录（已清空，仅保留目录结构）。

本目录原先存放：

- `validation/test_{DEV}_1.csv` — 各设备类型的测试指纹（agent 检索/决策流水线的输入）
- `validation/type|vendor/predict/…` — 设备类型 / 厂商预测结果输出
- `validation/baseline/…` — LLM 基线预测结果
- `unseen/` — unseen 设备检测的数据准备、LLaMA-3.1-8B + LoRA 微调与评估脚本
- 45/46 特征集对比实验数据

运行 `agent/agent.py` 的检索 / 决策流水线后，`validation/*/predict/` 下的
结果会自动重新生成；测试 CSV 等输入数据需由数据准备流程重新提供。

详见根目录 `readme.md`。
