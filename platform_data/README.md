# platform_data

平台原始数据目录（已清空，仅保留目录结构）。

本目录原先存放：

- `csv/local/1/` — 本地原始设备指纹 CSV（含 `vectorDB/` 向量库，局部检索底座）
- `csv/rag/` — RAG 知识域设备指纹（层次社区图构建输入）
- `csv/all/`、`csv/label/` — 全量采集数据与设备类型标签

数据由 `acquire_data.py`（Censys 平台采集）生成，由 `graph/construction.py`
消费以构建层次社区图与 HGT 设备嵌入。

注意：本目录整体位于 `.gitignore` 中（大数据文件不入库），仅本 README
被强制跟踪。

详见根目录 `readme.md`。
