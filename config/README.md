# Configuration

This directory contains the repository's fixed JSON and text configuration:

- `llm_config.json`: committed template for LLM endpoints and model names.
- `perspective_info.json`: perspective columns, prompts, and retrieval weights.
- `perspective_name.json`: perspective-to-feature mappings.
- `local_used_features.txt`: features used by graph construction and retrieval.
- `rag_devices.json`: device types known by the RAG pipeline.
- `all_IoT_devices.json`: complete device catalogue used by unseen detection.
- `new_devices.json`: candidate unseen device types.

Copy `llm_config.json` to `llm_config.local.json` and put credentials in the
local copy. The runtime prefers that file when present. `llm_config.local.json`,
`deepseek.json`, and `glm.json` may contain credentials and are excluded from
Git.
