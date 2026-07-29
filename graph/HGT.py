"""
HGT.py - 使用 Heterogeneous Graph Transformer (HGT) 在Device-Feature二部图上
         学习每个设备IP的最终向量表示（综合视角嵌入）
         Device节点初始嵌入为11个视角嵌入的均值（1024维）
         Feature节点初始嵌入为Qwen3对"feature_name: value"字符串的编码（1024维）
         并对高度数Feature节点施加1/log(degree)惩罚因子
         最终向量表示的维度为1024维

Data is loaded from entity_graph/node.csv and entity_graph/relation.csv.
Results are saved to platform_data/csv/rag/community/embedding_HGT/
Each device type gets its own file: ipraw_{dev}_embedding_overall_raw.csv

Usage:
    python graph/HGT.py                  # dual-GPU parallel (GPU 0 + GPU 1)
    python graph/HGT.py --gpu 0          # single GPU
    python graph/HGT.py --gpu -1         # CPU only
    python graph/HGT.py --epochs 200
"""

import os
import sys
import gc
import logging
import argparse
import multiprocessing as mp

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
from torch_geometric.nn import HGTConv, Linear
from langchain_huggingface import HuggingFaceEmbeddings

import warnings
warnings.filterwarnings("ignore")

# ─── 路径配置 / Path config ───────────────────────────────────────────
BASE_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOCAL_PATH = os.path.join(BASE_PATH, "platform_data", "csv", "rag")
ENTITY_GRAPH_PATH = os.path.join(BASE_PATH, "entity_graph")
EMBEDDING_MODEL_PATH = os.path.join(BASE_PATH, "qwen3_embedding_06b")
HGT_SAVE_PATH = os.path.join(LOCAL_PATH, "community", "embedding_HGT")
RAG_DEVICES_FILE = os.path.join(BASE_PATH, "rag_devices.json")

# 11个视角名称（与embedding_local CSV列前缀一致，排除hpart/http）
PERSPECTIVE_NAMES = ['as', 'whois', 'os', 'sw', 'hw', 'sd', 'body', 'htags', 'hfavicons', 'certificate', 'dns']


def load_rag_device_types():
    """Load the allowed device types from rag_devices.json (IoT list)."""
    import json
    with open(RAG_DEVICES_FILE, 'r') as f:
        data = json.load(f)
    return set(data.get('IoT', []))

# ─── 日志 / Logging ──────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)

os.environ["PYTORCH_ALLOC_CONF"] = "max_split_size_mb:128,expandable_segments:True,garbage_collection_threshold:0.8"


class HGTModel(torch.nn.Module):
    def __init__(self, in_channels, hidden_channels, out_channels, num_heads, num_layers, metadata):
        super().__init__()

        # Device和Feature节点均为1024维初始嵌入，共享相同的输入维度
        self.device_lin = Linear(in_channels, hidden_channels)
        self.feature_lin = Linear(in_channels, hidden_channels)

        self.convs = torch.nn.ModuleList()
        self.norms = torch.nn.ModuleList()
        self.dropout = nn.Dropout(p=0.1)

        node_types = metadata[0]
        for _ in range(num_layers):
            conv = HGTConv(hidden_channels, hidden_channels, metadata,
                           num_heads, group='sum')
            self.convs.append(conv)
            # 每层对每种节点类型独立的LayerNorm
            self.norms.append(nn.ModuleDict({
                nt: nn.LayerNorm(hidden_channels) for nt in node_types
            }))

        self.device_out = Linear(hidden_channels, out_channels)

    def forward(self, x_dict, edge_index_dict):
        # 输入投影
        x_dict['device'] = self.device_lin(x_dict['device']).relu()
        x_dict['feature'] = self.feature_lin(x_dict['feature']).relu()

        # HGT层：residual + Dropout + LayerNorm（公式3）
        # h_v^(l+1) = LayerNorm(h_v^(l) + Dropout(h̃_v^(l+1)))
        for conv, norm_dict in zip(self.convs, self.norms):
            h_dict = conv(x_dict, edge_index_dict)
            new_x_dict = {}
            for nt in x_dict:
                if nt in h_dict and nt in norm_dict:
                    new_x_dict[nt] = norm_dict[nt](x_dict[nt] + self.dropout(h_dict[nt]))
                else:
                    new_x_dict[nt] = x_dict[nt]
            x_dict = new_x_dict

        # 输出投影（仅对device节点）
        device_emb = self.device_out(x_dict['device'])
        return device_emb


def build_embedding_model(gpu: int):
    device_str = str(gpu) if gpu != -1 else "cpu"
    model = HuggingFaceEmbeddings(
        model_name=EMBEDDING_MODEL_PATH,
        model_kwargs={"device": device_str},
        encode_kwargs={"normalize_embeddings": True, "batch_size": 4},
        query_encode_kwargs={"normalize_embeddings": True, "batch_size": 1},
    )
    if gpu != -1:
        gc.collect()
        torch.cuda.empty_cache()
        torch.cuda.reset_peak_memory_stats()
    return model


def load_device_embeddings(device_nodes: pd.DataFrame, high_mem: bool = False) -> torch.Tensor:
    """
    从预计算的embedding_local CSV文件中加载各Device节点的11个视角嵌入，
    取均值得到1024维初始嵌入向量。
    low-mem模式使用chunked读取控制内存（cgroup限制32GB，CAMERA文件25GB）。
    high-mem模式一次性读取全量CSV（适用于H100等大内存环境）。
    """
    embedding_local_path = os.path.join(LOCAL_PATH, "embedding_local")
    ip_to_emb = {}

    if 'device_type' in device_nodes.columns:
        for dev_type, group in device_nodes.groupby('device_type'):
            csv_path = os.path.join(embedding_local_path, f"ipraw_{dev_type}_embedding.csv")
            if not os.path.exists(csv_path):
                logging.warning(f"[HGT] Embedding CSV not found: {csv_path}")
                for ip in group['ip'].values:
                    ip_to_emb[str(ip)] = [0.0] * 1024
                continue

            mode_str = "full-load" if high_mem else "chunked"
            logging.info(f"[HGT] Loading embedding CSV for {dev_type} ({mode_str})...")

            # 先读header确定可用列
            header_df = pd.read_csv(csv_path, nrows=0)
            all_cols = set(header_df.columns)
            del header_df

            target_ips = {str(ip) for ip in group['ip'].values}

            # 收集所有视角列
            perspective_col_groups = []
            needed_cols = ['ip']
            for p in PERSPECTIVE_NAMES:
                cols = [f"{p}{i+1}" for i in range(1024) if f"{p}{i+1}" in all_cols]
                if cols:
                    perspective_col_groups.append(cols)
                    needed_cols.extend(cols)

            dtype_map = {c: np.float32 for c in needed_cols if c != 'ip'}

            def _process_matched(matched):
                for _, row in matched.iterrows():
                    ip_str = row['ip']
                    persp_embs = []
                    for cols in perspective_col_groups:
                        persp_embs.append(row[cols].values.astype(np.float32))
                    avg = sum(persp_embs) / len(persp_embs) if persp_embs else np.zeros(1024, dtype=np.float32)
                    ip_to_emb[ip_str] = avg.tolist()

            total_matched = 0

            if high_mem:
                # 一次性全量读取
                emb_df = pd.read_csv(csv_path, usecols=needed_cols, dtype=dtype_map)
                emb_df['ip'] = emb_df['ip'].astype(str)
                matched = emb_df[emb_df['ip'].isin(target_ips)]
                total_matched = len(matched)
                _process_matched(matched)
                del emb_df, matched
            else:
                # 分块读取，每块5000行
                chunk_size = 5000
                for chunk in pd.read_csv(csv_path, usecols=needed_cols, dtype=dtype_map, chunksize=chunk_size):
                    chunk['ip'] = chunk['ip'].astype(str)
                    matched = chunk[chunk['ip'].isin(target_ips)]
                    if len(matched) == 0:
                        del chunk
                        continue
                    total_matched += len(matched)
                    _process_matched(matched)
                    del chunk, matched

            gc.collect()
            logging.info(f"[HGT] {dev_type}: {total_matched}/{len(target_ips)} IPs matched, {len(ip_to_emb)} embeddings computed")

            for ip in group['ip'].values:
                if str(ip) not in ip_to_emb:
                    ip_to_emb[str(ip)] = [0.0] * 1024
    else:
        logging.warning("[HGT] device_type column not found; using zero embeddings for devices.")
        for ip in device_nodes['ip'].values:
            ip_to_emb[str(ip)] = [0.0] * 1024

    features = [ip_to_emb.get(str(ip), [0.0] * 1024) for ip in device_nodes['ip'].values]
    return torch.tensor(features, dtype=torch.float)


def run_hgt_on_subset(gpu: int, device_types: list, num_epochs: int, node_df: pd.DataFrame, relation_df: pd.DataFrame, high_mem: bool = False):
    """
    在指定GPU上对一组设备类型运行HGT训练和embedding生成。
    每个设备类型独立保存为 ipraw_{dev}_embedding_overall_raw.csv。
    """
    tag = f"[HGT-GPU{gpu}]"
    device_str = f'cuda:{gpu}' if gpu >= 0 and torch.cuda.is_available() else 'cpu'
    torch_device = torch.device(device_str)
    logging.info(f"{tag} Processing device types: {device_types} on {device_str}")

    # ── 过滤出当前子集的Device节点 ──
    subset_device_nodes = node_df[
        (node_df['_labels'] == ':Device') &
        (node_df['device_type'].isin(device_types))
    ].copy().reset_index(drop=True)

    # ── 向量化过滤关系：只保留_start在当前Device子集中的边 ──
    subset_device_ids = set(int(x) for x in subset_device_nodes['_id'].values)
    logging.info(f"{tag} Filtering relations for {len(subset_device_ids)} devices...")
    rel_filtered = relation_df[
        relation_df['_start'].isin(subset_device_ids) &
        relation_df['_type'].fillna('').str.startswith('Has_')
    ].copy()

    # ── 收集这些Device连接的Feature节点 ──
    subset_feature_ids = set(rel_filtered['_end'].dropna().astype(int).unique().tolist())

    subset_feature_nodes = node_df[
        (node_df['_labels'] == ':Feature') &
        (node_df['_id'].isin(subset_feature_ids))
    ].copy().reset_index(drop=True)

    logging.info(f"{tag} Device nodes: {len(subset_device_nodes)}, Feature nodes: {len(subset_feature_nodes)}, Relations: {len(rel_filtered)}")

    # ── 创建节点ID映射 ──
    device_id_map = {int(row['_id']): idx for idx, row in subset_device_nodes.iterrows()}
    feature_id_map = {int(row['_id']): idx for idx, row in subset_feature_nodes.iterrows()}

    # ── 向量化构建边索引 ──
    rel_filtered['_start_idx'] = rel_filtered['_start'].map(device_id_map)
    rel_filtered['_end_idx'] = rel_filtered['_end'].map(feature_id_map)
    rel_filtered = rel_filtered.dropna(subset=['_start_idx', '_end_idx'])
    rel_filtered['_start_idx'] = rel_filtered['_start_idx'].astype(int)
    rel_filtered['_end_idx'] = rel_filtered['_end_idx'].astype(int)

    edge_dict = {}
    for rel_type, group in rel_filtered.groupby('_type'):
        edge_dict[str(rel_type)] = group[['_start_idx', '_end_idx']].values.tolist()

    logging.info(f"{tag} Edge types: {len(edge_dict)}")

    # ── 计算Feature节点的degree ──
    feature_degree = torch.zeros(len(subset_feature_nodes), dtype=torch.float)
    for edges in edge_dict.values():
        for _, feature_idx in edges:
            feature_degree[feature_idx] += 1

    # ── 构建Device节点初始嵌入 ──
    logging.info(f"{tag} Building device node features...")
    device_features = load_device_embeddings(subset_device_nodes, high_mem=high_mem)
    logging.info(f"{tag} Device feature shape: {device_features.shape}")

    # ── 构建Feature节点初始嵌入 ──
    logging.info(f"{tag} Building feature node features...")
    embedding_model = build_embedding_model(gpu)

    feature_features_list = []
    for _, row in subset_feature_nodes.iterrows():
        feat_name = str(row['feature_name']) if pd.notna(row.get('feature_name')) else ""
        feat_val = str(row['value']) if pd.notna(row.get('value')) else ""
        feat_str = f"{feat_name}: {feat_val}"
        emb = embedding_model.embed_query(feat_str)
        feature_features_list.append(emb)

    feature_features = torch.tensor(feature_features_list, dtype=torch.float)

    # degree惩罚因子
    penalty = torch.where(
        feature_degree > 1,
        1.0 / torch.log(feature_degree),
        torch.ones_like(feature_degree)
    )
    feature_features = feature_features * penalty.unsqueeze(1)
    logging.info(f"{tag} Feature feature shape: {feature_features.shape}")

    # 释放embedding模型显存
    del embedding_model
    gc.collect()
    if gpu >= 0:
        torch.cuda.empty_cache()

    # ── 创建异构图数据 ──
    data = HeteroData()
    data['device'].x = device_features
    data['feature'].x = feature_features

    for rel_type, edges in edge_dict.items():
        edge_tensor = torch.tensor(edges, dtype=torch.long).t().contiguous()
        data['device', rel_type, 'feature'].edge_index = edge_tensor
        data['feature', f'rev_{rel_type}', 'device'].edge_index = edge_tensor.flip([0])

    logging.info(f"{tag} Total edge types (incl. reverse): {len(data.edge_index_dict)}")

    # ── 初始化模型 ──
    model = HGTModel(
        in_channels=1024,
        hidden_channels=512,
        out_channels=1024,
        num_heads=8,
        num_layers=2,
        metadata=data.metadata(),
    ).to(torch_device)
    data = data.to(torch_device)

    # ── 训练 ──
    logging.info(f"{tag} Training HGT model for {num_epochs} epochs...")
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    model.train()

    for epoch in range(num_epochs):
        optimizer.zero_grad()
        device_emb = model(data.x_dict, data.edge_index_dict)

        all_edge_tensors = [
            data['device', rel_type, 'feature'].edge_index
            for rel_type in edge_dict
        ]
        if all_edge_tensors:
            all_edges = torch.cat(all_edge_tensors, dim=1)
            num_samples = min(1000, all_edges.shape[1])
            sample_idx = torch.randperm(all_edges.shape[1])[:num_samples]
            sampled_edges = all_edges[:, sample_idx]

            device_idx = sampled_edges[0]
            feature_idx = sampled_edges[1]

            device_emb_sample = device_emb[device_idx]
            feature_emb_sample = data.x_dict['feature'][feature_idx]
            feature_proj = model.device_out(model.feature_lin(feature_emb_sample))

            cos_sim = F.cosine_similarity(device_emb_sample, feature_proj, dim=1)
            loss = 1 - cos_sim.mean()
            loss += 0.001 * (device_emb.norm(2) / device_emb.shape[0])
        else:
            loss = 0.001 * (device_emb.norm(2) / device_emb.shape[0])

        loss.backward()
        optimizer.step()

        if (epoch + 1) % 10 == 0:
            logging.info(f"{tag} Epoch {epoch+1}/{num_epochs}, Loss: {loss.item():.4f}")

    # ── 生成最终embedding ──
    logging.info(f"{tag} Generating final device embeddings...")
    model.eval()
    with torch.no_grad():
        final_device_emb = model(data.x_dict, data.edge_index_dict)
        final_device_emb = final_device_emb.cpu().numpy()

    # ── 按设备类型分别保存 ──
    os.makedirs(HGT_SAVE_PATH, exist_ok=True)
    embedding_cols = [f"hgt_emb_{i}" for i in range(1024)]

    for dev_type in device_types:
        mask = subset_device_nodes['device_type'] == dev_type
        dev_indices = mask.values
        dev_ips = subset_device_nodes.loc[mask, 'ip'].values
        dev_embs = final_device_emb[dev_indices]

        result_df = pd.DataFrame(dev_embs, columns=embedding_cols)
        result_df.insert(0, 'ip', dev_ips)

        output_path = os.path.join(HGT_SAVE_PATH, f"ipraw_{dev_type}_embedding_overall_raw.csv")
        result_df.to_csv(output_path, index=False)
        logging.info(f"{tag} Saved {dev_type}: {len(result_df)} devices → {output_path}")

    logging.info(f"{tag} Done. Processed {len(device_types)} device types.")


def _worker_fn(gpu, device_types, num_epochs, subset_node_csv, subset_relation_csv, high_mem=False):
    """Worker process entry point for multiprocessing.
    Loads pre-filtered subset CSVs (much smaller than full entity_graph)."""
    node_df = pd.read_csv(subset_node_csv)
    relation_df = pd.read_csv(subset_relation_csv)
    run_hgt_on_subset(gpu, device_types, num_epochs, node_df, relation_df, high_mem=high_mem)


def _prepare_subset_csvs(device_types, node_df, relation_df, tag):
    """Filter node_df and relation_df for given device types, save to temp CSVs."""
    import tempfile
    tmp_dir = os.path.join(ENTITY_GRAPH_PATH, "tmp_subsets")
    os.makedirs(tmp_dir, exist_ok=True)

    # Filter device nodes
    dev_nodes = node_df[
        (node_df['_labels'] == ':Device') &
        (node_df['device_type'].isin(device_types))
    ].copy()
    dev_ids = set(int(x) for x in dev_nodes['_id'].values)

    # Filter relations: only edges from these devices
    rel_filtered = relation_df[
        relation_df['_start'].isin(dev_ids) &
        relation_df['_type'].fillna('').str.startswith('Has_')
    ].copy()

    # Collect feature IDs needed
    feat_ids = set(rel_filtered['_end'].dropna().astype(int).unique().tolist())
    feat_nodes = node_df[
        (node_df['_labels'] == ':Feature') &
        (node_df['_id'].isin(feat_ids))
    ].copy()

    # Combine and save
    subset_nodes = pd.concat([dev_nodes, feat_nodes], ignore_index=True)
    node_path = os.path.join(tmp_dir, f"node_{tag}.csv")
    rel_path = os.path.join(tmp_dir, f"relation_{tag}.csv")
    subset_nodes.to_csv(node_path, index=False)
    rel_filtered.to_csv(rel_path, index=False)

    logging.info(f"[HGT] Subset {tag}: {len(dev_nodes)} devices, {len(feat_nodes)} features, {len(rel_filtered)} relations → temp CSVs")
    return node_path, rel_path


def run_hgt(gpu: int = 1, num_epochs: int = 100, high_mem: bool = False, chunk_only: bool = False):
    """
    使用Heterogeneous Graph Transformer (HGT)在Device-Feature二部图上
    学习每个设备IP的最终向量表示（综合视角嵌入），最终向量维度为1024维。
    当gpu=1且双GPU可用时，自动将设备类型分配到GPU 0和GPU 1并行训练。
    """
    logging.info("[HGT] Starting HGT device embedding generation...")

    node_csv = os.path.join(ENTITY_GRAPH_PATH, "node.csv")
    relation_csv = os.path.join(ENTITY_GRAPH_PATH, "relation.csv")

    if not os.path.exists(node_csv) or not os.path.exists(relation_csv):
        logging.error(f"[HGT] entity_graph files not found. Run build.py --export first.")
        return

    # ── 读取node.csv获取所有设备类型 ──
    node_df = pd.read_csv(node_csv, usecols=['_id', '_labels', 'ip', 'device_type', 'feature_name', 'value'])
    device_nodes = node_df[node_df['_labels'] == ':Device']
    all_device_types = sorted(device_nodes['device_type'].unique().tolist())

    # ── 只处理 rag_devices.json 中列出的设备类型 ──
    rag_device_types = load_rag_device_types()
    all_device_types = [d for d in all_device_types if d in rag_device_types]
    device_nodes = device_nodes[device_nodes['device_type'].isin(all_device_types)]
    logging.info(f"[HGT] Device types (filtered by rag_devices.json): {all_device_types}")

    # ── 按设备数量均衡分配到两个GPU ──
    dev_counts = device_nodes['device_type'].value_counts().to_dict()
    # 按数量降序排列，交替分配到两个GPU（贪心均衡）
    sorted_devs = sorted(all_device_types, key=lambda d: dev_counts.get(d, 0), reverse=True)
    gpu0_devs, gpu1_devs = [], []
    gpu0_count, gpu1_count = 0, 0
    for dev in sorted_devs:
        cnt = dev_counts.get(dev, 0)
        if gpu0_count <= gpu1_count:
            gpu0_devs.append(dev)
            gpu0_count += cnt
        else:
            gpu1_devs.append(dev)
            gpu1_count += cnt

    logging.info(f"[HGT] GPU0 devices: {gpu0_devs} ({gpu0_count} devices)")
    logging.info(f"[HGT] GPU1 devices: {gpu1_devs} ({gpu1_count} devices)")

    # ── 单GPU模式 ──
    if gpu != 1 or not torch.cuda.is_available() or torch.cuda.device_count() < 2:
        actual_gpu = gpu if gpu >= 0 else 0
        logging.info(f"[HGT] Single-GPU mode (gpu={gpu}, high_mem={high_mem}, chunk_only={chunk_only})")
        relation_df = pd.read_csv(relation_csv)
        run_hgt_on_subset(actual_gpu, all_device_types, num_epochs, node_df, relation_df, high_mem=high_mem)
        return

    # ── 双GPU并行模式 ──
    # 三种内存模式：
    #   high_mem:    全量加载CSV，worker直接加载完整entity_graph（H100）
    #   chunk_only:  chunked读取embedding CSV，worker直接加载完整entity_graph（图结构完整）
    #   default:     chunked读取 + subset预过滤（图结构可能不完整，最省内存）
    use_subset = not high_mem and not chunk_only
    logging.info(f"[HGT] Dual-GPU parallel mode (high_mem={high_mem}, chunk_only={chunk_only}, subset={use_subset})")

    if use_subset:
        # V100/受限内存环境：主进程预过滤小子集CSV，worker只加载子集
        logging.info("[HGT] Loading relation.csv for subset preparation...")
        relation_df = pd.read_csv(relation_csv)

        logging.info("[HGT] Preparing subset CSVs...")
        gpu0_node_csv, gpu0_rel_csv = _prepare_subset_csvs(gpu0_devs, node_df, relation_df, "gpu0")
        gpu1_node_csv, gpu1_rel_csv = _prepare_subset_csvs(gpu1_devs, node_df, relation_df, "gpu1")

        # 释放主进程的大DataFrame
        del node_df, relation_df
        gc.collect()

        p0 = mp.Process(target=_worker_fn, args=(0, gpu0_devs, num_epochs, gpu0_node_csv, gpu0_rel_csv, False))
        p1 = mp.Process(target=_worker_fn, args=(1, gpu1_devs, num_epochs, gpu1_node_csv, gpu1_rel_csv, False))
    else:
        # high_mem 或 chunk_only：worker直接加载完整entity_graph，图结构完整
        p0 = mp.Process(target=_worker_fn, args=(0, gpu0_devs, num_epochs, node_csv, relation_csv, high_mem))
        p1 = mp.Process(target=_worker_fn, args=(1, gpu1_devs, num_epochs, node_csv, relation_csv, high_mem))

    p0.start()
    p1.start()

    p0.join()
    p1.join()

    if p0.exitcode != 0:
        logging.error(f"[HGT] GPU0 worker exited with code {p0.exitcode}")
    if p1.exitcode != 0:
        logging.error(f"[HGT] GPU1 worker exited with code {p1.exitcode}")

    # 清理临时文件（subset模式）
    if use_subset:
        for f in [gpu0_node_csv, gpu0_rel_csv, gpu1_node_csv, gpu1_rel_csv]:
            try:
                os.remove(f)
            except OSError:
                pass

    logging.info("[HGT] Dual-GPU training complete.")


def main():
    parser = argparse.ArgumentParser(description="HGT Device Embedding Generation")
    parser.add_argument(
        "--gpu", type=int, default=1, choices=[-1, 0, 1],
        help="GPU device number: 0 or 1 for single-GPU, 1 for dual-GPU parallel (default: 1), -1 for CPU"
    )
    parser.add_argument(
        "--epochs", type=int, default=100,
        help="Number of training epochs (default: 100)"
    )
    parser.add_argument(
        "--high-mem", action="store_true", default=False,
        help="Full-load CSVs, no OOM mitigations. Use on H100 or large-memory hosts."
    )
    parser.add_argument(
        "--chunk-only", action="store_true", default=False,
        help="Use chunked CSV reading only (no subset pre-filtering). Preserves complete graph structure."
    )
    args = parser.parse_args()

    log_filename = "HGT.log"
    file_handler = logging.FileHandler(log_filename, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logging.getLogger().addHandler(file_handler)

    run_hgt(gpu=args.gpu, num_epochs=args.epochs, high_mem=args.high_mem, chunk_only=args.chunk_only)


if __name__ == "__main__":
    main()
