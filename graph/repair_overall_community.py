#!/usr/bin/env python
"""Rebuild the comprehensive-view (overall) communities of selected device types.

Used for device types whose overall community layer is damaged or degenerate
(POWER_METER: corrupted assignment file; CONTROLLER: one giant community;
ALARM: 61% noise). The procedure is deterministic and label-free:

  1. source = the concatenated per-perspective embedding
     ``ipraw_{dev}_embedding_overall_raw.csv`` (13 perspectives x 256 dims);
     when it is missing, it is materialised from the raw-layout assignment file.
  2. row-wise L2 normalisation -> PCA(d) (random_state fixed).
  3. HDBSCAN grid over (d, min_cluster_size, min_samples, selection method);
     the configuration with the highest DBCV validity index is selected among
     candidates with >= 3 clusters whose largest cluster holds <= 50% of the
     devices (fallback: highest DBCV with >= 2 clusters).
  4. noise points (-1) are attached to their most probable cluster via HDBSCAN
     soft clustering, so every knowledge-base device has a community
     (``assignment`` = core | soft, ``membership`` = probability).

Every overwritten artifact (assignment CSV, clusterer, cluster_info.json,
cluster summaries) is copied to ``*.bak_before_rebuild_<stamp>`` first. The old
summaries no longer match the new cluster ids, so they are moved aside and must
be regenerated with ``graph/regen_overall_summaries.py``.

Usage:
  python graph/repair_overall_community.py --devices POWER_METER CONTROLLER ALARM [--dry-run]
"""

import argparse
import hashlib
import itertools
import json
import os
import shutil
import sys
import tempfile
import warnings
from datetime import datetime

import hdbscan
import joblib
import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.preprocessing import normalize

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from path_config import LOCAL_OVERALL_COMMUNITY_DIR  # noqa: E402

MAX_LARGEST_SHARE = 0.5
MIN_CLUSTERS = 3


def atomic_write(path, writer, suffix):
    fd, tmp = tempfile.mkstemp(prefix=".rebuild-", suffix=suffix, dir=os.path.dirname(path))
    os.close(fd)
    try:
        writer(tmp)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def atomic_json(path, value):
    def write(tmp):
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
    atomic_write(path, write, ".json")


def backup(path, stamp, move=False):
    if not os.path.exists(path):
        return None
    destination = f"{path}.bak_before_rebuild_{stamp}"
    if not os.path.exists(destination):
        (shutil.move if move else shutil.copy2)(path, destination)
    elif move:
        os.remove(path)
    return destination


def load_source(device_type, directory, dry_run):
    raw_path = os.path.join(directory, f"ipraw_{device_type}_embedding_overall_raw.csv")
    if os.path.exists(raw_path):
        return pd.read_csv(raw_path, low_memory=False), raw_path
    assignment_path = os.path.join(directory, f"ipraw_{device_type}_embedding_overall_pca.csv")
    frame = pd.read_csv(assignment_path, low_memory=False)
    frame = frame.drop(columns=[c for c in ("cluster", "assignment", "membership") if c in frame])
    if any(column.startswith("pca") for column in frame.columns):
        raise FileNotFoundError(
            f"{raw_path} is missing and {assignment_path} only holds reduced features"
        )
    if not dry_run:
        atomic_write(raw_path, lambda tmp: frame.to_csv(tmp, index=False), ".csv")
        print(f"[{device_type}] materialised {raw_path}", flush=True)
    return frame, raw_path


def evaluate(reduced, min_cluster_size, min_samples, method):
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        cluster_selection_method=method,
        prediction_data=True,
    ).fit(reduced)
    labels = clusterer.labels_
    valid = labels[labels != -1]
    n_clusters = len(set(valid.tolist()))
    largest = float(np.bincount(valid).max() / len(labels)) if n_clusters else 1.0
    dbcv = float("nan")
    if n_clusters > 1:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                dbcv = float(hdbscan.validity.validity_index(reduced.astype(np.float64), labels))
            except (ValueError, ZeroDivisionError):
                pass
    return clusterer, {
        "min_cluster_size": min_cluster_size,
        "min_samples": min_samples,
        "selection": method,
        "clusters": n_clusters,
        "noise_share": round(float((labels == -1).mean()), 4),
        "largest_core_share": round(largest, 4),
        "dbcv": None if np.isnan(dbcv) else round(dbcv, 4),
    }


def select(candidates):
    def dbcv(row):
        return row["dbcv"] if row["dbcv"] is not None else -np.inf
    eligible = [c for c in candidates
                if c["clusters"] >= MIN_CLUSTERS and c["largest_core_share"] <= MAX_LARGEST_SHARE]
    pool = eligible or [c for c in candidates if c["clusters"] >= 2]
    if not pool:
        return None
    return max(pool, key=lambda c: (dbcv(c), -c["noise_share"]))


def soft_assign(clusterer):
    labels = clusterer.labels_.copy()
    membership = clusterer.probabilities_.astype(float).copy()
    assignment = np.where(labels == -1, "soft", "core")
    noise = labels == -1
    if noise.any():
        vectors = hdbscan.all_points_membership_vectors(clusterer)
        vectors = vectors.reshape(len(labels), -1)
        labels[noise] = vectors[noise].argmax(axis=1)
        membership[noise] = vectors[noise].max(axis=1)
    return labels, assignment, membership


def rebuild(device_type, dims, seed, dry_run):
    directory = LOCAL_OVERALL_COMMUNITY_DIR
    frame, source_path = load_source(device_type, directory, dry_run)
    frame["ip"] = frame["ip"].astype(str)
    if frame["ip"].duplicated().any():
        raise ValueError(f"{source_path} contains duplicate IPs")
    feature_columns = [c for c in frame.columns if c != "ip"]
    matrix = frame[feature_columns].to_numpy(dtype=np.float64, copy=False)
    if not np.isfinite(matrix).all():
        raise ValueError(f"{source_path} contains non-finite values")
    n = len(frame)
    print(f"[{device_type}] source {source_path}: {matrix.shape}", flush=True)

    normalised = normalize(matrix)
    sizes = (5, 10, 20) if n < 1000 else (10, 20, 40)
    grid, fitted = [], {}
    for d in dims:
        d_eff = min(d, n - 1, matrix.shape[1])
        pca = PCA(n_components=d_eff, random_state=seed).fit(normalised)
        reduced = pca.transform(normalised)
        for mcs, ms, method in itertools.product(sizes, (None, 5), ("eom", "leaf")):
            clusterer, row = evaluate(reduced, mcs, ms, method)
            row["pca_dims"] = d_eff
            grid.append(row)
            fitted[len(grid) - 1] = (pca, reduced, clusterer)
            print(f"[{device_type}] {row}", flush=True)

    chosen = select(grid)
    if chosen is None:
        raise RuntimeError(f"[{device_type}] no configuration produced >= 2 clusters")
    pca, reduced, clusterer = fitted[grid.index(chosen)]
    labels, assignment, membership = soft_assign(clusterer)
    sizes_after = pd.Series(labels).value_counts()
    print(f"[{device_type}] selected {chosen}; after soft assignment: "
          f"{len(sizes_after)} clusters, largest share {sizes_after.max() / n:.3f}", flush=True)

    manifest = {
        "device_type": device_type,
        "created": datetime.now().isoformat(timespec="seconds"),
        "source": source_path,
        "source_rows": n,
        "source_dims": len(feature_columns),
        "source_ip_sha256": hashlib.sha256("\n".join(sorted(frame["ip"])).encode()).hexdigest(),
        "procedure": "l2-normalise -> PCA -> HDBSCAN grid (max DBCV s.t. >=3 clusters, "
                     "largest <=50%) -> soft assignment of noise",
        "seed": seed,
        "selected": chosen,
        "clusters_after_soft_assignment": int(len(sizes_after)),
        "soft_assigned_devices": int((assignment == "soft").sum()),
        "largest_share_after_soft_assignment": round(float(sizes_after.max() / n), 4),
        "cluster_sizes": {str(int(k)): int(v) for k, v in sizes_after.sort_index().items()},
        "grid": grid,
    }
    if dry_run:
        print(json.dumps({k: v for k, v in manifest.items() if k != "grid"}, indent=2), flush=True)
        return manifest

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    paths = {
        "assignment": os.path.join(directory, f"ipraw_{device_type}_embedding_overall_pca.csv"),
        "clusterer": os.path.join(directory, f"clusterer_{device_type}.joblib"),
        "pca": os.path.join(directory, f"pca_{device_type}.joblib"),
        "cluster_info": os.path.join(directory, "cluster_info.json"),
        "summaries": os.path.join(directory, f"{device_type}_cluster_summaries.json"),
        "manifest": os.path.join(directory, f"rebuild_manifest_{device_type}.json"),
    }
    for key in ("assignment", "clusterer", "pca", "cluster_info"):
        saved = backup(paths[key], stamp)
        if saved:
            print(f"[{device_type}] backup: {saved}", flush=True)
    moved = backup(paths["summaries"], stamp, move=True)
    if moved:
        print(f"[{device_type}] stale summaries moved to {moved}", flush=True)

    result = pd.DataFrame(reduced, columns=[f"pca{i}" for i in range(1, reduced.shape[1] + 1)])
    result.insert(0, "ip", frame["ip"].values)
    result["cluster"] = labels.astype(np.int64)
    result["assignment"] = assignment
    result["membership"] = np.round(membership, 6)
    atomic_write(paths["assignment"], lambda tmp: result.to_csv(tmp, index=False), ".csv")
    atomic_write(paths["clusterer"], lambda tmp: joblib.dump(clusterer, tmp), ".joblib")
    atomic_write(paths["pca"], lambda tmp: joblib.dump(pca, tmp), ".joblib")

    info = {}
    if os.path.exists(paths["cluster_info"]):
        with open(paths["cluster_info"], encoding="utf-8") as handle:
            info = json.load(handle)
    device_info = {}
    for label in sorted(set(labels.tolist())):
        points = reduced[labels == label]
        center = points.mean(axis=0)
        distances = np.linalg.norm(points - center, axis=1)
        device_info[str(int(label))] = {
            "center": center.astype(float).tolist(),
            "max_distance": float(distances.max()),
            "min_10_distance": float(np.sort(distances)[9]) if len(distances) >= 10 else -1,
            "node_count": int(len(points)),
        }
    info[device_type] = device_info
    atomic_json(paths["cluster_info"], info)
    manifest["backup_stamp"] = stamp
    atomic_json(paths["manifest"], manifest)
    print(f"[{device_type}] wrote {paths['assignment']} and {paths['manifest']}", flush=True)
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--devices", nargs="+", required=True)
    parser.add_argument("--dims", nargs="+", type=int, default=[16, 32])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--dry-run", action="store_true",
                        help="Run the grid and print the selection without writing files")
    args = parser.parse_args()
    for device in args.devices:
        rebuild(device, args.dims, args.seed, args.dry_run)
