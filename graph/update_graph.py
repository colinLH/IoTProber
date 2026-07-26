"""
Graph incremental update algorithm.

When new IoT devices are discovered, this module updates the hierarchical graph
in-place without rebuilding from scratch:

1.  Insert each new device node into the Layer-1 entity graph (Neo4j
    Device–Feature bipartite graph).

2.  For every single-perspective and the comprehensive-perspective, use the
    saved HDBSCAN clusterer (joblib) to predict the cluster of the new device
    via ``approximate_predict``.  Depending on confidence / distance to the
    cluster centre:
      * low confidence or cluster == -1  →  assign a brand-new cluster ID.
      * distance < min_10_distance       →  trigger an LLM re-summary of that
        cluster (logged with timestamp, token usage, elapsed time) and update
        min_10_distance.
      * distance > max_distance          →  update max_distance.
    Neo4j Cluster nodes that received new members are marked ``updated=False``.

3.  A global update counter tracks how many devices have been incrementally
    inserted.  When it exceeds 50, a *partial re-clustering* is triggered:
      * Collect all device nodes belonging to clusters with ``updated=False``.
      * Find overlapping clusters whose ``max_distance`` circles intersect
        (centre distance ≤ max_distance₁ + max_distance₂).
      * Re-run HDBSCAN on the union of those device embeddings.
      * Assign new cluster IDs starting from 0, offset so they do not collide
        with any non-participating cluster ID.
    The counter is reset after each partial re-clustering.
"""

import os
import sys
import json
import time
import logging
import datetime
import hashlib
import numpy as np
import pandas as pd
import hdbscan
import joblib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from util import load_perspective_info, load_perspective_cluster_info, load_local_used_features
from llm import LLM

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
)
log = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINOR_REVISION = os.path.join(BASE, "platform_data", "csv", "rag", "minor_revision")
SINGLE_DIR = os.path.join(MINOR_REVISION, "single")
OVERALL_DIR = os.path.join(MINOR_REVISION, "embedding_overall")

NEO4J_URL = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "avs01046"

PCA_COLS = [f"pca{i}" for i in range(1, 257)]
PERSPECTIVES = [
    "as", "body", "certificate", "dns", "hfavicons",
    "hpart", "htags", "http", "hw", "os", "sd", "sw", "whois",
]
MIN_CLUSTER_SIZE = 20
RECLUSTER_THRESHOLD = 50          # trigger partial re-clustering after this many updates
CONFIDENCE_THRESHOLD = 0.3        # approximate_predict membership strength below this → new cluster
SUMMARY_LLM = "CLAUDE"            # LLM config key used for re-summarisation
SUMMARY_LOG = os.path.join(BASE, "graph", "update_summary_log.jsonl")


# ─── Helpers ─────────────────────────────────────────────────────────────

def _value_hash(val: str) -> str:
    """Short MD5 hash for feature value (matches build_neo4j.py)."""
    return hashlib.md5(val.encode("utf-8")).hexdigest()[:16]


def _rel_type(feat: str) -> str:
    return "Has_" + feat.replace("-", "_").replace(".", "_")


def _load_cluster_info(perspective: str) -> dict:
    """Load cluster_info.json for a single-perspective or 'comprehensive'."""
    if perspective == "comprehensive":
        path = os.path.join(OVERALL_DIR, "cluster_info.json")
    else:
        path = os.path.join(SINGLE_DIR, f"embedding_{perspective}", "cluster_info.json")
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_cluster_info(perspective: str, info: dict):
    if perspective == "comprehensive":
        path = os.path.join(OVERALL_DIR, "cluster_info.json")
    else:
        path = os.path.join(SINGLE_DIR, f"embedding_{perspective}", "cluster_info.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=2)


def _load_clusterer(perspective: str, dev: str):
    """Load a saved HDBSCAN clusterer from joblib."""
    if perspective == "comprehensive":
        path = os.path.join(OVERALL_DIR, f"clusterer_{dev}.joblib")
    else:
        path = os.path.join(SINGLE_DIR, f"embedding_{perspective}", f"clusterer_{dev}.joblib")
    if not os.path.exists(path):
        return None
    return joblib.load(path)


def _compute_distance(point: np.ndarray, center: np.ndarray) -> float:
    return float(np.linalg.norm(point - center))


def _recompute_cluster_stats(points: np.ndarray) -> dict:
    """Recompute center, max_distance, min_10_distance for a set of points."""
    if len(points) == 0:
        return {}
    center = points.mean(axis=0)
    dists = np.linalg.norm(points - center, axis=1)
    max_dist = float(dists.max())
    if len(dists) >= 10:
        min_10 = float(np.sort(dists)[9])
    else:
        min_10 = -1
    return {
        "center": center.tolist(),
        "max_distance": max_dist,
        "min_10_distance": min_10,
        "node_count": len(points),
    }


# ─── Main class ──────────────────────────────────────────────────────────

class GraphUpdater:
    """
    Incremental graph update engine.

    Usage::

        updater = GraphUpdater()
        updater.update_devices([
            {"ip": "1.2.3.4", "device_type": "ALARM",
             "features": {"as-asn": "123", ...},
             "embeddings": {"as": [0.1, ...], "comprehensive": [0.2, ...]}},
            ...
        ])
    """

    def __init__(self, neo4j_graph=None, llm=None):
        self.base_path = BASE
        self.perspective_info = load_perspective_info()
        self.perspective_cluster_info = load_perspective_cluster_info()
        self.perspective_names = list(self.perspective_cluster_info.keys())
        self.features = load_local_used_features()

        # Neo4j connection (py2neo Graph or compatible)
        if neo4j_graph is not None:
            self.db = neo4j_graph
        else:
            try:
                from py2neo import Graph
                self.db = Graph(NEO4J_URL, auth=(NEO4J_USER, NEO4J_PASS))
            except Exception as e:
                log.warning("Neo4j connection failed: %s – operating in no-DB mode", e)
                self.db = None

        # LLM for cluster re-summarisation
        self.llm = llm if llm is not None else LLM()

        # Global update counter (persisted across runs)
        self.counter_file = os.path.join(BASE, "graph", "update_counter.json")
        self.update_counter = self._load_counter()

        # Per-perspective next-new-cluster-ID tracker (persisted)
        self.next_id_file = os.path.join(BASE, "graph", "next_cluster_ids.json")
        self.next_cluster_ids = self._load_next_ids()

    # ── persistence helpers ──────────────────────────────────────────

    def _load_counter(self) -> int:
        if os.path.exists(self.counter_file):
            with open(self.counter_file, "r") as f:
                return json.load(f).get("counter", 0)
        return 0

    def _save_counter(self):
        with open(self.counter_file, "w") as f:
            json.dump({"counter": self.update_counter}, f)

    def _load_next_ids(self) -> dict:
        if os.path.exists(self.next_id_file):
            with open(self.next_id_file, "r") as f:
                return json.load(f)
        return {}

    def _save_next_ids(self):
        with open(self.next_id_file, "w") as f:
            json.dump(self.next_cluster_ids, f)

    def _get_next_cluster_id(self, perspective: str, dev: str) -> int:
        """Return a new unique cluster ID for (perspective, dev) and increment.

        Ensures the new ID does not collide with existing cluster_info keys
        (HDBSCAN labels) NOR with Neo4j cluster_ids (global counter).
        """
        key = f"{perspective}_{dev}"
        cid = self.next_cluster_ids.get(key, 0)
        # Ensure it doesn't collide with existing IDs in cluster_info
        info = _load_cluster_info(perspective)
        existing = set()
        if dev in info:
            existing = set(int(k) for k in info[dev].keys())
        # Also check Neo4j cluster_ids to avoid collisions
        neo4j_ids = self._get_all_cluster_ids(perspective)
        existing = existing | neo4j_ids
        while cid in existing:
            cid += 1
        self.next_cluster_ids[key] = cid + 1
        self._save_next_ids()
        return cid

    # ── Step 1: Layer-1 entity graph insertion ───────────────────────

    def _insert_device_node(self, ip: str, device_type: str, features: dict):
        """
        Insert a single Device node + its Feature nodes into Neo4j Layer-1
        entity graph, mirroring build_neo4j.build_layer1 logic.
        """
        if self.db is None:
            log.warning("[L1] No Neo4j connection, skipping node insertion for %s", ip)
            return

        # MERGE Device node
        self.db.run(
            "MERGE (d:Device {ip: $ip, device_type: $dev})",
            ip=ip, dev=device_type,
        )

        for feat_name, feat_value in features.items():
            val = str(feat_value).strip()
            if not val:
                continue
            vh = _value_hash(val)
            rt = _rel_type(feat_name)
            self.db.run(
                "MERGE (d:Device {ip: $ip, device_type: $dev}) "
                "MERGE (f:Feature {feature_name: $feat, value_hash: $vh}) "
                "SET f.value = $val "
                "MERGE (d)-[:%s]-(f)" % rt,
                ip=ip, dev=device_type, feat=feat_name, vh=vh, val=val,
            )

        log.info("[L1] Inserted device %s (%s) with %d features", ip, device_type, len(features))

    # ── Step 2: Per-perspective cluster prediction & update ──────────

    def _predict_cluster(self, clusterer, embedding: np.ndarray):
        """
        Use approximate_predict to get (label, probability).
        Returns (label, prob).
        """
        if clusterer is None:
            return -1, 0.0
        point = embedding.reshape(1, -1)
        labels, probs = hdbscan.approximate_predict(clusterer, point)
        return int(labels[0]), float(probs[0])

    def _trigger_llm_summary(self, perspective: str, dev: str, cluster_id: int,
                             device_ips: list, cluster_info_entry: dict) -> dict:
        """
        Trigger an LLM re-summary for a cluster.  Logs timestamp, token usage,
        and elapsed time to SUMMARY_LOG (JSONL).

        Returns the summary log entry dict.
        """
        t_start = time.time()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Build prompt from perspective info and device IPs
        persp_desc = self.perspective_info.get(perspective, {}).get("prompt_info", perspective)

        prompt = (
            f"You are an expert in IoT device fingerprinting analysis.\n"
            f"Perspective: {perspective} ({persp_desc})\n"
            f"Device type: {dev}\n"
            f"Cluster ID: {cluster_id}\n"
            f"Number of devices in cluster: {len(device_ips)}\n"
            f"Device IPs: {', '.join(device_ips[:50])}\n\n"
            f"Please provide a concise summary of the common patterns and "
            f"distribution characteristics of these devices in JSON format."
        )

        messages = [{"role": "user", "content": prompt}]

        token_usage = {}
        summary_text = ""
        try:
            summary_text, token_usage = self.llm.chat_with_llm(
                SUMMARY_LLM, messages, whether_json=True, return_usage=True
            )
        except Exception as e:
            log.error("[Summary] LLM call failed for %s/%s/cluster %d: %s",
                      perspective, dev, cluster_id, e)
            summary_text = {"error": str(e)}

        elapsed = time.time() - t_start

        log_entry = {
            "timestamp": timestamp,
            "perspective": perspective,
            "device_type": dev,
            "cluster_id": cluster_id,
            "device_count": len(device_ips),
            "elapsed_seconds": round(elapsed, 3),
            "token_usage": token_usage,
            "summary": summary_text if isinstance(summary_text, dict) else str(summary_text),
        }

        # Append to JSONL log
        with open(SUMMARY_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")

        log.info("[Summary] %s/%s/cluster %d re-summarised in %.2fs, tokens=%s",
                 perspective, dev, cluster_id, elapsed, token_usage)

        return log_entry

    def _update_neo4j_cluster_link(self, ip: str, perspective: str, dev: str,
                                    cluster_id: int, is_new_cluster: bool):
        """
        Update Neo4j: create/link Cluster node to the new Device node.
        Set ``updated=False`` on the Cluster node.
        """
        if self.db is None:
            return

        if is_new_cluster:
            # Create a new Cluster node
            self.db.run(
                "MERGE (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                "SET c.hdbscan_label = -1, c.is_outlier = false, c.updated = false",
                cid=cluster_id, persp=perspective, dev=dev,
            )
        else:
            # Mark existing cluster as updated=false
            self.db.run(
                "MATCH (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                "SET c.updated = false",
                cid=cluster_id, persp=perspective, dev=dev,
            )

        # Link device → cluster
        self.db.run(
            "MATCH (d:Device {ip: $ip}) "
            "MATCH (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
            "MERGE (d)-[:IN_COMMUNITY {perspective: $persp}]->(c)",
            ip=ip, cid=cluster_id, persp=perspective, dev=dev,
        )

    def _update_single_perspective(self, dev: str, ip: str, perspective: str,
                                    embedding: np.ndarray):
        """
        Process one (device, perspective) pair:
        predict cluster, handle new cluster / distance updates / LLM summary.
        """
        clusterer = _load_clusterer(perspective, dev)
        if clusterer is None:
            log.warning("[Update] No clusterer for %s/%s, skipping", perspective, dev)
            return

        label, prob = self._predict_cluster(clusterer, embedding)
        cluster_info = _load_cluster_info(perspective)
        dev_info = cluster_info.get(dev, {})

        is_new_cluster = False
        assigned_cluster_id = label

        # Case 1: low confidence or noise → new cluster
        if label == -1 or prob < CONFIDENCE_THRESHOLD:
            assigned_cluster_id = self._get_next_cluster_id(perspective, dev)
            is_new_cluster = True

            # Record new cluster in cluster_info
            new_entry = {
                "center": embedding.tolist(),
                "max_distance": 0.0,
                "min_10_distance": -1,
                "node_count": 1,
            }
            dev_info[str(assigned_cluster_id)] = new_entry
            cluster_info[dev] = dev_info
            _save_cluster_info(perspective, cluster_info)

            log.info("[Update] %s/%s/%s: new cluster %d (prob=%.3f, label=%d)",
                     perspective, dev, ip, assigned_cluster_id, prob, label)

            self._update_neo4j_cluster_link(ip, perspective, dev, assigned_cluster_id, True)
            return

        # Case 2: assigned to existing cluster
        cluster_key = str(label)
        if cluster_key not in dev_info:
            log.warning("[Update] %s/%s: predicted label %d not in cluster_info, treating as new",
                        perspective, dev, label)
            assigned_cluster_id = self._get_next_cluster_id(perspective, dev)
            is_new_cluster = True
            dev_info[str(assigned_cluster_id)] = {
                "center": embedding.tolist(),
                "max_distance": 0.0,
                "min_10_distance": -1,
                "node_count": 1,
            }
            cluster_info[dev] = dev_info
            _save_cluster_info(perspective, cluster_info)
            self._update_neo4j_cluster_link(ip, perspective, dev, assigned_cluster_id, True)
            return

        entry = dev_info[cluster_key]
        center = np.array(entry["center"])
        dist = _compute_distance(embedding, center)

        # Update node count
        entry["node_count"] = entry.get("node_count", 0) + 1

        # Track incrementally added device for _get_cluster_device_ips / _get_cluster_points
        entry.setdefault("added_ips", []).append(ip)
        entry.setdefault("added_embeddings", []).append(embedding.tolist())

        # Check min_10_distance → trigger LLM re-summary
        center_recomputed = False
        if entry["min_10_distance"] != -1 and dist < entry["min_10_distance"]:
            log.info("[Update] %s/%s/%s: dist=%.4f < min_10=%.4f, triggering re-summary",
                     perspective, dev, ip, dist, entry["min_10_distance"])

            # Get all device IPs in this cluster from Neo4j (or from PCA CSV)
            device_ips = self._get_cluster_device_ips(perspective, dev, label)

            self._trigger_llm_summary(perspective, dev, label, device_ips, entry)

            # Update min_10_distance: recompute from all points including the new one
            all_points = self._get_cluster_points(perspective, dev, label)
            if all_points is not None and len(all_points) > 0:
                all_points = np.vstack([all_points, embedding.reshape(1, -1)])
                stats = _recompute_cluster_stats(all_points)
                entry["min_10_distance"] = stats["min_10_distance"]
                entry["center"] = stats["center"]
                entry["max_distance"] = stats["max_distance"]
                center_recomputed = True
            else:
                # Fallback: just update min_10 to the new distance
                entry["min_10_distance"] = dist

        # Check max_distance → update
        elif dist > entry["max_distance"]:
            entry["max_distance"] = dist
            log.info("[Update] %s/%s/%s: dist=%.4f > max=%.4f, updated max_distance",
                     perspective, dev, ip, dist, entry["max_distance"])

        # Update center incrementally (skip if already recomputed above)
        if not center_recomputed:
            old_count = entry["node_count"] - 1
            if old_count > 0:
                new_center = (np.array(entry["center"]) * old_count + embedding) / entry["node_count"]
                entry["center"] = new_center.tolist()

        dev_info[cluster_key] = entry
        cluster_info[dev] = dev_info
        _save_cluster_info(perspective, cluster_info)

        self._update_neo4j_cluster_link(ip, perspective, dev, assigned_cluster_id, False)

        log.info("[Update] %s/%s/%s → cluster %d (prob=%.3f, dist=%.4f)",
                 perspective, dev, ip, assigned_cluster_id, prob, dist)

    def _get_cluster_device_ips(self, perspective: str, dev: str, cluster_label: int) -> list:
        """Retrieve all IPs belonging to a cluster from the PCA CSV file
        and the incremental device log."""
        ips = []
        if perspective == "comprehensive":
            csv_path = os.path.join(OVERALL_DIR, f"ipraw_{dev}_embedding_overall_pca.csv")
        else:
            csv_path = os.path.join(SINGLE_DIR, f"embedding_{perspective}",
                                    f"ipraw_{dev}_embedding_{perspective}_pca.csv")
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path, usecols=["ip", "cluster"])
            ips = df[df["cluster"] == cluster_label]["ip"].astype(str).tolist()

        # Also include incrementally added devices tracked in cluster_info
        info = _load_cluster_info(perspective)
        dev_info = info.get(dev, {})
        entry = dev_info.get(str(cluster_label), {})
        if entry and "added_ips" in entry:
            ips.extend(entry["added_ips"])
        return ips

    def _get_cluster_points(self, perspective: str, dev: str, cluster_label: int):
        """Retrieve all PCA embedding points for a cluster from the PCA CSV
        and the incremental device log."""
        if perspective == "comprehensive":
            csv_path = os.path.join(OVERALL_DIR, f"ipraw_{dev}_embedding_overall_pca.csv")
        else:
            csv_path = os.path.join(SINGLE_DIR, f"embedding_{perspective}",
                                    f"ipraw_{dev}_embedding_{perspective}_pca.csv")

        points = None
        if os.path.exists(csv_path):
            df = pd.read_csv(csv_path)
            if perspective == "comprehensive":
                feature_cols = [c for c in df.columns if c not in ("ip", "cluster")]
            else:
                feature_cols = [c for c in df.columns if c.startswith("pca")]

            sub = df[df["cluster"] == cluster_label]
            if not sub.empty:
                points = sub[feature_cols].values

        # Also include incrementally added device embeddings from cluster_info
        info = _load_cluster_info(perspective)
        dev_info = info.get(dev, {})
        entry = dev_info.get(str(cluster_label), {})
        if entry and "added_embeddings" in entry:
            added = np.array(entry["added_embeddings"])
            if points is not None:
                points = np.vstack([points, added])
            else:
                points = added
        return points

    def _update_comprehensive(self, dev: str, ip: str, overall_embedding: np.ndarray):
        """Process the comprehensive-perspective cluster update."""
        self._update_single_perspective(dev, ip, "comprehensive", overall_embedding)

    # ── Step 3: Partial re-clustering ────────────────────────────────

    def _get_stale_clusters(self, perspective: str) -> list:
        """
        Query Neo4j for all Cluster nodes with ``updated=False`` for the given
        perspective.  Returns list of dicts: {cluster_id, device_type, hdbscan_label}.
        """
        if self.db is None:
            return []

        results = self.db.run(
            "MATCH (c:Cluster {perspective: $persp, updated: false}) "
            "RETURN c.cluster_id AS cid, c.device_type AS dev, c.hdbscan_label AS hlabel",
            persp=perspective,
        ).data()
        return results

    def _get_all_cluster_ids(self, perspective: str) -> set:
        """Get all cluster IDs currently in use for a perspective (from Neo4j)."""
        if self.db is None:
            return set()
        results = self.db.run(
            "MATCH (c:Cluster {perspective: $persp}) RETURN DISTINCT c.cluster_id AS cid",
            persp=perspective,
        ).data()
        return set(r["cid"] for r in results)

    def _find_overlapping_clusters(self, perspective: str, stale_clusters: list,
                                    cluster_info: dict) -> list:
        """
        Given stale clusters, find other clusters whose max_distance circles
        overlap (centre_distance ≤ max_distance₁ + max_distance₂).
        Returns the full set of cluster IDs to include in re-clustering.
        """
        stale_ids = set()
        stale_data = []  # (dev, cluster_id, center, max_distance)

        for sc in stale_clusters:
            dev = sc["dev"]
            cid = sc["cid"]
            info = cluster_info.get(dev, {})
            entry = info.get(str(sc["hlabel"]), None)
            if entry is None:
                # Try by cluster_id directly
                for k, v in info.items():
                    if int(k) == cid:
                        entry = v
                        break
            if entry is None:
                continue
            stale_ids.add((dev, cid))
            stale_data.append((dev, cid, np.array(entry["center"]), entry["max_distance"]))

        # Find overlapping clusters
        all_include = set(stale_ids)
        for dev in cluster_info:
            dev_info = cluster_info[dev]
            for ckey, centry in dev_info.items():
                cid = int(ckey)
                if (dev, cid) in stale_ids:
                    continue
                center2 = np.array(centry["center"])
                max2 = centry["max_distance"]

                for sdev, scid, center1, max1 in stale_data:
                    if sdev != dev:
                        continue
                    d = _compute_distance(center1, center2)
                    if d <= max1 + max2:
                        all_include.add((dev, cid))
                        break

        return all_include

    def _partial_recluster(self, perspective: str):
        """
        Perform partial re-clustering for a single perspective:
        1. Find all stale (updated=False) clusters.
        2. Find overlapping clusters.
        3. Collect all device nodes in the subset.
        4. Re-run HDBSCAN.
        5. Assign new cluster IDs that don't collide with non-participating IDs.
        6. Update Neo4j and cluster_info.

        Key mapping: Neo4j Cluster nodes use a global ``cluster_id`` counter
        (assigned in build_neo4j.py), while ``cluster_info.json`` keys and the
        PCA CSV ``cluster`` column use per-device HDBSCAN labels (0-based).
        The ``stale_clusters`` from Neo4j carry both ``cid`` (Neo4j cluster_id)
        and ``hlabel`` (HDBSCAN label).  We use ``hlabel`` to filter the CSV
        and ``cid`` to delete old Neo4j nodes.
        """
        log.info("[Recluster] Starting partial re-clustering for perspective '%s'", perspective)

        stale_clusters = self._get_stale_clusters(perspective)
        if not stale_clusters:
            log.info("[Recluster] No stale clusters for '%s', skipping", perspective)
            return

        cluster_info = _load_cluster_info(perspective)
        subset = self._find_overlapping_clusters(perspective, stale_clusters, cluster_info)

        if not subset:
            log.info("[Recluster] Empty subset for '%s', skipping", perspective)
            return

        log.info("[Recluster] %s: %d stale clusters, %d total clusters in subset",
                 perspective, len(stale_clusters), len(subset))

        # Build a lookup from stale_clusters: (dev, neo4j_cid) → hdbscan_label
        stale_lookup = {}
        for sc in stale_clusters:
            stale_lookup[(sc["dev"], sc["cid"])] = sc["hlabel"]

        # Group subset by device type: dev → set of Neo4j cluster_ids
        dev_clusters = {}
        for dev, cid in subset:
            dev_clusters.setdefault(dev, set()).add(cid)

        # Determine the starting new cluster_id (avoid collision with all existing Neo4j IDs)
        all_used_ids = self._get_all_cluster_ids(perspective)
        max_existing_id = max(all_used_ids) if all_used_ids else -1
        next_id = max_existing_id + 1

        for dev, cid_set in dev_clusters.items():
            # Load PCA CSV for this device
            if perspective == "comprehensive":
                csv_path = os.path.join(OVERALL_DIR, f"ipraw_{dev}_embedding_overall_pca.csv")
            else:
                csv_path = os.path.join(SINGLE_DIR, f"embedding_{perspective}",
                                        f"ipraw_{dev}_embedding_{perspective}_pca.csv")

            if not os.path.exists(csv_path):
                log.warning("[Recluster] CSV not found: %s", csv_path)
                continue

            df = pd.read_csv(csv_path)
            if perspective == "comprehensive":
                feat_cols = [c for c in df.columns if c not in ("ip", "cluster")]
            else:
                feat_cols = [c for c in df.columns if c.startswith("pca")]

            # Map Neo4j cluster_ids in cid_set → HDBSCAN labels for CSV filtering
            dev_info = cluster_info.get(dev, {})
            hlabels_to_include = set()
            for cid in cid_set:
                # From stale_clusters lookup
                hlabel = stale_lookup.get((dev, cid))
                if hlabel is not None:
                    hlabels_to_include.add(hlabel)
                # Also check cluster_info: if a key matches the cid numerically,
                # it may be a newly assigned cluster_id (from incremental update)
                # that was used directly as both Neo4j cluster_id and CSV label
                if str(cid) in dev_info:
                    hlabels_to_include.add(cid)

            sub_df = df[df["cluster"].isin(hlabels_to_include)]
            if sub_df.empty:
                log.warning("[Recluster] No devices found for %s/%s subset", perspective, dev)
                continue

            X = sub_df[feat_cols].values
            log.info("[Recluster] %s/%s: re-clustering %d devices",
                     perspective, dev, len(X))

            # Re-run HDBSCAN
            new_clusterer = hdbscan.HDBSCAN(min_cluster_size=MIN_CLUSTER_SIZE,
                                             prediction_data=True)
            new_labels = new_clusterer.fit_predict(X)

            if (new_labels == -1).all():
                new_labels[:] = 0

            # Assign new cluster IDs starting from next_id, avoiding collisions
            new_id_map = {}  # new hdbscan label → new cluster_id
            for hl in sorted(set(new_labels)):
                if hl == -1:
                    continue
                new_id_map[hl] = next_id
                next_id += 1

            # Update the CSV with new cluster labels
            sub_df = sub_df.copy()
            sub_df["cluster"] = [new_id_map.get(l, -1) for l in new_labels]

            # Update the original DataFrame
            df.loc[sub_df.index, "cluster"] = sub_df["cluster"]
            df.to_csv(csv_path, index=False)

            # Save new clusterer
            if perspective == "comprehensive":
                clusterer_path = os.path.join(OVERALL_DIR, f"clusterer_{dev}.joblib")
            else:
                clusterer_path = os.path.join(SINGLE_DIR, f"embedding_{perspective}",
                                               f"clusterer_{dev}.joblib")
            joblib.dump(new_clusterer, clusterer_path)

            # Update cluster_info for this device
            new_dev_info = {}
            for hl, cid in new_id_map.items():
                mask = new_labels == hl
                points = X[mask]
                stats = _recompute_cluster_stats(points)
                new_dev_info[str(cid)] = stats

            # Handle noise points (label == -1) as singletons
            noise_mask = new_labels == -1
            noise_ip_list = []
            if noise_mask.any():
                noise_indices = np.where(noise_mask)[0]
                for idx_in_sub in noise_indices:
                    noise_ip = str(sub_df.iloc[idx_in_sub]["ip"])
                    cid = next_id
                    next_id += 1
                    point = X[idx_in_sub]
                    new_dev_info[str(cid)] = {
                        "center": point.tolist(),
                        "max_distance": 0.0,
                        "min_10_distance": -1,
                        "node_count": 1,
                    }
                    noise_ip_list.append((noise_ip, cid))

            # Merge: remove old entries for participating clusters, add new ones
            old_keys_to_remove = set()
            for ckey in dev_info:
                ckey_int = int(ckey)
                # Remove if this HDBSCAN label is in the subset
                if ckey_int in hlabels_to_include:
                    old_keys_to_remove.add(ckey)
            for k in old_keys_to_remove:
                dev_info.pop(k, None)
            dev_info.update(new_dev_info)
            cluster_info[dev] = dev_info

            # Update Neo4j: remove old cluster nodes for subset, create new ones
            if self.db is not None:
                # Delete old IN_COMMUNITY edges and Cluster nodes for the subset
                for cid in cid_set:
                    self.db.run(
                        "MATCH (d:Device)-[r:IN_COMMUNITY]->(c:Cluster "
                        "{cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                        "DELETE r",
                        cid=cid, persp=perspective, dev=dev,
                    )
                    self.db.run(
                        "MATCH (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                        "DETACH DELETE c",
                        cid=cid, persp=perspective, dev=dev,
                    )

                # Create new Cluster nodes and edges for valid clusters
                for hl, cid in new_id_map.items():
                    self.db.run(
                        "MERGE (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                        "SET c.hdbscan_label = $hl, c.is_outlier = false, c.updated = true",
                        cid=cid, persp=perspective, dev=dev, hl=hl,
                    )
                    member_ips = sub_df[new_labels == hl]["ip"].astype(str).tolist()
                    for mip in member_ips:
                        self.db.run(
                            "MATCH (d:Device {ip: $ip}) "
                            "MATCH (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                            "MERGE (d)-[:IN_COMMUNITY {perspective: $persp}]->(c)",
                            ip=mip, cid=cid, persp=perspective, dev=dev,
                        )

                # Create noise singleton Cluster nodes and edges in Neo4j
                for noise_ip, cid in noise_ip_list:
                    self.db.run(
                        "MERGE (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                        "SET c.hdbscan_label = -1, c.is_outlier = true, c.updated = true",
                        cid=cid, persp=perspective, dev=dev,
                    )
                    self.db.run(
                        "MATCH (d:Device {ip: $ip}) "
                        "MATCH (c:Cluster {cluster_id: $cid, perspective: $persp, device_type: $dev}) "
                        "MERGE (d)-[:IN_COMMUNITY {perspective: $persp}]->(c)",
                        ip=noise_ip, cid=cid, persp=perspective, dev=dev,
                    )

            log.info("[Recluster] %s/%s: %d new clusters + %d noise singletons, IDs %s",
                     perspective, dev, len(new_id_map), len(noise_ip_list),
                     list(new_id_map.values()))

        _save_cluster_info(perspective, cluster_info)
        log.info("[Recluster] Perspective '%s' re-clustering complete", perspective)

    def _check_and_recluster(self):
        """Check if the global counter exceeds threshold and trigger re-clustering."""
        if self.update_counter < RECLUSTER_THRESHOLD:
            return

        log.info("[Recluster] Update counter %d ≥ threshold %d, triggering partial re-clustering",
                 self.update_counter, RECLUSTER_THRESHOLD)

        # Re-cluster all perspectives including comprehensive
        all_perspectives = list(self.perspective_names) + ["comprehensive"]
        for perspective in all_perspectives:
            self._partial_recluster(perspective)

        # Reset counter
        self.update_counter = 0
        self._save_counter()
        log.info("[Recluster] Counter reset to 0")

    # ── Public API ───────────────────────────────────────────────────

    def update_devices(self, devices: list):
        """
        Incrementally update the graph with a batch of new devices.

        Each device dict must contain:
            - ip: str
            - device_type: str (e.g. "ALARM", "CONTROLLER")
            - features: dict of {feature_name: value} for Layer-1
            - embeddings: dict of {perspective_name: [float, ...]} PCA embeddings
              (must include "comprehensive" for the overall perspective)
        """
        for dev_info in devices:
            ip = dev_info["ip"]
            dev_type = dev_info["device_type"]
            features = dev_info.get("features", {})
            embeddings = dev_info.get("embeddings", {})

            log.info("=== Updating device %s (%s) ===", ip, dev_type)

            # Step 1: Insert into Layer-1 entity graph
            self._insert_device_node(ip, dev_type, features)

            # Step 2: Update each single-perspective cluster
            for perspective in self.perspective_names:
                emb = embeddings.get(perspective)
                if emb is None:
                    log.warning("[Update] No embedding for %s/%s, skipping", perspective, ip)
                    continue
                emb_arr = np.array(emb, dtype=np.float64)
                self._update_single_perspective(dev_type, ip, perspective, emb_arr)

            # Step 2b: Update comprehensive-perspective cluster
            overall_emb = embeddings.get("comprehensive")
            if overall_emb is not None:
                self._update_comprehensive(dev_type, ip, np.array(overall_emb, dtype=np.float64))
            else:
                log.warning("[Update] No comprehensive embedding for %s, skipping", ip)

            # Increment global counter
            self.update_counter += 1
            self._save_counter()

            # Step 3: Check if partial re-clustering is needed
            self._check_and_recluster()

        log.info("Batch update complete. Counter: %d/%d", self.update_counter, RECLUSTER_THRESHOLD)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Incremental graph update")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be updated without modifying Neo4j")
    args = parser.parse_args()

    updater = GraphUpdater()

    # Example usage with a single test device
    # In practice, embeddings would be pre-computed from the embedding model
    example_devices = [
        {
            "ip": "192.168.1.100",
            "device_type": "ALARM",
            "features": {
                "as-asn": "12345",
                "as-name": "TEST-AS",
                "os-vendor": "Linux",
            },
            "embeddings": {
                # Each perspective's 256-dim PCA embedding
                "as": [0.0] * 256,
                "os": [0.0] * 256,
                # ... other perspectives ...
                "comprehensive": [0.0] * 3328,
            },
        },
    ]

    if args.dry_run:
        log.info("Dry run mode – no Neo4j modifications")
        updater.db = None

    updater.update_devices(example_devices)
