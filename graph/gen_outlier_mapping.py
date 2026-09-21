"""Generate outlier IP → cluster_id mapping files by querying Neo4j.

For each perspective under platform_data/csv/rag/community/single/embedding_{persp}/,
creates a JSON file: outlier_cluster_mapping.json
Structure: { "ip1": cluster_id1, "ip2": cluster_id2, ... }

Also generates one for the comprehensive view under community/embedding_overall/.

Usage:
    python graph/gen_outlier_mapping.py
"""
import os
import sys
import json
import time
from py2neo import Graph

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from path_config import (
    RAG_DATA_DIR,
    RAG_OVERALL_COMMUNITY_DIR,
    RAG_SINGLE_COMMUNITY_DIR,
    ROOT_DIR,
)

BASE = ROOT_DIR
DATA = RAG_DATA_DIR
COMM = RAG_SINGLE_COMMUNITY_DIR
OVERALL = RAG_OVERALL_COMMUNITY_DIR
NEO4J_URL = "neo4j://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "avs01046"
BATCH = 5000


def generate_mapping_for_perspective(g, perspective, output_dir):
    """Query Neo4j for all outlier (ip, cluster_id) pairs for this perspective,
    save as JSON mapping file."""
    mapping = {}
    total = 0

    # Query in batches using skip/limit for memory efficiency
    skip = 0
    while True:
        result = g.run(
            """
            MATCH (d:Device)-[:IN_COMMUNITY]->(c:Cluster)
            WHERE c.is_outlier = true AND c.perspective = $persp
            RETURN d.ip AS ip, c.cluster_id AS cid
            SKIP $skip LIMIT $limit
            """,
            persp=perspective, skip=skip, limit=BATCH,
        ).data()

        if not result:
            break

        for r in result:
            ip = str(r["ip"]).strip()
            cid = int(r["cid"])
            # Each outlier is a singleton, so ip -> cid is 1:1 per perspective
            mapping[ip] = cid
            total += 1

        skip += BATCH
        print(f"  [{perspective}] Fetched {len(mapping)} unique IPs so far...")

    output_file = os.path.join(output_dir, "outlier_cluster_mapping.json")
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(mapping, f)

    print(f"  [{perspective}] Saved {len(mapping)} outlier mappings to {output_file}")
    return len(mapping)


def main():
    print("Connecting to Neo4j...")
    g = Graph(NEO4J_URL, auth=(NEO4J_USER, NEO4J_PASS))

    # Discover perspectives from directories
    perspectives = [
        d for d in sorted(os.listdir(COMM))
        if d.startswith("embedding_") and os.path.isdir(os.path.join(COMM, d))
    ]

    print(f"Found {len(perspectives)} perspectives: {[p[len('embedding_'):] for p in perspectives]}")

    total_all = 0
    t0 = time.time()

    for persp_dir in perspectives:
        persp_name = persp_dir[len("embedding_"):]
        output_dir = os.path.join(COMM, persp_dir)
        print(f"\nProcessing perspective: {persp_name}")
        cnt = generate_mapping_for_perspective(g, persp_name, output_dir)
        total_all += cnt

    # Comprehensive view
    if os.path.isdir(OVERALL):
        print(f"\nProcessing perspective: comprehensive")
        cnt = generate_mapping_for_perspective(g, "comprehensive", OVERALL)
        total_all += cnt

    elapsed = time.time() - t0
    print(f"\nDone! Total outlier mappings: {total_all} in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
