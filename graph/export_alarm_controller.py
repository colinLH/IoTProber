"""Export ALARM and CONTROLLER Device-Feature subgraph from Neo4j
and append to entity_graph/{node,relation}.csv."""
import os
import sys
import pandas as pd
from py2neo import Graph

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from path_config import ENTITY_GRAPH_DIR, ROOT_DIR

BASE = ROOT_DIR
ENTITY_GRAPH = ENTITY_GRAPH_DIR
NEO4J = Graph("neo4j://localhost:7687", auth=("neo4j", "avs01046"))

existing_nodes = pd.read_csv(os.path.join(ENTITY_GRAPH, "node.csv"), usecols=["_id"])
max_id = int(existing_nodes["_id"].max())
next_id = max_id + 1
print(f"Existing max _id: {max_id}, starting new IDs from {next_id}")

node_rows = []
relation_rows = []
feature_id_cache = {}

for dev_type in ["ALARM", "CONTROLLER"]:
    devices = NEO4J.run(
        "MATCH (d:Device {device_type: $dt}) RETURN d.ip AS ip ORDER BY ip",
        dt=dev_type,
    ).data()
    print(f"{dev_type}: {len(devices)} devices")

    for dev in devices:
        ip = dev["ip"]
        device_id = next_id
        next_id += 1
        node_rows.append({
            "_id": device_id, "_labels": ":Device",
            "ip": ip, "device_type": dev_type,
            "feature_name": "", "value": "",
        })

        feats = NEO4J.run(
            "MATCH (d:Device {ip: $ip, device_type: $dt})-[r]->(f:Feature) "
            "RETURN f.feature_name AS fn, f.value AS fv, type(r) AS rt",
            ip=ip, dt=dev_type,
        ).data()

        for feat in feats:
            fn = feat["fn"] or ""
            fv = feat["fv"] or ""
            rt = feat["rt"]
            key = (fn, fv)
            feat_id = feature_id_cache.get(key)
            if feat_id is None:
                feat_id = next_id
                next_id += 1
                feature_id_cache[key] = feat_id
                node_rows.append({
                    "_id": feat_id, "_labels": ":Feature",
                    "ip": "", "device_type": "",
                    "feature_name": fn, "value": fv,
                })
            relation_rows.append({
                "_start": device_id, "_end": feat_id, "_type": rt,
            })

n_dev = len([n for n in node_rows if n["_labels"] == ":Device"])
n_feat = len([n for n in node_rows if n["_labels"] == ":Feature"])
print(f"New nodes: {len(node_rows)} ({n_dev} Device, {n_feat} Feature)")
print(f"New relations: {len(relation_rows)}")

new_nodes_df = pd.DataFrame(node_rows, columns=["_id", "_labels", "ip", "device_type", "feature_name", "value"])
new_rels_df = pd.DataFrame(relation_rows, columns=["_start", "_end", "_type"])

new_nodes_df.to_csv(os.path.join(ENTITY_GRAPH, "node.csv"), mode="a", header=False, index=False)
new_rels_df.to_csv(os.path.join(ENTITY_GRAPH, "relation.csv"), mode="a", header=False, index=False)
print("Appended successfully")

# Verify
verify = pd.read_csv(os.path.join(ENTITY_GRAPH, "node.csv"), usecols=["_id", "_labels", "device_type"])
devs = verify[verify["_labels"] == ":Device"]
print(f"Total devices now: {len(devs)}")
print(f"Device types: {sorted(devs['device_type'].unique().tolist())}")
print(devs["device_type"].value_counts().to_string())
