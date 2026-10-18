#!/usr/bin/env python3
"""Restore single-perspective summary JSON files from existing text reports.

The text reports and PCA/HDBSCAN assignments are the authoritative artifacts
for a few legacy perspectives whose machine-readable ``*_cluster_summaries``
files were never written.  This converter is deterministic and makes no LLM
calls.
"""

import argparse
import ast
import json
import os
import re
import sys
import tempfile
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from path_config import RAG_DATA_DIR


COMMUNITY_SINGLE = Path(RAG_DATA_DIR) / "community" / "single"
PERSPECTIVE_INFO_PATH = Path(__file__).resolve().parents[1] / "config" / "perspective_info.json"
PERSPECTIVE_INFO = json.loads(PERSPECTIVE_INFO_PATH.read_text(encoding="utf-8"))
CLUSTER_HEADER = re.compile(r"^CLUSTER\s+(-?\d+)\s+-\s+(\d+)\s+devices$")
FIELDS = {
    "Common Patterns:": "common_patterns",
    "Distribution Characteristics:": "distribution_characteristics",
    "Notable Similarities:": "notable_similarities",
    "Cluster Summary:": "cluster_summary",
}


def _parse_value(text: str):
    text = text.strip()
    try:
        return ast.literal_eval(text)
    except (SyntaxError, ValueError):
        return text


def parse_report(path: Path):
    rows = []
    current = None
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        match = CLUSTER_HEADER.match(line)
        if match:
            if current is not None:
                rows.append(current)
            current = {
                "cluster_id": int(match.group(1)),
                "device_count": int(match.group(2)),
                "analysis": {},
            }
            continue
        if current is None:
            continue
        for prefix, key in FIELDS.items():
            if line.startswith(prefix):
                current["analysis"][key] = _parse_value(line[len(prefix):])
                break
    if current is not None:
        rows.append(current)
    rows.sort(key=lambda row: row["cluster_id"])
    if len({row['cluster_id'] for row in rows}) != len(rows):
        raise ValueError(f"duplicate cluster IDs in {path}")
    return rows


def assignment_cluster_ids(path: Path):
    frame = pd.read_csv(path, usecols=["cluster"])
    clusters = pd.to_numeric(frame["cluster"], errors="raise").astype(int)
    return set(clusters[clusters >= 0].tolist())


def _short_value(value, limit=500):
    text = str(value).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 20] + f" ...[{len(text)} chars]"


def deterministic_missing_summaries(
    device: str, perspective: str, assignment_path: Path, missing_ids
):
    """Build compact local frequency summaries for report gaps."""
    columns = PERSPECTIVE_INFO[perspective]["cols"]
    assignments = pd.read_csv(assignment_path, usecols=["ip", "cluster"], dtype={"ip": str})
    assignments["cluster"] = pd.to_numeric(assignments["cluster"], errors="raise").astype(int)
    raw_path = Path(RAG_DATA_DIR) / f"ipraw_{device}.csv"
    raw = pd.read_csv(raw_path, usecols=["ip"] + columns, dtype={"ip": str}, low_memory=False)
    merged = assignments.merge(raw, on="ip", how="left")
    summaries = []
    for cluster_id in sorted(missing_ids):
        group = merged[merged["cluster"] == cluster_id]
        common_patterns = {}
        repeated = []
        for column in columns:
            values = group[column].dropna().astype(str)
            values = values[~values.str.strip().str.lower().isin({"", "nan", "none"})]
            counts = values.value_counts().head(3)
            common_patterns[column] = [
                {"value": _short_value(value), "count": int(count)}
                for value, count in counts.items()
            ]
            if not counts.empty:
                repeated.append(
                    f"{column}: top value appears in {int(counts.iloc[0])}/"
                    f"{len(group)} devices"
                )
        summaries.append({
            "cluster_id": int(cluster_id),
            "device_count": int(len(group)),
            "analysis": {
                "common_patterns": common_patterns,
                "distribution_characteristics": (
                    "Deterministic local frequency summary; no remote LLM call was used."
                ),
                "notable_similarities": repeated,
                "cluster_summary": (
                    f"Cluster {cluster_id} contains {len(group)} {device} devices. "
                    "The common patterns above list the three most frequent non-empty "
                    f"values for the {perspective} perspective."
                ),
            },
        })
    return summaries


def atomic_json_dump(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.remove(temp_name)


def restore(perspective: str, overwrite: bool = False):
    directory = COMMUNITY_SINGLE / f"embedding_{perspective}"
    outputs = []
    assignment_suffix = f"_embedding_{perspective}_pca.csv"
    for assignment_path in sorted(directory.glob(f"ipraw_*{assignment_suffix}")):
        device = assignment_path.name.removeprefix("ipraw_").removesuffix(
            assignment_suffix
        )
        report_path = directory / f"ipraw_{device}_cluster_report.txt"
        output_path = directory / f"{device}_cluster_summaries.json"
        if output_path.exists() and not overwrite:
            continue
        summaries = parse_report(report_path) if report_path.exists() else []
        report_ids = {row["cluster_id"] for row in summaries}
        assignment_ids = assignment_cluster_ids(assignment_path)
        extra_ids = report_ids - assignment_ids
        if extra_ids:
            raise ValueError(
                f"{device}/{perspective}: report contains unknown cluster IDs "
                f"{sorted(extra_ids)}"
            )
        missing_ids = assignment_ids - report_ids
        if missing_ids:
            summaries.extend(deterministic_missing_summaries(
                device, perspective, assignment_path, missing_ids
            ))
            summaries.sort(key=lambda row: row["cluster_id"])
        final_ids = {row["cluster_id"] for row in summaries}
        if final_ids != assignment_ids:
            raise AssertionError(f"failed to complete {device}/{perspective}")
        atomic_json_dump(output_path, summaries)
        outputs.append((device, len(summaries), output_path))
    return outputs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--perspectives", nargs="+", default=["hpart", "http"])
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    for perspective in args.perspectives:
        outputs = restore(perspective, overwrite=args.overwrite)
        for device, count, path in outputs:
            print(f"[{perspective}] {device}: restored {count} clusters -> {path}")
        if not outputs:
            print(f"[{perspective}] nothing to restore")


if __name__ == "__main__":
    main()
