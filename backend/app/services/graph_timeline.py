"""M16 graph and timeline logic with deterministic, case-scoped primitives."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID


def stable_layout(node_ids: list[UUID], *, seed: int = 0) -> dict[str, dict[str, float]]:
    out = {}
    for node in sorted(node_ids, key=str):
        digest = hashlib.sha256(f"{seed}:{node}".encode()).digest()
        out[str(node)] = {
            "x": int.from_bytes(digest[:4], "big") / 2**32,
            "y": int.from_bytes(digest[4:8], "big") / 2**32,
        }
    return out


def infer_edges(nodes: list[dict[str, Any]], *, rule_version: str = "1.0") -> list[dict[str, Any]]:
    edges = []
    for i, left in enumerate(nodes):
        for right in nodes[i + 1 :]:
            if left.get("sha256") and left.get("sha256") == right.get("sha256"):
                edges.append(
                    {
                        "source_id": left["id"],
                        "target_id": right["id"],
                        "relation": "same_bytes",
                        "origin": "inferred",
                        "confidence": 1.0,
                        "produced_by_rule": "same_sha256",
                        "rule_version": rule_version,
                    }
                )
    return edges


def assemble_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=lambda e: (e.get("occurred_at", ""), e.get("id", "")))


def export_graph(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], fmt: str) -> str:
    if fmt == "json":
        return json.dumps({"nodes": nodes, "edges": edges}, sort_keys=True, separators=(",", ":"))
    if fmt == "csv":
        return "source,target,relation\n" + "".join(
            f"{e['source_id']},{e['target_id']},{e['relation']}\n" for e in edges
        )
    raise ValueError("Unsupported graph export format")
