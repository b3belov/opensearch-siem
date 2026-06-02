#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.lib.opensearch_client import opensearch_auth, opensearch_verify


def summarize_cluster(
    health: dict[str, Any],
    nodes_stats: dict[str, Any],
    allocation: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    node = next(iter(nodes_stats.get("nodes", {}).values()), {})
    heap = node.get("jvm", {}).get("mem", {}).get("heap_used_percent")
    result: dict[str, Any] = {
        "status": health.get("status"),
        "nodes": health.get("number_of_nodes"),
        "active_shards": health.get("active_shards"),
        "unassigned_shards": health.get("unassigned_shards"),
        "relocating_shards": health.get("relocating_shards"),
        "heap_used_percent": heap,
    }
    if allocation:
        a = allocation[0]
        result["disk_used"] = a.get("disk.used")
        result["disk_avail"] = a.get("disk.avail")
        result["disk_percent"] = a.get("disk.percent")
    return result


def summarize_streams(cat_indices: list[dict[str, Any]]) -> dict[str, Any]:
    streams: dict[str, Any] = {}
    quarantine_total = 0
    for row in cat_indices:
        name = row.get("index", "")
        if not (name.startswith("logs-") or name.startswith("alerts-")):
            continue
        docs = int(row.get("docs.count") or 0)
        streams[name] = {"docs": docs, "size": row.get("store.size")}
        if name.endswith("-quarantine"):
            quarantine_total += docs
    return {"streams": streams, "quarantine_docs_total": quarantine_total}


def summarize_logstash(node_stats: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for pid, pdata in node_stats.get("pipelines", {}).items():
        events = pdata.get("events", {})
        dlq = pdata.get("dead_letter_queue", {})
        result[pid] = {
            "in": events.get("in"),
            "out": events.get("out"),
            "queue_events": pdata.get("queue", {}).get("events"),
            "dlq_size_bytes": dlq.get("queue_size_in_bytes"),
            "dlq_max_bytes": dlq.get("max_queue_size_in_bytes"),
        }
    return result


def _get(url: str, auth: tuple[str, str] | None = None) -> dict[str, Any]:
    resp = requests.get(url, auth=auth, verify=opensearch_verify(), timeout=15)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    os_url = os.environ.get("OPENSEARCH_URL", "https://127.0.0.1:9200")
    auth = opensearch_auth()  # raises SystemExit with guidance if creds unset
    ls_url = os.environ.get("LOGSTASH_MONITOR_URL", "http://127.0.0.1:9600")

    report: dict[str, Any] = {}
    try:
        alloc = _get(f"{os_url}/_cat/allocation?format=json&bytes=gb", auth)
        report["cluster"] = summarize_cluster(
            _get(f"{os_url}/_cluster/health", auth),
            _get(f"{os_url}/_nodes/stats/jvm", auth),
            alloc,
        )
        report["allocation"] = alloc
        report["streams"] = summarize_streams(
            # bound payload to managed streams; skip system/.kibana indices
            _get(f"{os_url}/_cat/indices/logs-*,alerts-*?format=json", auth)
        )
    except requests.RequestException as exc:
        raise SystemExit(f"ERROR: cannot reach OpenSearch at {os_url}: {exc}")

    try:
        report["logstash"] = summarize_logstash(_get(f"{ls_url}/_node/stats/pipelines"))
    except requests.RequestException as exc:
        report["logstash"] = {"error": f"Logstash monitoring API unreachable at {ls_url}: {exc}"}

    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
