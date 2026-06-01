from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("siem_status", ROOT / "scripts" / "siem-status.py")
assert SPEC and SPEC.loader
status = importlib.util.module_from_spec(SPEC)
sys.modules["siem_status"] = status
SPEC.loader.exec_module(status)


def test_summarize_cluster_extracts_key_fields() -> None:
    health = {"status": "green", "number_of_nodes": 1, "active_shards": 12}
    nodes = {"nodes": {"n1": {"jvm": {"mem": {"heap_used_percent": 41}}}}}
    out = status.summarize_cluster(health, nodes)
    assert out["status"] == "green"
    assert out["heap_used_percent"] == 41


def test_summarize_streams_separates_quarantine() -> None:
    cat = [
        {"index": "logs-acme-firewall", "docs.count": "100", "store.size": "1mb"},
        {"index": "logs-acme-unknown-quarantine", "docs.count": "5", "store.size": "1kb"},
        {"index": ".kibana_1", "docs.count": "3", "store.size": "1kb"},
    ]
    out = status.summarize_streams(cat)
    assert out["streams"]["logs-acme-firewall"]["docs"] == 100
    assert out["quarantine_docs_total"] == 5
    assert ".kibana_1" not in out["streams"]


def test_summarize_logstash_reads_pipeline_events() -> None:
    node_stats = {"pipelines": {"opensearch-output": {
        "events": {"in": 10, "out": 9},
        "queue": {"events": 1}}}}
    out = status.summarize_logstash(node_stats)
    assert out["opensearch-output"]["in"] == 10
    assert out["opensearch-output"]["queue_events"] == 1
