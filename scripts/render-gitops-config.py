#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.lib.gitops_config import (
    DESIRED,
    REPO_ROOT,
    load_customers,
    load_retention_policy_names,
    load_sources,
    make_jinja_env,
    read_yaml,
    validate_all,
)


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.rstrip() + "\n", encoding="utf-8")


def write_json(path: Path, value: dict[str, object]) -> None:
    write_text(path, json.dumps(value, indent=2, sort_keys=True))


def credential_ids_by_customer() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for customer_dir in sorted((DESIRED / "customers").iterdir()):
        if not customer_dir.is_dir():
            continue
        doc = read_yaml(customer_dir / "credentials.yml")
        result[doc["customer"]] = [item["id"] for item in doc["credentials"] if item["enabled"]]
    return result


def ingest_edge_credentials() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for customer_dir in sorted((DESIRED / "customers").iterdir()):
        if not customer_dir.is_dir():
            continue
        credential_doc = read_yaml(customer_dir / "credentials.yml")
        allowlist_doc = read_yaml(customer_dir / "allowlist.yml")
        allowed_cidrs = [entry["cidr"] for entry in allowlist_doc["entries"]]
        for item in credential_doc["credentials"]:
            result[item["id"]] = {
                "customerSlug": credential_doc["customer"],
                "enabled": item["enabled"],
                "secretRef": item["secretRef"],
                "allowedCidrs": allowed_cidrs,
            }
    return result


def stream_template(stream: str, policy_id: str) -> dict[str, object]:
    return {
        "index_patterns": [stream],
        "data_stream": {},
        "template": {
            "settings": {
                "index.number_of_shards": 1,
                "index.number_of_replicas": 0,
                "plugins.index_state_management.policy_id": policy_id,
            },
            "mappings": {
                "dynamic": True,
                "properties": {
                    "@timestamp": {"type": "date"},
                    "customer": {"properties": {"slug": {"type": "keyword"}}},
                    "source": {"properties": {"id": {"type": "keyword"}}},
                    "event": {
                        "properties": {
                            "dataset": {"type": "keyword"},
                            "original": {"type": "wildcard"},
                            "ingested": {"type": "date"},
                        }
                    },
                },
            },
        },
        "priority": 300,
    }


def render() -> None:
    validate_all()
    customers = load_customers()
    retention_names = load_retention_policy_names()
    sources = load_sources(customers, retention_names)
    credentials = credential_ids_by_customer()

    env = make_jinja_env(REPO_ROOT)

    customer_auth = env.get_template("logstash/templates/customer-auth.yml.j2").render(
        customers=customers.values(),
        credentials=credentials,
    )
    source_routing = env.get_template("logstash/templates/source-routing.yml.j2").render(sources=sources)

    streams: list[str] = []
    for source in sources:
        streams.append(f"logs-{source.customer}-{source.dataset}")
        streams.append(f"logs-{source.customer}-{source.dataset}-quarantine")
    for customer in customers.values():
        streams.append(f"logs-{customer.slug}-unknown-quarantine")
        streams.append(f"alerts-{customer.slug}")

    role = env.get_template("opensearch/base/security/logstash-writer-role.json.j2").render(streams=sorted(streams))

    write_text(REPO_ROOT / "gitops/rendered/logstash/customer-auth.yml", customer_auth)
    write_text(REPO_ROOT / "gitops/rendered/logstash/source-routing.yml", source_routing)
    write_text(
        REPO_ROOT / "gitops/rendered/ingest-edge/customer-auth.yml",
        yaml.safe_dump({"credentials": ingest_edge_credentials()}, sort_keys=True),
    )
    write_text(REPO_ROOT / "gitops/rendered/opensearch/security/logstash-writer-role.json", role)
    write_text(
        REPO_ROOT / "gitops/rendered/opensearch/streams.yml",
        yaml.safe_dump({"streams": sorted(streams)}, sort_keys=True),
    )
    for source in sources:
        stream = f"logs-{source.customer}-{source.dataset}"
        write_json(
            REPO_ROOT / f"gitops/rendered/opensearch/index-templates/{stream}-template.json",
            stream_template(stream, source.retention_policy),
        )
        write_json(
            REPO_ROOT / f"gitops/rendered/opensearch/index-templates/{stream}-quarantine-template.json",
            stream_template(f"{stream}-quarantine", "quarantine-7d"),
        )
    for customer in customers.values():
        unknown_stream = f"logs-{customer.slug}-unknown-quarantine"
        write_json(
            REPO_ROOT / f"gitops/rendered/opensearch/index-templates/{unknown_stream}-template.json",
            stream_template(unknown_stream, "quarantine-7d"),
        )


def main() -> None:
    render()
    print("rendered gitops config")


if __name__ == "__main__":
    main()
