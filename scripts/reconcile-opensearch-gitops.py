#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from scripts.lib.opensearch_client import opensearch_verify


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_yaml(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected YAML object")
    return value


def opensearch_name(value: str) -> str:
    return value.replace("-", "_")


def env_name_for(role: str, suffix: str) -> str:
    return f"{opensearch_name(role).upper()}_{suffix}"


def service_account(role: str) -> dict | None:
    path = REPO_ROOT / "gitops/desired/global/service-accounts.yml"
    doc = load_yaml(path)
    for account in doc.get("accounts", []):
        if account.get("role") == role:
            return account
    return None


def service_account_username(account: dict) -> str:
    role = account["role"]
    return os.environ.get(env_name_for(role, "USER"), opensearch_name(role))


def service_account_password(account: dict, dry_run: bool) -> str:
    role = account["role"]
    env_name = env_name_for(role, "PASSWORD")
    if value := os.environ.get(env_name):
        return value

    secret_path = REPO_ROOT / account["secretRef"]
    if secret_path.exists():
        return secret_path.read_text(encoding="utf-8").strip()

    if dry_run:
        return "dry-run-password"
    raise RuntimeError(f"missing {env_name} or {account['secretRef']}")


def opensearch_auth() -> tuple[str, str]:
    return os.environ["OPENSEARCH_USER"], os.environ["OPENSEARCH_PASSWORD"]


def orphaned_templates(
    desired_names: set[str],
    existing: list[dict],
    prefixes: tuple[str, ...],
) -> list[str]:
    # Parameterized on `prefixes` so this can later cover orphaned ISM
    # policies / data streams / roles by passing their name prefixes.
    result = []
    for item in existing:
        name = item.get("name", "")
        if not name.startswith(prefixes):
            continue
        if name not in desired_names:
            result.append(name)
    return sorted(result)


def report_drift(base_url: str, desired_names: set[str]) -> None:
    resp = requests.get(
        f"{base_url}/_index_template",
        auth=opensearch_auth(),
        verify=opensearch_verify(),
        timeout=30,
    )
    resp.raise_for_status()
    existing = resp.json().get("index_templates", [])
    orphans = orphaned_templates(desired_names, existing, prefixes=("logs-", "alerts-"))
    if orphans:
        os_url = os.environ.get("OPENSEARCH_URL", "https://127.0.0.1:9200")
        print("DRIFT: index templates present in OpenSearch but not in desired state.")
        print("To remove an orphan, source your env (set -a; . ./.env; set +a) then run:")
        print(f"  curl -X DELETE \"{os_url}/_index_template/<name>\" "
              f"-u \"$OPENSEARCH_USER:$OPENSEARCH_PASSWORD\"")
        print("Orphans:")
        for name in orphans:
            print(f"  {name}")
    else:
        print("no orphaned managed index templates")


def create_data_stream(base_url: str, name: str, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY-RUN PUT /_data_stream/{name}")
        return
    response = requests.put(
        f"{base_url}/_data_stream/{name}",
        auth=opensearch_auth(),
        verify=opensearch_verify(),
        timeout=30,
    )
    if response.status_code == 400:
        error_type = response.json().get("error", {}).get("type", "")
        if error_type == "resource_already_exists_exception":
            return
    response.raise_for_status()
    print(f"created data stream {name}")


def desired_stream_names() -> list[str]:
    path = REPO_ROOT / "gitops/rendered/opensearch/streams.yml"
    if not path.exists():
        return []
    doc = load_yaml(path)
    return list(doc.get("streams", []))


def update_existing_ism_policy(base_url: str, path: str, body: dict) -> requests.Response:
    current = requests.get(
        f"{base_url}{path}",
        auth=opensearch_auth(),
        verify=opensearch_verify(),
        timeout=30,
    )
    current.raise_for_status()
    metadata = current.json()
    return requests.put(
        f"{base_url}{path}?if_seq_no={metadata['_seq_no']}&if_primary_term={metadata['_primary_term']}",
        auth=opensearch_auth(),
        json=body,
        verify=opensearch_verify(),
        timeout=30,
    )


def put_json(base_url: str, path: str, body: dict, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY-RUN PUT {path}")
        return
    response = requests.put(
        f"{base_url}{path}",
        auth=opensearch_auth(),
        json=body,
        verify=opensearch_verify(),
        timeout=30,
    )
    if response.status_code == 409 and path.startswith("/_plugins/_ism/policies/"):
        response = update_existing_ism_policy(base_url, path, body)
    response.raise_for_status()
    print(f"applied {path}")


def reconcile(dry_run: bool) -> None:
    base_url = os.environ.get("OPENSEARCH_URL", "https://localhost:9200")

    applied_template_names: set[str] = set()
    for path in sorted((REPO_ROOT / "opensearch/base/index-templates").glob("*.json")):
        name = path.stem
        applied_template_names.add(name)
        put_json(base_url, f"/_index_template/{name}", load_json(path), dry_run)

    for path in sorted((REPO_ROOT / "gitops/rendered/opensearch/index-templates").glob("*.json")):
        name = path.stem
        applied_template_names.add(name)
        put_json(base_url, f"/_index_template/{name}", load_json(path), dry_run)

    for path in sorted((REPO_ROOT / "opensearch/base/ism").glob("*.json")):
        name = path.stem
        put_json(base_url, f"/_plugins/_ism/policies/{name}", load_json(path), dry_run)

    for stream in desired_stream_names():
        create_data_stream(base_url, stream, dry_run)

    role_path = REPO_ROOT / "gitops/rendered/opensearch/security/logstash-writer-role.json"
    if role_path.exists():
        role_name = "logstash_writer"
        put_json(base_url, f"/_plugins/_security/api/roles/{role_name}", load_json(role_path), dry_run)

        account = service_account("logstash-writer")
        if account is not None:
            username = service_account_username(account)
            put_json(
                base_url,
                f"/_plugins/_security/api/internalusers/{username}",
                {
                    "password": service_account_password(account, dry_run),
                    "backend_roles": [],
                    "attributes": {"managed_by": "opensearch-siem-gitops"},
                },
                dry_run,
            )
            put_json(
                base_url,
                f"/_plugins/_security/api/rolesmapping/{role_name}",
                {"backend_roles": [], "hosts": [], "users": [username]},
                dry_run,
            )

    report_drift(base_url, applied_template_names)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    reconcile(dry_run=args.dry_run)


if __name__ == "__main__":
    main()
