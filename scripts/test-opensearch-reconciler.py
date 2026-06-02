from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opensearch_reconciler", ROOT / "scripts" / "reconcile-opensearch-gitops.py"
)
assert SPEC and SPEC.loader
reconciler = importlib.util.module_from_spec(SPEC)
sys.modules["opensearch_reconciler"] = reconciler
SPEC.loader.exec_module(reconciler)


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error", response=self)


def test_put_json_updates_existing_ism_policy_with_concurrency_token(monkeypatch) -> None:
    put_urls: list[str] = []
    get_urls: list[str] = []

    def fake_put(url: str, **kwargs: Any) -> FakeResponse:
        put_urls.append(url)
        if len(put_urls) == 1:
            return FakeResponse(409)
        return FakeResponse(200)

    def fake_get(url: str, **kwargs: Any) -> FakeResponse:
        get_urls.append(url)
        return FakeResponse(200, {"_seq_no": 7, "_primary_term": 3})

    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")
    monkeypatch.setattr(reconciler.requests, "put", fake_put)
    monkeypatch.setattr(reconciler.requests, "get", fake_get)

    reconciler.put_json(
        "https://opensearch.local",
        "/_plugins/_ism/policies/critical-30d",
        {"policy": {"policy_id": "critical-30d"}},
        dry_run=False,
    )

    assert get_urls == ["https://opensearch.local/_plugins/_ism/policies/critical-30d"]
    assert put_urls == [
        "https://opensearch.local/_plugins/_ism/policies/critical-30d",
        "https://opensearch.local/_plugins/_ism/policies/critical-30d?if_seq_no=7&if_primary_term=3",
    ]


def test_orphaned_templates_detects_extras() -> None:
    desired = {"logs-acme-firewall-template", "logs-acme-firewall-quarantine-template"}
    existing = [
        {"name": "logs-acme-firewall-template"},
        {"name": "logs-acme-firewall-quarantine-template"},
        {"name": "logs-bravo-old-template"},
        {"name": ".kibana-template"},
    ]
    orphans = reconciler.orphaned_templates(desired, existing, prefixes=("logs-", "alerts-"))
    assert orphans == ["logs-bravo-old-template"]


def test_create_data_stream_ignores_already_exists(monkeypatch) -> None:
    puts: list[str] = []

    def fake_put(url, **kwargs):
        puts.append(url)
        return FakeResponse(400, {"error": {"type": "resource_already_exists_exception"}})

    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")
    monkeypatch.setattr(reconciler.requests, "put", fake_put)

    # must NOT raise on already-exists
    reconciler.create_data_stream("https://os.local", "logs-acme-firewall", dry_run=False)
    assert puts == ["https://os.local/_data_stream/logs-acme-firewall"]


def test_create_data_stream_raises_on_other_errors(monkeypatch) -> None:
    def fake_put(url, **kwargs):
        return FakeResponse(403, {"error": {"type": "security_exception"}})

    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")
    monkeypatch.setattr(reconciler.requests, "put", fake_put)

    import pytest
    with pytest.raises(requests.HTTPError):
        reconciler.create_data_stream("https://os.local", "logs-acme-firewall", dry_run=False)


def test_put_json_logs_applied_action(monkeypatch, caplog) -> None:
    import logging

    def fake_put(url, **kwargs):
        return FakeResponse(200)

    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")
    monkeypatch.setattr(reconciler.requests, "put", fake_put)

    with caplog.at_level(logging.INFO, logger="reconciler"):
        reconciler.put_json("https://os.local", "/_index_template/test", {}, dry_run=False)

    assert any("applied" in r.getMessage() and "/_index_template/test" in r.getMessage()
               for r in caplog.records)


def test_put_json_dry_run_logs_at_info(monkeypatch, caplog) -> None:
    import logging

    monkeypatch.setenv("OPENSEARCH_USER", "admin")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "secret")

    with caplog.at_level(logging.INFO, logger="reconciler"):
        reconciler.put_json("https://os.local", "/_index_template/test", {}, dry_run=True)

    assert any("DRY-RUN" in r.getMessage() for r in caplog.records)
