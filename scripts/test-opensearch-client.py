from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "opensearch_client", ROOT / "scripts" / "lib" / "opensearch_client.py"
)
assert SPEC and SPEC.loader
client = importlib.util.module_from_spec(SPEC)
sys.modules["opensearch_client"] = client
SPEC.loader.exec_module(client)


def test_verify_returns_false_without_ca(monkeypatch) -> None:
    monkeypatch.delenv("OPENSEARCH_CA", raising=False)
    assert client.opensearch_verify() is False


def test_verify_returns_ca_path_when_set(monkeypatch) -> None:
    monkeypatch.setenv("OPENSEARCH_CA", "secrets/certs/root-ca.crt")
    assert client.opensearch_verify() == "secrets/certs/root-ca.crt"


def test_auth_raises_friendly_when_missing(monkeypatch) -> None:
    monkeypatch.delenv("OPENSEARCH_USER", raising=False)
    monkeypatch.delenv("OPENSEARCH_PASSWORD", raising=False)
    import pytest
    with pytest.raises(SystemExit):
        client.opensearch_auth()
