from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ingest_edge_app", ROOT / "ingest-edge" / "app.py")
assert SPEC and SPEC.loader
app = importlib.util.module_from_spec(SPEC)
sys.modules["ingest_edge_app"] = app
SPEC.loader.exec_module(app)


def basic(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {encoded}"


def test_parse_basic_auth_accepts_valid_header() -> None:
    assert app.parse_basic_auth(basic("acme-primary", "secret")) == ("acme-primary", "secret")


def test_parse_basic_auth_rejects_missing_or_malformed_header() -> None:
    assert app.parse_basic_auth(None) is None
    assert app.parse_basic_auth("Bearer token") is None
    assert app.parse_basic_auth("Basic not-base64") is None


def test_ip_allowed_matches_cidr() -> None:
    assert app.ip_allowed("203.0.113.10", ["203.0.113.10/32"])
    assert not app.ip_allowed("203.0.113.11", ["203.0.113.10/32"])


def test_client_ip_ignores_forwarded_for_without_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", [])
    assert app.client_ip_for_request("10.0.0.10", "203.0.113.10") == "10.0.0.10"


def test_client_ip_uses_forwarded_for_from_trusted_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    assert app.client_ip_for_request("10.0.0.10", "203.0.113.10, 10.0.0.10") == "203.0.113.10"


def test_content_length_rejects_missing_negative_and_non_numeric() -> None:
    assert app.content_length({}) is None
    assert app.content_length({"Content-Length": "-1"}) is None
    assert app.content_length({"Content-Length": "abc"}) is None
    assert app.content_length({"Content-Length": "42"}) == 42


def test_upstream_failure_returns_503(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[int, str]] = []

    def raise_request_error(*args, **kwargs):
        raise requests.RequestException("boom")

    handler = object.__new__(app.Handler)
    handler.headers = {"Authorization": basic("acme-primary", "secret"), "Content-Length": "2"}
    handler.client_address = ("203.0.113.10", 12345)
    handler.rfile = SimpleNamespace(read=lambda length: b"{}")
    handler.wfile = SimpleNamespace(write=lambda body: None)
    handler.send_response = lambda status: calls.append((status, "response"))
    handler.send_header = lambda key, value: None
    handler.end_headers = lambda: None

    monkeypatch.setattr(app, "load_config", lambda: {
        "credentials": {
            "acme-primary": {
                "enabled": True,
                "secretRef": "secrets/local/customer-acme-password",
                "customerSlug": "acme",
                "allowedCidrs": ["203.0.113.10/32"],
            }
        }
    })
    monkeypatch.setattr(app, "secret_value", lambda secret_ref: "secret")
    monkeypatch.setattr(app.requests, "post", raise_request_error)

    handler.do_POST()
    assert calls[0] == (503, "response")


def test_load_config_caches_until_mtime_changes(tmp_path, monkeypatch) -> None:
    config_file = tmp_path / "customer-auth.yml"
    config_file.write_text("credentials:\n  a:\n    enabled: true\n", encoding="utf-8")

    reads: list[str] = []
    real_open = Path.open

    def counting_open(self, *args, **kwargs):
        mode = args[0] if args else kwargs.get("mode", "r")
        if self == config_file and "w" not in str(mode):
            reads.append("read")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(app, "CONFIG_PATH", config_file)
    monkeypatch.setattr(app, "_CONFIG_CACHE", None, raising=False)
    monkeypatch.setattr(app, "_CONFIG_MTIME", None, raising=False)
    monkeypatch.setattr(Path, "open", counting_open)

    app.load_config()
    app.load_config()
    assert len(reads) == 1  # second call served from cache

    config_file.write_text("credentials:\n  b:\n    enabled: false\n", encoding="utf-8")
    import os, time
    future = time.time() + 5
    os.utime(config_file, (future, future))
    app.load_config()
    assert len(reads) == 2  # mtime changed -> reloaded


def test_secret_value_caches_and_refreshes_on_mtime(tmp_path, monkeypatch) -> None:
    import os
    secret_file = tmp_path / "customer-acme-password"
    secret_file.write_text("first\n", encoding="utf-8")
    base = secret_file.stat().st_mtime
    os.utime(secret_file, (base, base))

    monkeypatch.setattr(app, "SECRET_ROOT", tmp_path)
    monkeypatch.setattr(app, "_SECRET_CACHE", {}, raising=False)

    # initial read
    assert app.secret_value("any/customer-acme-password") == "first"

    # change content WITHOUT bumping mtime -> cache returns stale value
    secret_file.write_text("second\n", encoding="utf-8")
    os.utime(secret_file, (base, base))
    assert app.secret_value("any/customer-acme-password") == "first"

    # bump mtime -> cache refreshes
    os.utime(secret_file, (base + 5, base + 5))
    assert app.secret_value("any/customer-acme-password") == "second"


def _run_accepted_post(monkeypatch, body: bytes):
    forwarded: dict = {"json": None}

    class FakeResp:
        status_code = 200
        content = b"{}"

    def fake_post(url, json=None, timeout=None):
        forwarded["json"] = json
        return FakeResp()

    handler = object.__new__(app.Handler)
    handler.headers = {"Authorization": basic("acme-primary", "secret"),
                       "Content-Length": str(len(body))}
    handler.client_address = ("203.0.113.10", 12345)
    handler.rfile = SimpleNamespace(read=lambda length: body)
    handler.wfile = SimpleNamespace(write=lambda b: None)
    handler.send_response = lambda status: None
    handler.send_header = lambda k, v: None
    handler.end_headers = lambda: None

    monkeypatch.setattr(app, "load_config", lambda: {
        "credentials": {"acme-primary": {"enabled": True,
            "secretRef": "secrets/local/customer-acme-password",
            "customerSlug": "acme", "allowedCidrs": ["203.0.113.10/32"]}}})
    monkeypatch.setattr(app, "secret_value", lambda ref: "secret")
    monkeypatch.setattr(app.requests, "post", fake_post)  # patch requests.post directly on the module
    handler.do_POST()
    return forwarded["json"]


def test_enrichment_strips_spoofed_fields(monkeypatch) -> None:
    body = json.dumps({
        "customer": {"slug": "victim"},
        "data_stream": {"namespace": "victim"},
        "@metadata": {"target_stream": "logs-victim-firewall"},
        "siem": {"source_id": "firewall", "credential_id": "forged"},
        "message": "hi",
    }).encode()
    out = _run_accepted_post(monkeypatch, body)
    assert out["customer"] == {"slug": "acme"}
    assert "data_stream" not in out
    assert "@metadata" not in out
    assert out["siem"]["source_id"] == "firewall"
    assert out["siem"]["credential_id"] == "acme-primary"
    assert out["siem"]["ingest_edge_client_ip"] == "203.0.113.10"
    assert out["message"] == "hi"
    assert set(out["siem"].keys()) == {"source_id", "credential_id", "ingest_edge_client_ip"}


def test_enrichment_absent_siem_field(monkeypatch) -> None:
    """No siem key in payload — source_id should be absent from result."""
    body = json.dumps({"message": "hi"}).encode()
    out = _run_accepted_post(monkeypatch, body)
    assert out["customer"] == {"slug": "acme"}
    assert "siem" in out
    assert "source_id" not in out["siem"]
    assert out["siem"]["credential_id"] == "acme-primary"


def test_enrichment_empty_source_id_omitted(monkeypatch) -> None:
    """Empty string source_id should NOT be forwarded."""
    body = json.dumps({"siem": {"source_id": ""}}).encode()
    out = _run_accepted_post(monkeypatch, body)
    assert "source_id" not in out["siem"]


def test_enrichment_non_dict_siem_handled(monkeypatch) -> None:
    """Non-dict siem (e.g. null or integer) should not raise — source_id absent."""
    for bad_siem in [None, 99, "string"]:
        body = json.dumps({"siem": bad_siem, "message": "test"}).encode()
        out = _run_accepted_post(monkeypatch, body)
        assert "source_id" not in out["siem"]
        assert out["customer"] == {"slug": "acme"}


def test_client_ip_walks_from_right_skipping_trusted(monkeypatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    # peer is trusted proxy; XFF lists spoofed client then real client then trusted hop
    result = app.client_ip_for_request("10.0.0.5", "1.1.1.1, 203.0.113.10, 10.0.0.9")
    assert result == "203.0.113.10"


def test_client_ip_returns_peer_when_peer_untrusted(monkeypatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    assert app.client_ip_for_request("203.0.113.10", "1.1.1.1") == "203.0.113.10"


def test_health_endpoint_returns_200() -> None:
    calls: list[int] = []
    handler = object.__new__(app.Handler)
    handler.path = "/health"
    handler.wfile = SimpleNamespace(write=lambda b: None)
    handler.send_response = lambda status: calls.append(status)
    handler.send_header = lambda k, v: None
    handler.end_headers = lambda: None
    handler.do_GET()
    assert calls == [200]


def test_unknown_get_path_returns_404() -> None:
    calls: list[int] = []
    handler = object.__new__(app.Handler)
    handler.path = "/"
    handler.wfile = SimpleNamespace(write=lambda b: None)
    handler.send_response = lambda status: calls.append(status)
    handler.send_header = lambda k, v: None
    handler.end_headers = lambda: None
    handler.do_GET()
    assert calls == [404]
