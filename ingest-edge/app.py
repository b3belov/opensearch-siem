#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Optional, Tuple

import requests
import yaml


CONFIG_PATH = Path(os.environ.get("INGEST_EDGE_CONFIG", "/app/config/customer-auth.yml"))
SECRET_ROOT = Path(os.environ.get("INGEST_EDGE_SECRET_ROOT", "/run/siem-secrets"))
LOGSTASH_URL = os.environ.get("LOGSTASH_URL", "http://central-logstash:9601")
TLS_CERT_PATH = Path(os.environ.get("INGEST_EDGE_TLS_CERT", "/run/siem-certs/central.crt"))
TLS_KEY_PATH = Path(os.environ.get("INGEST_EDGE_TLS_KEY", "/run/siem-certs/central.key"))
MAX_BODY_BYTES = int(os.environ.get("INGEST_EDGE_MAX_BODY_BYTES", str(1024 * 1024)))
TRUSTED_PROXY_CIDRS = [
    item.strip()
    for item in os.environ.get("TRUSTED_PROXY_CIDRS", "").split(",")
    if item.strip()
]


_CONFIG_CACHE: dict[str, Any] | None = None
_CONFIG_MTIME: float | None = None


def load_config() -> dict[str, Any]:
    global _CONFIG_CACHE, _CONFIG_MTIME
    mtime = CONFIG_PATH.stat().st_mtime
    if _CONFIG_CACHE is not None and _CONFIG_MTIME == mtime:
        return _CONFIG_CACHE
    with CONFIG_PATH.open("r", encoding="utf-8") as handle:
        doc = yaml.safe_load(handle)
    if not isinstance(doc, dict) or "credentials" not in doc:
        raise ValueError(f"{CONFIG_PATH}: expected credentials mapping")
    _CONFIG_CACHE = doc
    _CONFIG_MTIME = mtime
    return doc


def parse_basic_auth(header: Optional[str]) -> Optional[Tuple[str, str]]:
    if not header or not header.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(header.removeprefix("Basic ").strip()).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


# Secret values are cached in-process for the lifetime of the server, keyed by
# path and invalidated on mtime change (so a rotated secret is picked up on the
# next request). For the v1 single-process edge this is acceptable; a multi-
# process/HA v2 should prefer short-TTL or externally-managed secret rotation.
_SECRET_CACHE: dict[str, tuple[float, str]] = {}


def secret_value(secret_ref: str) -> str:
    path = SECRET_ROOT / Path(secret_ref).name
    mtime = path.stat().st_mtime
    cached = _SECRET_CACHE.get(str(path))
    if cached is not None and cached[0] == mtime:
        return cached[1]
    value = path.read_text(encoding="utf-8").strip()
    _SECRET_CACHE[str(path)] = (mtime, value)
    return value


def ip_allowed(client_ip: str, cidrs: list[str]) -> bool:
    address = ip_address(client_ip)
    return any(address in ip_network(cidr, strict=False) for cidr in cidrs)


def client_ip_for_request(peer_ip: str, forwarded_for: Optional[str]) -> str:
    if not TRUSTED_PROXY_CIDRS:
        return peer_ip
    if not ip_allowed(peer_ip, TRUSTED_PROXY_CIDRS):
        return peer_ip
    if not forwarded_for:
        return peer_ip
    return forwarded_for.split(",", 1)[0].strip()


def content_length(headers: Any) -> Optional[int]:
    value = headers.get("Content-Length")
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError:
        return None
    if parsed < 0:
        return None
    return parsed


class Handler(BaseHTTPRequestHandler):
    server_version = "OpenSearchSIEMIngestEdge/1.0"

    def do_POST(self) -> None:
        config = load_config()
        auth = parse_basic_auth(self.headers.get("Authorization"))
        if auth is None:
            self.reject(401, "missing basic auth")
            return

        username, password = auth
        credential = config["credentials"].get(username)
        if credential is None or not credential.get("enabled", False):
            self.reject(403, "unknown credential")
            return

        expected = secret_value(credential["secretRef"])
        if not secrets.compare_digest(password, expected):
            self.reject(403, "invalid credential")
            return

        client_ip = client_ip_for_request(self.client_address[0], self.headers.get("X-Forwarded-For"))
        if not ip_allowed(client_ip, credential.get("allowedCidrs", [])):
            self.reject(403, "source ip not allowed")
            return

        length = content_length(self.headers)
        if length is None:
            self.reject(400, "invalid content length")
            return
        if length > MAX_BODY_BYTES:
            self.reject(413, "request too large")
            return

        raw_body = self.rfile.read(length)
        try:
            event = json.loads(raw_body)
        except json.JSONDecodeError:
            self.reject(400, "invalid json")
            return

        if not isinstance(event, dict):
            self.reject(400, "event must be a json object")
            return

        event["customer"] = {"slug": credential["customerSlug"]}
        event["siem"] = {
            **event.get("siem", {}),
            "credential_id": username,
            "ingest_edge_client_ip": client_ip,
        }

        try:
            response = requests.post(LOGSTASH_URL, json=event, timeout=10)
        except requests.RequestException:
            self.reject(503, "upstream logstash unavailable")
            return
        self.send_response(response.status_code)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)

    def reject(self, status: int, message: str) -> None:
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    host = os.environ.get("INGEST_EDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("INGEST_EDGE_PORT", "5044"))
    server = ThreadingHTTPServer((host, port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
