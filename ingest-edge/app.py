#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any, Optional, Tuple

import threading

import requests
import yaml
from requests.adapters import HTTPAdapter

# Audit log. Lines are key=value greppable and intentionally contain only the
# credential ID (a tenant identifier like "acme-primary"), peer/client IP, and
# decision — NEVER the password or secret value.
LOG = logging.getLogger("ingest-edge")

MAX_CONCURRENCY = int(os.environ.get("INGEST_EDGE_MAX_CONCURRENCY", "64"))

SESSION = requests.Session()
SESSION.mount("http://", HTTPAdapter(pool_connections=MAX_CONCURRENCY, pool_maxsize=MAX_CONCURRENCY))
SESSION.mount("https://", HTTPAdapter(pool_connections=MAX_CONCURRENCY, pool_maxsize=MAX_CONCURRENCY))

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
    hops = [hop.strip() for hop in forwarded_for.split(",") if hop.strip()]
    for hop in reversed(hops):
        try:
            if ip_allowed(hop, TRUSTED_PROXY_CIDRS):
                continue
        except ValueError:
            return peer_ip
        return hop
    return peer_ip


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

    def do_GET(self) -> None:
        if self.path == "/health":
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.reject(404, "not found")

    def do_POST(self) -> None:
        config = load_config()
        auth = parse_basic_auth(self.headers.get("Authorization"))
        if auth is None:
            self.reject(401, "missing basic auth")
            return

        username, password = auth
        credential = config["credentials"].get(username)
        if credential is None or not credential.get("enabled", False):
            self.reject(403, "unknown credential", credential=username)
            return

        expected = secret_value(credential["secretRef"])
        if not secrets.compare_digest(password, expected):
            self.reject(403, "invalid credential", credential=username)
            return

        client_ip = client_ip_for_request(self.client_address[0], self.headers.get("X-Forwarded-For"))
        if not ip_allowed(client_ip, credential.get("allowedCidrs", [])):
            self.reject(403, "source ip not allowed", credential=username)
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

        client_siem = event.get("siem")
        source_id = client_siem.get("source_id") if isinstance(client_siem, dict) else None

        for untrusted in ("customer", "data_stream", "@metadata"):
            event.pop(untrusted, None)

        event["customer"] = {"slug": credential["customerSlug"]}
        siem: dict[str, Any] = {
            "credential_id": username,
            "ingest_edge_client_ip": client_ip,
        }
        if isinstance(source_id, str) and source_id:
            siem["source_id"] = source_id
        event["siem"] = siem

        try:
            response = SESSION.post(LOGSTASH_URL, json=event, timeout=10)
        except requests.RequestException:
            self.reject(503, "upstream logstash unavailable")
            return
        LOG.info(
            "accept customer=%s credential=%s client_ip=%s upstream=%s",
            credential["customerSlug"], username, client_ip, response.status_code,
        )
        self.send_response(response.status_code)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)

    def reject(self, status: int, message: str, credential: str = "-") -> None:
        peer = getattr(self, "client_address", ("-",))[0]
        # credential and reason are quoted with %r to prevent key=value log injection
        # (credential comes from a client-supplied Authorization header).
        LOG.info("reject status=%s peer=%s credential=%r reason=%r", status, peer, credential, message)
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args: Any, max_concurrency: int, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._semaphore = threading.BoundedSemaphore(max_concurrency)

    def process_request(self, request: Any, client_address: Any) -> None:
        self._semaphore.acquire()
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._semaphore.release()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    host = os.environ.get("INGEST_EDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("INGEST_EDGE_PORT", "5044"))
    server = BoundedThreadingHTTPServer((host, port), Handler, max_concurrency=MAX_CONCURRENCY)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    LOG.info("ingest-edge listening host=%s port=%s max_concurrency=%s", host, port, MAX_CONCURRENCY)
    server.serve_forever()


if __name__ == "__main__":
    main()
