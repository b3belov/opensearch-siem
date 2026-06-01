from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
import warnings
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

warnings.filterwarnings("ignore", message="urllib3 v2 only supports OpenSSL.*")
import requests  # noqa: E402
from urllib3.exceptions import InsecureRequestWarning  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
EDGE_APP = ROOT / "ingest-edge" / "app.py"
pytestmark = pytest.mark.filterwarnings("ignore:Unverified HTTPS request.*")
warnings.filterwarnings("ignore", category=InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


@dataclass
class FakeLogstash:
    server: ThreadingHTTPServer
    thread: threading.Thread
    requests: list[dict[str, Any]]

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/ingest"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


@dataclass
class EdgeProcess:
    process: subprocess.Popen[str]
    port: int

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)


def basic_auth(username: str, password: str) -> str:
    encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


def reserve_local_port() -> int:
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", 0))
    except PermissionError as exc:
        pytest.skip(f"local socket binding unavailable: {exc}")
    try:
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def make_fake_logstash() -> FakeLogstash:
    received: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            received.append(
                {
                    "path": self.path,
                    "headers": dict(self.headers),
                    "body": raw_body.decode("utf-8"),
                    "json": json.loads(raw_body),
                }
            )

            body = b'{"accepted":true}'
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    port = reserve_local_port()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return FakeLogstash(server=server, thread=thread, requests=received)


@pytest.fixture
def fake_logstash() -> Iterator[FakeLogstash]:
    server = make_fake_logstash()
    try:
        yield server
    finally:
        server.stop()


def write_edge_config(tmp_path: Path, allowed_cidrs: list[str]) -> tuple[Path, Path, Path, Path]:
    config_dir = tmp_path / "config"
    secret_dir = tmp_path / "secrets"
    cert_dir = tmp_path / "certs"
    config_dir.mkdir()
    secret_dir.mkdir()
    cert_dir.mkdir()

    (secret_dir / "customer-acme-password").write_text("secret\n", encoding="utf-8")
    (config_dir / "customer-auth.yml").write_text(
        "\n".join(
            [
                "credentials:",
                "  acme-primary:",
                "    customerSlug: acme",
                "    enabled: true",
                "    secretRef: secrets/local/customer-acme-password",
                "    allowedCidrs:",
                *[f"      - {cidr}" for cidr in allowed_cidrs],
                "",
            ]
        ),
        encoding="utf-8",
    )

    key_path = cert_dir / "central.key"
    cert_path = cert_dir / "central.crt"
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        pytest.skip("openssl is unavailable")

    return config_dir / "customer-auth.yml", secret_dir, cert_path, key_path


def start_edge(
    tmp_path: Path,
    upstream_url: str,
    *,
    allowed_cidrs: list[str],
    max_body_bytes: int = 1024 * 1024,
    trusted_proxy_cidrs: str = "127.0.0.1/32",
) -> EdgeProcess:
    config_path, secret_dir, cert_path, key_path = write_edge_config(tmp_path, allowed_cidrs)
    port = reserve_local_port()
    env = {
        **os.environ,
        "INGEST_EDGE_CONFIG": str(config_path),
        "INGEST_EDGE_SECRET_ROOT": str(secret_dir),
        "INGEST_EDGE_TLS_CERT": str(cert_path),
        "INGEST_EDGE_TLS_KEY": str(key_path),
        "INGEST_EDGE_MAX_BODY_BYTES": str(max_body_bytes),
        "INGEST_EDGE_HOST": "127.0.0.1",
        "INGEST_EDGE_PORT": str(port),
        "LOGSTASH_URL": upstream_url,
        "TRUSTED_PROXY_CIDRS": trusted_proxy_cidrs,
    }
    process = subprocess.Popen(
        [sys.executable, str(EDGE_APP)],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    edge = EdgeProcess(process=process, port=port)
    wait_for_edge(edge)
    return edge


def wait_for_edge(edge: EdgeProcess) -> None:
    deadline = time.monotonic() + 10
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if edge.process.poll() is not None:
            stdout, stderr = edge.process.communicate()
            pytest.fail(f"ingest-edge exited early\nstdout:\n{stdout}\nstderr:\n{stderr}")
        try:
            requests.get(edge.url, verify=False, timeout=0.25)
            return
        except requests.RequestException as exc:
            last_error = exc
            time.sleep(0.1)
    pytest.fail(f"ingest-edge did not become ready: {last_error}")


def post_event(edge: EdgeProcess, **kwargs: Any) -> requests.Response:
    return requests.post(f"{edge.url}/", verify=False, timeout=5, **kwargs)


def test_https_ingest_edge_forwards_enriched_events_to_logstash(
    tmp_path: Path, fake_logstash: FakeLogstash
) -> None:
    edge = start_edge(
        tmp_path,
        fake_logstash.url,
        allowed_cidrs=["203.0.113.10/32"],
    )
    try:
        response = post_event(
            edge,
            headers={
                "Authorization": basic_auth("acme-primary", "secret"),
                "Content-Type": "application/json",
                "X-Forwarded-For": "203.0.113.10, 127.0.0.1",
            },
            json={"siem": {"source_id": "firewall"}, "message": "test event"},
        )
    finally:
        edge.stop()

    assert response.status_code == 202
    assert response.json() == {"accepted": True}
    assert len(fake_logstash.requests) == 1

    forwarded = fake_logstash.requests[0]
    assert forwarded["path"] == "/ingest"
    assert forwarded["headers"]["Content-Type"].startswith("application/json")
    assert forwarded["json"] == {
        "customer": {"slug": "acme"},
        "message": "test event",
        "siem": {
            "credential_id": "acme-primary",
            "ingest_edge_client_ip": "203.0.113.10",
            "source_id": "firewall",
        },
    }


def test_https_ingest_edge_rejects_invalid_requests_before_logstash(
    tmp_path: Path, fake_logstash: FakeLogstash
) -> None:
    edge = start_edge(
        tmp_path,
        fake_logstash.url,
        allowed_cidrs=["203.0.113.10/32"],
        max_body_bytes=32,
    )
    try:
        cases = [
            (
                {},
                '{"message":"test"}',
                401,
                "missing basic auth",
            ),
            (
                {
                    "Authorization": basic_auth("acme-primary", "wrong"),
                    "X-Forwarded-For": "203.0.113.10",
                },
                '{"message":"test"}',
                403,
                "invalid credential",
            ),
            (
                {
                    "Authorization": basic_auth("acme-primary", "secret"),
                    "X-Forwarded-For": "203.0.113.10",
                },
                "{",
                400,
                "invalid json",
            ),
            (
                {
                    "Authorization": basic_auth("acme-primary", "secret"),
                    "X-Forwarded-For": "203.0.113.10",
                },
                '{"message":"' + ("x" * 64) + '"}',
                413,
                "request too large",
            ),
            (
                {"Authorization": basic_auth("acme-primary", "secret")},
                '{"message":"test"}',
                403,
                "source ip not allowed",
            ),
        ]
        for headers, body, expected_status, expected_error in cases:
            response = post_event(
                edge,
                headers={**headers, "Content-Type": "application/json"},
                data=body,
            )
            assert response.status_code == expected_status
            assert response.json() == {"error": expected_error}
    finally:
        edge.stop()

    assert fake_logstash.requests == []
