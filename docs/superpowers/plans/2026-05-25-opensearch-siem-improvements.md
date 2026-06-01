# OpenSearch SIEM Improvements Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the operability, reliability, and security gaps identified between the v1 design spec and the current implementation, without expanding the architecture beyond v1 scope.

**Architecture:** Nine independent phases (A–I), each shippable on its own. Phases A–C harden and instrument the runtime; D–G close GitOps/pipeline correctness gaps; H adds CI; I (optional, heaviest) provisions a real internal PKI so TLS verification can be enabled end-to-end. Earlier phases are higher value / lower risk and should land first.

**Tech Stack:** Python 3 stdlib `http.server` (ingest-edge), pytest, Logstash pipelines, OpenSearch ISM/data streams, Jinja2 rendering, Docker Compose, GitHub Actions, OpenSSL.

**Conventions in this repo (follow exactly):**
- Tests live in `scripts/test-*.py`, loaded via `importlib.util.spec_from_file_location`, using pytest + `monkeypatch`.
- Run a single module: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
- Run all python tests: `.venv/bin/python -m pytest scripts -v`
- Shell test harnesses are `scripts/test-*.sh`; invoke with `PYTHON=.venv/bin/python bash scripts/<name>.sh`.
- After changing `gitops/desired/**` OR any renderer/template, re-render: `.venv/bin/python scripts/render-gitops-config.py`.
- Commit frequently, one logical change per commit.

---

## Phase A — Ingest-edge hardening

Source: `ingest-edge/app.py`. Tests: `scripts/test-ingest-edge.py`.
Addresses analysis items: config-reload-per-request (#2), unbounded threads (#3), no health endpoint (#4/#9), no audit log (#19), spoofable XFF (#17), unstripped client fields (#18).

---

### Task 1: Cache config AND secrets with mtime instead of re-reading every request

Both `load_config()` ([app.py:31](../../../ingest-edge/app.py)) and `secret_value()` ([app.py:52](../../../ingest-edge/app.py)) read from disk on **every** POST. At the 10 GB/day target (~115 events/sec) that is per-event filesystem I/O on the hot path. Cache both with mtime invalidation so a rotated credential/secret is still picked up on the next request after the file changes.

**Files:**
- Modify: `ingest-edge/app.py` (the `load_config` and `secret_value` functions, ~lines 31-36 and 52-54)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
def test_load_config_caches_until_mtime_changes(tmp_path, monkeypatch) -> None:
    config_file = tmp_path / "customer-auth.yml"
    config_file.write_text("credentials:\n  a:\n    enabled: true\n", encoding="utf-8")

    reads: list[str] = []
    real_open = Path.open

    def counting_open(self, *args, **kwargs):
        if self == config_file:
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
```

(`Path` is already imported at top of the test file via `from pathlib import Path`. Add `from pathlib import Path` to the test imports if missing.)

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py::test_load_config_caches_until_mtime_changes -v`
Expected: FAIL (config is read on every call).

- [ ] **Step 3: Implement caching**

Replace the `load_config` function in `ingest-edge/app.py` with:

```python
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
```

Also replace the `secret_value` function (currently lines 52-54) with an mtime-cached version:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
Expected: PASS (all tests, including the existing ones).

- [ ] **Step 5: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py
git commit -m "perf(ingest-edge): cache credential config and secrets with mtime invalidation"
```

---

### Task 2: Strip untrusted client-supplied fields before enrichment

The edge must not let a payload smuggle `customer`, `data_stream`, `@metadata`, or arbitrary `siem.*` fields. Only `siem.source_id` is trusted from the client.

**Files:**
- Modify: `ingest-edge/app.py` (`do_POST`, the enrichment block ~lines 130-135)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Add a helper that runs a full accepted request and captures the forwarded body, then a test. Append to `scripts/test-ingest-edge.py`:

```python
def _run_accepted_post(monkeypatch, body: bytes):
    forwarded: dict = {}

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
    monkeypatch.setattr(app.requests, "post", fake_post)
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
```

Add `import json` to the test imports if not already present (it is used elsewhere; confirm at top).

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py::test_enrichment_strips_spoofed_fields -v`
Expected: FAIL (`@metadata`/`data_stream` survive, credential_id merge logic differs).

- [ ] **Step 3: Implement field stripping**

In `ingest-edge/app.py`, replace the enrichment block (currently):

```python
        event["customer"] = {"slug": credential["customerSlug"]}
        event["siem"] = {
            **event.get("siem", {}),
            "credential_id": username,
            "ingest_edge_client_ip": client_ip,
        }
```

with:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py
git commit -m "fix(ingest-edge): strip untrusted client fields, derive only source_id from payload"
```

---

### Task 3: Use rightmost-untrusted X-Forwarded-For address

**Files:**
- Modify: `ingest-edge/app.py` (`client_ip_for_request`, ~lines 62-69)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
def test_client_ip_walks_from_right_skipping_trusted(monkeypatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    # peer is trusted proxy; XFF lists spoofed client then real client then trusted hop
    result = app.client_ip_for_request("10.0.0.5", "1.1.1.1, 203.0.113.10, 10.0.0.9")
    assert result == "203.0.113.10"


def test_client_ip_returns_peer_when_peer_untrusted(monkeypatch) -> None:
    monkeypatch.setattr(app, "TRUSTED_PROXY_CIDRS", ["10.0.0.0/24"])
    assert app.client_ip_for_request("203.0.113.10", "1.1.1.1") == "203.0.113.10"
```

The existing `test_client_ip_uses_forwarded_for_from_trusted_proxy` (peer `10.0.0.10`, XFF `"203.0.113.10, 10.0.0.10"`, expects `203.0.113.10`) must still pass.

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -k client_ip -v`
Expected: the new `walks_from_right` test FAILs (current code takes leftmost).

- [ ] **Step 3: Implement rightmost-untrusted walk**

Replace `client_ip_for_request` with:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -k client_ip -v`
Expected: PASS (including the pre-existing trusted-proxy test).

- [ ] **Step 5: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py
git commit -m "fix(ingest-edge): use rightmost-untrusted XFF hop to resolve client IP"
```

---

### Task 4: Add a `/health` GET endpoint

**Files:**
- Modify: `ingest-edge/app.py` (add `do_GET` to `Handler`)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -k health -v`
Expected: FAIL (`do_GET` not defined).

- [ ] **Step 3: Implement `do_GET`**

Add this method to the `Handler` class in `ingest-edge/app.py` (place it above `do_POST`):

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -k "health or get" -v`
Expected: PASS.

- [ ] **Step 5: Document the endpoint**

Add to `README.md` under "Common Operations" (the `/health` curl uses `-k` until Phase I lands; after Phase I, swap to `--cacert secrets/certs/root-ca.crt`):

```markdown
### Check ingest-edge health

```bash
curl -k https://127.0.0.1:5044/health
```

Returns `{"status":"ok"}` when the listener is up. Used by the container healthcheck.
```

- [ ] **Step 6: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py README.md
git commit -m "feat(ingest-edge): add /health endpoint for liveness checks"
```

---

### Task 5: Structured audit logging of accept/reject decisions

**Files:**
- Modify: `ingest-edge/app.py` (add logging, log in `reject` and on accept)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
def test_reject_emits_audit_log(monkeypatch, caplog) -> None:
    import logging
    handler = object.__new__(app.Handler)
    handler.client_address = ("203.0.113.99", 5555)
    handler.wfile = SimpleNamespace(write=lambda b: None)
    handler.send_response = lambda status: None
    handler.send_header = lambda k, v: None
    handler.end_headers = lambda: None
    with caplog.at_level(logging.INFO, logger="ingest-edge"):
        handler.reject(403, "unknown credential")
    assert any("403" in r.message and "unknown credential" in r.message
               for r in caplog.records)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py::test_reject_emits_audit_log -v`
Expected: FAIL (no log emitted).

- [ ] **Step 3: Implement logging**

Near the top of `ingest-edge/app.py`, after the imports, add:

```python
import logging

# Audit log. Lines are key=value greppable and intentionally contain only the
# credential ID (a tenant identifier like "acme-primary"), peer/client IP, and
# decision — NEVER the password or secret value.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
LOG = logging.getLogger("ingest-edge")
```

Replace the `reject` method body so it logs the attempted credential (never the password) before responding. Add an optional `credential` parameter:

```python
    def reject(self, status: int, message: str, credential: str = "-") -> None:
        peer = getattr(self, "client_address", ("-",))[0]
        LOG.info("reject status=%s peer=%s credential=%s reason=%s", status, peer, credential, message)
        body = json.dumps({"error": message}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
```

Pass the attempted username to the credential-related `reject` calls in `do_POST` so rejections are traceable to a specific credential ID. After `username, password = auth` is unpacked, the unknown-credential / invalid-credential / source-ip rejections become:

```python
        credential = config["credentials"].get(username)
        if credential is None or not credential.get("enabled", False):
            self.reject(403, "unknown credential", credential=username)
            return

        expected = secret_value(credential["secretRef"])
        if not secrets.compare_digest(password, expected):
            self.reject(403, "invalid credential", credential=username)
            return
```

and the allowlist rejection: `self.reject(403, "source ip not allowed", credential=username)`. Leave the pre-auth `reject(401, "missing basic auth")` without a credential (none is known yet). Never pass `password` to the logger.

In `do_POST`, immediately after the upstream `requests.post` succeeds (before `self.send_response(response.status_code)`), add an accept audit line:

```python
        LOG.info(
            "accept customer=%s credential=%s client_ip=%s upstream=%s",
            credential["customerSlug"], username, client_ip, response.status_code,
        )
```

Also override the noisy default request logger by adding to `Handler`:

```python
    def log_message(self, fmt: str, *args: Any) -> None:
        return
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
Expected: PASS.

- [ ] **Step 5: Document the audit-log format**

Add a "Reading ingest-edge audit logs" subsection to `README.md` under "Common Operations" / "Troubleshooting" so operators know the format and how to trace a tenant:

```markdown
### Reading ingest-edge audit logs

The ingest edge emits one key=value line per decision (no passwords are logged):

```text
2026-06-01 12:00:00 INFO ingest-edge accept customer=acme credential=acme-primary client_ip=203.0.113.10 upstream=200
2026-06-01 12:00:01 INFO ingest-edge reject status=403 peer=203.0.113.99 credential=acme-primary reason=invalid credential
```

Trace one tenant's traffic with `docker compose logs ingest-edge | grep 'credential=acme-primary'`.
Common reject reasons: `unknown credential`, `invalid credential`, `source ip not allowed`.
```

- [ ] **Step 6: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py README.md
git commit -m "feat(ingest-edge): structured audit logging for accept/reject decisions"
```

---

### Task 6: Bound concurrent connections

**Files:**
- Modify: `ingest-edge/app.py` (server class + `main`)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
def test_bounded_server_semaphore_size() -> None:
    server = app.BoundedThreadingHTTPServer(
        ("127.0.0.1", 0), app.Handler, max_concurrency=7
    )
    try:
        assert server._semaphore._value == 7
    finally:
        server.server_close()


def test_module_uses_shared_session() -> None:
    import requests as _requests
    assert isinstance(app.SESSION, _requests.Session)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py::test_bounded_server_semaphore_size -v`
Expected: FAIL (`BoundedThreadingHTTPServer` not defined).

- [ ] **Step 3: Implement the bounded server**

Add `import threading` to the imports. Add a shared, connection-pooled `requests.Session` near the top of the module (after the `LOG` definition from Task 5) so per-event posts to Logstash reuse TCP connections (HTTP keep-alive) instead of opening a fresh connection each time:

```python
from requests.adapters import HTTPAdapter

MAX_CONCURRENCY = int(os.environ.get("INGEST_EDGE_MAX_CONCURRENCY", "64"))

SESSION = requests.Session()
SESSION.mount("http://", HTTPAdapter(pool_connections=MAX_CONCURRENCY, pool_maxsize=MAX_CONCURRENCY))
SESSION.mount("https://", HTTPAdapter(pool_connections=MAX_CONCURRENCY, pool_maxsize=MAX_CONCURRENCY))
```

In `do_POST`, change the upstream call from `requests.post(...)` to `SESSION.post(...)`:

```python
        try:
            response = SESSION.post(LOGSTASH_URL, json=event, timeout=10)
        except requests.RequestException:
            self.reject(503, "upstream logstash unavailable")
            return
```

Add this class above `def main()`:

```python
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
```

**Update the tests that patched the upstream call.** Because `do_POST` now calls `SESSION.post` instead of `requests.post`, update the two existing patch sites so they keep exercising the upstream path:
- In `test_upstream_failure_returns_503`: change `monkeypatch.setattr(app.requests, "post", raise_request_error)` to `monkeypatch.setattr(app.SESSION, "post", raise_request_error)`.
- In the `_run_accepted_post` helper (added in Task 2): change `monkeypatch.setattr(app.requests, "post", fake_post)` to `monkeypatch.setattr(app.SESSION, "post", fake_post)`.

Update `main` to use it:

```python
def main() -> None:
    host = os.environ.get("INGEST_EDGE_HOST", "0.0.0.0")
    port = int(os.environ.get("INGEST_EDGE_PORT", "5044"))
    server = BoundedThreadingHTTPServer((host, port), Handler, max_concurrency=MAX_CONCURRENCY)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    LOG.info("ingest-edge listening host=%s port=%s max_concurrency=%s", host, port, MAX_CONCURRENCY)
    server.serve_forever()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
Expected: PASS.

- [ ] **Step 5: Add the env var to compose**

In `docker-compose.yml`, under `ingest-edge.environment`, add:

```yaml
      - INGEST_EDGE_MAX_CONCURRENCY=64
```

- [ ] **Step 6: Document the tuning knob and commit**

Add to `README.md` (near the ingest-edge / "Security Notes" or "Common Operations" section):

```markdown
`INGEST_EDGE_MAX_CONCURRENCY` (default `64`) bounds the number of concurrent
ingest-edge request threads. Each thread does a blocking, connection-pooled POST
to Logstash. If Logstash per-event latency spikes (>100 ms), lower it to `32`;
raise it only if the host has spare CPU and Logstash keeps up.
```

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py docker-compose.yml README.md
git commit -m "feat(ingest-edge): bound concurrent request threads via semaphore"
```

---

## Phase B — Compose healthchecks and startup ordering

Addresses items #4/#8. No unit tests; verification is `docker compose config` + observed health state.

---

### Task 7: Add healthchecks for central-logstash and ingest-edge; gate ingest-edge on logstash health

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add a healthcheck to `central-logstash`**

In the `central-logstash` service, add (TCP liveness on the Logstash monitoring port, using only bash which the Logstash image ships):

```yaml
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'echo > /dev/tcp/localhost/9600'"]
      interval: 20s
      timeout: 10s
      retries: 12
      start_period: 90s
```

- [ ] **Step 2: Add a healthcheck to `ingest-edge`**

In the `ingest-edge` service, add (python is guaranteed present in the alpine image):

```yaml
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import ssl,urllib.request; urllib.request.urlopen('https://localhost:5044/health', context=ssl._create_unverified_context())\""]
      interval: 20s
      timeout: 10s
      retries: 6
      start_period: 15s
```

- [ ] **Step 3: Gate `ingest-edge` on a healthy logstash**

Replace the `ingest-edge` `depends_on` block:

```yaml
    depends_on:
      - central-logstash
```

with:

```yaml
    depends_on:
      central-logstash:
        condition: service_healthy
```

- [ ] **Step 4: Validate compose**

Run: `docker compose config --quiet`
Expected: exits 0, no errors.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml
git commit -m "feat(compose): healthchecks for logstash/ingest-edge and ordered startup"
```

---

## Phase C — Lightweight observability

Decision: no new services. Expose the Logstash monitoring API to localhost and add a Python status script that reports the signals from the spec's Operations section.

---

### Task 8: Expose the Logstash monitoring API on localhost

**Files:**
- Modify: `docker-compose.yml` (`central-logstash`)

- [ ] **Step 1: Publish 9600 to localhost only**

In `central-logstash`, replace:

```yaml
    expose:
      - "9601"
```

with:

```yaml
    expose:
      - "9601"
    ports:
      - "127.0.0.1:9600:9600"
```

- [ ] **Step 2: Validate and commit**

Run: `docker compose config --quiet`

```bash
git add docker-compose.yml
git commit -m "feat(compose): expose Logstash monitoring API on localhost:9600"
```

---

### Task 8b: Add a shared OpenSearch client helper

Both `siem-status.py` (Task 9) and `reconcile-opensearch-gitops.py` (Phase I Task 17) need the same auth + TLS-verify logic. Extract it once so the CA-aware verify behavior added in Phase I lives in a single place.

**Files:**
- Create: `scripts/lib/opensearch_client.py`
- Test: `scripts/test-opensearch-client.py`

- [ ] **Step 1: Write the failing test**

Create `scripts/test-opensearch-client.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-client.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement the helper**

Create `scripts/lib/opensearch_client.py`:

```python
from __future__ import annotations

import os


def opensearch_auth() -> tuple[str, str]:
    user = os.environ.get("OPENSEARCH_USER")
    password = os.environ.get("OPENSEARCH_PASSWORD")
    if not user or not password:
        raise SystemExit(
            "ERROR: OPENSEARCH_USER and OPENSEARCH_PASSWORD must be set. Example:\n"
            "  set -a; . ./.env; set +a\n"
            "  OPENSEARCH_USER=admin OPENSEARCH_PASSWORD=\"$OPENSEARCH_ADMIN_PASSWORD\" ..."
        )
    return user, password


def opensearch_verify():
    """Return a CA bundle path for TLS verification, or False to disable (pre-Phase-I)."""
    return os.environ.get("OPENSEARCH_CA") or False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-client.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/opensearch_client.py scripts/test-opensearch-client.py
git commit -m "feat(lib): shared OpenSearch auth + TLS-verify helper"
```

---

### Task 9: Add a `siem-status.py` operator script

Reports: OpenSearch cluster health/status, JVM heap %, disk watermark headroom, per-stream doc counts and sizes, quarantine doc counts, and Logstash pipeline event in/out + persistent-queue events. Pure read-only.

**Files:**
- Create: `scripts/siem-status.py`
- Test: `scripts/test-siem-status.py`

- [ ] **Step 1: Write the failing test**

Create `scripts/test-siem-status.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-siem-status.py -v`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement the script**

Create `scripts/siem-status.py`:

```python
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


def summarize_cluster(health: dict[str, Any], nodes_stats: dict[str, Any]) -> dict[str, Any]:
    node = next(iter(nodes_stats.get("nodes", {}).values()), {})
    heap = node.get("jvm", {}).get("mem", {}).get("heap_used_percent")
    return {
        "status": health.get("status"),
        "nodes": health.get("number_of_nodes"),
        "active_shards": health.get("active_shards"),
        "heap_used_percent": heap,
    }


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
        result[pid] = {
            "in": events.get("in"),
            "out": events.get("out"),
            "queue_events": pdata.get("queue", {}).get("events"),
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
        report["cluster"] = summarize_cluster(
            _get(f"{os_url}/_cluster/health", auth),
            _get(f"{os_url}/_nodes/stats/jvm", auth),
        )
        report["allocation"] = _get(f"{os_url}/_cat/allocation?format=json&bytes=gb", auth)
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
```

> Note: `_cat/indices/<wildcard>` returns an empty list (HTTP 200) when nothing matches, so a fresh cluster with no streams yet simply yields an empty `streams` map — no error.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-siem-status.py -v`
Expected: PASS.

- [ ] **Step 5: Document and commit**

Add a "Status / Monitoring" subsection to `README.md` under "Common Operations":

```markdown
### Status snapshot

```bash
set -a; . ./.env; set +a
OPENSEARCH_URL=https://127.0.0.1:9200 \
OPENSEARCH_USER=admin \
OPENSEARCH_PASSWORD="$OPENSEARCH_ADMIN_PASSWORD" \
  .venv/bin/python scripts/siem-status.py
```

Reports cluster status, heap %, disk allocation, per-stream doc counts, total
quarantine docs, and Logstash pipeline throughput / queue depth.

`OPENSEARCH_URL` defaults to `https://127.0.0.1:9200`. **Set it explicitly for a
remote cluster** (e.g. `OPENSEARCH_URL=https://opensearch.internal:9200`) — the
same default applies to `scripts/reconcile-opensearch-gitops.py`, so an unset
value silently targets localhost.
```

```bash
git add scripts/siem-status.py scripts/test-siem-status.py README.md
git commit -m "feat(ops): add read-only siem-status.py monitoring snapshot script"
```

---

## Phase D — Reconciler drift reporting

Addresses #5: the reconciler upserts but never reports/removes objects dropped from desired state.

---

### Task 10: Report orphaned managed index templates (with optional `--prune`)

**Files:**
- Modify: `scripts/reconcile-opensearch-gitops.py`
- Test: `scripts/test-opensearch-reconciler.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-opensearch-reconciler.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py::test_orphaned_templates_detects_extras -v`
Expected: FAIL (`orphaned_templates` undefined).

- [ ] **Step 3: Implement orphan detection + wire into reconcile**

`report_drift` (below) uses the shared `opensearch_verify()` helper created in Phase C Task 8b. Add the import once, near the top of `scripts/reconcile-opensearch-gitops.py` (after the existing imports; `import sys` is needed and `REPO_ROOT` is already defined):

```python
import sys
sys.path.insert(0, str(REPO_ROOT))
from scripts.lib.opensearch_client import opensearch_verify
```

`opensearch_verify()` returns `False` until `OPENSEARCH_CA` is set in the environment (Phase I Task 15 adds it to `.env`), so behavior is unchanged through Phases D–H — the verify flips on automatically once Phase I lands. Then add:

```python
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
```

> The credential is referenced via shell vars (`$OPENSEARCH_USER:$OPENSEARCH_PASSWORD`), printed once as a template with `<name>` — never expanded with a concrete password — so no secret is emitted to stdout or copy-pasted into shell history. `opensearch_verify()` is the shared helper imported above.

**Reuse the names already applied instead of re-globbing.** In `reconcile(...)`, accumulate each template `name` as it is PUT in the two existing template-apply loops (current lines 108-114) into a set, then pass it to `report_drift`. Replace those two loops with:

```python
    applied_template_names: set[str] = set()
    for path in sorted((REPO_ROOT / "opensearch/base/index-templates").glob("*.json")):
        name = path.stem
        applied_template_names.add(name)
        put_json(base_url, f"/_index_template/{name}", load_json(path), dry_run)

    for path in sorted((REPO_ROOT / "gitops/rendered/opensearch/index-templates").glob("*.json")):
        name = path.stem
        applied_template_names.add(name)
        put_json(base_url, f"/_index_template/{name}", load_json(path), dry_run)
```

(Only change vs. the current loops is the two `applied_template_names.add(name)` lines.)

Add `report_drift(base_url, applied_template_names)` as the **final statement** of `reconcile(...)` (after the role/user/mapping block, lines 120-143). The canonical end-state ordering of `reconcile()` — also referenced by Phase F Task 12 — is:

1. Apply base index templates (collecting `applied_template_names`)
2. Apply rendered index templates (collecting `applied_template_names`)
3. Apply ISM policies
4. **Create data streams** (added in Phase F Task 12)
5. Apply role / internaluser / rolesmapping
6. **Report drift** (this task) — runs last so it sees the full applied state

`reconcile()` currently has no early `return`, so appending both new calls is control-flow-safe; this ordering only fixes *where* each goes. `report_drift` does a GET and is read-only, so it runs in both dry-run and apply modes (acceptable — it never mutates).

```python
    report_drift(base_url, applied_template_names)
```

(Note: `logs-template` / `alerts-template` base templates start with `logs-`/`alerts-` and are collected into `applied_template_names`, so they are never flagged as orphans.)

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconcile-opensearch-gitops.py scripts/test-opensearch-reconciler.py
git commit -m "feat(reconciler): report index templates that drifted from desired state"
```

---

## Phase E — Per-source relay bundles

Addresses #7: the relay template hardcodes `source_id`/`dataset` to `firewall`, so multi-source customers get mislabeled bundles. Generate one syslog input per declared source on sequential ports.

---

### Task 11: Render relay pipeline from the customer's declared sources

**Files:**
- Modify: `relay/templates/pipeline.conf.j2`
- Modify: `scripts/generate-relay-bundle.sh` (the embedded Python render block)
- Test: `scripts/test-relay-bundle.sh` (extend assertions)

- [ ] **Step 1: Inspect the current relay test to match its style**

Run: `cat scripts/test-relay-bundle.sh`
Note how it invokes the generator and what it asserts; you will add assertions for a non-firewall source.

- [ ] **Step 2: Add reusable helpers to the shared lib**

The relay generator should not re-implement source globbing/parsing that already lives in `scripts/lib/gitops_config.py` ([`load_sources`](../../../scripts/lib/gitops_config.py)), nor duplicate the Jinja `Environment` setup that `render-gitops-config.py` already does. Add both helpers there so every path shares one implementation. Append to `scripts/lib/gitops_config.py`:

```python
from jinja2 import Environment, FileSystemLoader


def enabled_sources_for_customer(customer_slug: str) -> list[dict[str, str]]:
    """Glob + parse a single customer's enabled sources (id/dataset only).

    Used by the relay-bundle generator. Lighter than load_sources() — no
    cross-customer/retention validation — but the single source of truth for
    *how* a customer's source files are enumerated.
    """
    source_dir = DESIRED / "customers" / customer_slug / "sources"
    result: list[dict[str, str]] = []
    for path in sorted(source_dir.glob("*.yml")):
        doc = read_yaml(path)
        if not doc.get("enabled", False):
            continue
        result.append({"id": doc["id"], "dataset": doc["dataset"]})
    return result


def make_jinja_env(repo_root: Path) -> Environment:
    """Canonical Jinja environment for rendering repo templates.

    Single definition reused by render-gitops-config.py and the relay-bundle
    generator so the trim/lstrip/autoescape settings can never drift.
    """
    return Environment(
        loader=FileSystemLoader(str(repo_root)),
        trim_blocks=True,
        lstrip_blocks=True,
        autoescape=False,
    )
```

Then update `scripts/render-gitops-config.py` to use it: replace its inline `env = Environment(loader=FileSystemLoader(str(REPO_ROOT)), trim_blocks=True, lstrip_blocks=True, autoescape=False)` block with `env = make_jinja_env(REPO_ROOT)` and add `make_jinja_env` to the existing `from scripts.lib.gitops_config import (...)` import. Re-run `.venv/bin/python scripts/render-gitops-config.py` and `PYTHON=.venv/bin/python bash scripts/test-rendered-gitops-config.sh` to confirm rendered output is byte-identical (the settings match, so it must be).

- [ ] **Step 3: Rewrite the relay pipeline template**

Replace `relay/templates/pipeline.conf.j2` with:

```jinja
{% for source in sources %}
input {
  syslog {
    port => {{ source.port }}
    type => "{{ source.id }}"
    add_field => {
      "[customer][slug]" => "{{ customer_slug }}"
      "[siem][source_id]" => "{{ source.id }}"
      "[event][dataset]" => "{{ source.dataset }}"
    }
  }
}
{% endfor %}

output {
  http {
    url => "{{ central_url }}"
    http_method => "post"
    format => "json"
    content_type => "application/json"
    user => "{{ credential_id }}"
    password => "${CUSTOMER_FORWARDER_PASSWORD}"
    ssl_verification_mode => "full"
    ssl_certificate_authorities => ["/usr/share/logstash/config/certs/central-ca.crt"]
  }
}
```

- [ ] **Step 4: Feed sources into the renderer**

In `scripts/generate-relay-bundle.sh`, replace the second embedded Python block (the one rendering the bundle) with a version that imports the shared enumerator from Step 2, validates each value, and assigns ports starting at 5514:

```bash
"${PYTHON:-python3}" - "$repo_root" "$customer_slug" "$credential_id" <<'PY'
from pathlib import Path
import re
import sys

repo = Path(sys.argv[1])
customer_slug = sys.argv[2]
credential_id = sys.argv[3]

sys.path.insert(0, str(repo))
from scripts.lib.gitops_config import enabled_sources_for_customer, make_jinja_env

# Defense-in-depth: these values are interpolated unescaped into a Logstash
# .conf (autoescape can't help with Ruby-config syntax). guard against
# config-injection / breakout at the emission point. Pattern MUST match the
# id/dataset constraint in gitops/schemas/source.schema.json exactly so the
# generator never rejects a schema-valid source nor accepts an invalid one.
SAFE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")

sources = []
port = 5514
for src in enabled_sources_for_customer(customer_slug):
    sid, dataset = src["id"], src["dataset"]
    if not SAFE.match(sid) or not SAFE.match(dataset):
        raise SystemExit(f"unsafe source id/dataset: {sid!r}/{dataset!r}")
    sources.append({"id": sid, "dataset": dataset, "port": port})
    port += 1
if not sources:
    raise SystemExit(f"no enabled sources for customer {customer_slug}")

env = make_jinja_env(repo)
bundle = repo / "relay" / "bundles" / customer_slug
bundle.mkdir(parents=True, exist_ok=True)
(bundle / "logstash.yml").write_text(
    env.get_template("relay/templates/logstash.yml.j2").render(), encoding="utf-8")
(bundle / "pipeline.conf").write_text(
    env.get_template("relay/templates/pipeline.conf.j2").render(
        customer_slug=customer_slug,
        credential_id=credential_id,
        central_url="https://siem.example.com:5044",
        sources=sources,
    ), encoding="utf-8")
port_table = "\n".join(f"  {s['id']}: udp/tcp {s['port']}" for s in sources)
(bundle / "README.md").write_text(
    "Install central-ca.crt at /usr/share/logstash/config/certs/central-ca.crt "
    "and set CUSTOMER_FORWARDER_PASSWORD before starting the relay.\n\n"
    "Point each log source at the matching syslog listener port:\n"
    f"{port_table}\n",
    encoding="utf-8")
PY
```

The generated README now lists each source with its dedicated port (e.g. `firewall: udp/tcp 5514`, `windows: udp/tcp 5515`), so a customer admin can map senders and firewall rules without cross-referencing `pipeline.conf`.

- [ ] **Step 5: Extend the relay bundle test**

In `scripts/test-relay-bundle.sh`, after the bundle is generated for `acme`, add assertions that both sources are present with distinct ports. Add:

```bash
grep -q 'port => 5514' "$bundle_dir/pipeline.conf" || { echo "missing firewall port"; exit 1; }
grep -q 'port => 5515' "$bundle_dir/pipeline.conf" || { echo "missing windows port"; exit 1; }
grep -q '\[siem\]\[source_id\]" => "windows"' "$bundle_dir/pipeline.conf" || { echo "missing windows source_id"; exit 1; }
```

(Adjust `$bundle_dir` to match the variable name already used in that script.)

- [ ] **Step 6: Run the relay bundle test**

Run: `PYTHON=.venv/bin/python bash scripts/test-relay-bundle.sh`
Expected: PASS, bundle contains a syslog input per enabled source on ports 5514, 5515.

- [ ] **Step 7: Commit**

```bash
git add relay/templates/pipeline.conf.j2 scripts/generate-relay-bundle.sh scripts/test-relay-bundle.sh \
        scripts/lib/gitops_config.py scripts/render-gitops-config.py gitops/rendered
git commit -m "feat(relay): generate per-source syslog inputs from declared GitOps sources"
```

(Re-render before committing so any `gitops/rendered` whitespace from the `make_jinja_env` swap is captured: `.venv/bin/python scripts/render-gitops-config.py`. Output should be byte-identical, but stage it to keep the staleness gate green.)

---

## Phase F — Bootstrap data streams in the reconciler

Addresses #8: templates declare `data_stream: {}` but nothing explicitly creates the data streams, leaving retention/rollover dependent on implicit auto-creation. Make creation explicit and idempotent.

---

### Task 12: Create data streams from `gitops/rendered/opensearch/streams.yml`

**Files:**
- Modify: `scripts/reconcile-opensearch-gitops.py`
- Test: `scripts/test-opensearch-reconciler.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-opensearch-reconciler.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py -k data_stream -v`
Expected: FAIL (`create_data_stream` undefined).

- [ ] **Step 3: Implement data-stream creation + wire into reconcile**

Add to `scripts/reconcile-opensearch-gitops.py`:

```python
def create_data_stream(base_url: str, name: str, dry_run: bool) -> None:
    if dry_run:
        print(f"DRY-RUN PUT /_data_stream/{name}")
        return
    response = requests.put(
        f"{base_url}/_data_stream/{name}",
        auth=opensearch_auth(),
        verify=opensearch_verify(),  # shared helper imported in Task 10
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
```

Insert the data-stream creation loop at **position 4** of the canonical `reconcile()` ordering (see Phase D Task 10): immediately **after the ISM-policy apply loop** (current lines 116-118) and **before** the role/internaluser/rolesmapping block (current line 120). This guarantees the index templates with `data_stream: {}` already exist when the streams are created.

```python
    for stream in desired_stream_names():
        create_data_stream(base_url, stream, dry_run)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/reconcile-opensearch-gitops.py scripts/test-opensearch-reconciler.py
git commit -m "feat(reconciler): explicitly create data streams so ISM rollover applies"
```

---

## Phase G — Timestamp normalization

Addresses the lower-priority `@timestamp` gap. Honor a relay-supplied event time and stamp an ingest time, without breaking raw preservation.

---

### Task 13: Stamp ingest time and preserve event time in the normalize pipeline

**Files:**
- Modify: `logstash/pipeline/20-normalize.conf`
- Test: `scripts/test-logstash-config.sh` (extend existing config validation)

- [ ] **Step 1: Update the normalize pipeline**

Replace `logstash/pipeline/20-normalize.conf` with:

```ruby
input {
  pipeline {
    address => "normalize"
  }
}

filter {
  if ![event][original] and [message] {
    mutate {
      copy => {
        "message" => "[event][original]"
      }
    }
  }

  ruby {
    code => 'event.set("[event][ingested]", Time.now.utc.iso8601(3))'
  }
}

output {
  pipeline {
    send_to => "opensearch-output"
  }
}
```

Rationale comment is intentionally omitted (self-explanatory); `@timestamp` is already populated by the relay's JSON payload and the central `json` codec, so no `date` filter override is added — this only records when the central edge ingested the event.

- [ ] **Step 2: Add `event.ingested` to the index template mapping**

In `scripts/render-gitops-config.py`, inside `stream_template`, add an `ingested` property to the `event` mapping so it indexes as a date. Change the `event` properties block to:

```python
                    "event": {
                        "properties": {
                            "dataset": {"type": "keyword"},
                            "original": {"type": "wildcard"},
                            "ingested": {"type": "date"},
                        }
                    },
```

Also mirror this in `opensearch/base/index-templates/logs-template.json` by adding to the `event.properties` object:

```json
            "ingested": { "type": "date" }
```

- [ ] **Step 3: Re-render and validate the Logstash config**

Run:
```bash
.venv/bin/python scripts/render-gitops-config.py
bash scripts/test-logstash-config.sh
```
Expected: render succeeds; logstash config test passes (or skips Docker validation if Docker is unavailable).

- [ ] **Step 4: Run the rendered-config test**

Run: `PYTHON=.venv/bin/python bash scripts/test-rendered-gitops-config.sh`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add logstash/pipeline/20-normalize.conf scripts/render-gitops-config.py opensearch/base/index-templates/logs-template.json gitops/rendered
git commit -m "feat(pipeline): stamp event.ingested time and map it as a date"
```

---

## Phase H — Continuous integration

Decision: GitHub Actions. Run all validation suites and fail closed on stale rendered artifacts.

---

### Task 14: Add a render-staleness gate and a CI workflow

**Files:**
- Create: `scripts/test-render-staleness.sh`
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the staleness gate script**

Create `scripts/test-render-staleness.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

"${PYTHON:-python3}" scripts/render-gitops-config.py

if ! git diff --quiet -- gitops/rendered; then
  echo "ERROR: gitops/rendered is stale. Re-run scripts/render-gitops-config.py and commit." >&2
  git --no-pager diff --stat -- gitops/rendered >&2
  exit 1
fi

echo "rendered artifacts are up to date"
```

- [ ] **Step 2: Verify the gate passes locally on a clean tree**

Run:
```bash
.venv/bin/python scripts/render-gitops-config.py
git add -A gitops/rendered && git commit -m "chore: re-render gitops artifacts" || true
PYTHON=.venv/bin/python bash scripts/test-render-staleness.sh
```
Expected: prints "rendered artifacts are up to date".

- [ ] **Step 3: Write the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # CI pins 3.12; README states "Python 3.11 or newer" for local dev. The
      # deps are pure-Python and 3.11-compatible, so local 3.11 runs match CI.
      # If you bump this, update README's prerequisites line to match.
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
          cache-dependency-path: |
            requirements-gitops.txt
            ingest-edge/requirements.txt
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-gitops.txt
          pip install -r ingest-edge/requirements.txt
          pip install pytest
      - name: Python unit tests
        run: python -m pytest scripts -v
      - name: GitOps desired-state validation
        run: PYTHON=python bash scripts/test-gitops-config.sh
      - name: Rendered-config validation
        run: PYTHON=python bash scripts/test-rendered-gitops-config.sh
      - name: Render staleness gate
        run: PYTHON=python bash scripts/test-render-staleness.sh
      - name: Relay bundle test
        run: PYTHON=python bash scripts/test-relay-bundle.sh
      - name: Secret-ignore test
        run: bash scripts/test-secret-ignore.sh
      - name: Compose config validation
        run: docker compose config --quiet
```

- [ ] **Step 4: Validate the workflow file parses**

Run: `python -c "import yaml,sys; yaml.safe_load(open('.github/workflows/ci.yml')); print('ok')"`
Expected: prints `ok`.

- [ ] **Step 5: Commit**

```bash
chmod +x scripts/test-render-staleness.sh
git add scripts/test-render-staleness.sh .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions pipeline with render-staleness gate"
```

---

## Phase I — Internal PKI and TLS verification (OPTIONAL, heaviest, do last)

Addresses the disabled OpenSearch TLS verification in `90-opensearch-output.conf` and the reconciler. **This is the largest and riskiest change**: it replaces OpenSearch's bundled demo certificates with a self-managed internal CA so hostnames (`opensearch`, `localhost`, `127.0.0.1`) verify. It is reversible (revert the compose/security changes and regenerate demo certs). Consider executing it as its own focused branch. If skipped, leave `ssl_certificate_verification => false` documented as a known v1 limitation.

> **Pre-flight:** Confirm with the operator before running — this regenerates certificates and reconfigures the OpenSearch security plugin, which requires wiping and re-initializing the local cluster (`docker compose down && rm -rf data/opensearch`).

> **If you skip Phase I:** Phases A–H deliberately keep the `curl -k` examples, `verify=False` defaults (`OPENSEARCH_CA` unset → `opensearch_verify()` returns `False`), and the compose `-sku`/unverified healthchecks. That is the correct, self-consistent state for a skipped Phase I — **leave them as-is**. Only Phase I (below) flips them, and only Phase I adds `OPENSEARCH_CA` to `.env`. Add a short banner to the README intro so operators know which mode they are in: *"TLS to OpenSearch is unverified until the optional Phase I (internal PKI) is applied."*

---

### Task 15: Generate an internal CA and an OpenSearch node certificate

**Files:**
- Modify: `scripts/setup-local-secrets.sh`

- [ ] **Step 1: Add CA + node cert generation**

In `scripts/setup-local-secrets.sh`, after the existing `central.crt` block, add a block that creates an internal CA and an OpenSearch node cert with the right SANs (only when missing):

```bash
if [[ ! -f secrets/certs/root-ca.key || ! -f secrets/certs/root-ca.crt ]]; then
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout secrets/certs/root-ca.key \
    -out secrets/certs/root-ca.crt \
    -days 3650 \
    -subj "/CN=opensearch-siem-root-ca"
  chmod 600 secrets/certs/root-ca.key
  chmod 644 secrets/certs/root-ca.crt
fi

if [[ ! -f secrets/certs/opensearch.key || ! -f secrets/certs/opensearch.crt ]]; then
  openssl req -nodes -newkey rsa:2048 \
    -keyout secrets/certs/opensearch.key \
    -out secrets/certs/opensearch.csr \
    -subj "/CN=opensearch"
  openssl x509 -req -in secrets/certs/opensearch.csr \
    -CA secrets/certs/root-ca.crt -CAkey secrets/certs/root-ca.key -CAcreateserial \
    -out secrets/certs/opensearch.crt -days 825 \
    -extfile <(printf "subjectAltName=DNS:opensearch,DNS:localhost,IP:127.0.0.1")
  rm -f secrets/certs/opensearch.csr
  chmod 600 secrets/certs/opensearch.key
  chmod 644 secrets/certs/opensearch.crt
fi
```

- [ ] **Step 2: Add an admin client cert for security bootstrap**

Append:

```bash
# v1 single-node: OpenSearch matches the admin client cert by DN (CN=admin)
# only, so no extendedKeyUsage/keyUsage extensions are required. A multi-node
# v2+ deployment SHOULD constrain it:
#   -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature")
if [[ ! -f secrets/certs/admin.key || ! -f secrets/certs/admin.crt ]]; then
  openssl req -nodes -newkey rsa:2048 \
    -keyout secrets/certs/admin.key \
    -out secrets/certs/admin.csr \
    -subj "/CN=admin"
  openssl x509 -req -in secrets/certs/admin.csr \
    -CA secrets/certs/root-ca.crt -CAkey secrets/certs/root-ca.key -CAcreateserial \
    -out secrets/certs/admin.crt -days 825
  rm -f secrets/certs/admin.csr
  chmod 600 secrets/certs/admin.key
  chmod 644 secrets/certs/admin.crt
fi
```

- [ ] **Step 3: Confirm `.gitignore` excludes keys, certs, and serial files**

`-CAcreateserial` emits a `secrets/certs/*.srl` file. Add it to `.gitignore` next to the existing cert ignores:

```text
secrets/certs/*.srl
```

Then verify nothing sensitive is trackable:

```bash
git check-ignore secrets/certs/opensearch.key secrets/certs/root-ca.key secrets/certs/admin.key secrets/certs/root-ca.srl
```
Expected: all four paths echoed (keys via `secrets/certs/*.key`, the serial via the new `*.srl` rule). `*.crt` is already ignored. Add `.gitignore` to this task's commit.

- [ ] **Step 4: Regenerate and verify SANs**

Run:
```bash
bash scripts/setup-local-secrets.sh
openssl x509 -in secrets/certs/opensearch.crt -noout -text | grep -A1 "Subject Alternative Name"
```
Expected: shows `DNS:opensearch, DNS:localhost, IP Address:127.0.0.1`.

- [ ] **Step 5: Add `OPENSEARCH_CA` to generated `.env`**

So operator commands and the reconciler/status scripts verify TLS by default after Phase I, add the CA path to the `.env` heredoc in `scripts/setup-local-secrets.sh` (after the `TRUSTED_PROXY_CIDRS=` line):

```bash
OPENSEARCH_CA=secrets/certs/root-ca.crt
```

- [ ] **Step 6: Commit**

```bash
git add scripts/setup-local-secrets.sh .gitignore
git commit -m "feat(pki): generate internal CA + opensearch/admin certs in setup-local-secrets"
```

---

### Task 16: Configure OpenSearch to use the internal certificates

**Files:**
- Create: `opensearch/config/opensearch.yml`
- Modify: `docker-compose.yml` (`opensearch` service)

- [ ] **Step 1: Write the OpenSearch security config**

Create `opensearch/config/opensearch.yml`:

```yaml
cluster.name: opensearch-siem
node.name: opensearch
network.host: 0.0.0.0

plugins.security.ssl.transport.pemcert_filepath: certs/opensearch.crt
plugins.security.ssl.transport.pemkey_filepath: certs/opensearch.key
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/root-ca.crt
# Single-node v1: there is no inter-node transport traffic, so hostname
# verification on the transport channel is moot. A multi-node v2+ deployment
# MUST set this to true (and issue per-node certs with correct SANs).
plugins.security.ssl.transport.enforce_hostname_verification: false

plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/opensearch.crt
plugins.security.ssl.http.pemkey_filepath: certs/opensearch.key
plugins.security.ssl.http.pemtrustedcas_filepath: certs/root-ca.crt

plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - "CN=admin"
plugins.security.nodes_dn:
  - "CN=opensearch"
```

- [ ] **Step 2: Mount config + certs into the opensearch container**

In `docker-compose.yml` under `opensearch.volumes`, add:

```yaml
      - ./opensearch/config/opensearch.yml:/usr/share/opensearch/config/opensearch.yml:ro
      - ./secrets/certs/opensearch.crt:/usr/share/opensearch/config/certs/opensearch.crt:ro
      - ./secrets/certs/opensearch.key:/usr/share/opensearch/config/certs/opensearch.key:ro
      - ./secrets/certs/root-ca.crt:/usr/share/opensearch/config/certs/root-ca.crt:ro
      - ./secrets/certs/admin.crt:/usr/share/opensearch/config/certs/admin.crt:ro
      - ./secrets/certs/admin.key:/usr/share/opensearch/config/certs/admin.key:ro
```

- [ ] **Step 3: Recreate the cluster from clean state**

> Destructive: wipes local OpenSearch data. Confirm with operator first.

Run:
```bash
docker compose down
rm -rf data/opensearch
bash scripts/setup-local-secrets.sh
docker compose up -d opensearch
```

- [ ] **Step 4: Verify the security plugin initialized with the custom certs**

This is the riskiest step in the plan: swapping the demo certs means the security plugin must re-bootstrap the `.opendistro_security` index against the new admin DN. `allow_default_init_securityindex: true` + `OPENSEARCH_INITIAL_ADMIN_PASSWORD` (already set in `docker-compose.yml`) normally handles this on a clean data dir, but confirm before trusting it:

```bash
docker compose logs opensearch | grep -iE "security index|securityadmin|initialized"
```
Expected: a line indicating the security index was created/initialized. The healthcheck (`curl -sku`) will report unhealthy until this completes — allow up to `start_period` (120s).

**Fallback if the security index does NOT auto-initialize** (cluster stays red / 503s on the security API): run `securityadmin.sh` once using the admin cert, pointing at the bundled securityconfig.

First locate the tool and config dir in the 3.6.0 image (the path below is correct for OpenSearch 2.x and most 3.x, but verify rather than assume — the layout can shift between minor versions):

```bash
docker compose exec opensearch bash -lc 'find / -name securityadmin.sh 2>/dev/null; \
  ls -d config/opensearch-security 2>/dev/null || find / -type d -name opensearch-security 2>/dev/null'
```

Then run it with the discovered paths (adjust if `find` reported different locations):

```bash
docker compose exec opensearch bash -lc '\
  plugins/opensearch-security/tools/securityadmin.sh \
  -cd config/opensearch-security/ \
  -icl -nhnv \
  -cacert config/certs/root-ca.crt \
  -cert config/certs/admin.crt \
  -key config/certs/admin.key \
  -h localhost'
```

- [ ] **Step 5: Verify TLS now validates against the internal CA**

Run:
```bash
set -a; . ./.env; set +a
curl --cacert secrets/certs/root-ca.crt \
  -u "admin:$OPENSEARCH_ADMIN_PASSWORD" \
  https://127.0.0.1:9200/_cluster/health
```
Expected: JSON health response with **no** `-k`/insecure flag needed (cert verified via the internal CA against the `127.0.0.1` SAN).

- [ ] **Step 6: Commit**

```bash
git add opensearch/config/opensearch.yml docker-compose.yml
git commit -m "feat(pki): configure OpenSearch HTTP/transport TLS with internal CA"
```

---

### Task 17: Enable TLS verification in Logstash, the reconciler, and Dashboards

**Files:**
- Modify: `logstash/pipeline/90-opensearch-output.conf`
- Modify: `docker-compose.yml` (mount CA into logstash + dashboards; set dashboards CA env)
- Modify: `scripts/reconcile-opensearch-gitops.py` (use CA bundle instead of `verify=False`)
- Modify: `scripts/siem-status.py` (same)

- [ ] **Step 1: Mount the CA into logstash and enable verification**

In `docker-compose.yml` under `central-logstash.volumes`, add:

```yaml
      - ./secrets/certs/root-ca.crt:/usr/share/logstash/config/certs/root-ca.crt:ro
```

Replace the `opensearch` output block in `logstash/pipeline/90-opensearch-output.conf` with:

```ruby
output {
  opensearch {
    hosts => ["https://opensearch:9200"]
    index => "%{[@metadata][target_stream]}"
    action => "create"
    user => "${LOGSTASH_WRITER_USER}"
    password => "${LOGSTASH_WRITER_PASSWORD}"
    ssl => true
    ssl_certificate_verification => true
    cacert => "/usr/share/logstash/config/certs/root-ca.crt"
    manage_template => false
  }
}
```

- [ ] **Step 2: Point Dashboards at the internal CA**

In `docker-compose.yml` under `opensearch-dashboards`, add the CA mount and env:

```yaml
    volumes:
      - ./secrets/certs/root-ca.crt:/usr/share/opensearch-dashboards/config/certs/root-ca.crt:ro
```
and under `environment`:
```yaml
      - OPENSEARCH_SSL_VERIFICATIONMODE=full
      - 'OPENSEARCH_SSL_CERTIFICATEAUTHORITIES=["/usr/share/opensearch-dashboards/config/certs/root-ca.crt"]'
```

- [ ] **Step 3: Flip the remaining legacy `verify=False` sites in the reconciler**

`siem-status.py` (Task 9) and the reconciler's `report_drift` (Task 10) and `create_data_stream` (Task 12) already call `verify=opensearch_verify()` via the shared helper — and the `from scripts.lib.opensearch_client import opensearch_verify` import was already added to the reconciler in Phase D Task 10. So no new import is needed here; this step only flips the **three remaining hard-coded `verify=False`** sites that predate this plan:

1. `update_existing_ism_policy` — the `requests.get(...)` call (current line ~71-76).
2. `update_existing_ism_policy` — the `requests.put(...)` call (current line ~79-85).
3. `put_json` — the `requests.put(...)` call (current line ~92-98).

Replace `verify=False` with `verify=opensearch_verify()` in each. After this, **grep proves none remain**:

```bash
grep -n "verify=False" scripts/reconcile-opensearch-gitops.py scripts/siem-status.py
```
Expected: no matches.

(No duplicate `_verify()` is introduced — the reconciler's existing local `opensearch_auth()` stays as the single auth definition for that module; only `verify` is centralized.)

Run `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py scripts/test-siem-status.py scripts/test-opensearch-client.py -v` to confirm nothing broke.

- [ ] **Step 4: Update every README TLS-insecure reference**

`OPENSEARCH_CA` is now generated into `.env` (Task 15 Step 5), so `set -a; . ./.env; set +a` exports it and the Python scripts verify automatically. Make the README consistent — leaving an insecure example gives operators a false sense of security. Concretely, in `README.md`:

- **Test-event example** (currently `curl -k ... :5044`): replace `curl -k` with `curl --cacert secrets/certs/root-ca.crt`.
- **ingest-edge `/health` example** (added in Phase A Task 4): replace `curl -k` with `curl --cacert secrets/certs/root-ca.crt`.
- **Reconciler dry-run / apply blocks** ("Start The Stack" and "GitOps Change Flow"): the `set -a; . ./.env; set +a` already exports `OPENSEARCH_CA`, so no per-command flag is needed — but add a one-line note: "TLS is verified via `OPENSEARCH_CA` from `.env`."
- **Status snapshot block** (Phase C): same — `OPENSEARCH_CA` flows from `.env`.
- **Troubleshooting / Security Notes**: remove any wording that implies `-k` is acceptable locally.

Grep to confirm none remain: `grep -rn "curl -k\|verify=False\|-sku" README.md docs/` (the `-sku` in the compose healthcheck is intentional and lives in `docker-compose.yml`, not docs).

- [ ] **Step 5: End-to-end verification**

Run:
```bash
set -a; . ./.env; set +a
OPENSEARCH_URL=https://127.0.0.1:9200 OPENSEARCH_USER=admin \
OPENSEARCH_PASSWORD="$OPENSEARCH_ADMIN_PASSWORD" \
OPENSEARCH_CA=secrets/certs/root-ca.crt \
  .venv/bin/python scripts/reconcile-opensearch-gitops.py --dry-run
docker compose up -d central-logstash opensearch-dashboards ingest-edge
docker compose ps
docker compose logs --tail=30 central-logstash
```
Expected: reconciler dry-run runs with no TLS warnings; logstash logs show successful OpenSearch connection with verification enabled; all services healthy.

- [ ] **Step 6: Commit**

```bash
git add logstash/pipeline/90-opensearch-output.conf docker-compose.yml scripts/reconcile-opensearch-gitops.py scripts/siem-status.py README.md
git commit -m "feat(pki): enable OpenSearch TLS verification across logstash, reconciler, dashboards"
```

---

## Self-review notes

- **Spec coverage:** Observability (#1) → Phase C + B healthchecks; edge perf/concurrency/health/audit/XFF/field-stripping (#2,#3,#4,#9,#17,#18,#19) → Phase A; reconciler drift (#5) → Phase D; CI + staleness gate (#6) → Phase H; relay per-source (#7) → Phase E; data stream bootstrap (#8) → Phase F; `@timestamp` → Phase G; disabled TLS verification → Phase I.
- **Independence:** Phases A–H are independent and individually shippable. Phase I depends on nothing else but is destructive to local data and should be gated on operator confirmation.
- **Type consistency:** `load_config`/`_CONFIG_CACHE`/`_CONFIG_MTIME`, `secret_value`/`_SECRET_CACHE`, `SESSION`, `client_ip_for_request`, `BoundedThreadingHTTPServer(max_concurrency=…)`, `reject(..., credential=…)`, `orphaned_templates`/`report_drift(base_url, desired_names)`/`applied_template_names`, `create_data_stream`/`desired_stream_names`, `summarize_cluster`/`summarize_streams`/`summarize_logstash`, shared `opensearch_auth`/`opensearch_verify` (in `scripts/lib/opensearch_client.py`), and `enabled_sources_for_customer` (in `scripts/lib/gitops_config.py`) are each defined once and referenced consistently.
- **Known deferrals (explicitly out of v1 scope per design spec, intentionally not planned):** broker/Kafka, multi-VM HA, SOPS/age secret encryption, direct customer ingest, SOAR.
- **Deferred optimizations (acknowledged, not planned — would need both relay and edge changes):**
  - **NDJSON batch ingest.** The relay sends one HTTPS POST per event and the edge accepts one JSON object per request. Accepting batches would cut handshake/processing overhead by 1-2 orders of magnitude, but requires changing both the relay output and a new `POST /batch` edge endpoint. Revisit for v2.
  - **`INGEST_EDGE_MAX_CONCURRENCY` tuning.** Default 64 assumes blocking-but-pooled posts to Logstash. If Logstash per-event latency spikes (>100 ms), lower to 32; the knob is documented in `docker-compose.yml`.
  - **Data-stream existence batching.** `create_data_stream` does one PUT per stream each reconcile run (idempotent via already-exists handling). Fine for infrequent reconciles; for very large tenant counts a single `GET /_data_stream` + filter would save round-trips.
