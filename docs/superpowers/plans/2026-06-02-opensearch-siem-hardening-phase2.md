# OpenSearch SIEM Hardening Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the runtime safety, observability, and operational gaps that remain after Phase A-I, without expanding the architecture beyond v1 scope.

**Architecture:** Seven independent phases (J-P), each shippable on its own. J hardens the ingest-edge TLS and upstream error visibility. K fixes the backup job's insecure TLS and missing repository check. L adds Docker resource limits and log rotation. M enriches `siem-status.py` with DLQ and allocation metrics. N upgrades the Logstash healthcheck to verify pipeline state. O switches the reconciler from bare `print()` to structured logging. P adds an `.env.example` and parameterizes the relay bundle central URL.

**Tech Stack:** Python 3 stdlib `ssl` / `http.server` (ingest-edge), pytest, Docker Compose, Logstash monitoring API, bash, OpenSearch REST API.

**Conventions in this repo (follow exactly):**
- Tests live in `scripts/test-*.py`, loaded via `importlib.util.spec_from_file_location`, using pytest + `monkeypatch`.
- Run a single module: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
- Run all python tests: `.venv/bin/python -m pytest scripts -v`
- Shell test harnesses are `scripts/test-*.sh`; invoke with `PYTHON=.venv/bin/python bash scripts/<name>.sh`.
- After changing `gitops/desired/**` OR any renderer/template, re-render: `.venv/bin/python scripts/render-gitops-config.py`.
- Commit frequently, one logical change per commit.

---

## Phase J -- Ingest-edge TLS hardening and upstream error visibility

Source: `ingest-edge/app.py`. Tests: `scripts/test-ingest-edge.py`.
Addresses: TLS minimum version not enforced (allows downgrade); upstream non-2xx responses logged as "accept" instead of flagged.

---

### Task 1: Enforce TLS 1.2 minimum on the ingest-edge HTTPS listener

The `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)` at `ingest-edge/app.py:262` does not set a minimum protocol version. Python's default allows TLS 1.0/1.1 on some builds. Pin TLS 1.2 as the floor.

**Files:**
- Modify: `ingest-edge/app.py` (`main`, lines 262-264)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
def test_ssl_context_enforces_tls_1_2_minimum() -> None:
    import ssl
    context = app.create_ssl_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py::test_ssl_context_enforces_tls_1_2_minimum -v`
Expected: FAIL (`create_ssl_context` not defined).

- [ ] **Step 3: Implement `create_ssl_context`**

In `ingest-edge/app.py`, add this function above `main()`:

```python
def create_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK")
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    return context
```

Then replace the three lines in `main()`:

```python
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=TLS_CERT_PATH, keyfile=TLS_KEY_PATH)
    server.socket = context.wrap_socket(server.socket, server_side=True)
```

with:

```python
    context = create_ssl_context()
    server.socket = context.wrap_socket(server.socket, server_side=True)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py
git commit -m "fix(ingest-edge): enforce TLS 1.2 minimum on HTTPS listener"
```

---

### Task 2: Distinguish upstream success from upstream error in audit log

Currently `ingest-edge/app.py:209-211` logs "accept" for every upstream response, including 4xx/5xx from Logstash. An operator grepping for "accept" sees events that were actually rejected by Logstash. Log "accept" only for 2xx; log "upstream_error" for everything else so operators can distinguish.

**Files:**
- Modify: `ingest-edge/app.py` (`do_POST`, lines 209-216)
- Test: `scripts/test-ingest-edge.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-ingest-edge.py`:

```python
def test_upstream_non_2xx_logged_as_upstream_error(monkeypatch, caplog) -> None:
    import logging

    class FakeResp:
        status_code = 429
        content = b'{"error":"backpressure"}'

    def fake_post(url, json=None, timeout=None):
        return FakeResp()

    handler = object.__new__(app.Handler)
    handler.headers = {"Authorization": basic("acme-primary", "secret"),
                       "Content-Length": "2"}
    handler.client_address = ("203.0.113.10", 12345)
    handler.rfile = SimpleNamespace(read=lambda length: b"{}")
    handler.wfile = SimpleNamespace(write=lambda b: None)
    handler.send_response = lambda status: None
    handler.send_header = lambda k, v: None
    handler.end_headers = lambda: None

    monkeypatch.setattr(app, "load_config", lambda: {
        "credentials": {"acme-primary": {"enabled": True,
            "secretRef": "secrets/local/customer-acme-password",
            "customerSlug": "acme", "allowedCidrs": ["203.0.113.10/32"]}}})
    monkeypatch.setattr(app, "secret_value", lambda ref: "secret")
    monkeypatch.setattr(app.SESSION, "post", fake_post)

    with caplog.at_level(logging.INFO, logger="ingest-edge"):
        handler.do_POST()

    messages = [r.getMessage() for r in caplog.records]
    assert any("upstream_error" in m and "429" in m for m in messages), \
        f"expected upstream_error log, got: {messages}"
    assert not any("accept" in m for m in messages), \
        "non-2xx should not log 'accept'"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py::test_upstream_non_2xx_logged_as_upstream_error -v`
Expected: FAIL (currently logs "accept" for all status codes).

- [ ] **Step 3: Implement the split**

In `ingest-edge/app.py`, replace the block at lines 209-216:

```python
        LOG.info(
            "accept customer=%s credential=%s client_ip=%s upstream=%s",
            credential["customerSlug"], username, client_ip, response.status_code,
        )
        self.send_response(response.status_code)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)
```

with:

```python
        if 200 <= response.status_code < 300:
            LOG.info(
                "accept customer=%s credential=%s client_ip=%s upstream=%s",
                credential["customerSlug"], username, client_ip, response.status_code,
            )
        else:
            LOG.warning(
                "upstream_error customer=%s credential=%s client_ip=%s upstream=%s",
                credential["customerSlug"], username, client_ip, response.status_code,
            )
        self.send_response(response.status_code)
        self.send_header("Content-Length", str(len(response.content)))
        self.end_headers()
        self.wfile.write(response.content)
```

- [ ] **Step 4: Update the existing accept audit log test**

The existing `test_accept_emits_audit_log` uses `_run_accepted_post` which returns a 200, so it still passes. Verify:

Run: `.venv/bin/python -m pytest scripts/test-ingest-edge.py -v`
Expected: PASS (all tests including the new one).

- [ ] **Step 5: Document upstream_error in README**

In `README.md`, under "Reading ingest-edge audit logs", add after the existing sample lines:

```markdown
Lines with `upstream_error` indicate Logstash returned a non-2xx status (e.g.,
429 backpressure, 500 internal error). The event was forwarded but not
successfully ingested. Investigate with:

```bash
docker compose logs central-logstash | tail -50
.venv/bin/python scripts/siem-status.py  # check queue depth and DLQ
```
```

- [ ] **Step 6: Commit**

```bash
git add ingest-edge/app.py scripts/test-ingest-edge.py README.md
git commit -m "fix(ingest-edge): log upstream_error for non-2xx Logstash responses"
```

---

## Phase K -- Backup job TLS verification and repository check

Source: `backup/backup-opensearch.sh`, `backup/Dockerfile`. Addresses: backup script uses `curl -k` (skips TLS verification); no check that the snapshot repository exists before creating a snapshot.

---

### Task 3: Mount CA into backup container and enable TLS verification

The backup job at `backup/backup-opensearch.sh:10` uses `curl -sku` which disables TLS certificate verification. After Phase I, the internal CA is available and should be verified.

**Files:**
- Modify: `docker-compose.yml` (`backup-job` service, lines 125-144)
- Modify: `backup/backup-opensearch.sh`

- [ ] **Step 1: Mount the CA into the backup container**

In `docker-compose.yml`, under `backup-job.volumes`, add:

```yaml
      - ./secrets/certs/root-ca.crt:/etc/siem/root-ca.crt:ro
```

And add the CA path as an environment variable under `backup-job.environment`:

```yaml
      - OPENSEARCH_CA=/etc/siem/root-ca.crt
```

- [ ] **Step 2: Replace `curl -sku` with CA-verified curl**

Replace the entire content of `backup/backup-opensearch.sh` with:

```bash
#!/usr/bin/env bash
set -euo pipefail

if [[ "${BACKUP_ENABLED:-false}" != "true" ]]; then
  echo "backup disabled"
  exit 0
fi

if [[ -z "${OPENSEARCH_USER:-}" || -z "${OPENSEARCH_PASSWORD:-}" ]]; then
  echo "ERROR: OPENSEARCH_USER and OPENSEARCH_PASSWORD must be set." >&2
  exit 1
fi

if [[ -z "${OPENSEARCH_CA:-}" || ! -f "${OPENSEARCH_CA}" ]]; then
  echo "ERROR: OPENSEARCH_CA not set or file not found at '${OPENSEARCH_CA:-}'. Mount the CA certificate." >&2
  exit 1
fi
curl_tls_args=(--cacert "$OPENSEARCH_CA")

snapshot_name="snapshot-$(date -u +%Y%m%dT%H%M%SZ)"
curl -sf "${curl_tls_args[@]}" \
  -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY/$snapshot_name?wait_for_completion=false"
echo "started OpenSearch snapshot $snapshot_name"
```

- [ ] **Step 3: Validate compose**

Run: `docker compose config --quiet`
Expected: exits 0, no errors.

- [ ] **Step 4: Document backup prerequisites in README**

Add to `README.md` under the backup section or "Common Operations":

```markdown
### Running backups

The backup job requires three prerequisites before `docker compose --profile backup up`:

1. **Credentials:** `BACKUP_USER` and `BACKUP_PASSWORD` set in `.env` (defaults to admin).
2. **TLS:** `OPENSEARCH_CA` pointing to the CA certificate (mounted into the container).
3. **Repository:** A snapshot repository registered in OpenSearch. The script checks
   and prints a registration command if missing.

The backup script fails fast with an actionable error if any prerequisite is missing.
```

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml backup/backup-opensearch.sh README.md
git commit -m "fix(backup): enable TLS verification via mounted CA certificate"
```

---

### Task 4: Verify snapshot repository exists before creating a snapshot

The backup script blindly PUTs a snapshot. If the snapshot repository was never registered, the request fails with a cryptic 404. Check first and print an actionable error.

**Files:**
- Modify: `backup/backup-opensearch.sh`

- [ ] **Step 1: Add repository existence check**

In `backup/backup-opensearch.sh`, insert this block after the `curl_tls_args` setup and before the `snapshot_name=` line:

```bash
repo_check=$(curl -s -o /dev/null -w "%{http_code}" "${curl_tls_args[@]}" \
  -u "$OPENSEARCH_USER:$OPENSEARCH_PASSWORD" \
  "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY")
if [[ "$repo_check" != "200" ]]; then
  cat >&2 <<ERRMSG
ERROR: snapshot repository '$SNAPSHOT_REPOSITORY' not found (HTTP $repo_check).
Register it first, e.g.:

  curl -XPUT "$OPENSEARCH_URL/_snapshot/$SNAPSHOT_REPOSITORY" \\
    -H 'Content-Type: application/json' \\
    -d '{"type":"fs","settings":{"location":"/usr/share/opensearch/snapshots"}}'

See: https://opensearch.org/docs/latest/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/
ERRMSG
  exit 1
fi
```

- [ ] **Step 2: Commit**

```bash
git add backup/backup-opensearch.sh
git commit -m "fix(backup): verify snapshot repository exists before creating snapshot"
```

---

## Phase L -- Docker resource limits and log rotation

Source: `docker-compose.yml`. Addresses: no memory limits (a runaway JVM can OOM-kill sibling containers); no log rotation (container stdout can fill disk).

---

### Task 5: Add resource limits to all services

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add resource limits**

Add `mem_limit` to each service in `docker-compose.yml`. The limits are sized to the v1 target VM (32 GB RAM total). OpenSearch and Logstash each get 2g JVM heap; industry practice is 1.5-2x heap for total container memory (heap + Lucene mmap + GC + native overhead), so their container limits are set to 6g. Dashboards and ingest-edge are non-JVM, so they get smaller limits. Total: (6g x 2) + 1g + 512m + 256m = ~13.8g, well within 32 GB.

Under `opensearch`, after the `healthcheck` block, add:

```yaml
    mem_limit: 6g
```

Under `opensearch-dashboards`, after `depends_on`, add:

```yaml
    mem_limit: 1g
```

Under `central-logstash`, after `healthcheck`, add:

```yaml
    mem_limit: 6g
```

Under `ingest-edge`, after `healthcheck`, add:

```yaml
    mem_limit: 512m
```

Under `backup-job`, after `depends_on`, add:

```yaml
    mem_limit: 256m
```

- [ ] **Step 2: Validate compose**

Run: `docker compose config --quiet`
Expected: exits 0, no errors.

- [ ] **Step 3: Document resource limits in README**

Add a subsection to `README.md` under "Prerequisites" or "Configuration":

```markdown
### Memory and resource configuration

Default container memory limits assume a 32 GB VM:

| Service              | `mem_limit` | JVM heap | Notes                          |
|----------------------|-------------|----------|--------------------------------|
| opensearch           | 6g          | 2g       | Heap + Lucene mmap + GC        |
| central-logstash     | 6g          | 2g       | Heap + persistent queue        |
| opensearch-dashboards| 1g          | —        | Node.js                        |
| ingest-edge          | 512m        | —        | Python stdlib                  |
| backup-job           | 256m        | —        | curl + bash                    |

**Tuning for smaller VMs:** reduce `mem_limit` and JVM heap proportionally.
For a 16 GB VM, set opensearch/central-logstash to `mem_limit: 3g` with
`-Xms1g -Xmx1g` heap. Monitor with `docker compose stats`.
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml README.md
git commit -m "ops(compose): add memory limits to all services"
```

---

### Task 6: Add log rotation to all services

Without log driver configuration, Docker's default `json-file` driver stores unlimited container logs. Add a top-level `x-logging` anchor and apply it to every service.

**Files:**
- Modify: `docker-compose.yml`

- [ ] **Step 1: Add the logging anchor and apply to services**

At the very top of `docker-compose.yml`, before `services:`, add:

```yaml
x-logging: &default-logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "5"

```

Then add `logging: *default-logging` to each service. Under each service block (opensearch, opensearch-dashboards, central-logstash, ingest-edge, backup-job), add immediately after the service name line (before `image:` or `build:`):

```yaml
    logging: *default-logging
```

- [ ] **Step 2: Validate compose**

Run: `docker compose config --quiet`
Expected: exits 0, no errors.

- [ ] **Step 3: Document log rotation in README**

In the "Memory and resource configuration" section added by Task 5, append:

```markdown
**Container log rotation:** All services use `json-file` logging with
`max-size: 10m` and `max-file: 5` (50 MB per service). Adjust in the
`x-logging` anchor at the top of `docker-compose.yml`.
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml README.md
git commit -m "ops(compose): add log rotation to all services (10m x 5 files)"
```

---

## Phase M -- Enhanced siem-status.py: DLQ, disk, and allocation

Source: `scripts/siem-status.py`. Tests: `scripts/test-siem-status.py`.
Addresses: dead letter queue occupancy invisible; disk watermark proximity not reported; cluster health missing unassigned/relocating shards.

---

### Task 7: Add DLQ occupancy to Logstash status

The Logstash monitoring API at `/_node/stats/pipelines` includes dead letter queue size. Surface it in the status report so operators notice when the DLQ approaches its 512MB limit.

**Files:**
- Modify: `scripts/siem-status.py` (`summarize_logstash`, lines 41-50)
- Test: `scripts/test-siem-status.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-siem-status.py`:

```python
def test_summarize_logstash_includes_dlq() -> None:
    node_stats = {
        "pipelines": {
            "opensearch-output": {
                "events": {"in": 10, "out": 9},
                "queue": {"events": 1},
                "dead_letter_queue": {
                    "queue_size_in_bytes": 1048576,
                    "max_queue_size_in_bytes": 536870912,
                },
            }
        }
    }
    out = status.summarize_logstash(node_stats)
    assert out["opensearch-output"]["dlq_size_bytes"] == 1048576
    assert out["opensearch-output"]["dlq_max_bytes"] == 536870912


def test_summarize_logstash_handles_missing_dlq() -> None:
    node_stats = {
        "pipelines": {
            "relay-input": {
                "events": {"in": 5, "out": 5},
                "queue": {"events": 0},
            }
        }
    }
    out = status.summarize_logstash(node_stats)
    assert out["relay-input"]["dlq_size_bytes"] is None
    assert out["relay-input"]["dlq_max_bytes"] is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-siem-status.py::test_summarize_logstash_includes_dlq -v`
Expected: FAIL (`dlq_size_bytes` not in dict).

- [ ] **Step 3: Implement DLQ extraction**

In `scripts/siem-status.py`, replace the `summarize_logstash` function (lines 41-50) with:

```python
def summarize_logstash(node_stats: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for pid, pdata in node_stats.get("pipelines", {}).items():
        events = pdata.get("events", {})
        dlq = pdata.get("dead_letter_queue", {})
        result[pid] = {
            "in": events.get("in"),
            "out": events.get("out"),
            "queue_events": pdata.get("queue", {}).get("events"),
            "dlq_size_bytes": dlq.get("queue_size_in_bytes"),
            "dlq_max_bytes": dlq.get("max_queue_size_in_bytes"),
        }
    return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-siem-status.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Document DLQ fields in README**

Add a subsection to `README.md` under "Status snapshot" (or "Troubleshooting") explaining the DLQ fields:

```markdown
### Understanding dead letter queue (DLQ) output

`siem-status.py` reports `dlq_size_bytes` and `dlq_max_bytes` per pipeline.
The DLQ holds events that failed processing (e.g., mapping errors, filter
exceptions). When `dlq_size_bytes` approaches `dlq_max_bytes` (default
512 MB), new failures are silently dropped.

**What to do when DLQ is growing:**
1. Check Logstash logs: `docker compose logs central-logstash | grep -i error`
2. Identify the failing pipeline and fix the root cause (bad mapping, filter bug)
3. Once fixed, the DLQ drains automatically on restart
```

- [ ] **Step 6: Commit**

```bash
git add scripts/siem-status.py scripts/test-siem-status.py README.md
git commit -m "feat(status): report Logstash dead letter queue occupancy"
```

---

### Task 8: Add unassigned shards and disk watermark proximity to cluster summary

`summarize_cluster` currently reports only status, node count, active shards, and heap. Add unassigned shards (a common cluster health issue) and the disk allocation details so operators can see how close the cluster is to the high watermark.

**Files:**
- Modify: `scripts/siem-status.py` (`summarize_cluster`, lines 16-24)
- Test: `scripts/test-siem-status.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-siem-status.py`:

```python
def test_summarize_cluster_includes_unassigned_and_disk() -> None:
    health = {
        "status": "yellow",
        "number_of_nodes": 1,
        "active_shards": 12,
        "unassigned_shards": 3,
        "relocating_shards": 0,
    }
    nodes = {"nodes": {"n1": {"jvm": {"mem": {"heap_used_percent": 55}}}}}
    alloc = [{"disk.used": "100gb", "disk.avail": "400gb", "disk.percent": "20"}]
    out = status.summarize_cluster(health, nodes, alloc)
    assert out["unassigned_shards"] == 3
    assert out["relocating_shards"] == 0
    assert out["disk_used"] == "100gb"
    assert out["disk_avail"] == "400gb"
    assert out["disk_percent"] == "20"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-siem-status.py::test_summarize_cluster_includes_unassigned_and_disk -v`
Expected: FAIL (signature mismatch -- `summarize_cluster` takes 2 args, not 3).

- [ ] **Step 3: Implement the expanded summary**

In `scripts/siem-status.py`, replace the `summarize_cluster` function (lines 16-24) with:

```python
def summarize_cluster(
    health: dict[str, Any],
    nodes_stats: dict[str, Any],
    allocation: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    node = next(iter(nodes_stats.get("nodes", {}).values()), {})
    heap = node.get("jvm", {}).get("mem", {}).get("heap_used_percent")
    result: dict[str, Any] = {
        "status": health.get("status"),
        "nodes": health.get("number_of_nodes"),
        "active_shards": health.get("active_shards"),
        "unassigned_shards": health.get("unassigned_shards"),
        "relocating_shards": health.get("relocating_shards"),
        "heap_used_percent": heap,
    }
    if allocation:
        a = allocation[0]
        result["disk_used"] = a.get("disk.used")
        result["disk_avail"] = a.get("disk.avail")
        result["disk_percent"] = a.get("disk.percent")
    return result
```

Then update the `main()` function's `summarize_cluster` call (line 66-68). Replace:

```python
        report["cluster"] = summarize_cluster(
            _get(f"{os_url}/_cluster/health", auth),
            _get(f"{os_url}/_nodes/stats/jvm", auth),
        )
        report["allocation"] = _get(f"{os_url}/_cat/allocation?format=json&bytes=gb", auth)
```

with:

```python
        alloc = _get(f"{os_url}/_cat/allocation?format=json&bytes=gb", auth)
        report["cluster"] = summarize_cluster(
            _get(f"{os_url}/_cluster/health", auth),
            _get(f"{os_url}/_nodes/stats/jvm", auth),
            alloc,
        )
        report["allocation"] = alloc
```

Keep `report["allocation"]` for backward compatibility -- operators or external tools may parse it. The disk summary fields are also available in `report["cluster"]` for convenience.

- [ ] **Step 4: Update the existing cluster test**

The existing `test_summarize_cluster_extracts_key_fields` passes 2 args. The new signature is backward-compatible (`allocation` defaults to `None`), so it still passes.

Run: `.venv/bin/python -m pytest scripts/test-siem-status.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/siem-status.py scripts/test-siem-status.py
git commit -m "feat(status): add unassigned shards and disk watermark to cluster summary"
```

---

## Phase N -- Logstash pipeline-aware healthcheck

Source: `docker-compose.yml`. Addresses: current Logstash healthcheck (`echo > /dev/tcp/localhost/9600`) only tests TCP connectivity, not pipeline health. A deadlocked pipeline passes the check.

---

### Task 9: Replace TCP healthcheck with pipeline stats API check

The Logstash monitoring API at `http://localhost:9600/_node/stats/pipelines` returns pipeline details. A healthy check should confirm at least one pipeline is loaded.

**Files:**
- Modify: `docker-compose.yml` (`central-logstash.healthcheck`, lines 85-90)

- [ ] **Step 1: Replace the healthcheck**

In `docker-compose.yml`, replace the `central-logstash.healthcheck` block:

```yaml
    healthcheck:
      test: ["CMD-SHELL", "bash -c 'echo > /dev/tcp/localhost/9600'"]
      interval: 20s
      timeout: 10s
      retries: 12
      start_period: 90s
```

with:

```yaml
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9600/_node/stats/pipelines >/dev/null 2>&1"]
      interval: 20s
      timeout: 10s
      retries: 12
      start_period: 90s
```

`curl -sf` exits non-zero on HTTP errors (4xx/5xx) and when the connection fails. A 200 from the pipelines stats endpoint means the monitoring API is up and pipelines are loaded. Piping to `>/dev/null` avoids transferring the full JSON to grep. The Logstash OSS image ships with `curl`.

- [ ] **Step 2: Validate compose**

Run: `docker compose config --quiet`
Expected: exits 0, no errors.

- [ ] **Step 3: Commit**

```bash
git add docker-compose.yml
git commit -m "fix(compose): Logstash healthcheck verifies pipeline stats, not just TCP port"
```

---

## Phase O -- Reconciler structured logging

Source: `scripts/reconcile-opensearch-gitops.py`. Tests: `scripts/test-opensearch-reconciler.py`.
Addresses: reconciler uses bare `print()` without timestamps, log levels, or machine-parseable format.

---

### Task 10: Switch reconciler from print() to structured logging

Replace all `print()` calls in the reconciler with `logging.getLogger("reconciler")` calls so output includes timestamps, levels, and is greppable.

**Files:**
- Modify: `scripts/reconcile-opensearch-gitops.py`
- Test: `scripts/test-opensearch-reconciler.py`

- [ ] **Step 1: Write the failing test**

Append to `scripts/test-opensearch-reconciler.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py::test_put_json_logs_applied_action -v`
Expected: FAIL (no log records, reconciler uses `print()`).

- [ ] **Step 3: Implement structured logging**

In `scripts/reconcile-opensearch-gitops.py`, add after the existing imports (line 11):

```python
import logging
```

Replace the import at line 16:

```python
from scripts.lib.opensearch_client import opensearch_verify
```

with:

```python
from scripts.lib.opensearch_client import opensearch_auth, opensearch_verify
```

Then delete the local `opensearch_auth()` function at lines 69-70:

```python
def opensearch_auth() -> tuple[str, str]:
    return os.environ["OPENSEARCH_USER"], os.environ["OPENSEARCH_PASSWORD"]
```

This eliminates the duplicate. The shared `opensearch_auth()` from `scripts/lib/opensearch_client.py` raises `SystemExit` with guidance when env vars are missing, instead of crashing with a bare `KeyError`.

Add after the updated import line:

```python
LOG = logging.getLogger("reconciler")
```

Then replace every `print(...)` call in the file with the corresponding `LOG` call. The replacements are:

In `report_drift` (lines 102-110), replace:

```python
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

with:

```python
        LOG.warning("DRIFT: index templates present in OpenSearch but not in desired state.")
        LOG.info("To remove an orphan, source your env (set -a; . ./.env; set +a) then run:")
        LOG.info("  curl -X DELETE \"%s/_index_template/<name>\" "
                 "-u \"$OPENSEARCH_USER:$OPENSEARCH_PASSWORD\"", os_url)
        LOG.warning("Orphans:")
        for name in orphans:
            LOG.warning("  %s", name)
    else:
        LOG.info("no orphaned managed index templates")
```

In `create_data_stream` (lines 115 and 128), replace:

```python
        print(f"DRY-RUN PUT /_data_stream/{name}")
```

with:

```python
        LOG.info("DRY-RUN PUT /_data_stream/%s", name)
```

and replace:

```python
    print(f"created data stream {name}")
```

with:

```python
    LOG.info("created data stream %s", name)
```

In `put_json` (lines 159 and 171), replace:

```python
        print(f"DRY-RUN PUT {path}")
```

with:

```python
        LOG.info("DRY-RUN PUT %s", path)
```

and replace:

```python
    print(f"applied {path}")
```

with:

```python
    # Log the path only — body may contain passwords (e.g. internalusers endpoint).
    LOG.info("applied %s", path)
```

In `main()` (line 223), add logging configuration at the start of `main`:

```python
def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    reconcile(dry_run=args.dry_run)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest scripts/test-opensearch-reconciler.py -v`
Expected: PASS (all tests).

- [ ] **Step 5: Document reconciler log format in README**

In `README.md`, under "Common Operations" or "Troubleshooting", add:

```markdown
### Reading reconciler logs

The reconciler emits structured log lines with timestamps and levels:

```text
2026-06-01 12:00:00 INFO reconciler applied /_index_template/logs-acme-firewall-template
2026-06-01 12:00:00 WARNING reconciler DRIFT: index templates present in OpenSearch but not in desired state.
```

`INFO` lines show applied objects and dry-run output. `WARNING` lines flag drift
(orphaned templates). Filter with `grep WARNING` to find issues.
```

- [ ] **Step 6: Commit**

```bash
git add scripts/reconcile-opensearch-gitops.py scripts/test-opensearch-reconciler.py README.md
git commit -m "refactor(reconciler): switch from print() to structured logging and consolidate opensearch_auth"
```

---

## Phase P -- Environment variable documentation and relay URL parameterization

Addresses: no `.env.example` showing required variables; relay bundle generator hardcodes `https://siem.example.com:5044`.

---

### Task 11: Create `.env.example` with all required variables

Operators have to cross-reference `docker-compose.yml`, `scripts/setup-local-secrets.sh`, and the README to find which environment variables exist. A `.env.example` file documents them in one place.

**Files:**
- Create: `.env.example`

- [ ] **Step 1: Write the file**

Create `.env.example`:

```bash
# OpenSearch SIEM Environment Variables
# Copy to .env and fill in values, or run scripts/setup-local-secrets.sh to generate.

# OpenSearch admin password (generated by setup-local-secrets.sh)
OPENSEARCH_ADMIN_PASSWORD=

# Logstash writer service account
LOGSTASH_WRITER_USER=logstash_writer
LOGSTASH_WRITER_PASSWORD=

# JVM heap for OpenSearch (default: 2g each for min/max)
OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g

# Enable backup job (requires snapshot repository registration)
BACKUP_ENABLED=false
BACKUP_USER=admin
BACKUP_PASSWORD=
SNAPSHOT_REPOSITORY=siem-snapshots

# Trusted proxy CIDRs for X-Forwarded-For (comma-separated, empty = disabled)
TRUSTED_PROXY_CIDRS=

# Path to the internal CA certificate for TLS verification
OPENSEARCH_CA=secrets/certs/root-ca.crt

# Central SIEM URL for relay bundles (used by scripts/generate-relay-bundle.sh)
RELAY_CENTRAL_URL=https://siem.example.com:5044
```

- [ ] **Step 2: Commit**

```bash
git add .env.example
git commit -m "docs: add .env.example documenting all environment variables"
```

---

### Task 12: Parameterize the relay bundle central URL

`scripts/generate-relay-bundle.sh:74` hardcodes `central_url="https://siem.example.com:5044"`. Read it from the `RELAY_CENTRAL_URL` environment variable so operators set it once in `.env`.

**Files:**
- Modify: `scripts/generate-relay-bundle.sh` (line 74)

- [ ] **Step 1: Add the environment variable**

In `scripts/generate-relay-bundle.sh`, at the top of the second Python block, add `import os` to the imports and add the URL lookup with a fail-fast check. The imports section becomes:

```python
from pathlib import Path
import os
import re
import sys
```

After the `sys.path.insert(0, str(repo))` line, add:

```python
central_url = os.environ.get("RELAY_CENTRAL_URL")
if not central_url:
    raise SystemExit(
        "ERROR: RELAY_CENTRAL_URL not set. Set it in .env or environment.\n"
        "  Example: RELAY_CENTRAL_URL=https://siem.example.com:5044"
    )
```

Then replace the hardcoded URL in the template render call:

```python
        central_url="https://siem.example.com:5044",
```

with:

```python
        central_url=central_url,
```

- [ ] **Step 2: Verify the relay bundle test still passes**

Run: `RELAY_CENTRAL_URL=https://siem.example.com:5044 PYTHON=.venv/bin/python bash scripts/test-relay-bundle.sh`
Expected: PASS. The env var must be set because the script now fails fast without it.

- [ ] **Step 3: Update CI workflow to pass `RELAY_CENTRAL_URL`**

In `.github/workflows/ci.yml`, replace the relay bundle test step:

```yaml
      - name: Relay bundle test
        run: PYTHON=python bash scripts/test-relay-bundle.sh
```

with:

```yaml
      - name: Relay bundle test
        run: RELAY_CENTRAL_URL=https://siem.example.com:5044 PYTHON=python bash scripts/test-relay-bundle.sh
```

- [ ] **Step 4: Commit**

```bash
git add scripts/generate-relay-bundle.sh .github/workflows/ci.yml
git commit -m "feat(relay): read central URL from RELAY_CENTRAL_URL environment variable"
```

---

## Self-review notes

- **Spec coverage:** TLS minimum version (#1) -> Phase J Task 1; backup TLS (#2) -> Phase K Task 3; upstream error logging (#3) -> Phase J Task 2; resource limits (#4) -> Phase L Task 5; log rotation (#5) -> Phase L Task 6; DLQ monitoring (#6) -> Phase M Task 7; Logstash healthcheck (#7) -> Phase N Task 9; reconciler logging (#8) -> Phase O Task 10; `.env.example` (#9) -> Phase P Task 11; relay URL (#10) -> Phase P Task 12; backup repository check (#12) -> Phase K Task 4. Operational runbooks (#11) were dropped as out of scope for an implementation plan (documentation-only, no code/test).
- **Independence:** All seven phases (J-P) are independent and individually shippable. No phase depends on another.
- **Type consistency:** `create_ssl_context() -> ssl.SSLContext` with cipher restriction (Task 1); `summarize_cluster(health, nodes_stats, allocation=None)` signature is backward-compatible with the existing 2-arg callers (Task 8); `summarize_logstash` return shape extended with `dlq_size_bytes`/`dlq_max_bytes` (Task 7); `LOG = logging.getLogger("reconciler")` uses a distinct logger name from ingest-edge's `"ingest-edge"` (Task 10); `opensearch_auth()` consolidated from local duplicate to shared `scripts/lib/opensearch_client.py` import (Task 10).
- **CI consistency:** `.github/workflows/ci.yml` relay bundle test step passes `RELAY_CENTRAL_URL` to match Task 12's fail-fast requirement (Task 12).
- **Backward compatibility:** `report["allocation"]` preserved alongside the new `report["cluster"]` disk fields (Task 8). `summarize_cluster` 3rd arg defaults to `None` for existing 2-arg callers.
- **Known deferrals:** Operational runbooks (documentation-only, no code changes). NDJSON batch ingest, Kafka broker, multi-node HA remain out of v1 scope per the design spec.
