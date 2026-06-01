# Hardening Ledger: OpenSearch SIEM Single-VM Architecture Implementation Plan

**Plan:** [2026-05-25-opensearch-siem-single-vm-architecture.md](./2026-05-25-opensearch-siem-single-vm-architecture.md)
**Status:** stopped-by-user
**Verified at commit:** unavailable-not-a-git-repository

---

## Iteration 1 - 2026-05-25 13:55

**Dispatched concerns:** ISSUES, UX, reusability, security, performance
**Codebase commit at analysis:** unavailable-not-a-git-repository

Subagent dispatch was not used in this iteration because the available subagent tool is restricted unless the user explicitly requests sub-agents or parallel agent work. Analysis was performed locally across the required hardening axes.

### Findings

#### F-1.1 - [severity: high] - ISSUES/security - Ingest edge publishes HTTPS relay URL but implements plain HTTP
- **Location in plan:** Task 5 and Task 7
- **Description:** The relay bundle sends to `https://siem.example.com:5044`, but `ingest-edge/app.py` uses `ThreadingHTTPServer` without TLS and Compose exposes that service directly on `5044`. This violates the approved architecture requirement that customer relays forward over TLS, and the generated relay bundle will not be able to connect to the planned central listener.
- **Suggested change:** Add TLS support to `ingest-edge` using mounted `central.crt` and `central.key`, add Compose mounts/env vars for those files, update `scripts/setup-local-secrets.sh` to generate them before ingest-edge starts, and update `scripts/test-ingest-edge.sh` to prove the server accepts HTTPS locally.
- **Rationale (incl. codebase grounding):** The plan currently creates `secrets/certs/central.{crt,key}` for an older Logstash TLS design but then removes the Logstash cert mount and never mounts certs into `ingest-edge`.
- **Decision:** applied
- **Plan diff:** Added TLS cert/key settings and socket wrapping to `ingest-edge`, mounted `secrets/certs` into Compose, expanded Compose validation to require TLS config, and added an HTTPS smoke test using a temporary self-signed cert.

#### F-1.2 - [severity: high] - ISSUES - Retention policies are created but not attached to customer streams
- **Location in plan:** Task 4 and Task 6
- **Description:** The plan creates global ISM policy JSON files and a generic `logs-*` data stream template, but it never generates per-stream templates or policy bindings that attach each source's declared `retentionPolicy` to its data stream. This means the requested 7-day default and selected 30-day critical retention may not actually run.
- **Suggested change:** Extend the renderer to produce `gitops/rendered/opensearch/index-templates/<stream>.json` for each source with the source's `retentionPolicy`, and update the reconciler to apply rendered templates instead of only static base templates. Remove the empty `plugins.index_state_management.rollover_alias` from the generic logs template.
- **Rationale (incl. codebase grounding):** The source desired state includes `retentionPolicy`, but generated OpenSearch artifacts only include stream names and a writer role.
- **Decision:** applied
- **Plan diff:** Extended the renderer to generate per-stream OpenSearch index templates with `plugins.index_state_management.policy_id`, added generated-template stale checks, updated the reconciler to apply rendered templates, and removed the empty rollover alias from the generic logs template.

#### F-1.3 - [severity: high] - security - Ingest edge security is only build-tested, not behavior-tested
- **Location in plan:** Task 5, Step 6
- **Description:** The ingest-edge test only compiles and builds the Docker image. It does not verify missing auth, wrong password, unknown credential, denied IP, accepted customer credential, or customer slug overwrite behavior. The central tenant boundary could be broken while all tests still pass.
- **Suggested change:** Add `pytest` unit tests or a small integration test for `parse_basic_auth`, `ip_allowed`, credential lookup, customer slug overwrite, malformed JSON rejection, and upstream Logstash failure handling. Require these tests before the Docker build smoke test.
- **Rationale (incl. codebase grounding):** The plan's strongest security claim is enforced in `ingest-edge/app.py`, but no test asserts those claims.
- **Decision:** applied
- **Plan diff:** Added `scripts/test-ingest-edge.py` with behavior tests for auth parsing, IP allowlists, trusted proxy handling, content length validation, and upstream failure response; updated the test wrapper to run pytest before building the image.

#### F-1.4 - [severity: medium] - security/reliability - Ingest edge has no request size limit or upstream error handling
- **Location in plan:** Task 5, Step 4
- **Description:** The handler trusts `Content-Length`, reads the full request body into memory, and lets `requests.post()` exceptions escape. Large requests can pressure memory, and Logstash outages can produce connection resets instead of a clear `503`.
- **Suggested change:** Add `INGEST_EDGE_MAX_BODY_BYTES`, reject oversized or missing/invalid content lengths with `413`/`400`, catch `requests.RequestException`, and return `503 upstream unavailable`.
- **Rationale (incl. codebase grounding):** Version one targets high-ish ingestion bursts on a small VM; the ingest boundary must fail predictably under malformed or oversized requests.
- **Decision:** applied
- **Plan diff:** Added `INGEST_EDGE_MAX_BODY_BYTES`, strict content-length validation, `413` oversized request handling, and `503` handling for Logstash upstream request failures.

#### F-1.5 - [severity: medium] - security - Logstash uses unsafe YAML loading for generated routing config
- **Location in plan:** Task 5, Step 8
- **Description:** The Logstash Ruby filter uses `YAML.load_file` for `source-routing.yml`. Even though the file is generated, it is still mounted configuration. Safe parsing is a better default for an authorization/routing map.
- **Suggested change:** Use `YAML.safe_load(File.read("/usr/share/logstash/gitops/source-routing.yml"), permitted_classes: [], aliases: false).fetch("sources")` if available in the Logstash runtime, and make `scripts/test-logstash-config.sh` prove the syntax is accepted. If JRuby compatibility blocks `safe_load`, document that generated config is trusted and add a renderer-side YAML scalar-only guarantee.
- **Rationale (incl. codebase grounding):** The routing file is part of the tenant isolation boundary and should not rely on general object deserialization.
- **Decision:** applied
- **Plan diff:** Replaced `YAML.load_file` in the planned Logstash routing filter with `YAML.safe_load(..., permitted_classes: [], permitted_symbols: [], aliases: false)`.

#### F-1.6 - [severity: medium] - ISSUES/UX - IP allowlist semantics are ambiguous behind proxies or Docker networking
- **Location in plan:** Task 5, Task 10
- **Description:** `ingest-edge` checks `self.client_address[0]`. This works only if the container sees the real customer source IP. If a reverse proxy, load balancer, or Docker userland proxy hides the source address, allowlists may validate the proxy address instead of the customer.
- **Suggested change:** Add a deployment rule: v1 IP allowlisting is enforced at the host firewall or a trusted TLS reverse proxy before `ingest-edge`, and `ingest-edge` only accepts `X-Forwarded-For` from an explicitly configured trusted proxy CIDR. Add docs and config env names for `TRUSTED_PROXY_CIDRS` if proxy mode is supported.
- **Rationale (incl. codebase grounding):** The approved architecture uses IP allowlisting as an additional security measure, so the plan must specify exactly where the real client IP is observed.
- **Decision:** applied
- **Plan diff:** Added trusted-proxy CIDR handling in `ingest-edge`, added `TRUSTED_PROXY_CIDRS` to Compose and `.env` bootstrap output, and documented that v1 allowlists should be enforced where the real client IP is visible.

### Iteration summary
- Findings raised: 6 | applied: 6 | rejected: 0 | deferred: 0
- Plan commit: unavailable-not-a-git-repository
