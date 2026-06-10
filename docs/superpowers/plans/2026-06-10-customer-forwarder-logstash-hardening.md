# Hardening Ledger: 2026-06-10-customer-forwarder-logstash

**Plan:** [2026-06-10-customer-forwarder-logstash.md](./2026-06-10-customer-forwarder-logstash.md)
**Status:** in-progress
**Verified at commit:** 79492e34ebf4fd5af30fa626beca24116d3e7b3c

---

## Iteration 1 — 2026-06-10 16:25

**Dispatched concerns:** ISSUES, UX, reusability, security, performance
**Codebase commit at analysis:** 67dca25c32bbab3233d7b8326b17f1c393ce5c7f

### Findings

#### F-1.1 — [severity: high] — [ISSUES/performance] — Missing `parse-and-normalize` pipeline receiver
- **Location in plan:** Task 4, Steps 3-4
- **Description:** `00-inputs.conf` sends to `parse-and-normalize`, but no planned pipeline file declares `input { pipeline { address => "parse-and-normalize" } }`.
- **Suggested change:** Add `customer-forwarder/pipeline/10-parse-input.conf`, include it first in `pipelines.yml`, and add validation coverage.
- **Rationale (incl. codebase grounding):** The central Logstash pipelines use a receiver input at the start of each downstream pipeline in `logstash/pipeline/10-route-and-enrich.conf`, `20-normalize.conf`, and `90-opensearch-output.conf`.
- **Decision:** applied
- **Plan diff:** Added `10-parse-input.conf`, included it in `parse-and-normalize`, and added a compose/pipeline test asserting the receiver exists.

#### F-1.2 — [severity: high] — [ISSUES] — Stale generated index templates are not removed
- **Location in plan:** Task 2
- **Description:** The renderer writes current templates but does not delete obsolete managed templates, so old `logs-acme-firewall*` and `logs-acme-windows*` files would remain deployable.
- **Suggested change:** Add stale-template cleanup to `scripts/render-gitops-config.py` and update rendered-config tests to assert new templates exist and old ones are absent.
- **Rationale (incl. codebase grounding):** `scripts/render-gitops-config.py` writes templates for current sources, while `scripts/reconcile-opensearch-gitops.py` applies every JSON file under `gitops/rendered/opensearch/index-templates`.
- **Decision:** applied
- **Plan diff:** Added `remove_stale_index_templates()` and rendered-config assertions for new and removed template files.

#### F-1.3 — [severity: high] — [security/UX] — Validate central ingest environment before forwarding credentials
- **Location in plan:** Task 4, Steps 1, 4-6
- **Description:** `CENTRAL_INGEST_URL`, credentials, and CA path were passed directly to Logstash, risking insecure forwarding or opaque failures.
- **Suggested change:** Add environment validation for HTTPS-only URL, no embedded credentials, safe characters, non-placeholder credentials, valid host, and readable host CA file.
- **Rationale (incl. codebase grounding):** `scripts/generate-relay-bundle.sh` already performs strict central URL validation, and `ingest-edge/app.py` expects TLS-protected central ingest.
- **Decision:** applied
- **Plan diff:** Added `customer-forwarder/scripts/validate-env.py`, negative tests, `.env.example` placeholders, CA validation, and wrapper invocation before Docker validation.

#### F-1.4 — [severity: med] — [ISSUES/UX/performance/reusability] — Queue config is validated but ignored
- **Location in plan:** Task 3 and Task 4
- **Description:** `forwarder.yml` defined queue values while runtime `logstash.yml` hardcoded the same defaults.
- **Suggested change:** Render `config/logstash.yml` from `forwarder.yml` and test that queue changes affect rendered output.
- **Rationale (incl. codebase grounding):** The existing central Logstash queue settings live in `logstash/config/logstash.yml`; if the forwarder exposes queue values in local config, they need a render path.
- **Decision:** applied
- **Plan diff:** Added `templates/config/logstash.yml.j2`, `render_logstash()`, `write_rendered_logstash()`, render CLI output for `config/logstash.yml`, and a queue-render test.

#### F-1.5 — [severity: med] — [ISSUES] — Docker validation depends on missing `.env`
- **Location in plan:** Task 4, Steps 2 and 6
- **Description:** Compose declares `env_file: .env`, but a clean checkout has only `.env.example`.
- **Suggested change:** Have the Logstash config validation wrapper create a temporary `.env` when absent and remove it on exit.
- **Rationale (incl. codebase grounding):** The existing central Logstash validation avoids service-level `.env` dependency by passing environment explicitly.
- **Decision:** applied
- **Plan diff:** Added temporary `.env` creation, early cleanup trap, and combined cleanup with the Docker temp directory.

#### F-1.6 — [severity: med] — [security] — Prevent Logstash config injection from local forwarder config
- **Location in plan:** Task 3
- **Description:** `listen_host` was weakly validated and rendered into Logstash config with `autoescape=False`; copied catalog was not schema-validated.
- **Suggested change:** Copy and validate the source catalog schema locally, constrain `listen_host`, and add malicious input tests.
- **Rationale (incl. codebase grounding):** `scripts/generate-relay-bundle.sh` already guards unescaped Logstash config interpolation with safe patterns.
- **Decision:** applied
- **Plan diff:** Added copied `source-catalog.schema.json`, schema validation in `load_catalog()`, `SAFE_LOGSTASH_STRING`, malicious `listen_host` test, and catalog-schema test.

#### F-1.7 — [severity: med] — [security/UX] — Exposed collector ports need constraints and docs
- **Location in plan:** Task 3, Task 4, Task 5
- **Description:** Default collector ports are exposed broadly without explicit customer-network protection guidance.
- **Suggested change:** Document required firewall/VPN/source ACL protection for `5514`, `8081`, and `8082`.
- **Rationale (incl. codebase grounding):** Central `ingest-edge` assigns customer identity from the forwarder credential, so hosts that can reach the customer forwarder can inject events under that customer.
- **Decision:** applied
- **Plan diff:** Added a customer-forwarder README security section for collector-port exposure.

#### F-1.8 — [severity: med] — [UX] — Customer docs omit source protocol and port handoff
- **Location in plan:** Task 5
- **Description:** Supported source IDs were listed without protocol, port, sender expectation, or smoke-test handoff.
- **Suggested change:** Add an inputs table for each source.
- **Rationale (incl. codebase grounding):** The forwarder uses syslog on `5514` and HTTP JSON on `8081`/`8082`; the central README only documents central `ingest-edge` HTTP usage.
- **Decision:** applied
- **Plan diff:** Added a README inputs table with source ID, protocol, port, sender expectation, and smoke-test command.

#### F-1.9 — [severity: med] — [performance] — Pipeline worker and batch sizing is unspecified
- **Location in plan:** Task 4
- **Description:** Three Logstash pipelines with default worker counts can over-parallelize small customer hosts with a 512 MB heap.
- **Suggested change:** Add explicit conservative `pipeline.workers`, `pipeline.batch.size`, and `pipeline.batch.delay`.
- **Rationale (incl. codebase grounding):** The central stack runs with much larger Logstash memory; the static customer forwarder should not silently inherit default worker behavior on small hosts.
- **Decision:** applied
- **Plan diff:** Added explicit worker and batch settings in `customer-forwarder/config/pipelines.yml` plus a validation test.

#### F-1.10 — [severity: med] — [performance] — HTTP forwarding is one event per request
- **Location in plan:** Task 4 and Task 5
- **Description:** Object-per-request HTTP forwarding may bottleneck on high-volume Sysmon input.
- **Suggested change:** Keep object-only delivery in v1, but document the decision, add conservative HTTP output pooling/timeouts, and provide an operator load-smoke helper.
- **Rationale (incl. codebase grounding):** Current `ingest-edge` parses one JSON object and synchronously forwards one request to central Logstash.
- **Decision:** applied
- **Plan diff:** Added HTTP output pool/timeout settings, a `load-smoke.py` helper, and README performance guidance.

#### F-1.11 — [severity: med] — [reusability] — Compose port bindings duplicate `forwarder.yml`
- **Location in plan:** Task 4 and Task 5
- **Description:** Ports are defined in local config and repeated in Compose, risking drift.
- **Suggested change:** Add validation that Compose published ports match enabled source ports.
- **Rationale (incl. codebase grounding):** Existing relay generation derives ports from a single source list before rendering.
- **Decision:** applied
- **Plan diff:** Added `customer-forwarder/test/test_compose_config.py` to compare Compose ports with `ForwarderConfig.enabled_sources()`.

#### F-1.12 — [severity: low] — [UX/reusability] — Error/help polish and schema helper reuse
- **Location in plan:** Task 1 and Task 3
- **Description:** Unknown source errors did not list valid IDs, and source catalog schema validation duplicated existing helper logic.
- **Suggested change:** Improve unknown-source errors and reuse/refactor existing schema validation helper.
- **Rationale (incl. codebase grounding):** `scripts/lib/gitops_config.py` already has centralized jsonschema error formatting.
- **Decision:** applied
- **Plan diff:** Added supported-ID error text and refactored `validate_schema()` through `validate_schema_file()`.

### Iteration summary
- Findings raised: 12 | applied: 12 | rejected: 0 | deferred: 0
- Plan commit: 79492e34ebf4fd5af30fa626beca24116d3e7b3c
