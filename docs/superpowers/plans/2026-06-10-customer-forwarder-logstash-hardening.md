# Hardening Ledger: 2026-06-10-customer-forwarder-logstash

**Plan:** [2026-06-10-customer-forwarder-logstash.md](./2026-06-10-customer-forwarder-logstash.md)
**Status:** stopped-by-user
**Verified at commit:** 738dbb2ee041a55d8c3a88c23d1a214631fdf124

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

## Iteration 2 — 2026-06-10 17:32

**Dispatched concerns:** ISSUES, UX, reusability, security, performance
**Codebase commit at analysis:** 1fbb42c59cb686cde65aae0b9f32e5897b93ca7f

### Findings

#### F-2.1 — [severity: high] — [ISSUES/security/UX] — Env and CA validation can execute or mutate customer-local material
- **Location in plan:** Task 4, Steps 1, 5-6; Task 5, README
- **Description:** Shell-sourcing `.env` breaks quoted heap values and can execute command substitution before validation. The validation wrapper also planned to create or touch `customer-forwarder/.env` and `customer-forwarder/certs/central-ca.crt`, which could hide fake local trust material under ignored paths.
- **Suggested change:** Parse env files as data, quote `LS_JAVA_OPTS` in `.env.example`, never shell-source `.env`, validate heap/memory sizing, restrict `CENTRAL_CA_CERT` to the mounted cert directory, require parseable PEM, and use temporary env/cert material for tests.
- **Rationale (incl. codebase grounding):** The plan already ignored customer cert and env paths, so accidental mutation would be invisible in normal status output. Compose also needs shell-safe `.env` values.
- **Decision:** applied
- **Plan diff:** Rewrote env validation around `--env-file`, safe `KEY=value` parsing, CA PEM checks, heap/memory validation, quoted `.env.example`, temp test env/certs, and wrapper logic that does not mutate customer-local secret paths.

#### F-2.2 — [severity: high] — [security] — Local source identity can be spoofed by payload fields
- **Location in plan:** Task 3, Step 9; Task 4, Step 4; Task 5 parser smoke
- **Description:** Inputs added routing fields directly to the event body, while parser branches and central routing trust `siem.source_id`. A sender could submit forged `siem.source_id`, `customer`, or routing fields to the wrong local port.
- **Suggested change:** Store configured source metadata in `@metadata`, remove untrusted routing fields at the parse boundary, and then replace `siem.source_id`, `event.dataset`, `observer.type`, and `observer.name` from metadata.
- **Rationale (incl. codebase grounding):** Central `ingest-edge` preserves client-provided `siem.source_id`, and central Logstash routes on it, so the customer forwarder must canonicalize before forwarding.
- **Decision:** applied
- **Plan diff:** Updated `00-inputs.conf.j2`, added canonicalization to `10-parse-input.conf`, and added parser smoke coverage with a forged Windows AD payload proving the configured port wins.

#### F-2.3 — [severity: med] — [ISSUES] — Parser fixtures are created but not exercised
- **Location in plan:** Task 5, Steps 1, 4, 6
- **Description:** Static fixtures existed, but required tests only checked config syntax and did not prove parser output fields.
- **Suggested change:** Add a Docker-backed parser smoke that runs Logstash with a file output, sends all v1 fixtures, and asserts normalized source IDs, datasets, observer name, `event.original`, and `event.ingested`.
- **Rationale (incl. codebase grounding):** Logstash config syntax checks do not catch field-branching mistakes in parser filters.
- **Decision:** applied
- **Plan diff:** Added `customer-forwarder/scripts/parser-smoke.py` and included it in `scripts/test-customer-forwarder.sh` with Docker-unavailable skip behavior.

#### F-2.4 — [severity: med] — [reusability] — Legacy relay bundle treats non-syslog catalog inputs as syslog
- **Location in plan:** Task 2, Step 4
- **Description:** Updating relay tests to expect Windows source ports would make the legacy relay advertise Windows AD/Sysmon as syslog, conflicting with the catalog input type and the new HTTP JSON forwarder.
- **Suggested change:** Keep `relay/` as a syslog-only compatibility path and filter relay sources by catalog `input: syslog`.
- **Rationale (incl. codebase grounding):** `relay/templates/pipeline.conf.j2` renders only syslog inputs, while `windows-ad` and `windows-sysmon` are cataloged as `winlogbeat-json`.
- **Decision:** applied
- **Plan diff:** Updated relay generator steps and tests to include only `generic-syslog` and assert Windows sources are absent from relay output.

#### F-2.5 — [severity: med] — [performance] — Persistent queue sizing lacks disk headroom validation
- **Location in plan:** Task 3, Steps 5, 7-8; Task 5 README
- **Description:** Queue and DLQ values were regex-validated but not checked for semantic bounds or available disk headroom.
- **Suggested change:** Parse size values, enforce sane minimum/maximum limits, reject DLQ larger than queue, and add a disk free-space preflight with 20% headroom.
- **Rationale (incl. codebase grounding):** Persistent queue is the outage buffer; bad sizing fails at runtime or exhausts customer disk.
- **Decision:** applied
- **Plan diff:** Added queue size parsing, semantic validation, disk-headroom helper, tests, and README disk guidance.

#### F-2.6 — [severity: med] — [UX] — README run path bypasses env validation
- **Location in plan:** Task 5, Step 9
- **Description:** Customer instructions validated and rendered config but did not run the env validator operators depend on before `docker compose up`.
- **Suggested change:** Include `scripts/validate-env.py --env-file .env` in the documented validation path.
- **Rationale (incl. codebase grounding):** The runtime wrapper validates env before Docker config validation; operator docs should match the supported path.
- **Decision:** applied
- **Plan diff:** Added env validation to `customer-forwarder/README.md` before the run command.

#### F-2.7 — [severity: med] — [UX] — Windows input wording implies native Beats protocol
- **Location in plan:** Task 5, Step 9
- **Description:** The README called Windows inputs "Winlogbeat-compatible", which could be read as native Beats input support even though the forwarder exposes HTTP JSON inputs.
- **Suggested change:** State that Windows inputs require HTTP POST JSON shaped like Winlogbeat events, not native Beats protocol.
- **Rationale (incl. codebase grounding):** The planned inputs use Logstash `http` with JSON codec on ports `8081` and `8082`, not a Beats input.
- **Decision:** applied
- **Plan diff:** Updated the README input table sender expectations for `windows-ad` and `windows-sysmon`.

#### F-2.8 — [severity: med] — [reusability] — Catalog drift guards miss schema and duplicate dataset checks
- **Location in plan:** Task 3, Steps 2, 5, 7; Task 5, Step 2
- **Description:** The copied catalog test compared only `sources.yml`, and local catalog loading only checked duplicate IDs.
- **Suggested change:** Compare copied `sources.schema.json` too and enforce duplicate dataset rejection in the local catalog loader.
- **Rationale (incl. codebase grounding):** Central catalog loading rejects duplicate datasets, so customer-forwarder validation should preserve the same invariant.
- **Decision:** applied
- **Plan diff:** Added schema-copy test and duplicate-dataset validation/test in `forwarder_config.py`.

#### F-2.9 — [severity: med] — [performance] — Load smoke can pass while output backs up
- **Location in plan:** Task 5, Step 5
- **Description:** The load smoke helper measured client-side POST status/rate only, so it could pass while the output pipeline was stalled or queues were growing.
- **Suggested change:** Add optional concurrency and Logstash `_node/stats/pipelines` monitoring, then fail if output events do not advance or queued events grow unexpectedly.
- **Rationale (incl. codebase grounding):** Logstash accepts local input independently from downstream HTTPS forwarding, so input success is not delivery success.
- **Decision:** applied
- **Plan diff:** Extended `load-smoke.py` with `--monitor-url`, `--concurrency`, output event checks, queue growth checks, and README guidance.

#### F-2.10 — [severity: med] — [UX/performance] — Runtime guardrails are missing from Compose
- **Location in plan:** Task 4, Steps 1-2, 5; Task 5, Step 3
- **Description:** The planned Compose service had no container memory ceiling, log rotation, or heap-vs-memory validation.
- **Suggested change:** Add `FORWARDER_MEM_LIMIT`, `mem_limit`, JSON-file log rotation, and validation that `LS_JAVA_OPTS` is well formed and below the memory ceiling.
- **Rationale (incl. codebase grounding):** The customer forwarder is intended for small customer hosts and should not silently consume unbounded logs or memory.
- **Decision:** applied
- **Plan diff:** Added Compose logging/memory guardrails, `.env.example` memory setting, env heap validation, and Compose guardrail tests.

#### F-2.11 — [severity: low] — [UX] — `forwarder_name` is not emitted in events
- **Location in plan:** Task 3, Step 9; Task 4, Step 4; Task 5 tests
- **Description:** `forwarder_name` was configurable but not visible in forwarded events.
- **Suggested change:** Emit it as `observer.name` from trusted metadata.
- **Rationale (incl. codebase grounding):** Central operators need to distinguish customer-side forwarder instances without trusting event-body fields.
- **Decision:** applied
- **Plan diff:** Added `forwarder_name` to rendered source metadata, canonicalized it to `[observer][name]`, and asserted it in tests and parser smoke.

#### F-2.12 — [severity: low] — [security/reusability] — Dependency and parser enum drift can age the package
- **Location in plan:** Task 1, Step 4; Task 3, Step 1
- **Description:** The central GitOps source schema duplicated the parser enum already controlled by the catalog, and the forwarder pinned an older Jinja2 patch level.
- **Suggested change:** Make the GitOps source parser field a safe string pattern and rely on catalog matching for exact values; pin Jinja2 to a patched 3.1.x baseline.
- **Rationale (incl. codebase grounding):** Parser membership should be maintained in one catalog, and customer-distributed dependencies should not start from stale patch pins.
- **Decision:** applied
- **Plan diff:** Replaced the GitOps parser enum with a safe pattern and updated `customer-forwarder/requirements.txt` to `Jinja2==3.1.6` with a note to keep a patched 3.1.x baseline.

### Iteration summary
- Findings raised: 12 | applied: 12 | rejected: 0 | deferred: 0
- Plan commit: 738dbb2ee041a55d8c3a88c23d1a214631fdf124

## Iteration 3 — 2026-06-11 09:41

**Dispatched concerns:** ISSUES, UX, reusability, security, performance
**Codebase commit at analysis:** 4cf0a8ac3bcbf54b09ae3d0e85c131a9c9d199b9

### Findings

#### F-3.1 — [severity: high] — [ISSUES] — Clean-checkout Logstash validation still depended on local `.env` and ignored certs
- **Location in plan:** Task 4, Step 6
- **Description:** The wrapper validated through the main Compose file, so a clean checkout could still fail on a missing `.env` or accidentally use customer-local ignored material.
- **Suggested change:** Generate temp env, CA, HTTP cert material, and a standalone validation Compose file under a temp project directory.
- **Decision:** applied
- **Plan diff:** Replaced the wrapper with a temp-only validation path and added an early resolved-digest check before Docker validation.

#### F-3.2 — [severity: med] — [security/UX] — Windows HTTP collectors needed a deployable sender/security contract
- **Location in plan:** Task 3, Task 4, Task 5 README
- **Description:** Windows AD/Sysmon HTTP ports were documented as plain HTTP examples without a production sender path or local collector authentication.
- **Suggested change:** Require Logstash HTTP input TLS, Basic auth, and client-certificate authentication; document sender requirements and provide Windows examples.
- **Decision:** applied
- **Plan diff:** Added `http_collector` config/schema, HTTP input TLS/auth rendering, `.env.example` credentials, `http-certs` volume, README curl examples, and `examples/windows/` sender docs/script.

#### F-3.3 — [severity: med] — [security] — CA validation accepted fake PEM wrappers
- **Location in plan:** Task 4, Step 5
- **Description:** `ssl.PEM_cert_to_DER_cert` could accept syntactic wrappers that were not usable CA trust files.
- **Suggested change:** Validate CA files with `ssl.create_default_context(cafile=...)` and generate real temporary CA material in tests.
- **Decision:** applied
- **Plan diff:** Updated validation and tests to use real self-signed CA generation plus a fake PEM negative test.

#### F-3.4 — [severity: med] — [security/reusability] — Central credential ID validation was looser than the catalog contract
- **Location in plan:** Task 4, Step 5
- **Description:** Forwarder credentials allowed uppercase, dots, colons, and underscores even though central IDs should use the same stable lowercase slug convention.
- **Suggested change:** Enforce `^[a-z][a-z0-9-]{1,40}$` and add negative tests.
- **Decision:** applied
- **Plan diff:** Added `CENTRAL_CREDENTIAL_ID_RE` and tests for uppercase, underscore, dot, colon, and overlong IDs.

#### F-3.5 — [severity: med] — [ISSUES] — Parser branches had duplicate mutate replacement blocks and weak smoke assertions
- **Location in plan:** Task 4 parser files; Task 5 parser smoke
- **Description:** AD and Sysmon parser branches used repeated `replace` blocks, and smoke coverage did not prove AD 4625 failure or Sysmon event 3 network classification.
- **Suggested change:** Merge `replace` hashes and assert the important parser outputs in the Docker-backed smoke.
- **Decision:** applied
- **Plan diff:** Merged parser replacements, changed the Sysmon fixture to event ID 3, and added parser-smoke assertions for AD action/outcome and Sysmon network action/category.

#### F-3.6 — [severity: med] — [ISSUES] — Parser smoke bound fixed host ports
- **Location in plan:** Task 5 parser smoke
- **Description:** Fixed localhost ports made the smoke test flaky on developer and CI hosts.
- **Suggested change:** Let Docker allocate host ports dynamically and inspect the mapped ports before sending fixtures.
- **Decision:** applied
- **Plan diff:** Parser smoke now publishes `127.0.0.1::container_port`, resolves mapped ports with `docker port`, and sends to those mapped ports.

#### F-3.7 — [severity: med] — [reusability] — Relay generation still bypassed full catalog validation
- **Location in plan:** Task 2, Step 4
- **Description:** The relay helper directly read desired source YAML and could miss the same dataset/parser enforcement used by central GitOps.
- **Suggested change:** Have relay generation call `load_source_catalog()`, `load_customers()`, `load_retention_policy_names()`, and `load_sources(...)` before filtering syslog sources.
- **Decision:** applied
- **Plan diff:** Replaced the direct enumeration path and added a relay regression requiring catalog mismatch failures to surface.

#### F-3.8 — [severity: med] — [performance/ISSUES] — Disk sizing undercounted multi-pipeline persistent queues
- **Location in plan:** Task 3, Task 4, Task 5 README
- **Description:** Global persisted queues across three pipelines would consume more disk than the one-queue headroom formula.
- **Suggested change:** Persist only the output pipeline, keep upstream pipelines in-memory, and test the queue scope.
- **Decision:** applied
- **Plan diff:** Added `queue.type: memory` to `inputs` and `parse-and-normalize`, `queue.type: persisted` to `output-ingest-edge`, and tests/documentation for one queue plus one DLQ.

#### F-3.9 — [severity: med] — [performance] — Load smoke could pass while output was backed up
- **Location in plan:** Task 5 load smoke
- **Description:** The helper accepted client-side POST success without requiring output pipeline progress or bounded queue growth.
- **Suggested change:** Require output `events.out` advancement by count or threshold and default max queue growth to zero.
- **Decision:** applied
- **Plan diff:** Added `validate_stats_progress()`, `--min-output-events`, `--max-queue-growth`, HTTPS/auth options, and unit tests for output delta and queue growth.

#### F-3.10 — [severity: med] — [UX/reusability] — Central-to-customer handoff and first-run proof were missing
- **Location in plan:** Task 5 README; Task 6 summary
- **Description:** The plan did not state what central operators must hand to customers or what evidence proves the first run worked.
- **Suggested change:** Add a handoff checklist and first-run proof commands/output expectations.
- **Decision:** applied
- **Plan diff:** Added README handoff/proof section and final summary bullets for credential/catalog handoff and runtime proof.

#### F-3.11 — [severity: med] — [reusability] — Catalog snapshot lacked sync provenance
- **Location in plan:** Task 3, Task 5 catalog-copy tests
- **Description:** The copied catalog had no generated metadata proving which central commit and files produced it.
- **Suggested change:** Add a sync script and tracked lock file with commit, timestamp, checksums, and supported IDs.
- **Decision:** applied
- **Plan diff:** Added `sync-source-catalog.py`, `source-catalog.lock`, endpoint-helper copy, checksum assertions, and lock-content tests.

#### F-3.12 — [severity: med] — [reusability/ISSUES] — Parser catalog values were not reused for dispatch
- **Location in plan:** Task 3 input template; Task 4 parser filters; Task 5 compose tests
- **Description:** Parser branches keyed off `siem.source_id` instead of the catalog parser value, creating drift risk if parser names and source IDs ever differ.
- **Suggested change:** Render `[@metadata][forwarder][parser]` from the catalog and branch on that metadata.
- **Decision:** applied
- **Plan diff:** Added parser metadata rendering, canonical `siem.parser`, parser-branch conditions by metadata, and a test that every catalog parser has a pipeline branch.

#### F-3.13 — [severity: low] — [security/reusability] — Dependencies and image were pinned but not locked
- **Location in plan:** Task 3 dependencies; Task 4 Compose; Task 5 tests
- **Description:** Python dependencies and the Logstash image used exact-looking versions without hashes or immutable image digest enforcement.
- **Suggested change:** Add a hash-locked `requirements.lock` and require the Logstash image to include a resolved `@sha256:` digest.
- **Decision:** applied
- **Plan diff:** Added `requirements.lock` generation/install instructions, image digest resolution instructions, Compose/static tests, parser-smoke digest check, and wrapper guardrail.

#### F-3.14 — [severity: low] — [reusability] — Central ingest URL validation was duplicated
- **Location in plan:** Task 2 relay generation; Task 3 sync; Task 4 env validation; Task 5 catalog-copy tests
- **Description:** Relay and customer-forwarder validation could diverge because each owned its own central HTTPS URL parser.
- **Suggested change:** Extract shared endpoint validation and copy it into the customer package with shared test vectors.
- **Decision:** applied
- **Plan diff:** Added `scripts/lib/endpoint_validation.py`, copied it through the forwarder sync script, imported it in `validate-env.py`, and added copy/vector tests.

### Iteration summary
- Findings raised: 14 | applied: 14 | rejected: 0 | deferred: 0
- Plan commit: pending
