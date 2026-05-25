# Hardening Ledger: 2026-05-25-opensearch-siem-improvements

**Plan:** [2026-05-25-opensearch-siem-improvements.md](./2026-05-25-opensearch-siem-improvements.md)
**Status:** in-progress
**Verified at commit:** abbc02251ebe173323964b65e4adaa4dd0ebdb34

---

## Iteration 1 — 2026-05-25 19:46

**Dispatched concerns:** ISSUES, UX, reusability, security, performance
**Codebase commit at analysis:** uncommitted (no commits yet in repo)

### Findings

28 raw findings from 5 subagents. Triage: 6 confirmations/noise dropped (e.g. "existing tests still pass", "field stripping is sound"), 4 merged (Phase D/F ordering ×2; env-var doc overlaps). 18 actionable, all approved and applied.

#### F-1.1 — [high] — [performance] — Cache secret_value() with mtime
- **Location in plan:** Phase A, Task 1
- **Decision:** applied
- **Plan diff:** Renamed Task 1 to cover config + secrets; added `_SECRET_CACHE` impl, a mtime-refresh test, updated commit message.

#### F-1.2 — [high] — [performance] — Reuse module-level requests.Session to Logstash
- **Location in plan:** Phase A, Task 6
- **Decision:** applied
- **Plan diff:** Added pooled `SESSION` + `HTTPAdapter`, switched `do_POST` to `SESSION.post`, added `test_module_uses_shared_session`, and a note to repoint the two existing `app.requests.post` monkeypatches to `app.SESSION.post`.

#### F-1.3 — [high] — [UX] — siem-status.py graceful error on missing creds
- **Location in plan:** Phase C, Task 9
- **Decision:** applied (folded into F-1.10 shared helper)
- **Plan diff:** `opensearch_auth()` (shared) raises `SystemExit` with guidance; `main()` uses it; OpenSearch/Logstash unreachable now produce readable errors not tracebacks.

#### F-1.4 — [med] — [issues] — Pin exact reconcile() ordering
- **Location in plan:** Phase D Task 10 + Phase F Task 12
- **Decision:** applied
- **Plan diff:** Added canonical 6-step ordering to Task 10; Task 12 pins data-stream loop to position 4 (after ISM, before roles); report_drift is final statement.

#### F-1.5 — [med] — [security] — Validate source id/dataset charset in relay generator
- **Location in plan:** Phase E, Task 11
- **Decision:** applied
- **Plan diff:** Added `SAFE = ^[a-z0-9_-]+$` guard at the config-emission point (autoescape=False / unescaped interpolation into Logstash .conf).

#### F-1.6 — [med] — [UX] — Audit log include attempted credential on rejection
- **Location in plan:** Phase A, Task 5
- **Decision:** applied
- **Plan diff:** `reject(..., credential="-")` logs credential; do_POST passes username to the 403 paths; explicit "never log password" note.

#### F-1.7 — [med] — [UX] — Phase I: enumerate README TLS edits + OPENSEARCH_CA in .env
- **Location in plan:** Phase I, Task 15 & Task 17
- **Decision:** applied
- **Plan diff:** Task 15 adds `OPENSEARCH_CA` to generated `.env`; Task 17 Step 4 enumerates each `curl -k`/insecure site to change plus a grep verification.

#### F-1.8 — [med] — [UX] — Drift report prints remediation command
- **Location in plan:** Phase D, Task 10
- **Decision:** applied
- **Plan diff:** `report_drift` now prints a `curl -X DELETE …/_index_template/<name>` line per orphan.

#### F-1.9 — [med] — [issues] — Phase I: verify security index initializes with custom certs
- **Location in plan:** Phase I, Task 16
- **Decision:** applied
- **Plan diff:** Added Step 4 (log-check for security-index init) with a `securityadmin.sh` fallback; renumbered commit step.

#### F-1.10 — [med] — [reusability] — Extract shared opensearch_auth/verify helper
- **Location in plan:** Phase C (new Task 8b) + Phase I Task 17
- **Decision:** applied
- **Plan diff:** New Task 8b creates `scripts/lib/opensearch_client.py` (+test); siem-status and reconciler import it; removed duplicate `_verify()`.

#### F-1.11 — [med] — [reusability] — Relay generator reuse source enumeration
- **Location in plan:** Phase E, Task 11
- **Decision:** applied
- **Plan diff:** Added `enabled_sources_for_customer()` to `gitops_config.py`; relay generator imports it via sys.path instead of re-globbing; renumbered steps; added lib to commit.

#### F-1.12 — [low] — [security] — gitignore secrets/certs/*.srl
- **Location in plan:** Phase I, Task 15
- **Decision:** applied
- **Plan diff:** Step 3 adds `*.srl` ignore + verifies; commit adds `.gitignore`.

#### F-1.13 — [low] — [security] — Comment enforce_hostname_verification=false as single-node-only
- **Location in plan:** Phase I, Task 16
- **Decision:** applied
- **Plan diff:** Added explanatory comment in opensearch.yml.

#### F-1.14 — [low] — [issues] — CI pip caching
- **Location in plan:** Phase H, Task 14
- **Decision:** applied
- **Plan diff:** Added `cache: pip` + `cache-dependency-path` to setup-python.

#### F-1.15 — [low] — [reusability] — Reuse applied template names for drift
- **Location in plan:** Phase D, Task 10
- **Decision:** applied
- **Plan diff:** Replaced `desired_template_names()` re-glob with `applied_template_names` accumulated in the apply loops, passed to `report_drift(base_url, desired_names)`.

#### F-1.16 — [low] — [UX] — Document /health in README
- **Location in plan:** Phase A, Task 4
- **Decision:** applied
- **Plan diff:** Added a "Check ingest-edge health" README step; renumbered commit step; README added to commit.

#### F-1.17 — [low] — [performance] — Filter _cat/indices to logs-*/alerts-*
- **Location in plan:** Phase C, Task 9
- **Decision:** applied
- **Plan diff:** `_cat/indices/logs-*,alerts-*` to bound payload; note on empty-match behavior.

#### F-1.18 — [low] — [docs] — Record deferred optimizations
- **Location in plan:** Self-review
- **Decision:** applied
- **Plan diff:** Added "Deferred optimizations" subsection (NDJSON batching, MAX_CONCURRENCY tuning, data-stream existence batching); refreshed type-consistency list.

### Dropped in triage (not applied)
- Confirmations that existing tests still pass (ISSUES #2/#3, security #6) — no action needed.
- "field stripping is sound" (security) — confirmation.
- event.ingested mapping "verify both edits" (ISSUES #7) — plan already does both.
- OPENSEARCH_PASSWORD-in-.env (UX #2) — rejected; README already maps `OPENSEARCH_PASSWORD="$OPENSEARCH_ADMIN_PASSWORD"` inline, and F-1.3/F-1.10 cover the failure mode.

### Iteration summary
- Findings raised: 18 (after triage) | applied: 18 | rejected: 0 | deferred: 0
- Plan commit: abbc02251ebe173323964b65e4adaa4dd0ebdb34
