# Hardening Ledger: 2026-06-02-opensearch-siem-hardening-phase2

**Plan:** [2026-06-02-opensearch-siem-hardening-phase2.md](./2026-06-02-opensearch-siem-hardening-phase2.md)
**Status:** in-progress
**Verified at commit:** 0d74a33ad4a90a663082fd78dc5fd6a42fff97d0

---

## Iteration 1 — 2026-06-02

**Dispatched concerns:** ISSUES, UX, reusability, security, performance
**Codebase commit at analysis:** b3ce644b77f28b8ceb598fa9511919d088187a26

### Findings

22 raw findings from 5 subagents. Triage: 10 confirmations/noise dropped (agents self-concluded "no issue" or "plan is correct"), 0 merged across axes. 12 actionable, all approved and applied.

#### F-1.1 — [high] — [security] — Backup TLS fallback to -k undermines the fix
- **Location in plan:** Task 3, Step 2
- **Decision:** applied
- **Plan diff:** Replaced silent fallback to `curl -k` with fail-closed `exit 1` when `OPENSEARCH_CA` is unset or file missing.

#### F-1.2 — [high] — [reusability] — Reconciler duplicates opensearch_auth() from shared library
- **Location in plan:** Task 10, Step 3
- **Decision:** applied
- **Plan diff:** Import `opensearch_auth` from shared `scripts/lib/opensearch_client.py` alongside `opensearch_verify`; delete local duplicate at lines 69-70; updated commit message.

#### F-1.3 — [high] — [UX] — .env.example incomplete: missing BACKUP_USER, BACKUP_PASSWORD, SNAPSHOT_REPOSITORY
- **Location in plan:** Task 11, Step 1
- **Decision:** applied
- **Plan diff:** Added `BACKUP_USER=admin`, `BACKUP_PASSWORD=`, `SNAPSHOT_REPOSITORY=siem-snapshots` to `.env.example`.

#### F-1.4 — [high] — [performance] — Docker memory limits too tight for 2g JVM heap
- **Location in plan:** Task 5, Step 1
- **Decision:** applied
- **Plan diff:** Changed `mem_limit` from `4g` to `6g` for both `opensearch` and `central-logstash`; updated sizing rationale and total calculation.

#### F-1.5 — [med] — [issues] — report["allocation"] silently removed (breaking change)
- **Location in plan:** Task 8, Step 3
- **Decision:** applied
- **Plan diff:** Kept `report["allocation"] = alloc` for backward compatibility alongside the new `report["cluster"]` disk fields.

#### F-1.6 — [med] — [UX] — DLQ status output lacks actionable guidance
- **Location in plan:** Task 7
- **Decision:** applied
- **Plan diff:** Added Step 5 "Document DLQ fields in README" with operator guidance on what DLQ values mean and what to do; renumbered commit to Step 6; README added to commit.

#### F-1.7 — [med] — [UX] — Resource limits not documented for operator tuning
- **Location in plan:** Task 5
- **Decision:** applied
- **Plan diff:** Added Step 3 "Document resource limits in README" with sizing table and tuning guidance; renumbered commit to Step 4; README added to commit.

#### F-1.8 — [med] — [UX] — New log messages (upstream_error, reconciler format) not documented
- **Location in plan:** Task 2 and Task 10
- **Decision:** applied
- **Plan diff:**
  - Task 2: Added Step 5 "Document upstream_error in README" with investigation steps; renumbered commit to Step 6; README added to commit.
  - Task 10: Added Step 5 "Document reconciler log format in README" with sample output; renumbered commit to Step 6.

#### F-1.9 — [med] — [UX] — Relay URL should fail fast, not default to example.com
- **Location in plan:** Task 12, Step 1
- **Decision:** applied
- **Plan diff:** Replaced `os.environ.get("RELAY_CENTRAL_URL", "https://siem.example.com:5044")` with fail-fast check that raises `SystemExit` when unset; updated test command to pass `RELAY_CENTRAL_URL=...`.

#### F-1.10 — [low] — [UX] — Backup repository error message syntax hard to copy-paste
- **Location in plan:** Task 4, Step 1
- **Decision:** applied
- **Plan diff:** Replaced multi-echo error message with heredoc `cat >&2 <<ERRMSG` block with properly formatted curl example and docs link.

#### F-1.11 — [low] — [security] — Reconciler put_json has no guard against future password logging
- **Location in plan:** Task 10, Step 3
- **Decision:** applied
- **Plan diff:** Added comment to `put_json`'s log line: "Log the path only -- body may contain passwords (e.g. internalusers endpoint)."

#### F-1.12 — [low] — [performance] — Healthcheck curl | grep could be simplified
- **Location in plan:** Task 9, Step 1
- **Decision:** applied
- **Plan diff:** Simplified healthcheck from `curl -sf ... | grep -q '"events"'` to `curl -sf ... >/dev/null 2>&1`; updated rationale.

### Dropped in triage (not applied)
- ISSUES-1: "Task 1 references non-existent create_ssl_context()" — agent self-concluded "correct per TDD."
- ISSUES-3: "import logging location ambiguous" — plan specifies "after line 11" which is unambiguous.
- ISSUES-4: "Logging setup before argparse" — stylistic preference, both orderings work.
- ISSUES-5: "Plan refers to backup-job volumes without location" — plan says "under backup-job.volumes" which is clear.
- SEC-3: "Upstream error log could leak sensitive data" — agent concluded "logging is safe, no change needed."
- SEC-4: "Logstash healthcheck curl flags" — agent concluded "safe for localhost, no fix needed."
- SEC-5: ".env.example documents default values" — agent concluded "plan complies, no code change needed."
- PERF-2: "DLQ stats already in existing API response" — confirmation, no extra calls.
- PERF-3: "Cluster summary extra API call" — confirmation, call count unchanged.
- PERF-4: "Reconciler logging overhead" — confirmation, negligible.

### Iteration summary
- Findings raised: 12 (after triage) | applied: 12 | rejected: 0 | deferred: 0
- Plan commit: 0d74a33ad4a90a663082fd78dc5fd6a42fff97d0

## Iteration 2 — 2026-06-02

**Dispatched concerns:** ISSUES, UX, security, reusability+performance (combined)
**Codebase commit at analysis:** 0d74a33ad4a90a663082fd78dc5fd6a42fff97d0

### Findings

18 raw findings from 4 subagents. Triage: 12 dropped (wrong premises — backup-job already has volumes section; Docker bind mounts create directories; reconciler/ingest-edge run in separate containers; backup repo check runs infrequently; ingest-edge healthcheck not touched by plan; x-logging has no conflicts; caplog overhead negligible; log format difference is by design; relay bundle ops guide is scope creep). 1 merged (ISSUES F-2.1 + ISSUES F-2.4 + UX-2.1 all describe same CI breakage). 5 actionable, all approved and applied.

#### F-2.1 — [high] — [issues+UX, merged] — CI workflow breaks: relay bundle test needs RELAY_CENTRAL_URL
- **Location in plan:** Task 12 (interaction with `.github/workflows/ci.yml:38`)
- **Decision:** applied
- **Plan diff:** Added Step 3 to Task 12: update CI workflow relay bundle test step to pass `RELAY_CENTRAL_URL=https://siem.example.com:5044`; renumbered commit to Step 4; `.github/workflows/ci.yml` added to commit.

#### F-2.2 — [med] — [security] — Backup script validates CA but not credentials
- **Location in plan:** Task 3, Step 2
- **Decision:** applied
- **Plan diff:** Added credential validation check (`OPENSEARCH_USER`/`OPENSEARCH_PASSWORD`) before the CA check in `backup-opensearch.sh`.

#### F-2.3 — [med] — [UX] — Backup TLS requirement undocumented for operators
- **Location in plan:** Task 3
- **Decision:** applied
- **Plan diff:** Added Step 4 "Document backup prerequisites in README" covering credentials, TLS, and repository requirements; renumbered commit to Step 5; README added to commit.

#### F-2.4 — [low] — [UX] — Log rotation settings worth brief README mention
- **Location in plan:** Task 6
- **Decision:** applied
- **Plan diff:** Added Step 3 "Document log rotation in README" as a one-liner in the resource configuration section; renumbered commit to Step 4; README added to commit.

#### F-2.5 — [low] — [security] — create_ssl_context() could restrict cipher suites
- **Location in plan:** Task 1, Step 3
- **Decision:** applied
- **Plan diff:** Added `context.set_ciphers(...)` with modern forward-secrecy cipher string after `minimum_version` in `create_ssl_context()`.

### Dropped in triage (not applied)
- ISSUES F-2.2: "backup-job has no volumes section" — wrong premise; backup-job has volumes at lines 137-139.
- ISSUES F-2.3: "Alpine lacks /etc/siem directory" — Docker bind mounts create target directories automatically.
- ISSUES F-2.5: "opensearch_auth behavior change" — agent self-concluded "not an issue, intended improvement."
- SEC F-2.1: "ingest-edge healthcheck may leak info" — plan doesn't modify ingest-edge healthcheck; out of scope.
- SEC F-2.2: "reconciler tests don't cover missing env var" — already covered by test-opensearch-client.py at the shared lib level.
- REUSE F-2.1: "backup repo check adds latency" — runs once per backup invocation (infrequent), trivial overhead.
- REUSE F-2.2: "logging pattern inconsistency" — wrong premise; services run in separate containers/processes.
- REUSE F-2.3: "caplog overhead in tests" — agent assessed as "low priority", 10-50ms negligible.
- REUSE F-2.4: "log format differs between services" — intentional (audit vs operational), not a bug.
- REUSE F-2.5: "x-logging anchor conflicts" — no existing x-* blocks in docker-compose.yml.
- UX-2.2: "healthcheck change not documented" — infrastructure detail visible via `docker compose ps`, not operator-facing.
- UX-2.5: "relay bundle ops guide" — scope creep beyond this plan.

### Iteration summary
- Findings raised: 5 (after triage) | applied: 5 | rejected: 0 | deferred: 0
- Plan commit: pending
