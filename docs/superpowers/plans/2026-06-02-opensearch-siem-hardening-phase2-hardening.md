# Hardening Ledger: 2026-06-02-opensearch-siem-hardening-phase2

**Plan:** [2026-06-02-opensearch-siem-hardening-phase2.md](./2026-06-02-opensearch-siem-hardening-phase2.md)
**Status:** in-progress
**Verified at commit:** b3ce644b77f28b8ceb598fa9511919d088187a26

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
- Plan commit: pending
