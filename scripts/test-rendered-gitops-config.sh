#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

before="$(git status --porcelain)"
"${PYTHON:-python3}" scripts/render-gitops-config.py
after="$(git status --porcelain)"

if [[ "$before" != "$after" ]]; then
  echo "rendered artifacts are stale; run scripts/render-gitops-config.py and commit the result" >&2
  git status --short >&2
  exit 1
fi

test -f gitops/rendered/logstash/customer-auth.yml
test -f gitops/rendered/logstash/source-routing.yml
test -f gitops/rendered/ingest-edge/customer-auth.yml
test -f gitops/rendered/opensearch/index-templates/logs-acme-firewall-template.json
test -f gitops/rendered/opensearch/security/logstash-writer-role.json

"${PYTHON:-python3}" - <<'PY'
from __future__ import annotations

import json
from pathlib import Path

for path in sorted(Path("gitops/rendered/opensearch/index-templates").glob("*.json")):
    template = json.loads(path.read_text(encoding="utf-8"))
    wildcard_patterns = [pattern for pattern in template["index_patterns"] if pattern.endswith("-*")]
    if wildcard_patterns:
        joined = ", ".join(wildcard_patterns)
        raise SystemExit(f"{path}: generated data-stream templates must use exact patterns, got {joined}")

role = json.loads(Path("gitops/rendered/opensearch/security/logstash-writer-role.json").read_text(encoding="utf-8"))
if "cluster:monitor/main" not in role["cluster_permissions"]:
    raise SystemExit("logstash writer role must allow cluster:monitor/main for output plugin health checks")
for permission in role["index_permissions"]:
    if "indices:data/write/bulk*" not in permission["allowed_actions"]:
        raise SystemExit("logstash writer role must allow indices:data/write/bulk* for Logstash bulk writes")
PY

echo "rendered gitops config is current"
