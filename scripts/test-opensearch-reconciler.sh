#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

"${PYTHON:-python3}" -m pytest scripts/test-opensearch-reconciler.py -q

output="$("${PYTHON:-python3}" scripts/reconcile-opensearch-gitops.py --dry-run)"
printf '%s\n' "$output"

grep -q "DRY-RUN PUT /_plugins/_security/api/roles/logstash_writer" <<<"$output"
grep -q "DRY-RUN PUT /_plugins/_security/api/internalusers/logstash_writer" <<<"$output"
grep -q "DRY-RUN PUT /_plugins/_security/api/rolesmapping/logstash_writer" <<<"$output"

echo "opensearch reconciler dry-run passed"
