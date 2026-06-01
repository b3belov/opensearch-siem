#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export PYTHONPYCACHEPREFIX="$repo_root/.pytest_cache/pycache"

"${PYTHON:-python3}" -m py_compile ingest-edge/app.py
"${PYTHON:-python3}" -m pytest scripts/test-ingest-edge.py scripts/test-ingest-edge-e2e.py -q

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker build -f ingest-edge/Dockerfile -t opensearch-siem-ingest-edge:test .
else
  echo "docker unavailable; skipped ingest-edge image build"
fi

echo "ingest-edge tests and build passed"
